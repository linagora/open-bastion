# PAM Access plugin for LemonLDAP::NG
#
# This plugin provides:
# - /pam : Web interface for users to generate temporary PAM access tokens
# - /pam/verify : Server-to-server endpoint to validate one-time user tokens
# - /pam/authorize : Server-to-server endpoint for authorization checks
#
# User tokens are one-time use tokens stored as sessions (kind=PAMTOKEN).
# They are destroyed after first use for security.
# Server authentication uses Bearer tokens obtained via Device Authorization Grant.

package Lemonldap::NG::Portal::Plugins::PamAccess;

use strict;
use Mouse;
use JSON                                   qw(from_json to_json);
use Digest::SHA                            qw(sha256_hex hmac_sha256_hex);
use Lemonldap::NG::Common::Session;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.22.0';

# Persistent-session key prefix for ephemeral bastion-hop cert fingerprints.
# One key per fingerprint ($EPH_CERT_PREFIX.<fp>) so concurrent hops don't
# clobber each other. See /pam/bastion-cert and _checkSshFingerprint, and the
# note on $VOUCHER_KIND below for what per-key does and does not buy under
# Apache::Session::Lock::Null -- this keyspace still has the limits vouchers
# no longer have, because a hop fingerprint is looked up by value and cannot
# be addressed by a record id the way a (user, bastion_id) voucher can.
our $EPH_CERT_PREFIX = '_pamEphCert::';

# Bastion vouchers live in their own session record, one per (user,
# bastion_id), the way the core stores an authorization code: a
# Common::Session on the global store, carrying its TTL in _utime, with
# kind => 'PAMVOUCHER'.
#
# They used to live in the user's persistent session -- first as a single
# `_pamBastionVouchers` JSON map, then (issue #54) one key per bastion. Both
# shapes made minting a read-modify-write on a hash the store rewrites
# wholesale, which no plugin can make atomic: Apache::Session::Lock::Null is
# installed everywhere and DESTROY serialises the whole data hash. Per-key
# narrowed the losing window to update()'s tie-to-untie; it could not close
# it, and the expiry sweep that kept the keyspace bounded had to decide from
# a snapshot, so it could delete a nonce another bastion had just refreshed.
#
# One record per voucher removes the shared hash, and with it both problems:
# nothing else is written alongside, and the store's own purge bounds the
# keyspace through _utime, so there is no sweep to get wrong.
#
# Both old shapes are still READ, so a voucher minted before the upgrade
# still works. Neither is written or deleted any more: a portal cluster is
# upgraded node by node, and deleting a key an older node still mints into
# would hand that node's users a nonce their shell does not have.
our $VOUCHER_KIND = 'PAMVOUCHER';
our $VOUCHER_PREFIX = '_pamVoucher::';           # legacy, read-only
our $LEGACY_VOUCHER_KEY = '_pamBastionVouchers'; # legacy, read-only

# Persistent-session key prefix under which the ssh-ca plugin stores the
# user's SSO certificates, one per fingerprint (issue #66). Duplicated here
# rather than read from $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_PREFIX
# because pam-access must resolve fingerprints on portals where ssh-ca is not
# loaded (the certificates are still in the session). Keep in sync with
# SSHCA.pm. `_sshCerts` is the pre-upgrade array, still read as a fallback.
our $SSO_CERT_PREFIX = '_sshCert::';

# Signed answers of the /pam/* endpoints (issue #100). A caller asks for one
# with `Accept: $SIGNED_RESPONSE_TYPE`; the JWS carries `typ: $SIGNED_RESPONSE_TYP`
# so that no other token signed by the same key (ID token, logout token,
# signed introspection) can pass for a pam answer. See _respond.
our $SIGNED_RESPONSE_TYPE = 'application/ob-pam-response+jwt';
our $SIGNED_RESPONSE_TYP  = 'ob-pam-response+jwt';
our $SIGNED_RESPONSE_TTL  = 60;

# Shape of an X-Nonce, shared by the request-signature verifier and the
# signed-response binding: what open-bastion sends is <unix_ms>-<uuid-v4>.
our $NONCE_RE = qr{\A[0-9A-Za-z._:-]{1,128}\z};

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'PamAccess';

# Access to OIDC module for token generation/validation
has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

# RP name for PAM tokens
has rpName => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->conf->{pamAccessRp} || 'pam-access' },
);

# One-shot flag for the "no RP allowlist configured" warning emitted by
# _checkCallerRp. Without this, every /pam/* call would log a warning.
has _rpAllowlistWarned => (
    is      => 'rw',
    default => 0,
);

# One-shot flag for the warning emitted by _checkRequestSignature when
# pamAccessRequestSigningMode holds a value it does not recognise.
has _signingModeWarned => (
    is      => 'rw',
    default => 0,
);

# One-shot flag for the legacy-mode warning emitted by _resolveServerGroup
# when pamAccessServerGroups is empty. Without this, every call to
# /pam/authorize would log a warning.
has _serverGroupLegacyWarned => (
    is      => 'rw',
    default => 0,
);

# Steps computing groups and macros of a user looked up without a session.
# LLNG <= 2.23 exposes Main::Run::groupsAndMacros(), which honours the
# `groupsBeforeMacros` option; that option was dropped upstream (#3482) and
# groups are now always computed first.
sub groupsAndMacros {
    my ($self) = @_;
    return $self->p->can('groupsAndMacros')
      ? $self->p->groupsAndMacros
      : qw(setGroups setMacros);
}

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check that OIDC issuer is enabled
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'PamAccess plugin requires OIDC issuer to be enabled');
        return 0;
    }

    # Route for server-to-server authorization (Bearer token auth)
    $self->addUnauthRoute(
        pam => { authorize => '_signed_authorize' },
        ['POST']
      )

      # Route for server heartbeat (refresh token based)
      ->addUnauthRoute(
        pam => { heartbeat => '_signed_heartbeat' },
        ['POST']
      )

      # Route for one-time token verification (server-to-server)
      ->addUnauthRoute(
        pam => { verify => '_signed_verifyToken' },
        ['POST']
      )

      # Route for NSS user info lookup (server-to-server)
      ->addUnauthRoute(
        pam => { userinfo => '_signed_userinfo' },
        ['POST']
      )

      # Route for bastion token generation (bastion -> LLNG)
      # Returns a JWT that proves the bastion has a valid session
      # DEPRECATED: the SendEnv/pam_getenv transport this JWT relied on is
      # Route for an enrolled server to read back its own identity, i.e. the
      # id the portal assigned it at enrollment (server -> LLNG).
      ->addUnauthRoute(
        pam => { whoami => '_signed_whoami' },
        ['POST']
      )

      # Route for bastion ephemeral-certificate vouching (bastion -> LLNG).
      # The bastion sends an ephemeral public key + the (bastion_id, user)
      # voucher minted by /pam/authorize; LLNG returns a short-lived,
      # CA-signed user certificate the bastion uses to connect to the backend.
      ->addUnauthRoute(
        pam => { 'bastion-cert' => 'bastionCert' },
        ['POST']
      )

      # Redirect unauthenticated users to portal for /pam
      ->addUnauthRoute(
        pam => { '*' => 'pamRedirectToPortal' },
        ['GET']
      )

      # Routes for authenticated users (token generation interface)
      ->addAuthRoute(
        pam => { '*' => 'pamInterface' },
        [ 'GET', 'POST' ]
      );

    return 1;
}

# Steps used by the server-to-server endpoints to resolve a user.
#
# Those lookups are not authentication events: nobody is authenticating, and
# $req->address is the calling server, not whoever triggered the lookup.
# Running them through the *named* step pipeline would expose them to every
# plugin hooked on those steps -- the CrowdSec agent reporting a failure
# against the bastion's own address, NewLocationWarning treating that address
# as a new location for the user, and any custom alerting plugin we know
# nothing about.
#
# Main::Process dispatches a coderef step directly, consulting neither
# aroundSub nor afterSub (see Main/Process.pm), so wrapping each step in a
# closure keeps the lookup invisible to all of them at once, without touching
# any other plugin.
sub machineLookupSteps {
    my ($self) = @_;
    my $p = $self->p;
    return [
        map {
            my $step = $_;
            sub { return $p->$step( $_[0] ) }
        } (
            'getUser', 'setSessionInfo',
            $self->groupsAndMacros, 'setLocalGroups'
        )
    ];
}

# ROUTE HANDLERS

# Redirect unauthenticated users to portal (preserving REQUEST_URI)
sub pamRedirectToPortal {
    my ( $self, $req ) = @_;
    $self->p->api->goToPortal( $req, $req->{env}->{REQUEST_URI} );
    return $self->p->sendRedirection($req);
}

# GET /pam - Display the token generation interface (standalone page)
sub pamInterface {
    my ( $self, $req ) = @_;
    return $self->generateToken($req) if $req->method =~ /^post$/i;

    return $self->p->sendHtml(
        $req,
        'pamaccess',
        params => {
            TOKEN      => '',
            LOGIN      => $req->userData->{ $self->conf->{whatToTrace} } || '',
            EXPIRES_IN => '',
            SHOW_TOKEN => 0,
            DEFAULT_DURATION => $self->conf->{pamAccessTokenDuration} || 600,
            MAX_DURATION     => $self->conf->{pamAccessMaxDuration}   || 3600,
            js => "$self->{p}->{staticPrefix}/common/js/pamaccess.js",
        }
    );
}

# POST /pam - Generate a new PAM access token (one-time use)
sub generateToken {
    my ( $self, $req ) = @_;

    # Get requested duration
    my $duration =
      $req->param('duration') || $self->conf->{pamAccessTokenDuration} || 600;

    # Enforce maximum duration
    my $maxDuration = $self->conf->{pamAccessMaxDuration} || 3600;
    $duration = $maxDuration if $duration > $maxDuration;

    my $login  = $req->userData->{ $self->conf->{whatToTrace} };
    my $groups = $req->userData->{groups} || '';

    # Calculate _utime for automatic cleanup by purgeCentralCache
    # _utime + timeout = expiration time
    # So: _utime = now + duration - timeout
    my $now     = time();
    my $timeout = $self->conf->{timeout} || 7200;
    my $utime   = $now + $duration - $timeout;

    # Create one-time token as a session with kind=PAMTOKEN
    my $tokenInfo = {
        _type         => 'pamtoken',
        _utime        => $utime,
        _pamUser      => $login,
        _pamGroups    => $groups,
        _pamUid       => $req->userData->{uid} || $login,
        _pamCreatedAt => $now,
        _pamExpiresAt => $now + $duration,
    };

    # Add exported variables for user provisioning
    my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
    for my $key ( keys %$exportedVars ) {
        my $attr  = $exportedVars->{$key};
        my $value = $req->userData->{$attr};
        $tokenInfo->{"_pamAttr_$key"} = $value
          if defined $value && $value ne '';
    }

    my $tokenSession = $self->p->getApacheSession(
        undef,
        info => $tokenInfo,
        kind => 'PAMTOKEN'
    );

    unless ( $tokenSession && $tokenSession->id ) {
        $self->logger->error('Failed to create PAM token session');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Token generation failed' },
            code => 500
        );
    }

    my $token = $tokenSession->id;
    $self->logger->info(
        "PAM one-time token generated for user $login (TTL: ${duration}s)");

    # Mark this user as known to pam-access on this portal. Its only reader,
    # /pam/bastion-token, is gone (issue #57); the marker is kept because it is
    # the trail issue #10 asks for -- requiring a periodic /pam/verify before
    # sudo -- and stamping it costs one write on a session already being
    # written.
    $self->p->updatePersistentSession( $req, { _pamSeen => time() } );

    # Audit log for token generation
    $self->p->auditLog(
        $req,
        code    => 'PAM_TOKEN_GENERATED',
        user    => $login,
        message =>
          "PAM one-time token generated for user $login (TTL: ${duration}s)",
        ttl => $duration,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            token      => $token,
            login      => $login,
            expires_in => $duration,
        }
    );
}

# POST /pam/authorize - Server-to-server authorization check
sub authorize {
    my ( $self, $req ) = @_;

    # 1-3. Caller gate: a valid Bearer token, obtained through the Device
    #      Authorization Grant, carrying a pam scope (see _checkCaller).
    my ( $tokenSession, $bail ) = $self->_checkCaller( $req, 'authorize' );
    return $bail if $bail;

    # Log server identity from token: the voucher we mint binds to the
    # individual bastion, matching what /pam/bastion-cert checks.
    my $server_id = $self->_callerId($tokenSession);
    $self->logger->info(
        "PAM authorize request from enrolled server: $server_id");

    # 3b. Liveness gate (opt-in, pamAccessHeartbeatRequired): the calling
    #     server must have beaten recently, so a machine whose PAM stack has
    #     stopped reporting can no longer authorize anybody.
    my $hb_bail =
      $self->_checkCallerHeartbeat( $req, $tokenSession, $server_id );
    return $hb_bail if $hb_bail;

    # 4. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM authorize: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user              = $body->{user};
    my $host              = $body->{host}    || '';
    my $service           = $body->{service} || 'ssh';
    my $body_server_group = $body->{server_group};

    unless ($user) {
        return $self->_badRequest( $req, 'Missing user parameter' );
    }

    # Resolve the authoritative server_group for this enrolled client.
    # If pamAccessServerGroups is configured, we enforce the mapping:
    #   - enrolled client_id found  → use the mapped group, reject if the
    #     request body claims a different group;
    #   - enrolled client_id absent → reject (unknown server).
    # If pamAccessServerGroups is empty, fall back to the legacy behaviour
    # (group from body) so existing deployments keep working; a warning is
    # emitted to encourage admins to lock down.
    # pamAccessServerGroups is keyed by OIDC client_id (one client per project,
    # the group shared by every bastion of that project), NOT by the per-device
    # _deviceId. Resolve the group by client_id; $server_id (the _deviceId when
    # present) stays the audit / voucher-binding identity. Passing $server_id
    # here rejected every enrollment carrying a _deviceId, because that digest is
    # never a key in the map ("Unknown enrolled server").
    my $group_client_id = $tokenSession->data->{client_id} // $server_id;
    my $server_group =
      $self->_resolveServerGroup( $req, $group_client_id, $body_server_group,
        'PAM authorize' );
    if ( ref $server_group eq 'HASH' && $server_group->{rejected} ) {
        $self->p->auditLog(
            $req,
            code          => 'PAM_AUTHZ_SERVER_GROUP_MISMATCH',
            user          => $user,
            message       => $server_group->{message},
            host          => $host,
            service       => $service,
            server_id     => $server_id,
            claimed_group => $body_server_group,
            reason        => $server_group->{reason},
        );
        return $self->_forbiddenResponse( $req, $server_group->{message} );
    }

    $self->logger->debug(
"PAM authorize: checking user '$user' for host '$host', service '$service', server_group '$server_group'"
    );

    # 4. Lookup user (without active session)
    $req->user($user);
    $req->data->{_pamAuthorize} = 1;
    $req->steps( $self->machineLookupSteps );

    # Tell Lib::Choice which sub-module to use for this server-to-server
    # getUser/setSessionInfo run (no interactive auth flow available here).
    $req->data->{_authChoice} = $self->conf->{pamAccessChoice}
      if $self->conf->{pamAccessChoice};

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->notice(
"PAM authorize: User '$user' not found, asked by server '$server_id' (error: $error)"
        );

        # Audit log for authorization failure (user not found)
        $self->p->auditLog(
            $req,
            code         => 'PAM_AUTHZ_USER_NOT_FOUND',
            user         => $user,
            message      => "PAM authorization failed: user '$user' not found",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
        );

        return $self->_respond(
            $req,
            {
                authorized => JSON::false,
                user       => $user,
                reason     => 'User not found',
            },
            code => 200
        );
    }

    # 4b. Optional SSH fingerprint binding
    # Same contract as /pam/verify: if the caller provides a 'fingerprint',
    # it must match an active (non-revoked, non-expired) SSH CA certificate
    # in the user's persistent session. This hardens authorize against stale
    # KRLs on the SSH server side.
    my ( $fingerprint, $fp_bail ) = $self->_parseFingerprintOrReject(
        $req, $body, $user,
        label        => 'PAM authorize',
        action       => 'authorization rejected',
        audit_code   => 'PAM_AUTHZ_SSH_FP_MALFORMED',
        audit_code_required => 'PAM_AUTHZ_SSH_FP_REQUIRED',
        audit_fields => {
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
        },
    );
    return $fp_bail if $fp_bail;
    my $sshCheck;    # captured for the bastion-voucher cap below
    if ( defined $fingerprint ) {

        $sshCheck = $self->_checkSshFingerprint( $user, $fingerprint );
        unless ( $sshCheck->{ok} ) {
            $self->logger->info(
                "PAM authorize: SSH fingerprint check failed for user '$user' "
                  . "($sshCheck->{reason})" );
            $self->p->auditLog(
                $req,
                code    => 'PAM_AUTHZ_SSH_FP_REJECTED',
                user    => $user,
                message =>
"PAM authorization denied: SSH fingerprint check failed for user '$user'",
                host         => $host,
                service      => $service,
                server_group => $server_group,
                server_id    => $server_id,
                fingerprint  => $fingerprint,
                reason       => $sshCheck->{reason},
            );
            return $self->_respond(
                $req,
                {
                    authorized => JSON::false,
                    user       => $user,
                    reason     => 'SSH fingerprint not recognized',
                },
                code => 200
            );
        }
        $req->sessionInfo->{_pamSshCertLabel}  = $sshCheck->{label};
        $req->sessionInfo->{_pamSshCertSerial} = $sshCheck->{serial};
    }

    # 5. Evaluate authorization rule based on server_group
    my $result = $self->_checkPamRule( $req, $host, $service, $server_group );
    my $authorized   = $result->{authorized};
    my $sudo_allowed = $result->{sudo_allowed};

    # Get groups for response
    my $groups    = $req->sessionInfo->{groups} || '';
    my @groupList = split /[,;\s]+/, $groups;

    $self->logger->info( "PAM authorize: user '$user' "
          . ( $authorized ? 'granted' : 'denied' )
          . " access to host '$host'"
          . ( $authorized && $sudo_allowed ? ' (sudo allowed)' : '' ) );

    # Audit log for authorization result
    if ($authorized) {
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTHZ_SUCCESS',
            user    => $user,
            message =>
              "PAM authorization granted for user '$user' on host '$host'",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
            groups       => \@groupList,
            sudo_allowed => $sudo_allowed,
        );
    }
    else {
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTHZ_DENIED',
            user    => $user,
            message =>
              "PAM authorization denied for user '$user' on host '$host'",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
            groups       => \@groupList,
            reason       => 'Access denied by rule',
        );
    }

    # Build response with permissions
    my $response = {
        authorized => $authorized ? JSON::true : JSON::false,
        user       => $user,
        groups     => \@groupList,
    };

    # Add permissions for authorized users
    if ($authorized) {
        $response->{permissions} =
          { sudo_allowed => $sudo_allowed ? JSON::true : JSON::false, };

        # Surface the matched SSH cert details when fingerprint binding was
        # used, so the caller can log/cache which key was actually checked.
        if ( defined $req->sessionInfo->{_pamSshCertLabel} ) {
            $response->{ssh_cert_label} = $req->sessionInfo->{_pamSshCertLabel};
        }
        if ( defined $req->sessionInfo->{_pamSshCertSerial} ) {
            $response->{ssh_cert_serial} =
              $req->sessionInfo->{_pamSshCertSerial};
        }

        # Add user attributes for NSS/cache (from exported vars)
        my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
        for my $key ( keys %$exportedVars ) {
            my $attr  = $exportedVars->{$key};
            my $value = $req->sessionInfo->{$attr};
            if ( defined $value && $value ne '' ) {
                $response->{$key} = $value;
            }
        }

        # Check if offline mode is enabled for this user
        my $offlineEnabled = $self->_evaluateOfflineMode($req);
        if ($offlineEnabled) {
            my $offlineTtl = $self->conf->{pamAccessOfflineTtl} || 86400;
            $response->{offline} = {
                enabled => JSON::true,
                ttl     => $offlineTtl,
            };
            $self->logger->debug(
"PAM authorize: offline mode enabled for user '$user' (TTL: ${offlineTtl}s)"
            );
        }

        # Bastion vouching: when the caller is itself a bastion, mint a
        # reusable (bastion_id, user) voucher bound to this real connection.
        # The bastion later presents it to /pam/bastion-cert to obtain
        # short-lived certs for THIS user only — closing the hole where a
        # bastion could vouch for any user it never saw. Bound to the user's
        # SSO cert lifetime when a fingerprint matched above.
        #
        # Only the interactive SSH login issues a voucher. A sudo elevation on
        # the bastion ('sudo'/'sudo-i', canonicalized to 'sudo' by the PAM
        # module) also reaches /pam/authorize, but a sudo authorization check
        # must have no voucher side effect at all — neither rotating the stored
        # nonce nor returning one in the response. Gate issuance on the login
        # service so sudo stays voucher-free.
        if (   $self->_isBastionGroup($server_group)
            && $self->_isVoucherMintingService($service) )
        {
            my ( $nonce, $vexp ) = $self->_mintBastionVoucher(
                $req, $user, $server_id,
                ( $sshCheck && $sshCheck->{ok} )
                ? $sshCheck->{expires_at}
                : undef
            );
            if ($nonce) {
                $response->{bastion_voucher}            = $nonce;
                $response->{bastion_voucher_expires_in} = $vexp - time();
                $self->logger->debug(
"PAM authorize: issued bastion voucher for user '$user' (bastion='$server_id', exp=$vexp)"
                );
            }
        }
    }
    else {
        $response->{reason} = 'Access denied by rule';
    }

    return $self->_respond( $req, $response, code => 200 );
}

# HELPER METHODS

# Check PAM authorization rule for a specific service type
# Returns: { authorized => 0|1, sudo_allowed => 0|1 }
sub _checkPamRule {
    my ( $self, $req, $host, $service, $server_group ) = @_;

    # Set variables available for rule evaluation
    $req->sessionInfo->{_pamHost}        = $host;
    $req->sessionInfo->{_pamService}     = $service;
    $req->sessionInfo->{_pamServerGroup} = $server_group || 'default';

    my $result = {
        authorized   => 0,
        sudo_allowed => 0,
    };

    # Determine which rule set to use based on service type
    my $ssh_authorized = $self->_evaluateRule( $req, $server_group, 'ssh' );

    # For SSH service, check SSH rules
    if ( $service eq 'sshd' || $service eq 'ssh' ) {
        $result->{authorized} = $ssh_authorized;
    }

    # For sudo service, check both SSH (must be connected) and sudo rules
    elsif ( $service eq 'sudo' ) {

        # User must first be authorized for SSH
        if ($ssh_authorized) {
            $result->{authorized} = 1;
            $result->{sudo_allowed} =
              $self->_evaluateRule( $req, $server_group, 'sudo' );
        }
    }

    # For other services, deny
    else {
        $result->{authorized} = 0;
    }

    # Also compute sudo_allowed for SSH requests (for response)
    if ( $service eq 'sshd' || $service eq 'ssh' ) {
        $result->{sudo_allowed} =
          $self->_evaluateRule( $req, $server_group, 'sudo' );
    }

    return $result;
}

# Evaluate a specific rule type for a server group
sub _evaluateRule {
    my ( $self, $req, $server_group, $rule_type ) = @_;

    $server_group ||= 'default';

    # Select the appropriate rule set
    my $rules;
    if ( $rule_type eq 'ssh' ) {
        $rules = $self->conf->{pamAccessSshRules} || {};
    }
    elsif ( $rule_type eq 'sudo' ) {
        $rules = $self->conf->{pamAccessSudoRules} || {};
    }
    else {
        return 0;
    }

    my $rule;

    # 1. Look for rule matching the requested server_group
    if ( exists $rules->{$server_group} ) {
        $rule = $rules->{$server_group};
        $self->logger->debug(
            "PAM authorize: using $rule_type rule for group '$server_group'");
    }

    # 2. Fallback to 'default' group
    elsif ( exists $rules->{default} ) {
        $rule = $rules->{default};
        $self->logger->debug(
"PAM authorize: $rule_type rule for '$server_group' not found, using 'default'"
        );
    }

    # 3. No rule found -> deny
    else {
        $self->logger->debug(
            "PAM authorize: no $rule_type rule for '$server_group' or 'default'"
        );
        return 0;
    }

    # Simple boolean
    return $rule if defined $rule && $rule =~ /^[01]$/;

    # Empty or undefined rule -> deny
    return 0 unless defined $rule && $rule ne '';

    # Evaluate rule as expression
    my $result =
      $self->p->HANDLER->buildSub( $self->p->HANDLER->substitute($rule) )
      ->( $req, $req->sessionInfo );

    return $result ? 1 : 0;
}

# Evaluate if offline mode is enabled for this user
sub _evaluateOfflineMode {
    my ( $self, $req ) = @_;

    my $rule = $self->conf->{pamAccessOfflineEnabled};

    # Not configured or disabled
    return 0 unless defined $rule && $rule ne '' && $rule ne '0';

    # Simple boolean true
    return 1 if $rule eq '1';

    # Evaluate as expression
    my $result =
      $self->p->HANDLER->buildSub( $self->p->HANDLER->substitute($rule) )
      ->( $req, $req->sessionInfo );

    return $result ? 1 : 0;
}

sub _unauthorizedResponse {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Unauthorized';

    return $self->_respond(
        $req,
        { error => $message },
        code    => 401,
        headers => [ 'WWW-Authenticate' => 'Bearer realm="pam"' ],
    );
}

sub _forbiddenResponse {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Forbidden';

    return $self->_respond( $req, { error => $message }, code => 403 );
}

sub _badRequest {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Bad Request';

    return $self->_respond( $req, { error => $message }, code => 400 );
}

# ---------------------------------------------------------------------------
# Signed responses (issue #100, linagora/open-bastion#339)
#
# A host takes its access decisions from these answers -- `valid: true` from
# /pam/verify, allow/deny + sudo + voucher from /pam/authorize, the passwd
# entry from /pam/userinfo -- and nothing but TLS vouched for them: anyone
# holding a certificate the host accepts (overly broad CA, verify_ssl off, a
# TLS-intercepting proxy) could answer `valid: true` for anybody.
#
# So a caller may ask for a signed answer, `Accept: $SIGNED_RESPONSE_TYPE`,
# and gets a compact JWS signed like an ID token, with the key the portal
# publishes at its jwks_uri (/oauth2/jwks?client_id=<its client_id>). The
# same model as RFC 9701 signed introspection. Without that Accept, nothing
# changes: plain JSON, byte for byte.
#
# Five endpoints opt in: authorize, verify, userinfo, whoami, heartbeat. Their
# routes point at _signed_<handler> wrappers (see _signedRoute), the single
# point of entry that stamps the endpoint before the handler runs and checks
# what it returns. Every answer they give then goes through _respond --
# refusals included, because a host that requires signatures must be able to
# tell a real `valid: false` or 403 from a forged one, and treats anything
# unsigned as a transport error.
# /pam/bastion-cert does not opt in: sshd checks its certificate against the
# SSH CA, and the shared helpers above keep answering it in plain JSON.
#
# Claims: iss, aud (the caller's client_id, once it has passed the caller
# gate), iat/exp (60 s), endpoint, req_nonce (the request's X-Nonce, echoed),
# req_sha256 (hex SHA-256 of the raw request body), http_status, and resp --
# the exact JSON object the plain answer carries. req_nonce and req_sha256
# bind the answer to ONE request: a recorded `valid: true` can neither be
# replayed nor moved to another user or fingerprint. Hence a signed answer
# requires an X-Nonce, whether or not request signing (#81) is on.
#
# A signing failure never degrades to the plain success body: it is an
# UNSIGNED 500 `response_signing_unavailable`, which a host requiring
# signatures reads as a transport error, i.e. fails closed.

# HELPER: mark the request as served by a signed endpoint, and refuse a
# signed answer that would not be bound to its request. Called by
# _signedRoute before the handler runs, so before any work. Returns the
# response to send, or undef to carry on.
sub _startSignedEndpoint {
    my ( $self, $req, $endpoint ) = @_;

    $req->data->{pamSignedEndpoint} = $endpoint;
    return undef unless $self->_wantsSignedResponse($req);
    return undef if defined $self->_requestNonce($req);

    $self->logger->warn(
        "PAM $endpoint: signed answer requested without a valid X-Nonce");
    return $self->_respond( $req, { error => 'nonce_required' }, code => 400 );
}

# Route handler => endpoint name, for the five signed endpoints. init() routes
# each of them to the generated `_signed_<handler>` method below rather than
# to the handler itself.
our %SIGNED_HANDLERS = (
    authorize   => 'authorize',
    verifyToken => 'verify',
    userinfo    => 'userinfo',
    whoami      => 'whoami',
    heartbeat   => 'heartbeat',
);
for my $handler ( keys %SIGNED_HANDLERS ) {
    my $endpoint = $SIGNED_HANDLERS{$handler};
    no strict 'refs';
    *{"_signed_$handler"} = sub {
        my ( $self, $req, @args ) = @_;
        return $self->_signedRoute( $req, $endpoint, $handler, @args );
    };
}

# ROUTE WRAPPER for the signed endpoints: the single point of entry.
#
# 1. _startSignedEndpoint, before anything else (nonce_required).
# 2. The handler, which answers through _respond.
# 3. A fail-closed guard on what it returned. Signing only holds if EVERY
#    exit of a handler goes through _respond, and nothing but review enforces
#    that: one `$self->p->sendJSONresponse(...)` added on some refusal path
#    tomorrow would hand a host that asked for a signature an unsigned
#    answer -- which a careful host refuses, but which a careless one may
#    take at face value. So when a signed answer was asked for, anything
#    that is neither a JWS nor our own deliberate response_signing_unavailable
#    is logged and replaced by that 500.
sub _signedRoute {
    my ( $self, $req, $endpoint, $handler, @args ) = @_;

    if ( my $bail = $self->_startSignedEndpoint( $req, $endpoint ) ) {
        return $bail;
    }

    my $res = $self->$handler( $req, @args );
    return $res unless $self->_wantsSignedResponse($req);
    return $res if $req->data->{pamSigningUnavailable};
    if ( ref $res eq 'ARRAY' and ref $res->[1] eq 'ARRAY' ) {
        my %h = @{ $res->[1] };
        my ($ct) = map { $h{$_} } grep { lc($_) eq 'content-type' } keys %h;
        return $res if defined $ct and lc($ct) eq $SIGNED_RESPONSE_TYPE;
    }

    $self->logger->error(
        "PAM $endpoint: unsigned answer escaped the signing path");
    return $self->_sendSigningUnavailable($req);
}

# HELPER: does the Accept header list $SIGNED_RESPONSE_TYPE? Media types are
# case-insensitive; parameters (`;q=...`) are ignored.
sub _wantsSignedResponse {
    my ( $self, $req ) = @_;

    my $accept = $req->env->{HTTP_ACCEPT};
    return 0 unless defined $accept and $accept ne '';
    for my $range ( split /,/, $accept ) {
        my ($type) = split /;/, $range, 2;
        next unless defined $type;
        $type =~ s/\A\s+|\s+\z//g;
        return 1 if lc($type) eq $SIGNED_RESPONSE_TYPE;
    }
    return 0;
}

# HELPER: the request's X-Nonce when it is well formed, else undef.
sub _requestNonce {
    my ( $self, $req ) = @_;

    my $nonce = $req->env->{HTTP_X_NONCE};
    return ( defined $nonce and $nonce =~ $NONCE_RE ) ? $nonce : undef;
}

# HELPER: answer $body, the way sendJSONresponse would -- or, when the
# request asked for it on a signed endpoint, as a signed JWS. Same arguments
# as sendJSONresponse, plus `jwks => 1` (heartbeat success only) to embed the
# signing RP's public keys in the token.
sub _respond {
    my ( $self, $req, $body, %args ) = @_;

    my $with_jwks = delete $args{jwks};
    my $endpoint  = $req->data->{pamSignedEndpoint};
    return $self->p->sendJSONresponse( $req, $body, %args )
      unless $endpoint and $self->_wantsSignedResponse($req);

    my $code = $args{code} || 200;

    # Main::Run::sendJSONresponse adds the form token to every JSON body it
    # sends; do the same, so that `resp` is exactly the plain answer.
    $body->{token} = $req->token if ref $body eq 'HASH' and $req->token;

    my $oidc = $self->oidc;

    # The relying party the caller's token belongs to, once the caller has
    # passed the gate (see _checkCaller). Before that -- a missing or invalid
    # credential, or a request we refused at the door -- there is no
    # audience: the answer is signed with pamAccessRp's key and carries no
    # `aud`, which a host must only accept on an answer that grants nothing.
    my $caller = $req->data->{pamCallerSession};
    my $rp     = $caller ? $self->_resolveRp($caller) : undef;
    my $aud =
      $rp ? $oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID} : undef;
    my $signRp = $rp || $self->rpName;

    # _createJWT reads the partner's options through a nested lookup, which
    # would autovivify an empty RP named after pamAccessRp in the issuer's
    # live rpOptions when that RP is not declared. Lend it an empty entry for
    # the duration instead: `local` deletes it again on the way out, and an
    # empty entry means "sign with oidcServiceSignatureKey", the right default.
    my $rpOptions = $oidc->rpOptions;
    local $rpOptions->{$signRp} = {} unless $rpOptions->{$signRp};
    my $rpOpts = $rpOptions->{$signRp};

    my $alg = $self->_responseSigningAlg($rpOpts);
    return $self->_signingUnavailable( $req, $endpoint,
        'invalid pamAccessResponseSigningAlg' )
      unless $alg;

    # _createJWT silently drops `typ` for an RP flagged NoJwtHeader, and a
    # pam answer without its dedicated typ is precisely what a host must
    # refuse. Say so here rather than emit a token nobody will accept.
    return $self->_signingUnavailable( $req, $endpoint,
        "RP '$signRp' sets oidcRPMetaDataOptionsNoJwtHeader" )
      if $rpOpts->{oidcRPMetaDataOptionsNoJwtHeader};

    my $now     = time();
    my $nonce   = $self->_requestNonce($req);
    my $payload = {
        iss => $oidc->get_issuer($req),
        ( defined $aud && $aud ne '' ? ( aud => $aud ) : () ),
        iat      => $now,
        exp      => $now + $SIGNED_RESPONSE_TTL,
        endpoint => $endpoint,
        ( defined $nonce ? ( req_nonce => $nonce ) : () ),
        req_sha256  => sha256_hex( $req->content // '' ),
        http_status => $code + 0,
        resp        => $body,
        ( $with_jwks ? ( jwks => $self->_signingJwks($rpOpts) ) : () ),
    };

    my $jwt = eval {
        $oidc->createJWT( $payload, $alg, $signRp,
            { typ => $SIGNED_RESPONSE_TYP } );
    };
    return $self->_signingUnavailable( $req, $endpoint,
        'createJWT failed' . ( $@ ? ": $@" : '' ) )
      unless $jwt;

    my $res = $self->p->sendBinaryResponse(
        $req, $jwt,
        type    => $SIGNED_RESPONSE_TYPE,
        code    => $code,
        headers => [
            @{ $args{headers} || [ $req->spliceHdrs ] },
            'Vary'          => 'Accept',
            'Cache-Control' => 'no-cache, no-store, must-revalidate',
            'Pragma'        => 'no-cache',
            'Expires'       => '0',
        ],
    );

    # CORS, as Main::Run::sendJSONresponse applies it to the plain answer, so
    # that both variants carry the same headers.
    if ( $self->p->_checkSelfCors($req) ) {
        push @{ $res->[1] },
          'Access-Control-Allow-Origin'      => $req->origin,
          'Access-Control-Allow-Methods'     => '*',
          'Access-Control-Allow-Credentials' => 'true';
    }
    else {
        $self->p->setCorsHeaderFromConfig($res);
    }
    return $res;
}

# Algorithms a pam answer may be signed with: asymmetric only. `none` would
# sign nothing, and HS* would sign with the RP's client secret, which every
# host of the project holds -- any of them could then forge answers for all
# the others.
my %RESPONSE_SIGNING_ALGS = map { $_ => 1 }
  qw(RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES256K ES384 ES512 EdDSA);

# HELPER: pamAccessResponseSigningAlg, else the RP's ID token algorithm when
# it is asymmetric, else RS256. undef when the configured value is not an
# acceptable algorithm: that is a signing failure, never a fallback.
sub _responseSigningAlg {
    my ( $self, $rpOpts ) = @_;

    my $alg = $self->conf->{pamAccessResponseSigningAlg};
    if ( defined $alg and $alg ne '' ) {
        return $alg if $RESPONSE_SIGNING_ALGS{$alg};
        $self->logger->error( "PamAccess: pamAccessResponseSigningAlg '$alg'"
              . ' is not an asymmetric signature algorithm' );
        return undef;
    }
    my $idAlg = $rpOpts->{oidcRPMetaDataOptionsIDTokenSignAlg} // '';
    return $RESPONSE_SIGNING_ALGS{$idAlg} ? $idAlg : 'RS256';
}

# HELPER: the public signature keys of an RP: the same signature keys
# /oauth2/jwks?client_id=<rp> publishes (Issuer::OpenIDConnect::jwks), built
# the same way. Encryption keys are not included: they are not needed to
# verify an answer. Carried by the signed heartbeat so that hosts can follow a
# key rotation through a chain of signed answers rather than a TLS-only fetch.
sub _signingJwks {
    my ( $self, $rpOpts ) = @_;

    my $oidc = $self->oidc;
    my $list =
         $rpOpts->{oidcRPMetaDataOptionsSigningKey}
      || $self->conf->{oidcServiceSignatureKey}
      || '';
    my @keys = map { $oidc->_buildJwk( 'Sig', $oidc->get_public_key($_) ) }
      split /\s*,\s*/, $list;
    return { keys => \@keys };
}

# HELPER: a signed answer was asked for and cannot be produced. Unsigned on
# purpose -- there is nothing to sign it with -- and never the plain success
# body: a host requiring signatures must see a transport error.
sub _signingUnavailable {
    my ( $self, $req, $endpoint, $why ) = @_;

    $self->logger->error("PAM $endpoint: cannot sign the response ($why)");
    return $self->_sendSigningUnavailable($req);
}

# The unsigned 500 itself. Flagged in $req->data so that _signedRoute's guard
# recognises it as deliberate without parsing the body.
sub _sendSigningUnavailable {
    my ( $self, $req ) = @_;

    $req->data->{pamSigningUnavailable} = 1;
    return $self->p->sendJSONresponse(
        $req,
        { error => 'response_signing_unavailable' },
        code => 500
    );
}

# Scopes accepted at the /pam/* server-to-server endpoints. They are matched
# EXACTLY against the whitespace-separated tokens of the granted scope
# (RFC 6749 §3.3), not with a loose regex: the historical
# /\bpam(?::server)?\b/ also accepted 'pam-x' and 'x-pam' (a '-' is a word
# boundary) while rejecting 'pam_server', so an RP granted a scope that merely
# looked like ours reached these endpoints.
my %PAM_SCOPES = map { $_ => 1 } qw(pam pam:server);

sub _hasPamScope {
    my ( $self, $scope ) = @_;
    return 0 unless defined $scope && $scope ne '';
    for my $s ( split /\s+/, $scope ) {
        return 1 if $PAM_SCOPES{$s};
    }
    return 0;
}

# Per-endpoint wording of the shared caller gate below. Each endpoint kept the
# exact log lines and API error messages it had before the factorisation, so
# nothing a client parses changes.
#   no_token / bad_token : [ log line, 401 message ]
#   bad_grant            : [ log line, 403 message ]
#   grant_log_extra      : appended to the grant-type log line
#   scope_log            : wording of the scope log line
my %CALLER_GATE = (
    authorize => {
        label     => 'PAM authorize',
        no_token  => [ 'No Bearer token provided', 'Bearer token required' ],
        bad_token =>
          [ 'Invalid or expired Bearer token', 'Invalid or expired token' ],
        bad_grant => [
            'Token not from Device Authorization Grant',
'Server not enrolled. Use Device Authorization Grant to register this server.',
        ],
        grant_log_extra => '. Server must enroll via /oauth2/device',
    },
    verify => {
        label    => 'PAM verify',
        no_token =>
          [ 'No server Bearer token provided', 'Server Bearer token required' ],
        bad_token => [
            'Invalid or expired server token',
            'Invalid or expired server token'
        ],
        bad_grant => [
            'Server token not from Device Authorization Grant',
            'Server not enrolled. Use Device Authorization Grant.',
        ],
    },
    userinfo => {
        label    => 'PAM userinfo',
        no_token =>
          [ 'No server Bearer token provided', 'Server Bearer token required' ],
        bad_token => [
            'Invalid or expired server token',
            'Invalid or expired server token'
        ],
        bad_grant => [
            'Server token not from Device Authorization Grant',
            'Server not enrolled. Use Device Authorization Grant.',
        ],
    },
    heartbeat => {
        label     => 'PAM heartbeat',
        bad_grant => [
            'Token not from Device Authorization Grant',
            'Token not from Device Authorization Grant',
        ],
        scope_log => 'refresh token has invalid scope',
    },
    whoami => {
        label    => 'PAM whoami',
        no_token =>
          [ 'No server Bearer token provided', 'Server Bearer token required' ],
        bad_token => [
            'Invalid or expired server token',
            'Invalid or expired server token'
        ],
        bad_grant => [
            'Server token not from Device Authorization Grant',
            'Server not enrolled. Use Device Authorization Grant.',
        ],
    },
    'bastion-cert' => {
        label     => 'PAM bastion-cert',
        no_token  => [ 'No Bearer token provided', 'Bearer token required' ],
        bad_token =>
          [ 'Invalid or expired Bearer token', 'Invalid or expired token' ],
        bad_grant => [
            'Token not from Device Authorization Grant',
            'Server not enrolled. Use Device Authorization Grant.',
        ],
    },
);

# HELPER: the caller gate shared by every /pam/* server-to-server endpoint.
#
# All six answer the same question -- "is this caller an enrolled PAM server?"
# -- and used to answer it with six copies of the same code. Two copies had
# silently lost the scope test: any device-grant token, from any RP with any
# scope, could enumerate users (and every pamAccessExportedVars attribute)
# through /pam/userinfo, or burn a stolen one-time token through /pam/verify.
#
# The gate is the union of what the six endpoints checked:
#   1. a caller credential: a Bearer access token (five endpoints) or, for
#      /pam/heartbeat, the refresh-token session already resolved from the
#      request body and passed as `session`;
#   2. that credential comes from the Device Authorization Grant
#      (grant_type eq 'device_code');
#   3. it carries a pam scope (exact match, see _hasPamScope).
#
# Returns ( $session, undef ) when the caller passes, ( undef, $response )
# otherwise -- the response already carries that endpoint's own wording, so
# callers just `return $bail if $bail`.
# ---------------------------------------------------------------------------
# Request signing (issue #81, linagora/open-bastion#188)
#
# open-bastion's PAM/NSS client signs every call to the portal when
# `request_signing_secret` is configured, and has done for a while — but
# nothing on this side ever read the headers. The client signed, nothing
# checked, and the replay-protection chain was a no-op that only cost
# bandwidth. This is the missing verifier.
#
# Wire format, settled by open-bastion#188:
#
#   X-Timestamp      unix seconds, decimal
#   X-Nonce          <unix_ms>-<uuid-v4>
#   X-Signature-256  sha256=<64 lowercase hex>
#
#   message = <timestamp>.<nonce>.<method>.<path>.<body>
#   HMAC-SHA256, key = the raw bytes of the configured secret.
#
# Four literal '.' separators, always present; a bodyless request signs the
# empty string, so the message still ends with a trailing '.'. <path> carries
# no scheme, host or query string. <body> is the raw bytes as sent — which is
# why the HMAC is computed here, before anything decodes and re-encodes the
# JSON.
#
# Rollout. Turning verification on is a breaking change for any fleet where
# some hosts have the secret and some do not, so there are three modes:
#
#   off       (default) headers ignored entirely.
#   optional  a signed request must verify; an unsigned one passes. This is
#             the mode to run while the secret is being rolled out.
#   required  the headers are mandatory. Fail closed.
#
# Note that `optional` still fails closed on a BAD signature — it waives the
# requirement to sign, never the requirement to sign correctly.
#
# The signature is defence in depth on top of TLS, not a substitute for it.
# Do not relax verify_ssl because of it.
sub _checkRequestSignature {
    my ( $self, $req, $label ) = @_;

    my $mode = $self->conf->{pamAccessRequestSigningMode} || 'off';
    return undef if $mode eq 'off';

    # An unrecognised value (a typo such as 'optionnal') falls through to the
    # required branch below. Fail-closed is the right default, but silently
    # turning a typo into the strictest mode is how a deployment discovers it
    # in production: say so, once.
    unless ( $mode eq 'optional' or $mode eq 'required' ) {
        unless ( $self->_signingModeWarned ) {
            $self->logger->warn( "PamAccess: pamAccessRequestSigningMode is"
                  . " '$mode', which is not one of off/optional/required —"
                  . " treating it as 'required' (this warning is emitted"
                  . " only once)" );
            $self->_signingModeWarned(1);
        }
    }

    my $secret = $self->conf->{pamAccessRequestSigningSecret};
    unless ( defined $secret and $secret ne '' ) {
        $self->logger->error( "$label: pamAccessRequestSigningMode is"
              . " '$mode' but pamAccessRequestSigningSecret is empty" );
        return $self->_forbiddenResponse( $req,
            'Request signing is misconfigured' );
    }

    my $ts    = $req->env->{HTTP_X_TIMESTAMP};
    my $nonce = $req->env->{HTTP_X_NONCE};
    my $sig   = $req->env->{HTTP_X_SIGNATURE_256};

    my $signed = grep { defined $_ and $_ ne '' } ( $ts, $nonce, $sig );
    unless ($signed) {
        return undef if $mode eq 'optional';
        return $self->_signatureRefusal( $req, $label, 'unsigned',
            'Request signature required' );
    }

    # A partially signed request is malformed in either mode: it is not the
    # "old client that does not sign" case optional exists for.
    my ($given) =
      defined $sig ? ( $sig =~ /\Asha256=([0-9a-f]{64})\z/ ) : ();
    unless ( defined $ts
        and $ts =~ /\A[0-9]{1,11}\z/
        and defined $nonce
        and $nonce =~ $NONCE_RE
        and defined $given )
    {
        return $self->_signatureRefusal( $req, $label, 'malformed_headers',
            'Malformed request signature' );
    }

    # 1. Timestamp, first: it is the cheapest check, and it bounds both how
    #    long a captured request stays replayable and how big the nonce store
    #    has to be. Doing it before the HMAC also stops an attacker making the
    #    portal hash for requests it has already lost.
    my $window = $self->_confPositiveInt( 'pamAccessRequestSigningWindow', 300 );
    my $skew   = abs( time() - $ts );
    if ( $skew > $window ) {
        return $self->_signatureRefusal( $req, $label, 'stale_timestamp',
            'Request timestamp outside the accepted window' );
    }

    # 2. HMAC, second — and it MUST come before the nonce claim. _claimNonce
    #    WRITES to the shared session backend, so claiming first let any
    #    unauthenticated caller create one storage record per request with
    #    nothing but a parseable header set and a fresh timestamp, both of
    #    which it controls: storage exhaustion against the very store this
    #    protection leans on. It also burned the nonce, so a request the
    #    attacker had captured could be invalidated before its legitimate
    #    retry. One SHA-256 over a short message is in any case cheaper than
    #    the two storage roundtrips below.
    my $path = $req->uri // '';
    $path =~ s/\?.*\z//s;
    my $message = join '.', $ts, $nonce, uc( $req->method // '' ), $path,
      ( $req->content // '' );
    my $expected = hmac_sha256_hex( $message, $secret );

    unless ( _constantTimeEq( $expected, $given ) ) {
        return $self->_signatureRefusal( $req, $label, 'bad_signature',
            'Invalid request signature' );
    }

    # 3. Nonce, last. This is the actual replay protection — the window only
    #    bounds it — and only a caller holding the secret ever reaches it.
    if ( my $reason = $self->_claimNonce( $nonce, $window ) ) {
        return $self->_signatureRefusal( $req, $label, $reason,
            'Request nonce refused' );
    }

    return undef;
}

# HELPER: hex-string comparison that does not leak where it differs.
# Both arguments are 64 lowercase hex characters by construction.
sub _constantTimeEq {
    my ( $a, $b ) = @_;

    return 0 unless defined $a and defined $b;
    return 0 unless length($a) == length($b);
    my $diff = 0;
    $diff |= ord( substr $a, $_, 1 ) ^ ord( substr $b, $_, 1 )
      for ( 0 .. length($a) - 1 );
    return $diff == 0 ? 1 : 0;
}

# HELPER: record a nonce as used, or say why it cannot be.
#
# One session per nonce, keyed on its digest and expiring with the signing
# window — the same shape oidc-jar uses for its `jti` replay cache, and stored
# in the shared session backend so it works across workers and nodes.
#
# Read-then-create is not atomic (the LLNG store offers no insert-if-absent),
# so two replays landing in the same instant can both pass. Replaying a
# captured request within that window is a far smaller target than replaying
# it for the whole 300 s the window would otherwise leave open, which is what
# this closes.
sub _claimNonce {
    my ( $self, $nonce, $window ) = @_;

    my $id = sha256_hex( 'pam-request-nonce:' . $nonce );
    my %opts = (
        storageModule        => $self->conf->{globalStorage},
        storageModuleOptions => $self->conf->{globalStorageOptions},
        hashStore            => 0,
        id                   => $id,
        kind                 => 'PAMNONCE',
    );

    my $existing = Lemonldap::NG::Common::Session->new( {%opts} );
    if ( !$existing->error and $existing->data and $existing->data->{_type} ) {
        return 'nonce_replayed';
    }

    my $now     = time();
    my $timeout = $self->conf->{timeout} || 72000;
    my $stored  = Lemonldap::NG::Common::Session->new( {
            %opts,
            force => 1,
            info  => {
                _type  => 'pam_nonce',
                _utime => $now + $window - $timeout,
            },
        }
    );
    if ( $stored->error ) {
        $self->logger->error(
            'PAM: nonce replay-cache write failed: ' . $stored->error );

        # Cannot prove the nonce is fresh: refuse rather than accept a
        # request whose replay protection we know is not in force.
        return 'nonce_store_failed';
    }

    return undef;
}

# HELPER: log, audit and refuse, uniformly for every signature failure.
sub _signatureRefusal {
    my ( $self, $req, $label, $reason, $message ) = @_;

    $self->logger->warn("$label: request signature refused ($reason)");
    $self->p->auditLog(
        $req,
        code    => 'PAM_REQUEST_SIGNATURE_REFUSED',
        message => "PAM call refused: $message",
        reason  => $reason,
    );
    return $self->_forbiddenResponse( $req, $message );
}

sub _checkCaller {
    my ( $self, $req, $endpoint, %opts ) = @_;

    my $gate = $CALLER_GATE{$endpoint}
      or die "PamAccess: no caller gate defined for '$endpoint'";
    my $label = $gate->{label};

    # Before anything else: the request signature, when the deployment has
    # turned it on. Cheap checks first, and nothing else is worth doing for a
    # request we are going to refuse (issue #81).
    if ( my $bail = $self->_checkRequestSignature( $req, $label ) ) {
        return ( undef, $bail );
    }

    my $session = $opts{session};
    unless ($session) {
        my $access_token = $self->oidc->getEndPointAccessToken($req);
        unless ($access_token) {
            $self->logger->warn("$label: $gate->{no_token}[0]");
            return ( undef,
                $self->_unauthorizedResponse( $req, $gate->{no_token}[1] ) );
        }

        $session = $self->oidc->getAccessToken($access_token);
        unless ($session) {
            $self->logger->warn("$label: $gate->{bad_token}[0]");
            return ( undef,
                $self->_unauthorizedResponse( $req, $gate->{bad_token}[1] ) );
        }
    }

    my $grant_type = $session->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn( "$label: $gate->{bad_grant}[0] "
              . "(grant_type: '$grant_type')"
              . ( $gate->{grant_log_extra} || '' ) );
        return ( undef,
            $self->_forbiddenResponse( $req, $gate->{bad_grant}[1] ) );
    }

    my $scope = $session->data->{scope} || '';
    unless ( $self->_hasPamScope($scope) ) {
        $self->logger->warn( "$label: "
              . ( $gate->{scope_log} || 'Invalid token scope' )
              . " '$scope'" );
        return ( undef,
            $self->_forbiddenResponse( $req, 'Invalid token scope' ) );
    }

    if ( my $bail = $self->_checkCallerRp( $req, $session, $label ) ) {
        return ( undef, $bail );
    }

    # The caller is now identified: a signed answer is addressed to its RP
    # (`aud`) and signed with that RP's key (see _respond). Not before -- a
    # token refused above must not get answers signed with the key of
    # whichever relying party it was issued to.
    $req->data->{pamCallerSession} = $session;

    return ( $session, undef );
}

# HELPER: bind the presented token to a relying party this portal recognises
# as a PAM caller (issue #50).
#
# The gate above tests the grant type and the scope, and nothing else. But
# `grant_type => device_code` is stamped for EVERY RP using the device flow,
# not just PAM ones, and the core's getAccessToken performs no audience or RP
# check at all. So any device-grant token whose scope contains a pam token
# reached /pam/*. The cheapest attacker is not an unrelated RP: it is a
# compromise of any ordinary enrolled host in the same project, which already
# holds exactly such a token.
#
# pamAccessAllowedRps is the binding. It lists RP configuration keys — the
# same vocabulary as pamAccessRp — and is EMPTY by default, which keeps the
# historical behaviour so an upgrade is not a rupture. Setting it also turns
# on the second half of the fix, in _resolveServerGroup: a deployment that has
# named its PAM relying parties is a deployment that can name its bastions,
# and a self-declared `server_group` is no longer accepted for one.
sub _checkCallerRp {
    my ( $self, $req, $session, $label ) = @_;

    my $allowed = $self->_allowedRps;
    unless ( keys %$allowed ) {
        unless ( $self->_rpAllowlistWarned ) {
            $self->logger->warn(
                    'PamAccess: pamAccessAllowedRps is empty; /pam/* accepts '
                  . 'ANY device-grant token carrying a pam scope, including '
                  . 'one issued to an unrelated relying party — set it to the '
                  . 'RPs that may call PAM (this warning is emitted only once)'
            );
            $self->_rpAllowlistWarned(1);
        }
        return undef;
    }

    my $rp = $self->_resolveRp($session) // '';
    return undef if $rp ne '' and $allowed->{$rp};

    my $client_id = $session->data->{client_id} // 'unknown';
    $self->logger->warn( "$label: token was issued to RP '"
          . ( $rp ne '' ? $rp : 'unknown' )
          . "' (client_id '$client_id'), which is not in pamAccessAllowedRps" );
    $self->p->auditLog(
        $req,
        code      => 'PAM_CALLER_RP_REFUSED',
        message   => 'PAM call refused: token was not issued to a PAM'
          . ' relying party',
        rp        => $rp,
        server_id => $client_id,
        reason    => 'rp_not_allowed',
    );
    return $self->_forbiddenResponse( $req, 'Token is not a PAM token' );
}

# HELPER: pamAccessAllowedRps as a lookup hash. Accepts the comma/space
# separated string the Manager stores, and a hashref for programmatic configs.
sub _allowedRps {
    my ($self) = @_;

    my $conf = $self->conf->{pamAccessAllowedRps};
    return {} unless defined $conf;
    if ( ref $conf eq 'HASH' ) {
        return { map { $_ => 1 } grep { $_ ne '' } keys %$conf };
    }
    return {} if ref $conf;
    return { map { $_ => 1 } grep { $_ ne '' } split /[,;\s]+/, $conf };
}

# HELPER: the relying party (configuration key) a token session belongs to.
#
# There is no single field for this. `rp` is stamped by the core's
# newAccessToken only, so it is present on Bearer tokens and absent from the
# refresh tokens the device grant mints; the synthetic session built by
# oidc-device-organization stamps `_clientConfKey` instead. Hence the three
# steps, cheapest first, with the client_id scan as the general fallback —
# this is the resolution /pam/heartbeat already performed inline.
#
# Returns undef when the token belongs to no RP this portal still declares,
# which for _checkCallerRp means "not on the allowlist".
sub _resolveRp {
    my ( $self, $session ) = @_;

    my $data    = $session->data;
    my $options = $self->oidc->rpOptions;

    for my $k ( $data->{rp}, $data->{_clientConfKey} ) {
        return $k if $k and $options->{$k};
    }

    # Last resort: find the configuration key whose client_id is the one the
    # token was issued to. This assumes client_ids are unique across RPs,
    # which the bastion setup requires anyway -- a host trusted to vouch for
    # arbitrary users has to be distinguishable at enrollment.
    #
    # If two RPs do share a client_id the answer is arbitrary: only one key is
    # returned, and an allowlist naming the other one refuses a caller it
    # meant to admit. `sort` is there so that arbitrary at least means stable
    # -- without it Perl's per-process hash order would let two portal nodes,
    # or the same node after a restart, disagree about the same token. Do not
    # build anything on which key comes back.
    my $cid = $data->{client_id} // '';
    return undef unless $cid ne '';
    for my $k ( sort keys %$options ) {
        return $k
          if ( $options->{$k}->{oidcRPMetaDataOptionsClientID} // '' ) eq $cid;
    }
    return undef;
}

# HELPER: identity of the enrolled caller, for audit logs and voucher binding.
# Prefer the per-device id (stamped at enrollment by oidc-device-organization)
# so a project-wide client_id still yields an id unique per machine; fall back
# to client_id for legacy enrollments.
sub _callerId {
    my ( $self, $session ) = @_;
    my $data = $session->data;
    return $data->{_deviceId} || $data->{client_id} || 'unknown';
}

# POST /pam/verify - Verify and consume a one-time PAM token
sub verifyToken {
    my ( $self, $req ) = @_;

    # 1. Caller gate: a valid Bearer token, obtained through the Device
    #    Authorization Grant, carrying a pam scope (see _checkCaller). The
    #    scope test used to be missing here: any device-grant token could burn
    #    a stolen or guessed one-time token.
    my ( $serverSession, $bail ) = $self->_checkCaller( $req, 'verify' );
    return $bail if $bail;

    # 2. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM verify: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user_token = $body->{token};
    unless ($user_token) {
        return $self->_badRequest( $req, 'token parameter required' );
    }

    # Get server info for audit
    my $server_id = $serverSession->data->{client_id} || 'unknown';

    # 3. Retrieve the PAMTOKEN session
    my $tokenSession =
      $self->p->getApacheSession( $user_token, kind => 'PAMTOKEN' );
    unless ($tokenSession) {
        $self->logger->info("PAM verify: Invalid or expired token");

        # Audit log for authentication failure
        $self->p->auditLog(
            $req,
            code      => 'PAM_AUTH_INVALID_TOKEN',
            message   => 'PAM authentication failed: invalid or expired token',
            server_id => $server_id,
            reason    => 'Invalid or expired token',
        );

        return $self->_respond(
            $req,
            {
                valid => JSON::false,
                error => 'Invalid or expired token',
            },
            code => 200
        );
    }

    # 3b. CONSUME IT NOW, before any check runs.
    #
    # The token is one-time, and every exit path below discards it anyway, so
    # burning it here changes no outcome — but it is what makes the single-use
    # claim mean something. LLNG sessions have no locking, and consumption
    # used to sit ~145 lines later, past a persistent-session load: two
    # concurrent /pam/verify calls (a login racing a sudo, or
    # `scp host1: host2:`) both read the token before either deleted it, and
    # both answered valid (issue #53). The remaining window is now two
    # adjacent store round-trips.
    #
    # HOW the loser is detected, because it is not obvious and it is easy to
    # "simplify" wrongly. Common::Session->remove re-ties the session with the
    # options it is given, then deletes. It is the RE-TIE that fails for the
    # loser: the record is already gone, so tying dies ("Object does not exist
    # in the data store") and remove returns false. The delete itself is not
    # conditional — Store::File's unlink is guarded by `if (-e $file)` with no
    # else, i.e. deleting an absent record is a silent success. So `noCache
    # => 1` is not a hardening detail here, it is the part that works: without
    # it the re-tie would succeed from the node-local cache and both callers
    # would be told they won.
    #
    # This assumes the backend's retrieve-on-missing fails rather than
    # returning an empty record. True of the File, DBI and REST stores; a
    # backend that resolved a missing id silently would reopen the full
    # window.
    #
    # A failed remove therefore means we did not win it — or that the store is
    # unreachable, which for a one-time credential is equally a refusal.
    # $tokenSession->data is a snapshot taken at load time, so the checks
    # below still see everything they need.
    #
    # Not claimed: atomicity. Two calls whose re-ties both complete before
    # either delete still both win. That is the "two adjacent store
    # round-trips" above, and no plugin can close it without a
    # compare-and-swap the store does not offer.
    unless ( $tokenSession->remove( { noCache => 1 } ) ) {
        $self->logger->warn( "PAM verify: could not consume the one-time token"
              . " (concurrent use, or store failure): "
              . ( $tokenSession->error // 'unknown' ) );
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTH_TOKEN_NOT_CONSUMED',
            user    => $tokenSession->data->{_pamUser} || 'unknown',
            message => 'PAM authentication failed: the one-time token could'
              . ' not be consumed',
            server_id => $server_id,
            reason    => 'token_not_consumed',
        );
        return $self->_respond(
            $req,
            {
                valid => JSON::false,
                error => 'Invalid or expired token',
            },
            code => 200
        );
    }

    # 4. Verify token type
    my $type = $tokenSession->data->{_type} || '';
    unless ( $type eq 'pamtoken' ) {
        $self->logger->warn("PAM verify: Wrong token type '$type'");

        # Audit log for security error
        $self->p->auditLog(
            $req,
            code      => 'PAM_AUTH_WRONG_TOKEN_TYPE',
            message   => "PAM authentication failed: wrong token type '$type'",
            server_id => $server_id,
            reason    => 'Invalid token type',
        );

        return $self->_respond(
            $req,
            {
                valid => JSON::false,
                error => 'Invalid token type',
            },
            code => 200
        );
    }

    # 5. Check expiration
    my $expiresAt = $tokenSession->data->{_pamExpiresAt} || 0;
    if ( time() > $expiresAt ) {
        my $user = $tokenSession->data->{_pamUser} || 'unknown';
        $self->logger->info("PAM verify: Token expired");

        # Audit log for expired token
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTH_TOKEN_EXPIRED',
            user    => $user,
            message =>
              "PAM authentication failed: token expired for user '$user'",
            server_id => $server_id,
            reason    => 'Token expired',
        );

        return $self->_respond(
            $req,
            {
                valid => JSON::false,
                error => 'Token expired',
            },
            code => 200
        );
    }

    # 6. Extract user info
    my $user      = $tokenSession->data->{_pamUser}   || '';
    my $groups    = $tokenSession->data->{_pamGroups} || '';
    my @groupList = $groups ? split( /[,;\s]+/, $groups ) : ();

    # Extract exported attributes (prefixed with _pamAttr_)
    my %attrs;
    for my $key ( keys %{ $tokenSession->data } ) {
        if ( $key =~ /^_pamAttr_(.+)$/ ) {
            $attrs{$1} = $tokenSession->data->{$key};
        }
    }

    # 6b. Optional SSH fingerprint binding
    # When the caller (e.g. Open-Bastion) passes a 'fingerprint' field, verify
    # that the user's persistent session holds a matching, non-revoked,
    # non-expired SSH CA certificate record. This binds the PAM token to a
    # known SSH key even if the SSH server's KRL is stale.
    my ( $fingerprint, $fp_bail ) = $self->_parseFingerprintOrReject(
        $req, $body, $user,
        label         => 'PAM verify',
        action        => 'authentication rejected',
        audit_code    => 'PAM_AUTH_SSH_FP_MALFORMED',
        audit_code_required => 'PAM_AUTH_SSH_FP_REQUIRED',
        audit_fields  => { server_id => $server_id },
        response_body =>
          { valid => JSON::false, error => 'Malformed SSH fingerprint' },
    );
    return $fp_bail if $fp_bail;

    my $ps;
    if ( defined $fingerprint ) {

        # Load the persistent session once; the _pamSeen stamp below
        # reuses the same $ps instead of going through
        # updatePersistentSession (which would re-read it).
        $ps = $self->p->getPersistentSession($user);
        my $sshCheck =
          $self->_checkSshFingerprint( $user, $fingerprint, ps => $ps );
        unless ( $sshCheck->{ok} ) {
            $self->logger->info(
                    "PAM verify: SSH fingerprint check failed for user '$user' "
                  . "($sshCheck->{reason})" );
            $self->p->auditLog(
                $req,
                code      => 'PAM_AUTH_SSH_FP_REJECTED',
                user      => $user,
                server_id => $server_id,
                message   =>
"PAM authentication rejected: SSH fingerprint check failed for user '$user'",
                fingerprint => $fingerprint,
                reason      => $sshCheck->{reason},
            );
            return $self->_respond(
                $req,
                {
                    valid => JSON::false,
                    error => 'SSH fingerprint not recognized',
                },
                code => 200
            );
        }
        $attrs{ssh_cert_label} = $sshCheck->{label}
          if defined $sshCheck->{label};
        $attrs{ssh_cert_serial} = $sshCheck->{serial}
          if defined $sshCheck->{serial};
    }

    # 7. The token was already consumed in step 3b.

    # Refresh the user's pam-access persistence marker (see generateToken for
    # why it is still stamped). Only reached once every check has passed, so a
    # failed verify never stamps. When the fingerprint branch ran above it
    # already loaded the persistent session, so reuse it and skip a second
    # read+write via updatePersistentSession's inner getPersistentSession.
    # In the no-fingerprint branch $ps is undef and we fall back to the core
    # helper which also handles the disablePersistentStorage case.
    if ( $ps && !$ps->error ) {
        $ps->update( { _pamSeen => time() } );
    }
    else {
        $self->p->updatePersistentSession( $req, { _pamSeen => time() },
            $user );
    }

    $self->logger->info("PAM verify: Token consumed for user '$user'");

    # Audit log for successful authentication
    $self->p->auditLog(
        $req,
        code      => 'PAM_AUTH_SUCCESS',
        user      => $user,
        message   => "PAM authentication successful for user '$user'",
        server_id => $server_id,
        groups    => \@groupList,
    );

    # 8. Return success with user info and exported attributes
    return $self->_respond(
        $req,
        {
            valid  => JSON::true,
            user   => $user,
            groups => \@groupList,
            ( %attrs ? ( attrs => \%attrs ) : () ),
        },
        code => 200
    );
}

# POST /pam/whoami - An enrolled server reads back its own identity.
#
# The portal assigns each enrolment a stable per-device id (_deviceId, stamped
# by oidc-device-organization) and that id — not the shared, project-wide
# client_id — is what identifies the machine everywhere it matters: it is the
# `bastion=<id>` written into the key-id of every hop certificate, which the
# backends' AuthorizedPrincipalsCommand matches against
# /etc/open-bastion/allowed_bastions. An operator adding a backend therefore
# has to be able to read a bastion's id, and there was no way to: the value is
# a digest computed portal-side, /pam/authorize does not return the caller's
# identity, /pam/heartbeat does not either, and /oauth2/introspect does not
# export private session keys (verified: it answers active/aud/exp/client_id/
# scope/nbf/iat/sub/iss/token_type and nothing more).
#
# /pam/bastion-token's `probe: true` mode used to answer this question. That
# endpoint is gone (#57) — it minted a JWT even when the user lookup had
# failed — so this replaces the one part of it that was worth keeping, and
# nothing else: no signing, no session writes, no side effect of any kind.
# It is a pure read behind the standard caller gate, which means it inherits
# the RP allowlist (#50) and request signing (#81) for free.
#
# POST rather than GET for two reasons: every other /pam/* server-to-server
# endpoint is POST, and GET /pam/* is already claimed by the catch-all that
# redirects browsers to the portal.
sub whoami {
    my ( $self, $req ) = @_;

    my ( $session, $bail ) = $self->_checkCaller( $req, 'whoami' );
    return $bail if $bail;

    my $client_id = $session->data->{client_id} // '';
    my $server_id = $self->_callerId($session);

    my $response = {
        server_id => $server_id,

        # Compatibility alias. The removed probe answered `bastion_id`, and
        # ob-bastion-id reads exactly that field, so shipping both means the
        # client only has to change its URL. `server_id` is the canonical
        # name — it matches the audit trail's vocabulary, and this endpoint
        # serves every enrolled server, not only bastions.
        bastion_id => $server_id,
        client_id  => $client_id,
    };

    # The authoritative group, when the portal has one. Deliberately NOT the
    # body-declared fallback of the legacy path: a server asking "who am I"
    # must not be told back what it just claimed about itself.
    my $map = $self->conf->{pamAccessServerGroups} || {};
    if ( ref $map eq 'HASH' and defined $map->{$client_id} ) {
        $response->{server_group} = $map->{$client_id};
    }

    # info, not debug: reading a server's identity is a rare operator action
    # (bringing a backend up, filling an allowed_bastions list), and the probe
    # mode this replaces logged at info too. Keeping it there means the trail
    # of "who asked for their id, and when" survives a production log level.
    $self->logger->info(
        "PAM whoami: '$client_id' identified as '$server_id'");

    return $self->_respond( $req, $response, code => 200 );
}

# POST /pam/heartbeat - Server heartbeat for monitoring
sub heartbeat {
    my ( $self, $req ) = @_;

    # 1. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM heartbeat: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    # 2. Extract refresh_token from body
    my $refresh_token_id = $body->{refresh_token};
    unless ($refresh_token_id) {
        return $self->_badRequest( $req, 'refresh_token required' );
    }

    # 3. Validate refresh token exists
    my $rtSession = $self->oidc->getRefreshToken($refresh_token_id);
    unless ($rtSession) {
        $self->logger->warn('PAM heartbeat: invalid or expired refresh_token');
        return $self->_unauthorizedResponse( $req, 'Invalid refresh_token' );
    }

    # 4. Same caller gate as the other /pam/* endpoints, applied to the
    #    refresh-token session resolved above rather than to a Bearer token:
    #    the credential must come from the Device Authorization Grant and
    #    carry a pam scope. This endpoint mints access tokens and slides the
    #    refresh token's lifetime, so it must only accept tokens meant for
    #    pam-access; without the scope test any device_code refresh token
    #    issued for another RP could obtain access tokens here and keep itself
    #    alive indefinitely.
    #    (the session it validates is the $rtSession passed in, so only the
    #    rejection is of interest here)
    my ( undef, $bail ) =
      $self->_checkCaller( $req, 'heartbeat', session => $rtSession );
    return $bail if $bail;

    # 5. Resolve the RP (conf key) this refresh token belongs to — the same
    #    resolution the caller gate above ran, see _resolveRp.
    my $now = time();
    my $rp  = $self->_resolveRp($rtSession);
    unless ($rp) {
        $self->logger->error(
            'PAM heartbeat: cannot resolve RP for refresh token');
        return $self->_unauthorizedResponse( $req, 'Unknown client' );
    }

    # 6. Update metadata in refresh_token session AND slide its expiration.
    #    LLNG purges sessions on (time - _utime > timeout); pushing _utime
    #    forward by OfflineSessionExpiration on every beat is what makes a
    #    live server's credential effectively never expire, while a server
    #    that stops beating ages out after that window (the grace period).
    my $hostname = $body->{hostname} || 'unknown';
    my $offlineExp =
      $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsOfflineSessionExpiration}
      || $self->conf->{oidcServiceOfflineSessionExpiration}
      || 2592000;

    my $updates = {
        _pamServer      => 1,
        _pamHostname    => $hostname,
        _pamServerGroup => $body->{server_group} || 'default',
        _pamVersion     => $body->{version}      || '',
        _pamNodeRole    => $body->{node_role}    || '',
        _pamLastSeen    => $now,
        _pamStatus      => 'active',
        _utime          => $now + $offlineExp - $self->conf->{timeout},
    };

    # Store stats as JSON string if provided
    if ( $body->{stats} ) {
        $updates->{_pamStats} = to_json( $body->{stats} );
    }

    # Store the list of users currently connected on this machine ("who is
    # connected"), reported by ob-heartbeat. Always persist a JSON array so
    # consumers can rely on _pamSessions being an array consistent with
    # _pamSessionCount; coerce a malformed (non-array) payload to an empty list.
    if ( $body->{sessions} ) {
        my $sessions = $body->{sessions};
        unless ( ref $sessions eq 'ARRAY' ) {
            $self->logger->warn(
                'PAM heartbeat: ignoring malformed "sessions" (not an array)');
            $sessions = [];
        }
        $updates->{_pamSessions}     = to_json($sessions);
        $updates->{_pamSessionCount} = scalar @$sessions;
    }

    # First heartbeat = enrollment timestamp
    unless ( $rtSession->data->{_pamEnrolledAt} ) {
        $updates->{_pamEnrolledAt} = $now;
    }

    # Update the refresh_token session
    $self->oidc->updateRefreshToken( $rtSession->id, $updates );

    $self->logger->debug("PAM heartbeat from $hostname");

    # 7. Mint a fresh access token from the refresh token's stored (synthetic)
    #    session data. We deliberately do NOT use the core /oauth2/token
    #    refresh grant: its offline branch re-resolves the user in the UserDB,
    #    which fails for the synthetic organization identity. Minting here keeps
    #    the server's identity self-contained (RFC spirit: short access token,
    #    long refresh token, refresh loop driven by the device).
    my $scope = $rtSession->data->{scope} || '';
    # Carry the per-device identifier across refreshes: newAccessToken() only
    # persists this $info hash, not arbitrary $rtSession->data keys, so without
    # this the bastion_id would revert to the shared client_id after the first
    # heartbeat (the device-grant token has it, the refreshed ones would not).
    my %at_extra = ( grant_type => 'device_code' );
    $at_extra{_deviceId} = $rtSession->data->{_deviceId}
      if $rtSession->data->{_deviceId};

    # Liveness markers consumed by _checkCallerHeartbeat when
    # pamAccessHeartbeatRequired is enabled: when this token was minted, plus a
    # reference to the refresh-token session that holds the live _pamLastSeen
    # (so a server that keeps beating stays fresh even if its PAM module reuses
    # the same access token until it expires). The reference is the session
    # *storage* id — already hashed when hashedSessionStore is on — never the
    # refresh token itself, so an access-token record can never be replayed as
    # a credential here.
    $at_extra{_pamLastSeen} = $now;
    $at_extra{_pamRtRef}    = $rtSession->storageId || $rtSession->id;
    my $access_token =
      $self->oidc->newAccessToken( $req, $rp, $scope, $rtSession->data,
        \%at_extra );

    unless ($access_token) {
        $self->logger->error('PAM heartbeat: failed to mint access token');
        return $self->_respond(
            $req,
            { error => 'token generation failed' },
            code => 500
        );
    }

    my $at_ttl =
      $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAccessTokenExpiration}
      || $self->conf->{oidcServiceAccessTokenExpiration}
      || 3600;

    # 8. Respond with the fresh access token + next heartbeat interval. A
    #    signed answer also carries the current signature keys (`jwks`), so
    #    that a host learns a new key from a token signed by one it already
    #    trusts -- see "Key rotation" in the README.
    my $interval = $self->conf->{pamAccessHeartbeatInterval} || 300;
    return $self->_respond(
        $req,
        {
            status         => 'ok',
            access_token   => "$access_token",
            expires_in     => $at_ttl + 0,
            next_heartbeat => $interval,
            server_time    => $now,
        },
        jwks => 1,
    );
}

# POST /pam/userinfo - Get user info for NSS module
sub userinfo {
    my ( $self, $req ) = @_;

    # 1. Caller gate: a valid Bearer token, obtained through the Device
    #    Authorization Grant, carrying a pam scope (see _checkCaller). The
    #    scope test used to be missing here: any device-grant token, from any
    #    RP with any scope, got full NSS enumeration (groups plus every
    #    pamAccessExportedVars attribute).
    my ( $serverSession, $bail ) = $self->_checkCaller( $req, 'userinfo' );
    return $bail if $bail;

    # An NSS lookup carries no client address, so the enrolled server is the
    # only way to tell which host asked. Same precedence as /pam/authorize.
    my $server_id = $self->_callerId($serverSession);
    $self->logger->info(
        "PAM userinfo request from enrolled server: $server_id");

    # 2. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error(
            "PAM userinfo: Invalid JSON body from '$server_id': $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user = $body->{user};
    unless ($user) {
        return $self->_badRequest( $req, 'user parameter required' );
    }

    # 3. Lookup user in backend
    $req->user($user);
    $req->data->{_pamUserinfo} = 1;
    $req->steps( $self->machineLookupSteps );

    # Tell Lib::Choice which sub-module to use for this server-to-server
    # getUser/setSessionInfo run (no interactive auth flow available here).
    $req->data->{_authChoice} = $self->conf->{pamAccessChoice}
      if $self->conf->{pamAccessChoice};

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->notice(
"PAM userinfo: User '$user' not found, asked by server '$server_id' (error: $error)"
        );
        return $self->_respond(
            $req,
            {
                found => JSON::false,
                user  => $user,
            },
            code => 200
        );
    }

    # 4. Build response with user attributes
    my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
    my %attrs;

    for my $key ( keys %$exportedVars ) {
        my $attr  = $exportedVars->{$key};
        my $value = $req->sessionInfo->{$attr};
        $attrs{$key} = $value if defined $value && $value ne '';
    }

    # Always include basic info
    my $groups    = $req->sessionInfo->{groups} || '';
    my @groupList = split /[,;\s]+/, $groups;

    $self->logger->debug(
        "PAM userinfo: Found user '$user' (server: $server_id)");

    return $self->_respond(
        $req,
        {
            found  => JSON::true,
            user   => $user,
            groups => \@groupList,
            %attrs,
        },
        code => 200
    );
}

# Generate a UUID v4 using cryptographically secure random bytes
sub _generateUUID {
    my ($self) = @_;

    # Use cryptographically secure random bytes (required for JWT jti claim)
    my @bytes;
    if ( eval { require Crypt::URandom; 1 } ) {
        @bytes = unpack( 'C16', Crypt::URandom::urandom(16) );
    }
    elsif ( -r '/dev/urandom' ) {

        # Fallback to /dev/urandom if Crypt::URandom not available
        open my $fh, '<:raw', '/dev/urandom'
          or do {
            $self->logger->error(
'PAM: Cannot open /dev/urandom for UUID generation'
            );
            return undef;
          };
        read $fh, my $buf, 16;
        close $fh;
        @bytes = unpack( 'C16', $buf );
    }
    else {
        # No secure random source available
        $self->logger->error(
'PAM: No cryptographically secure random source available '
              . '(install Crypt::URandom or ensure /dev/urandom is readable)' );
        return undef;
    }

    # Set version 4 (random)
    $bytes[6] = ( $bytes[6] & 0x0f ) | 0x40;

    # Set variant (RFC 4122)
    $bytes[8] = ( $bytes[8] & 0x3f ) | 0x80;

    return
      sprintf(
        '%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x',
        @bytes );
}

# HELPER: Resolve the authoritative server_group for an enrolled client.
# Returns either a plain string (the group) or a hashref { rejected=>1,
# message, reason } that the caller turns into a 403 response.
#
#  - pamAccessServerGroups configured + client_id mapped:
#      use mapped group; if caller_body_group is given and differs, reject.
#  - pamAccessServerGroups configured + client_id missing:
#      reject (unknown server, strict lockdown).
#  - pamAccessServerGroups empty (legacy):
#      use body-provided group or 'default'; warn once.
sub _resolveServerGroup {
    my ( $self, $req, $client_id, $body_group, $log_prefix ) = @_;
    $log_prefix ||= 'PAM';

    my $map     = $self->conf->{pamAccessServerGroups} || {};
    my $has_map = ref $map eq 'HASH' && scalar( keys %$map ) > 0;

    if ($has_map) {
        my $mapped = $map->{ $client_id // '' };
        unless ( defined $mapped && $mapped ne '' ) {
            return {
                rejected => 1,
                message  => "Unknown enrolled server '$client_id'",
                reason   => 'unmapped_client_id',
            };
        }
        if (   defined $body_group
            && $body_group ne ''
            && $body_group ne $mapped )
        {
            return {
                rejected => 1,
                message  =>
"Server '$client_id' is not authorized for server_group '$body_group'",
                reason => 'server_group_mismatch',
            };
        }
        return $mapped;
    }

    # Legacy / back-compat path: the group comes from the request body.
    #
    # That is what lets any enrolled host declare itself a bastion and collect
    # (bastion_id, user) vouchers for users it never saw (issue #50). The
    # voucher binding itself is sound — it is bound to the caller's own device
    # id — which is precisely the problem: the attacker's device id is what
    # gets the hop certificates.
    #
    # A deployment that has set pamAccessAllowedRps has named its PAM relying
    # parties, so it can name its bastions too: from then on a bastion group
    # must come from pamAccessServerGroups and is refused in the body. Left
    # unset, nothing changes.
    if (   defined $body_group
        && $body_group ne ''
        && $self->_isBastionGroup($body_group)
        && keys %{ $self->_allowedRps } )
    {
        return {
            rejected => 1,
            message  =>
"Server '$client_id' may not declare itself a member of bastion group"
              . " '$body_group'",
            reason => 'self_declared_bastion',
        };
    }

    # Emit the warning only once per process so the logs don't fill up for
    # deployments that haven't configured the mapping yet.
    unless ( $self->_serverGroupLegacyWarned ) {
        $self->logger->warn(
"$log_prefix: pamAccessServerGroups is empty; trusting caller-provided "
              . "server_group — configure the mapping to harden authorization "
              . "(this warning is emitted only once)" );
        $self->_serverGroupLegacyWarned(1);
    }
    return defined $body_group && $body_group ne '' ? $body_group : 'default';
}

# HELPER: parse and format-validate the `fingerprint` field of a PAM
# request body. Centralises the SHA256 regex shared by /pam/authorize
# and /pam/verify plus their common "malformed" handling.
#
# Returns ( $fingerprint, undef ) on success — $fingerprint is either
#   the validated string, or undef when the caller did not provide one
#   (which every caller treats as "skip the fingerprint check").
# Returns ( undef, $psgi_response ) when the caller must bail out with
#   the provided PSGI response (malformed format).
#
# %opts:
#   label            - log prefix ("PAM authorize" / "PAM verify")
#   action           - audit message action phrase
#   audit_code       - audit code for the malformed event
#   audit_code_required - audit code for the pamAccessRequireFingerprint
#                      refusal. Distinct from audit_code: a SIEM rule for
#                      "a caller sent us garbage" and one for "a caller has
#                      not rolled out the fingerprint spool yet" want
#                      different thresholds, and telling them apart on the
#                      `reason` field alone means parsing the payload.
#   audit_fields     - hashref of extra audit fields (host, server_id, ...)
#   response_body    - hashref returned as JSON on malformed (authorize
#                      uses { error => ... }, verify uses
#                      { valid => JSON::false, error => ... })
sub _parseFingerprintOrReject {
    my ( $self, $req, $body, $user, %opts ) = @_;

    my $fp = $body->{fingerprint};
    if ( defined $fp ) {
        $fp =~ s/^\s+|\s+$//g;
        $fp = undef if $fp eq '';
    }

    my $label        = $opts{label}         || 'PAM';
    my $action       = $opts{action}        || 'rejected';
    my $audit_code   = $opts{audit_code};
    my $audit_req    = $opts{audit_code_required} || $audit_code;
    my $audit_fields = $opts{audit_fields}  || {};
    my $body_out     = $opts{response_body}
      || { error => 'Malformed SSH fingerprint' };

    # The fingerprint is optional by contract, and several guarantees quietly
    # depend on it: the voucher TTL cap, and the binding a backend re-checks.
    # pamAccessRequireFingerprint (off by default) lets a deployment that has
    # rolled out the client-side spool refuse the unbound case outright rather
    # than silently downgrading (issue #55).
    if ( !defined $fp and $self->conf->{pamAccessRequireFingerprint} ) {
        $self->logger->info(
            "$label: no SSH fingerprint supplied for user '$user' and"
              . " pamAccessRequireFingerprint is set" );
        $self->p->auditLog(
            $req,
            code    => $audit_req,
            user    => $user,
            message => "PAM $action: no SSH fingerprint supplied for user"
              . " '$user' (pamAccessRequireFingerprint)",
            reason => 'fingerprint_required',
            %$audit_fields,
        );
        # Keep the caller's body shape (verify carries `valid => false`) and
        # only swap the message, so clients always get the expected fields.
        return ( undef,
            $self->_respond(
                $req,
                { %$body_out, error => 'SSH fingerprint required' },
                code => 400
            ) );
    }

    return ( undef, undef ) unless defined $fp;
    return ( $fp,   undef ) if $fp =~ m{\ASHA256:[A-Za-z0-9+/]+={0,2}\z};

    $self->logger->info("$label: malformed SSH fingerprint for user '$user'");
    $self->p->auditLog(
        $req,
        code    => $audit_code,
        user    => $user,
        message => "PAM $action: malformed SSH fingerprint for user '$user'",
        reason  => 'malformed_fingerprint',
        %$audit_fields,
    );

    return ( undef, $self->_respond( $req, $body_out, code => 400 ) );
}

# HELPER: last heartbeat received from the server presenting $tokenSession,
# or undef when that server has never beaten.
#
# /pam/heartbeat stamps `_pamLastSeen` on the refresh-token session it beats
# against, and on every access token it mints — together with `_pamRtRef`, the
# storage id of that refresh-token session. We therefore know both when the
# presented token was minted and, by following the reference, the *live* value:
# a server that keeps beating stays fresh even when its PAM module reuses one
# access token for its whole lifetime. Take the most recent of the two; a token
# that predates this feature (or comes straight from the device grant, before
# any heartbeat) carries neither and yields undef.
sub _callerLastSeen {
    my ( $self, $tokenSession ) = @_;

    my $lastSeen = $tokenSession->data->{_pamLastSeen};
    undef $lastSeen unless defined $lastSeen && $lastSeen =~ /\A\d+\z/;

    my $rtRef = $tokenSession->data->{_pamRtRef};
    if ( defined $rtRef && $rtRef ne '' ) {

        # Fetched raw: `_pamRtRef` is the storage id, already hashed when
        # hashedSessionStore is enabled, so it must not be hashed again.
        my $rt = eval { $self->oidc->getRefreshToken( $rtRef, 1 ) };
        if ( $rt && !$rt->error ) {
            my $live = $rt->data->{_pamLastSeen};
            $lastSeen = $live
              if defined $live
              && $live =~ /\A\d+\z/
              && ( !defined $lastSeen || $live > $lastSeen );
        }
    }

    return $lastSeen;
}

# HELPER: enforce pamAccessHeartbeatRequired on /pam/authorize.
#
# When enabled, the calling server must have sent a heartbeat within
# pamAccessInactiveThreshold seconds (default 900, i.e. three missed beats at
# the default pamAccessHeartbeatInterval of 300s): a machine whose ob-heartbeat
# has stopped — decommissioned, cloned, or with its PAM stack tampered with —
# stops being able to authorize anybody, instead of coasting on a still-valid
# access token.
#
# Disabled by default, so existing deployments are unaffected.
#
# Returns undef when the caller may proceed, or the 403 response to send.
sub _checkCallerHeartbeat {
    my ( $self, $req, $tokenSession, $server_id ) = @_;

    return undef unless $self->conf->{pamAccessHeartbeatRequired};

    my $lastSeen = $self->_callerLastSeen($tokenSession);
    unless ( defined $lastSeen ) {
        $self->logger->warn(
                "PAM authorize: no heartbeat recorded for server '$server_id' "
              . "(pamAccessHeartbeatRequired is enabled)" );
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTHZ_NO_HEARTBEAT',
            message =>
              "PAM authorization denied: server '$server_id' has never "
              . "sent a heartbeat",
            server_id => $server_id,
            reason    => 'no_heartbeat',
        );
        return $self->_forbiddenResponse( $req,
            'Server has not sent a heartbeat' );
    }

    # 3 missed beats at the default 300s pamAccessHeartbeatInterval
    my $threshold =
      $self->_confPositiveInt( 'pamAccessInactiveThreshold', 900 );
    my $age = time() - $lastSeen;
    if ( $age > $threshold ) {
        $self->logger->warn(
                "PAM authorize: last heartbeat from server '$server_id' is "
              . "${age}s old, max ${threshold}s" );
        $self->p->auditLog(
            $req,
            code    => 'PAM_AUTHZ_STALE_HEARTBEAT',
            message => "PAM authorization denied: last heartbeat from server "
              . "'$server_id' is ${age}s old (max ${threshold}s)",
            server_id => $server_id,
            age       => $age,
            max_age   => $threshold,
            reason    => 'stale_heartbeat',
        );
        return $self->_forbiddenResponse( $req, 'Server heartbeat is stale' );
    }

    return undef;
}

# HELPER: Look up the user's persistent session and verify that an SSH CA
# certificate with the given fingerprint is registered, active, and not
# revoked/expired. Returns { ok => 1, serial, label, key_id } on match,
# { ok => 0, reason => '...' } otherwise.
sub _checkSshFingerprint {
    my ( $self, $user, $fingerprint, %opts ) = @_;

    return { ok => 0, reason => 'no-user' }
      unless defined $user && $user ne '';
    return { ok => 0, reason => 'no-fingerprint' }
      unless defined $fingerprint && $fingerprint ne '';

    # `exists` rather than `//` so a caller who explicitly passes
    # `ps => undef` (because their own getPersistentSession returned undef)
    # doesn't trigger a second redundant load here.
    my $ps =
      exists $opts{ps} ? $opts{ps} : $self->p->getPersistentSession($user);
    return { ok => 0, reason => 'no-session' } unless $ps;
    if ( $ps->error ) {
        $self->logger->error(
            "PAM verify: persistent session error for $user: " . $ps->error );
        return { ok => 0, reason => 'session-error' };
    }

    my $now = time();

    # Ephemeral bastion-hop certs are registered per-fingerprint by
    # /pam/bastion-cert (see $EPH_CERT_PREFIX) rather than in _sshCerts, so check
    # that keyspace first — a direct key lookup, and it also covers users whose
    # _sshCerts is empty.
    my $ephRaw = $ps->data->{ $EPH_CERT_PREFIX . $fingerprint };
    if ($ephRaw) {
        my $rec = eval { from_json($ephRaw) };
        if ( $@ || ref($rec) ne 'HASH' ) {

            # Corrupted entry: ignore it and fall through to _sshCerts rather
            # than failing the whole lookup.
            $self->logger->warn(
                "PAM verify: corrupted ephemeral cert record for $user: $@");
        }
        else {
            # Gate acceptance on the BINDING window, not the SSH cert's own
            # expires_at. The hop cert is deliberately short-lived (~120s,
            # pamAccessBastionCertTtl) — just long enough for sshd to accept it
            # at connection time — but the resulting backend SSH session lives
            # much longer, and a later sudo (fresh OTP) on that still-open
            # session legitimately presents the same fingerprint. Binding to the
            # cert's expiry broke sudo a couple of minutes into every session;
            # bind to binding_expires_at instead (falls back to expires_at for
            # records minted before this field existed). Still return the real
            # expires_at so callers (e.g. voucher minting) keep cert semantics.
            my $bindExp = $rec->{binding_expires_at} || $rec->{expires_at};
            if ( !$bindExp || $bindExp >= $now ) {
                return {
                    ok         => 1,
                    serial     => $rec->{serial},
                    key_id     => $rec->{key_id},
                    expires_at => $rec->{expires_at},
                    ephemeral  => 1,
                };
            }
        }
    }

    # ssh-ca stores SSO certificates one per fingerprint too, so the common
    # case is a second direct key lookup. Sessions written before that change
    # still carry the `_sshCerts` array; scan it as a fallback.
    my @certs;
    my $ssoRaw = $ps->data->{ $SSO_CERT_PREFIX . $fingerprint };
    if ( defined $ssoRaw and $ssoRaw ne '' ) {
        my $rec = eval { from_json($ssoRaw) };
        if ( $@ || ref($rec) ne 'HASH' ) {
            $self->logger->error(
                "PAM verify: corrupted SSO cert record for $user: $@");
            return { ok => 0, reason => 'corrupted' };
        }
        push @certs, $rec;
    }
    elsif ( my $raw = $ps->data->{_sshCerts} ) {
        my $legacy = eval { from_json($raw) };
        if ( $@ || ref($legacy) ne 'ARRAY' ) {
            $self->logger->error(
                "PAM verify: corrupted _sshCerts for $user: $@");
            return { ok => 0, reason => 'corrupted' };
        }
        @certs = @$legacy;
    }
    return { ok => 0, reason => 'no-certs' } unless @certs;

    for my $cert (@certs) {
        next unless ( $cert->{fingerprint} || '' ) eq $fingerprint;
        if ( $cert->{revoked_at} ) {
            return { ok => 0, reason => 'revoked' };
        }
        if ( $cert->{expires_at} && $cert->{expires_at} < $now ) {
            return { ok => 0, reason => 'expired' };
        }
        return {
            ok         => 1,
            serial     => $cert->{serial},
            label      => $cert->{label},
            key_id     => $cert->{key_id},
            expires_at => $cert->{expires_at},
        };
    }
    return { ok => 0, reason => 'not-found' };
}

# Is $server_group one of the configured bastion groups?
# Read a positive-integer duration from conf, falling back to $default when
# the key is unset or misconfigured. A non-numeric or <= 0 value would mint
# immediately-expired vouchers or break the ssh-keygen -V validity spec.
sub _confPositiveInt {
    my ( $self, $key, $default ) = @_;
    my $v = $self->conf->{$key};
    return $default unless defined $v && $v ne '';
    unless ( $v =~ /\A[0-9]+\z/ && $v > 0 ) {
        $self->logger->warn(
            "PamAccess: ignoring invalid $key value '$v', using $default");
        return $default;
    }
    return $v + 0;
}

sub _isBastionGroup {
    my ( $self, $server_group ) = @_;
    return 0 unless defined $server_group && $server_group ne '';
    my $bastion_groups = $self->conf->{pamAccessBastionGroups} || 'bastion';
    for my $allowed ( split /[,;\s]+/, $bastion_groups ) {
        return 1 if $server_group eq $allowed;
    }
    return 0;
}

# Whether the PAM service that triggered this /pam/authorize is allowed to mint
# (and therefore rotate) the bastion voucher. Only the interactive SSH login
# should: it is the one whose minted nonce is exported into the user's shell
# environment. Other services that also authorize for the same (bastion_id,
# user) — notably sudo/sudo-i — must leave the existing voucher untouched, or
# they rotate the nonce and break the voucher already handed to the login shell
# (the bastion then fails at /pam/bastion-cert with voucher_mismatch).
# Configurable via pamAccessBastionVoucherServices (default: "sshd ssh").
sub _isVoucherMintingService {
    my ( $self, $service ) = @_;
    return 0 unless defined $service && $service ne '';
    my $services = $self->conf->{pamAccessBastionVoucherServices} || 'sshd ssh';
    for my $allowed ( split /[,;\s]+/, $services ) {
        return 1 if $service eq $allowed;
    }
    return 0;
}

# Ensure a reusable (bastion_id, user) voucher exists in the user's persistent
# session: reuse the current still-valid nonce when present (only extending its
# expiry), otherwise generate a fresh one. Returns ($nonce, $exp) or ().
#
# Validity is capped by the user's SSO certificate expiry when the caller
# supplied a fingerprint we could match. When it did not, the voucher used to
# get the full pamAccessBastionVoucherTtl (12h by default), so the documented
# property "revoking the SSO invalidates the voucher with no additional delay"
# silently depended on an OPTIONAL binding being in play (issue #55). Without
# that binding the cap is now pamAccessBastionVoucherUnboundTtl (15 min), short
# enough that the claim holds approximately rather than not at all.
sub _mintBastionVoucher {
    my ( $self, $req, $user, $bastion_id, $cert_expires_at ) = @_;

    my $now    = time();
    my $ttlCap =
      $self->_confPositiveInt( 'pamAccessBastionVoucherTtl', 43200 );    # 12h
    unless ($cert_expires_at) {
        my $unbound =
          $self->_confPositiveInt( 'pamAccessBastionVoucherUnboundTtl', 900 );
        $ttlCap = $unbound if $unbound < $ttlCap;
    }
    my $exp = $now + $ttlCap;
    $exp = $cert_expires_at
      if $cert_expires_at && $cert_expires_at > $now && $cert_expires_at < $exp;

    # The voucher already held for this (user, bastion_id), from its own
    # record or, for a session written before the upgrade, from one of the two
    # persistent-session shapes.
    my $entry = $self->_readVoucherRecord( $user, $bastion_id );
    unless ( defined $entry ) {
        $self->logger->error(
            "PAM authorize: bastion voucher store unreachable for '$user'");
        return ();
    }
    $entry = $self->_legacyVoucherEntry( $user, $bastion_id ) unless %$entry;
    $entry = undef
      unless ref $entry eq 'HASH' and ( $entry->{exp} || 0 ) > $now;

    # Idempotent reuse. A user routinely holds several concurrent sessions on
    # the same bastion, and the (bastion_id, user) voucher is shared across all
    # of them (it is keyed per bastion, not per session). Minting a fresh nonce
    # on every /pam/authorize would overwrite the nonce already exported into
    # the other live sessions' shells, which then fail at /pam/bastion-cert with
    # voucher_mismatch (symptom: "works only from the most recent login"). So
    # keep an existing still-valid nonce and only extend its expiry; generate a
    # new nonce solely when none is usable (the read above already discarded an
    # expired entry for this bastion_id).
    my $nonce;
    if ( $entry && ( $entry->{nonce} // '' ) ne '' ) {
        $nonce = $entry->{nonce};
        $exp   = $entry->{exp}
          if ( $entry->{exp} || 0 ) > $exp;    # never shorten a live voucher
    }
    else {
        $nonce = $self->_generateUUID();
        unless ($nonce) {
            $self->logger->error(
                'PAM authorize: cannot generate bastion voucher nonce');
            return ();
        }
    }

    # One record, holding one voucher. Nothing else is stored alongside it, so
    # a concurrent mint for another bastion cannot lose this one and this one
    # cannot delete that one -- which is what the shared-hash shapes could not
    # promise.
    #
    # Two mints for the SAME bastion still race, and the outcome depends on
    # whether a nonce already exists. Once one does, they agree: both read it,
    # both write it back, and the loser only fails to extend an expiry the
    # winner extended too. With no live nonce yet -- a first connection, or an
    # expired or purged record -- both read nothing, both generate their own,
    # and the last write wins: the loser has already handed its shell a nonce
    # that is no longer in the store, so its next hop gets voucher_mismatch
    # and it recovers at the following authorize, which reuses the survivor.
    #
    # That is issue #54's symptom, narrowed from "any two concurrent mints" to
    # "two concurrent FRESH mints for the same (user, bastion_id)". It is not
    # gone, and it is not fixable here: the store offers no compare-and-swap,
    # so there is no way to make "generate only if absent" one operation.
    # Please do not "fix" it by rotating on every mint -- that reintroduces
    # the failure this helper's idempotent reuse exists to prevent.
    unless ( $self->_writeVoucherRecord( $user, $bastion_id, $nonce, $exp ) ) {
        $self->logger->error(
            "PAM authorize: cannot store bastion voucher for '$user'");
        return ();
    }

    return ( $nonce, $exp );
}

# HELPER: the store options for a voucher record.
#
# Built here rather than through p->getApacheSession so the record is pinned
# to the global store with no local cache: a voucher is minted on the node the
# bastion's /pam/authorize reached and spent on whichever node answers
# /pam/bastion-cert, so a node-local copy would only ever be a stale one. Same
# reasoning, and same shape, as the request-nonce cache.
#
# hashStore is pinned off because the id is derived, not random: read and
# write must agree on it whatever hashedSessionStore says globally.
sub _voucherStoreOpts {
    my ( $self, $user, $bastion_id ) = @_;

    return (
        storageModule        => $self->conf->{globalStorage},
        storageModuleOptions => $self->conf->{globalStorageOptions},
        hashStore            => 0,
        kind                 => $VOUCHER_KIND,
        id                   =>
          sha256_hex( 'pam-bastion-voucher:' . $user . ':' . $bastion_id ),
    );
}

# HELPER: read the voucher record for (user, bastion_id).
#
# Returns the stored entry as { nonce, exp }, an empty hashref when there is
# no record, or undef when the store could not be reached -- a distinction the
# callers need: "no voucher" is an answer, "cannot tell" is not.
sub _readVoucherRecord {
    my ( $self, $user, $bastion_id ) = @_;

    my $s = Lemonldap::NG::Common::Session->new(
        { $self->_voucherStoreOpts( $user, $bastion_id ) } );

    # A missing record and an unreachable store both surface as an error here,
    # and only the second one may refuse a request, so tell them apart by the
    # message. "Object does not exist [in the] data store" is the idiom every
    # Apache::Session store backend raises on a miss -- DBI, File, Postgres,
    # Oracle, and the Browseable ones (Redis, LDAP, ...) which match on that
    # same string themselves; "Invalid session ID" comes from the SHA256 id
    # generator. A backend whose miss message matches neither is read as a
    # store failure: the request is refused rather than silently treated as
    # "no voucher", which is the safe way round but worth knowing when adding
    # one.
    if ( $s->error ) {
        return {} if $s->error =~ /(?:Object does not exist|Invalid session)/i;
        $self->logger->error(
            'PAM: bastion voucher store read failed: ' . $s->error );
        return undef;
    }
    my $data = $s->data;
    return {} unless ref $data eq 'HASH' and ( $data->{nonce} // '' ) ne '';
    return { nonce => $data->{nonce}, exp => $data->{exp} || 0 };
}

# HELPER: write (or refresh) the voucher record. Returns true on success.
sub _writeVoucherRecord {
    my ( $self, $user, $bastion_id, $nonce, $exp ) = @_;

    # _utime carries the TTL to the store's purge, the way an authorization
    # code does it: purgeCentralCache drops a record once _utime + timeout has
    # passed. It is a sweep, not a clock, so exp is stored and checked too --
    # the record must stop being valid on time even if nothing has purged yet.
    my $timeout = $self->conf->{timeout} || 72000;
    my $s       = Lemonldap::NG::Common::Session->new( {
            $self->_voucherStoreOpts( $user, $bastion_id ),
            force => 1,
            info  => {
                _type      => 'pam_bastion_voucher',
                _utime     => $exp - $timeout,
                nonce      => $nonce,
                exp        => $exp,
                user       => $user,
                bastion_id => $bastion_id,
            },
        }
    );
    if ( $s->error ) {
        $self->logger->error(
            'PAM: bastion voucher store write failed: ' . $s->error );
        return 0;
    }
    return 1;
}

# HELPER: read a voucher from one of the two pre-upgrade persistent-session
# shapes -- the per-bastion key first, then the shared map. Read-only: see the
# note on $VOUCHER_PREFIX for why neither is written or cleaned up here.
# Returns undef when the session holds neither, or cannot be read.
sub _legacyVoucherEntry {
    my ( $self, $user, $bastion_id ) = @_;

    my $ps = $self->p->getPersistentSession($user);
    unless ( $ps and !$ps->error ) {

        # Only pre-upgrade vouchers live there, so this is no longer fatal to
        # minting: we lose the chance to carry an old nonce forward and mint a
        # fresh one instead. Before the move, the same failure refused the
        # voucher outright.
        $self->logger->warn(
                "PAM authorize: cannot read the persistent session of '$user' "
              . "for a pre-upgrade bastion voucher" );
        return undef;
    }
    my ($entry) = $self->_legacyVoucherEntryFromPs( $ps, $bastion_id );
    return $entry;
}

# HELPER: the same lookup against an already-loaded persistent session.
# Returns ( $entry, $corrupted ). The flag matters to /pam/bastion-cert, which
# answers 500 rather than 403 when the stored value is unreadable: that is an
# operator's problem, not a "reconnect to the bastion" for the user.
sub _legacyVoucherEntryFromPs {
    my ( $self, $ps, $bastion_id ) = @_;

    my $raw = $ps->data->{ $VOUCHER_PREFIX . $bastion_id };
    if ( defined $raw and $raw ne '' ) {
        my $entry = eval { from_json($raw) };
        return ( undef, 1 ) if $@ or ref $entry ne 'HASH';
        return ( $entry, 0 );
    }

    $raw = $ps->data->{$LEGACY_VOUCHER_KEY};
    return ( undef, 0 ) unless defined $raw and $raw ne '';
    my $map = eval { from_json($raw) };
    return ( undef, 1 ) if $@ or ref $map ne 'HASH';
    my $entry = $map->{$bastion_id};
    return ( ref $entry eq 'HASH' ? $entry : undef, 0 );
}

# Validate a (bastion_id, user) voucher presented by a bastion at
# /pam/bastion-cert. $ps is the user's already-loaded persistent session, kept
# as an argument because the caller needs it anyway and because a voucher
# minted before the upgrade still lives in it. Returns { ok => 1 } or
# { ok => 0, reason => '...' } with a machine-readable reason.
sub _checkBastionVoucher {
    my ( $self, $ps, $user, $bastion_id, $voucher ) = @_;

    return { ok => 0, reason => 'no_session' } unless $ps;
    return { ok => 0, reason => 'session_error' } if $ps->error;
    return { ok => 0, reason => 'no_voucher_supplied' }
      unless defined $voucher && $voucher ne '';

    # The voucher's own record first; then, for a session written before the
    # upgrade, the per-bastion key and the shared map it replaced.
    my $entry = $self->_readVoucherRecord( $user, $bastion_id );
    return { ok => 0, reason => 'voucher_store_failed' }
      unless defined $entry;
    unless (%$entry) {
        my $corrupted;
        ( $entry, $corrupted ) =
          $self->_legacyVoucherEntryFromPs( $ps, $bastion_id );
        return { ok => 0, reason => 'voucher_corrupted' } if $corrupted;
    }

    return { ok => 0, reason => 'voucher_expired' }
      unless $entry && ref $entry eq 'HASH';
    return { ok => 0, reason => 'voucher_expired' }
      if ( $entry->{exp} || 0 ) <= time();
    return { ok => 0, reason => 'voucher_mismatch' }
      unless ( $entry->{nonce} || '' ) eq $voucher;

    return { ok => 1 };
}

# POST /pam/bastion-cert - Sign a short-lived user certificate for a bastion
#
# The bastion proves: (1) it holds a valid device-grant token for a bastion
# group (Bearer); (2) it holds a fresh (bastion_id, user) voucher minted by
# /pam/authorize when this user actually connected to it. LLNG then signs the
# supplied ephemeral public key with the ssh-ca CA key, optionally pinning the
# cert to the bastion's IP (source-address, gated by
# pamAccessBastionCertPinSourceAddress) and encoding bastion_id in the key-id
# so the backend can enforce its allowed-bastions list.
#
# Request: { user, target_host, target_group, public_key, voucher }
# Response: { certificate, expires_in, serial, key_id }
sub bastionCert {
    my ( $self, $req ) = @_;

    # 1-3. Same caller gate as every other /pam/* endpoint (_checkCaller): a
    #      valid device-grant token with a pam scope. We do NOT require any
    #      "bastion group" here (see NB below); the voucher checked in step 6
    #      is the sole authorization.
    my ( $tokenSession, $bail ) = $self->_checkCaller( $req, 'bastion-cert' );
    return $bail if $bail;

    # Prefer the per-device identifier (stamped at enrollment by the
    # oidc-device-organization plugin) so a project-wide client_id still yields a
    # unique id per bastion; fall back to client_id for legacy enrollments.
    my $bastion_id = $self->_callerId($tokenSession);

    # NB: we deliberately do NOT re-derive or require a "bastion group" here.
    # The only security property that matters at this endpoint — a bastion may
    # mint a certificate ONLY for a user who actually connected to it — is
    # carried entirely by the voucher checked below. That voucher is minted by
    # /pam/authorize ONLY for a host whose resolved server_group is in
    # pamAccessBastionGroups, and it binds (bastion_id, user); so its mere
    # existence proves the caller was treated as a bastion at connection time.
    # (How strong that proof is depends on configuration: when
    # pamAccessServerGroups maps client_id->group the group is authoritative;
    # in legacy mode, with that mapping empty, /pam/authorize trusts the
    # caller-provided server_group, so configure the mapping to harden this.)
    # Re-checking the group from the access-token session here was both
    # redundant and wrong for the intended model (one OIDC client_id per
    # *project*, with finer-grained PAM groups inside it): the device-grant
    # session carries no per-host server_group, so it always resolved to
    # "default" and rejected every legitimate hop.

    # 5. Parse + validate request body.
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM bastion-cert: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user         = $body->{user};
    my $target_host  = $body->{target_host}  || '';
    my $target_group = $body->{target_group} || 'default';
    my $public_key   = $body->{public_key};
    my $voucher      = $body->{voucher};

    return $self->_badRequest( $req, 'Missing user parameter' ) unless $user;

    # The principal we sign equals the unix login; reject separators that
    # ssh-keygen -n would split into multiple principals or that would poison
    # the key-id encoding.
    return $self->_badRequest( $req, 'Invalid user parameter' )
      if $user =~ m{[\s,/;]};

    return $self->_badRequest( $req, 'Missing public_key parameter' )
      unless $public_key;
    return $self->_badRequest( $req, 'Missing voucher parameter' )
      unless $voucher;

    # Strict SSH public key validation (same contract as ssh-ca /ssh/sign).
    unless ( $public_key =~
        /\A(ssh-\w+|ecdsa-sha2-\w+)\s+[A-Za-z0-9+\/]+={0,2}(?:\s+[^\r\n]*)?\z/ )
    {
        return $self->_badRequest( $req, 'Invalid SSH public key format' );
    }

    # 6. Voucher check: proves this user really connected to THIS bastion.
    my $ps   = $self->p->getPersistentSession($user);
    my $vres =
      $self->_checkBastionVoucher( $ps, $user, $bastion_id, $voucher );
    unless ( $vres->{ok} ) {
        $self->logger->info(
                "PAM bastion-cert: voucher rejected for user '$user' "
              . "(bastion='$bastion_id', reason=$vres->{reason})" );
        $self->p->auditLog(
            $req,
            code        => 'PAM_BASTION_CERT_VOUCHER_REJECTED',
            user        => $user,
            message     => "PAM bastion-cert denied: $vres->{reason}",
            bastion_id  => $bastion_id,
            target_host => $target_host,
            reason      => $vres->{reason},
        );

        # Machine-readable reason so ob-ssh-proxy can show a precise message
        # (e.g. 'voucher_expired' -> "reconnect to the bastion"). Internal
        # conditions (session backend failure, voucher store unreachable,
        # unreadable pre-upgrade value) are server errors, not authorization
        # denials: 5xx keeps clients and monitoring from treating them as a
        # 403 "reconnect to the bastion".
        my $internal = $vres->{reason} =~
          /\A(?:no_session|session_error|voucher_corrupted|voucher_store_failed)\z/;
        return $self->p->sendJSONresponse(
            $req,
            {
                error => $internal ? 'voucher_check_failed'
                : 'voucher_rejected',
                reason => $vres->{reason}
            },
            code => $internal ? 500 : 403
        );
    }

    # 7. Reach the ssh-ca plugin to sign with the CA key.
    my $sshca =
      $self->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
    unless ( $sshca && $sshca->can('_signSshKey') && $sshca->sshPrivKey ) {
        $self->logger->error(
            'PAM bastion-cert: SSHCA plugin not available/initialised');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'SSH CA not available' },
            code => 500
        );
    }

    # 8. Encode bastion identity in the key-id for the backend to allowlist.
    #    Sanitize each part so the `k=v;` encoding stays unambiguous.
    my $clean = sub { my $v = shift // ''; $v =~ s/[^A-Za-z0-9._-]/_/g; $v };
    my $keyId = sprintf( 'bastion=%s;user=%s;target=%s',
        $clean->($bastion_id), $clean->($user), $clean->($target_host) );

    my $ttl    = $self->_confPositiveInt( 'pamAccessBastionCertTtl', 120 );

    # Binding window: how long the backend's SSH-fingerprint check
    # (_checkSshFingerprint) keeps accepting this hop cert's fingerprint for a
    # still-open session — independent of the SSH cert's own (short) validity.
    # Must cover a realistic backend session (default 24h); never shorter than
    # the cert TTL.
    my $bindingTtl =
      $self->_confPositiveInt( 'pamAccessBastionBindingTtl', 86400 );
    $bindingTtl = $ttl if $bindingTtl < $ttl;

    my $serial = $sshca->_getNextSerial;
    my %signOpts = ( validity => "+${ttl}s" );

    # Optionally pin the cert to the vouching bastion's IP (sshd-native
    # enforcement), so a leaked ephemeral cert is only usable from the bastion
    # that requested it. Off by default: the observed address must match the
    # bastion's SSH egress address (no NAT/PAT, no reverse proxy in between).
    my $pinSource  = $self->conf->{pamAccessBastionCertPinSourceAddress};
    my $bastion_ip = $req->address;
    my $valid_ip = defined $bastion_ip && $bastion_ip =~ /\A[0-9a-fA-F:.]+\z/;
    if ($pinSource) {

        # Fail closed (issue #56). The observed address can be absent or empty
        # behind some FastCGI and socket front-ends; minting an unpinned cert
        # there produced a certificate indistinguishable from a pinned one, and
        # nothing in the audit record said which it was. The option is opt-in,
        # so an operator who turned it on asked for the guarantee, not for a
        # best effort.
        unless ($valid_ip) {
            $self->logger->error(
                "PAM bastion-cert: source-address pin requested but the"
                  . " observed address is unusable ("
                  . ( defined $bastion_ip ? "'$bastion_ip'" : 'undef' )
                  . "), refusing to mint an unpinned certificate" );
            $self->p->auditLog(
                $req,
                code    => 'PAM_BASTION_CERT_PIN_UNAVAILABLE',
                user    => $user,
                message => "Refused to mint an unpinned bastion certificate"
                  . " for '$user': no usable source address",
                bastion_id => $bastion_id,
            );
            return $self->_forbiddenResponse( $req,
                'Source address pin required but unavailable' );
        }
        $signOpts{source_address} = $bastion_ip;
    }

    my $result =
      $sshca->_signSshKey( $public_key, [$user], 2, $serial, $keyId,
        \%signOpts );
    unless ( $result && $result->{certificate} ) {
        $self->logger->error(
            "PAM bastion-cert: signing failed for user '$user'");
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to sign certificate' },
            code => 500
        );
    }

    # Register the ephemeral cert's public-key fingerprint so the backend this
    # hop targets accepts it: its /pam/authorize SSH-fingerprint binding
    # (_checkSshFingerprint) only admits fingerprints we know, otherwise the
    # vouched hop is denied as "fingerprint not-found".
    #
    # Stored under a PER-FINGERPRINT key ($EPH_CERT_PREFIX.<fp>), NOT in the
    # shared _sshCerts list, deliberately:
    #   * Concurrency — see the note on $VOUCHER_KIND: per key, two hops
    #     minted at the same time only collide inside update()'s
    #     tie-to-untie window instead of over the whole helper.
    #   * Separation — _sshCerts holds the user's SSO certs owned by ssh-ca,
    #     which intentionally keeps expired records (revoking via the KRL). We
    #     must not prune those, so ephemeral hop certs live in their own keyspace.
    # Entries self-expire via expires_at (enforced in _checkSshFingerprint); we
    # opportunistically drop our OWN expired keys in the same update. This is
    # the residual vouchers used to share and no longer do: the undefs come
    # from a snapshot, so a hop registered concurrently under a key we saw
    # expired can be dropped, and that hop's backend then denies its
    # fingerprint until the user re-hops. Moving these to their own records
    # would need a way to find one by fingerprint, which a session id derived
    # from (user, bastion_id) gives vouchers and nothing gives these.
    my $eph_fp = $sshca->_sshKeyFingerprint($public_key);
    if ( $eph_fp && $ps && !$ps->error ) {
        my $now  = time();
        my %upd  = (
            $EPH_CERT_PREFIX . $eph_fp => to_json(
                {
                    serial             => $serial,
                    key_id             => $keyId,
                    issued_at          => $now,
                    expires_at         => $now + $ttl,
                    binding_expires_at => $now + $bindingTtl,
                }
            )
        );
        for my $k ( keys %{ $ps->data } ) {
            next unless index( $k, $EPH_CERT_PREFIX ) == 0;
            next if $k eq $EPH_CERT_PREFIX . $eph_fp;
            my $r = eval { from_json( $ps->data->{$k} // '' ) };
            # Drop on the binding window (fallback to the cert expiry for
            # pre-existing records), matching _checkSshFingerprint's acceptance
            # rule — otherwise we would prune entries that are still bindable.
            my $rexp =
              ref($r) eq 'HASH'
              ? ( $r->{binding_expires_at} || $r->{expires_at} )
              : undef;
            $upd{$k} = undef
              if $@
              || ref($r) ne 'HASH'
              || ( $rexp && $rexp < $now );
        }
        $ps->update( \%upd );
    }
    elsif ( !$eph_fp ) {
        $self->logger->warn(
                "PAM bastion-cert: could not compute fingerprint for ephemeral "
              . "key (user '$user'); the backend fp binding may deny this hop" );
    }

    $self->p->auditLog(
        $req,
        code    => 'PAM_BASTION_CERT_ISSUED',
        user    => $user,
        message =>
          "Bastion ephemeral cert issued for '$user' to '$target_host'",
        bastion_id   => $bastion_id,
        target_host  => $target_host,
        target_group => $target_group,
        serial       => $serial,
        key_id       => $keyId,
        ttl          => $ttl,
        (
            $signOpts{source_address}
            ? ( source_address => $signOpts{source_address} )
            : ()
        ),
    );

    $self->logger->info( "PAM bastion-cert: issued cert serial=$serial for "
          . "user '$user' (bastion='$bastion_id' -> '$target_host', ttl=${ttl}s)"
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            certificate => $result->{certificate},
            expires_in  => $ttl + 0,
            serial      => $serial,
            key_id      => $keyId,
        }
    );
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::PamAccess - PAM authentication/authorization plugin

=head1 SYNOPSIS

Enable this plugin in LemonLDAP::NG Manager:
General Parameters > Plugins > PAM Access > Activation

=head1 DESCRIPTION

This plugin provides three main features:

=head2 User Token Generation (/pam)

Authenticated users can generate temporary ONE-TIME access tokens that can
be used as passwords for PAM authentication (e.g., SSH login).

Tokens are stored as sessions with kind='PAMTOKEN' and are automatically
destroyed after first use, preventing replay attacks.

=head2 Token Verification (/pam/verify)

Servers validate and consume one-time user tokens. The token is destroyed
immediately upon successful verification, ensuring single-use semantics.

=head2 Server Authorization (/pam/authorize)

Servers can check if a user is authorized to access a service, even when
the user authenticates via SSH key (no token involved).

=head1 CALLER AUTHENTICATION

Every server-to-server endpoint (C</pam/authorize>, C</pam/verify>,
C</pam/userinfo>, C</pam/heartbeat> and C</pam/bastion-cert>) applies the same
gate to its caller:

=over

=item *

a caller credential: a Bearer access token, or — for C</pam/heartbeat>, which
authenticates through the request body — the refresh token it presents;

=item *

that credential must come from the Device Authorization Grant
(C<grant_type> = C<device_code>), i.e. the server must be enrolled;

=item *

it must carry the C<pam> or C<pam:server> scope. The scope is matched
B<exactly> against the whitespace-separated values of the granted scope
(RFC 6749 section 3.3): C<pam-x>, C<x-pam> or C<pam:server:extra> are not
C<pam>.

=back

Failing the first check yields C<401>, the other two C<403>.

=head1 SIGNED RESPONSES

A caller sending C<Accept: application/ob-pam-response+jwt> to
C</pam/authorize>, C</pam/verify>, C</pam/userinfo>, C</pam/whoami> or
C</pam/heartbeat> receives, instead of the JSON object, a compact JWS with
C<Content-Type: application/ob-pam-response+jwt> and the same HTTP status.
Every answer is signed, refusals included. Without that header nothing
changes. C</pam/bastion-cert> is never signed.

The JWS header carries C<typ: ob-pam-response+jwt> and the C<kid> of the
signing key: the caller's relying party C<oidcRPMetaDataOptionsSigningKey>,
else C<oidcServiceSignatureKey> -- i.e. the keys published by the JWKS
endpoint with C<?client_id=E<lt>callerE<gt>>. Claims:

  iss          issuer
  aud          the caller's client_id, absent until the caller has passed
               the caller gate (a host MUST only accept a missing aud on an
               answer that grants nothing: anyone can obtain a signed
               aud-less refusal for a nonce and body of its choice)
  iat, exp     now, now + 60
  endpoint     authorize | verify | userinfo | whoami | heartbeat
  req_nonce    the request's X-Nonce, verbatim
  req_sha256   hex SHA-256 of the raw request body
  http_status  the HTTP status of the answer
  resp         the JSON object the plain answer carries
  jwks         (heartbeat success only) the same signature keys as
               /oauth2/jwks?client_id= (encryption keys are not included:
               they are not needed to verify an answer)

A signed answer requires an C<X-Nonce> (C<[0-9A-Za-z._:-]{1,128}>): without
one the request is refused with a signed C<400 {"error":"nonce_required"}>
before any work is done. When the answer cannot be signed (an algorithm that
is not asymmetric, an RP flagged C<oidcRPMetaDataOptionsNoJwtHeader>, no
usable key) the portal answers an B<unsigned>
C<500 {"error":"response_signing_unavailable"}>, never the plain body.

=head1 ENDPOINTS

=head2 GET /pam

Display the token generation interface (requires authentication).

=head2 POST /pam

Generate a new one-time PAM access token.

Parameters:
- duration: Token validity in seconds (optional, default: 600)

Response:
{
  "token": "session_id",
  "login": "username",
  "expires_in": 600
}

=head2 POST /pam/verify

Verify and consume a one-time user token (server-to-server).

Requires: Server Bearer token in Authorization header (from Device Auth Grant)

Request body:
{
  "token": "user_token_to_verify"
}

Response:
{
  "valid": true/false,
  "user": "username",
  "groups": ["group1", "group2"],
  "error": "..." (only if invalid)
}

IMPORTANT: The token is destroyed after successful verification (one-time use).

=head2 POST /pam/authorize

Check if a user is authorized (server-to-server).

Requires: Bearer token in Authorization header

Request body:
{
  "user": "username",
  "host": "server.example.com",
  "service": "ssh"
}

Response:
{
  "authorized": true/false,
  "user": "username",
  "groups": ["group1", "group2"],
  "reason": "..." (only if denied)
}

When the calling server belongs to a bastion group (see
C<pamAccessBastionGroups>), a successful authorization also returns:
{
  "bastion_voucher": "uuid",
  "bastion_voucher_expires_in": 43200
}

The voucher is a reusable (bastion, user) capability stored in the user's
persistent session; the bastion later presents it to C</pam/bastion-cert>.

=head2 POST /pam/bastion-cert

Sign a short-lived ephemeral SSH user certificate for a bastion-to-backend
hop (requires the ssh-ca plugin). The bastion proves it holds a valid
device-grant Bearer token for a bastion group, plus a fresh
(bastion, user) voucher minted by C</pam/authorize> when the user actually
connected to it. When C<pamAccessBastionCertPinSourceAddress> is enabled the
certificate is pinned to the bastion's IP (C<source-address> critical
option); it always encodes the bastion identity in its key-id so backends
can enforce an allowed-bastions list.

Requires: Bearer token in Authorization header

Request body:
{
  "user": "username",
  "target_host": "backend.example.com",
  "target_group": "production",
  "public_key": "ssh-ed25519 AAAA... ephemeral",
  "voucher": "uuid"
}

Response:
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "expires_in": 120,
  "serial": 1234,
  "key_id": "bastion=...;user=...;target=..."
}

On voucher rejection, returns 403 with a machine-readable reason
(C<no_voucher_supplied>, C<voucher_expired>, C<voucher_mismatch>); internal
failures (session backend error, corrupted voucher map) return 500.

=head2 POST /pam/heartbeat

Server heartbeat for monitoring enrolled PAM servers.

Request body:
{
  "refresh_token": "session_id_of_refresh_token",
  "hostname": "server.example.com",
  "server_group": "production",
  "version": "1.0.0",
  "stats": { "auth_success": 42, "auth_failure": 3 }
}

Response:
{
  "status": "ok",
  "next_heartbeat": 300,
  "server_time": 1702742400
}

=head1 CONFIGURATION

=over

=item pamAccessActivation

Enable/disable the plugin (default: 0)

=item portalDisplayPamAccess

Rule for displaying the menu tab (default: 0)

=item pamAccessTokenDuration

Default token validity in seconds (default: 600)

=item pamAccessMaxDuration

Maximum token validity in seconds (default: 3600)

=item pamAccessRp

OIDC Relying Party name for tokens (default: 'pam-access')

=item pamAccessResponseSigningAlg

Algorithm of the signed responses (see L</SIGNED RESPONSES>). Empty
(default): the relying party's C<oidcRPMetaDataOptionsIDTokenSignAlg> when it
is asymmetric, else C<RS256>. Only RS*, PS*, ES* and EdDSA are accepted: any
other value makes every signed answer an unsigned C<500>.

=item pamAccessHeartbeatInterval

Expected interval between server heartbeats in seconds (default: 300)

=item pamAccessInactiveThreshold

Maximum age, in seconds, of the last heartbeat of a server calling
C</pam/authorize> when C<pamAccessHeartbeatRequired> is enabled (default: 900,
i.e. three missed beats at the default C<pamAccessHeartbeatInterval> of 300s).
Must be a positive integer; invalid values fall back to the default. Ignored
when C<pamAccessHeartbeatRequired> is off.

=item pamAccessHeartbeatRequired

When enabled, C</pam/authorize> additionally requires the calling server to
have sent a heartbeat less than C<pamAccessInactiveThreshold> seconds ago; a
server that has never beaten, or has stopped beating, is answered C<403>
(C<Server has not sent a heartbeat> / C<Server heartbeat is stale>) instead of
being allowed to authorize users on the strength of a still-valid access
token. Enable it to make a decommissioned, cloned or tampered-with machine
lose its authority within the threshold rather than at token expiry.

Liveness is read from the heartbeat markers C</pam/heartbeat> stamps: on the
refresh-token session it beats against, and on every access token it mints
(C<_pamLastSeen>, plus C<_pamRtRef> pointing back at the refresh-token session
so the I<live> value is used even when a server reuses one access token for
its whole lifetime). Consequently a server must beat at least once after
enrollment before it can authorize anybody; the plain device-grant token
carries no marker.

(default: 0, i.e. no liveness requirement)

=item pamAccessBastionGroups

Comma/space-separated list of server groups considered bastions
(default: 'bastion'). Members of these groups get a bastion voucher from
C</pam/authorize> and may call C</pam/bastion-cert>.

=item pamAccessBastionVoucherServices

Comma/space-separated list of PAM service names whose C</pam/authorize> call
is allowed to mint (and rotate) the bastion voucher (default: 'sshd ssh').
Only the interactive SSH login should mint, since its nonce is exported into
the user's shell. Other services that also authorize for the same bastion and
user — notably C<sudo>/C<sudo-i> — must be excluded, otherwise they rotate the
nonce and invalidate the voucher already held by the login shell (which then
fails at C</pam/bastion-cert> with C<voucher_mismatch>).

=item pamAccessBastionVoucherTtl

Maximum validity of a bastion voucher in seconds (default: 43200, i.e. 12h).
The voucher is further capped by the user's SSO certificate expiry when
known. Must be a positive integer; invalid values fall back to the default.

=item pamAccessBastionVoucherUnboundTtl

Maximum validity of a voucher minted when the caller supplied no SSH
fingerprint, so nothing binds it to the user's SSO certificate expiry
(default: 900, i.e. 15 minutes). Only ever lowers the cap: a value above
C<pamAccessBastionVoucherTtl> has no effect.

=item pamAccessRequireFingerprint

Refuse C</pam/verify> and C</pam/authorize> with HTTP 400 when the caller
supplies no SSH fingerprint (default: 0). Off by default because the
fingerprint is optional by contract; turn it on once the client-side spool is
deployed everywhere, to make the binding a requirement rather than a
best effort.

=item pamAccessBastionCertTtl

Validity of the ephemeral certificates issued by C</pam/bastion-cert>, in
seconds (default: 120). Must be a positive integer; invalid values fall
back to the default.

=item pamAccessBastionBindingTtl

How long a hop certificate's fingerprint stays bindable on the target
backend, in seconds (default: 86400, i.e. 24h). This is independent of
C<pamAccessBastionCertTtl>: the SSH certificate is short-lived (just long
enough for sshd to accept the connection), but the resulting backend SSH
session lives much longer, and a later C<sudo> on that still-open session
(with a fresh one-time token) must keep validating against the same
fingerprint. C<_checkSshFingerprint> therefore accepts the fingerprint until
this binding window elapses rather than until the certificate expires. Must
be a positive integer; values below C<pamAccessBastionCertTtl> are raised to
it. Revocation still applies. Only affects hop certificates
(C</pam/bastion-cert>); direct C<_sshCerts> certificates keep their own
(longer) validity.

=item pamAccessBastionCertPinSourceAddress

When enabled, the ephemeral certificate issued by C</pam/bastion-cert> is
pinned to the bastion's IP through the C<source-address> critical option,
so that a leaked certificate can only be used from the bastion that
requested it (sshd-native enforcement). It is B<recommended to enable this>
whenever there is no NAT/PAT between the bastions and the portal, as it adds
a strong, transparent restriction at no cost. Leave it disabled when the
address LemonLDAP::NG observes does not match the bastion's SSH egress
address (portal behind a reverse proxy, multi-homed bastion, NAT/PAT),
otherwise legitimate certificates would be rejected by the backend.
(default: 0, disabled)

=item pamAccessChoice

When LemonLDAP::NG uses Choice authentication, name of the
authChoiceModules entry (e.g. C<1_LDAP>) to use for the server-to-server
endpoints C</pam/authorize> and C</pam/userinfo>.
Leave empty if Choice is not used.

=back

=head1 SERVER-TO-SERVER LOOKUPS AND PLUGIN HOOKS

C</pam/authorize> and C</pam/userinfo> resolve a user on behalf of a remote
host. These are not authentication events: nobody is
authenticating, and the address the portal observes is the calling server's.

Any plugin hooked on the steps they run would therefore see an
"authentication" that never happened, attributed to the wrong address. With
L<Lemonldap::NG::Portal::Plugins::CrowdSecAgent> enabled that is remotely
exploitable: sshd resolves an offered login through NSS I<before>
authenticating, so an unknown login tried against a bastion would make it
report itself until CrowdSec bans its own IP.
L<Lemonldap::NG::Portal::Plugins::NewLocationWarning> would likewise treat
the bastion's address as a new location for the user.

These endpoints therefore run their steps as coderefs, which
L<Lemonldap::NG::Portal::Main::Process> dispatches without consulting
C<aroundSub> or C<afterSub>. No plugin -- core or custom, present or future --
observes them, and none is modified. Genuine SSH failures are reported by the
bastion itself, which knows the real client address.

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::DeviceAuthorization> for server enrollment

=head1 AUTHORS

=over

=item Xavier Guimard L<yadd@debian.org>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
