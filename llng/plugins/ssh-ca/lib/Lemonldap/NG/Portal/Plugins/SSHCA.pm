# SSH Certificate Authority plugin for LemonLDAP::NG
#
# This plugin provides SSH certificate signing functionality:
# - /ssh/ca : Public CA key endpoint (no auth required)
# - /ssh/revoked : Key Revocation List (KRL) endpoint (no auth required)
# - /ssh/sign : Sign user's SSH public key (auth required)
# - /ssh/mycerts : List the caller's own certificates (auth required)
# - /ssh/myrevoke : Self-revoke one of the caller's own certificates (auth)
# - /ssh/admin : Administration interface (auth + sshCaAdminRule)
# - /ssh/certs : List/search issued certificates (auth + sshCaAdminRule)
# - /ssh/revoke : Revoke any certificate (auth + sshCaAdminRule)
#
# The three administration endpoints are guarded by `sshCaAdminRule`, a
# boolOrExpr evaluated against the caller's session. It has NO permissive
# default: when it is unset the endpoints answer 403 (see _forbidNonAdmin).
#
# Requires configuration of SSH CA key in LLNG keys store.

package Lemonldap::NG::Portal::Plugins::SSHCA;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Time::HiRes qw(gettimeofday);
use Digest::SHA qw(sha256);
use MIME::Base64 qw(decode_base64 encode_base64);
use URI;
use Lemonldap::NG::Common::Apache::Session;
use Lemonldap::NG::Handler::Main::MsgActions;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.23.0';

# Persistent-session key prefix for issued certificate records, one key per
# certificate ($CERT_PREFIX.<fingerprint>).
#
# Certificates used to share a single `_sshCerts` JSON array, so every sign
# and every revocation was a read-modify-write over a blob the store rewrites
# wholesale: two concurrent /ssh/sign calls, or a revoke racing a sign, lost
# one of the two records (issue #66). Per key, Common::Session->update re-ties
# with noCache => 1 and sets only the named keys, so writers now collide only
# when their tie-to-untie windows overlap — there is still no locking
# (Apache::Session::Lock::Null), but the window is a store round-trip instead
# of a whole request.
#
# The fingerprint is the key because it is what every reader looks up
# (pam-access binds PAM tokens to it) and because re-signing the same key is
# meant to REPLACE its record — which per key is a plain overwrite. Sessions
# written before the upgrade keep their `_sshCerts` array; it is still read,
# and drained into per-key records on the next write.
our $CERT_PREFIX = '_sshCert::';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'SSHCA';

# Key policy defaults (see sshCaAllowedKeyTypes / sshCaMinKeyBits).
#
# `ssh-dss` is deliberately absent: DSA is capped at 1024-bit keys with
# SHA-1 signatures, has been disabled at compile time in OpenSSH since 9.8
# and removed outright in OpenSSH 10. Operators who still need it can put
# `dss` back in sshCaAllowedKeyTypes.
use constant SSHCA_DEFAULT_KEY_TYPES => 'ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa';
use constant SSHCA_DEFAULT_MIN_BITS  => 2048;

# Key types whose size is fixed by the algorithm/curve. `family` is the
# token used in sshCaAllowedKeyTypes, `bits` the effective key size — these
# are NOT comparable with an RSA modulus size, hence `sized => 0`: the
# sshCaMinKeyBits floor only applies to variable-size families.
my %SSHCA_FIXED_KEY_TYPES = (
    'ssh-ed25519'                        => [ 'ed25519',  256 ],
    'sk-ssh-ed25519@openssh.com'         => [ 'sk-ed25519', 256 ],
    'ecdsa-sha2-nistp256'                => [ 'ecdsa',    256 ],
    'ecdsa-sha2-nistp384'                => [ 'ecdsa',    384 ],
    'ecdsa-sha2-nistp521'                => [ 'ecdsa',    521 ],
    'sk-ecdsa-sha2-nistp256@openssh.com' => [ 'sk-ecdsa', 256 ],
);

has key => (
    is      => 'rw',
    lazy    => 1,
    builder => sub {
        $_[0]->conf->{sshCaKeyRef}
          ? $_[0]->conf->{keys}->{ $_[0]->conf->{sshCaKeyRef} }
          : undef;
    },
);

has sshPubKey  => ( is => 'rw' );
has sshPrivKey => ( is => 'rw' );

# Compiled `sshCaAdminRule`. Always a code ref after init(): when the
# parameter is unset or does not compile, it is the constant-false sub, so
# every code path that consults it fails closed.
has adminRule => ( is => 'rw' );

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check parameters
    unless ( $self->key
        and ref $self->key
        and $self->key->{keyPublic}
        and $self->key->{keyPrivate} )
    {
        $self->logger->error('SSH CA Key not configured');
        return 0;
    }

    unless (
        $self->sshPubKey(
            $self->_pemToSshPublicKey(
                $self->key->{keyPublic},
                $self->conf->{sshCaKeyRef}
            )
        )
      )
    {
        $self->logger->error(
            'SSH CA: Failed to convert public key to SSH format');
        return 0;
    }
    unless (
        $self->sshPrivKey(
            $self->_pemToOpenSSHPrivateKey( $self->key->{keyPrivate} )
        )
      )
    {
        $self->logger->error(
            'SSH CA: Failed to convert private key to SSH format');
        return 0;
    }
    $self->sshPrivKey( $self->sshPrivKey . "\n" )
      unless $self->sshPrivKey =~ /\n$/s;

    # Build the administration rule (issue #58).
    #
    # /ssh/admin, /ssh/certs and /ssh/revoke expose EVERY user's certificates
    # and let the caller revoke any of them. They used to rely solely on
    # locationRules being set on the portal vhost, which is not a default
    # deny: a portal whose vhost has `"default": "accept"` and no `^/ssh`
    # rule (the shape shipped by every open-bastion config) handed full SSH
    # CA administration to any authenticated user. The plugin now carries its
    # own rule and denies when it is unset — an unconfigured deployment loses
    # the admin UI, never the other way round.
    my $adminRule = $self->conf->{sshCaAdminRule};
    $adminRule = '' unless defined $adminRule;
    $adminRule =~ s/^\s+|\s+$//g;
    if ( $adminRule eq '' or $adminRule eq '0' ) {
        $self->logger->warn(
                'SSH CA: sshCaAdminRule is not set, the administration '
              . 'endpoints (/ssh/admin, /ssh/certs, /ssh/revoke) are denied' );
        $self->adminRule( sub { 0 } );
    }
    else {
        my $rule = $self->p->buildRule( $adminRule, 'sshCaAdmin' );
        unless ($rule) {

            # buildRule() already logged the compilation error. Fail closed on
            # the admin endpoints only: users must still be able to sign their
            # own keys, so don't abort the whole plugin.
            $self->logger->error(
                    'SSH CA: unable to compile sshCaAdminRule, the '
                  . 'administration endpoints are denied' );
            $rule = sub { 0 };
        }
        $self->adminRule($rule);
    }

    # GET /ssh/ca - Public CA key (no auth required)
    $self->addUnauthRoute(
        ssh => { ca => 'sshCaPublicKey' },
        ['GET']
    )

      # POST /ssh/sign - Sign user's SSH key (auth required)
      ->addAuthRoute(
        ssh => { sign => 'sshCaSign' },
        ['POST']
      )

      # GET /ssh/mycerts - List current user's certificates (auth required)
      ->addAuthRoute(
        ssh => { mycerts => 'sshMyCerts' },
        ['GET']
      )

      # POST /ssh/myrevoke - User revokes one of their own certificates
      ->addAuthRoute(
        ssh => { myrevoke => 'sshMyCertRevoke' },
        ['POST']
      )

      # GET /ssh/admin - Display the revocation interface (auth required, admin)
      ->addAuthRoute(
        ssh => { admin => 'sshAdminInterface' },
        ['GET']
      )

      # GET /ssh/certs - List/search certificates (auth required, admin)
      ->addAuthRoute(
        ssh => { certs => 'sshCertsList' },
        ['GET']
      )

      # POST /ssh/revoke - Revoke a certificate (auth required, admin)
      ->addAuthRoute(
        ssh => { revoke => 'sshCertRevoke' },
        ['POST']
      )

      # GET /ssh - Display the signing interface (standalone page, auth required)
      ->addAuthRoute(
        ssh => { '*' => 'sshInterface' },
        ['GET']
      )

      # Redirect unauthenticated users to portal for /ssh (except /ssh/ca and /ssh/revoked)
      ->addUnauthRoute(
        ssh => { '*' => 'sshRedirectToPortal' },
        ['GET']
      );

    # GET /ssh/revoked - Key Revocation List (no auth required)
    unless ( $self->conf->{sshCaKrlPath} ) {
        $self->logger->error('SSH CA: No KRL path configured');
    }
    else {
        $self->addUnauthRoute(
            ssh => { revoked => 'sshCaKrl' },
            ['GET']
        )->addAuthRoute(
            ssh => { revoked => 'sshCaKrl' },
            ['GET']
        );

        # Make sure a *parsable* KRL exists from the start (issue #64).
        # Serving an empty body (or nothing at all) leaves consumers with a
        # file sshd cannot parse as a KRL; a header-only KRL generated by
        # ssh-keygen is the correct representation of "nothing revoked yet".
        $self->_ensureKrl( $self->conf->{sshCaKrlPath} );
    }

    # Multi-node replication of the KRL (issue #9). The KRL file is local to
    # each portal host, so a revocation on node A must be propagated to node B.
    # We rely on LLNG's message broker (requires ::Redis / ::MQTT / ::Pg — the
    # default ::NoBroker only dispatches in-process). Every node registers a
    # handler that updates its own KRL file on receiving a 'sshCaRevoke' event.
    # Drift recovery (broker outage, node added later) is handled out of band
    # by the external sshca-rebuild-krl cron script, which scans the
    # persistent sessions (source of truth) and rewrites the local KRL.
    Lemonldap::NG::Handler::Main::MsgActions::addMsgAction(
        'sshCaRevoke',
        sub {
            my ( $class, $msg, $req ) = @_;
            my $serial = $msg->{serial};

            # The broker payload is the only path into _updateKrl that is not
            # matched against a stored certificate record first, so validate
            # it here (issue #65): the serial ends up verbatim in the
            # ssh-keygen KRL spec file, where a newline would inject extra
            # directives (`id:`, `key:`, `hash:`).
            unless ( $self->_validSerial($serial) ) {
                $self->logger->error(
                    'SSH CA: ignoring sshCaRevoke event with invalid serial');
                return;
            }
            $self->logger->debug(
                "SSH CA: broker event sshCaRevoke serial=$serial");
            $self->_updateKrl($serial);
        }
    );

    $self->logger->debug('SSH CA plugin initialized');

    return 1;
}

# Redirect unauthenticated users to portal (preserving REQUEST_URI)
sub sshRedirectToPortal {
    my ( $self, $req ) = @_;
    $self->p->api->goToPortal( $req, $req->{env}->{REQUEST_URI} );
    return $self->p->sendRedirection($req);
}

# GET /ssh - Display the signing interface (standalone page)
sub sshInterface {
    my ( $self, $req ) = @_;

    my $maxValidityDays = $self->conf->{sshCaCertMaxValidity} || 365;

    return $self->p->sendHtml(
        $req, 'sshca',
        params => {
            MAX_VALIDITY_DAYS => $maxValidityDays,
            js => "$self->{p}->{staticPrefix}/common/js/sshca.js",
        }
    );
}

# =============================================================================
# ROUTE HANDLERS
# =============================================================================

# GET /ssh/ca.pub - Return SSH CA public key
sub sshCaPublicKey {
    my ( $self, $req ) = @_;

    return [
        200,
        [
            'Content-Type'  => 'text/plain; charset=utf-8',
            'Cache-Control' => 'public, max-age=3600',
        ],
        [ $self->sshPubKey ]
    ];
}

# GET /ssh/revoked - Return SSH Key Revocation List (KRL)
sub sshCaKrl {
    my ( $self, $req ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath};

    # No KRL yet (fresh install, or the file was removed): generate a valid
    # empty one rather than serving an empty body (issue #64). This is a
    # no-op once the file exists, so the normal path costs one stat().
    $self->_ensureKrl($krlPath) unless $krlPath and -s $krlPath;

    unless ( $krlPath and -f $krlPath ) {

        # Generation failed (no ssh-keygen, unwritable directory, ...).
        # Keep the historical empty-body answer: sshd falls back to its
        # flat-key-file parser on an unparsable RevokedKeys, so this is a
        # fail-open (revocations unenforced) but not a lockout.
        $self->logger->error(
            'SSH CA: no KRL available, returning an empty response');
        return [
            200,
            [
                'Content-Type'  => 'application/octet-stream',
                'Cache-Control' => 'public, max-age=300',
            ],
            ['']
        ];
    }

    # Shared lock: pairs with the exclusive lock taken by _writeKrl. The
    # rename() there already makes torn reads impossible; this just keeps a
    # reader from racing an in-progress rebuild on filesystems where that
    # guarantee is weaker. Best effort — a lock failure never fails the read.
    my $krlData;
    {
        my $lockFh = $self->_krlLock( $krlPath, 1 );
        open my $fh, '<:raw', $krlPath or do {
            $self->logger->error("SSH CA: Cannot read KRL file: $!");
            return $self->p->sendError( $req, 'Cannot read KRL', 500 );
        };
        local $/;
        $krlData = <$fh>;
        close $fh;

        # $lockFh is released here, on every exit path (including the die-less
        # early return above, which unwinds the same lexical scope).
    }

    # Never hand out a KRL we cannot parse (issue #59). A KRL truncated
    # mid-write keeps a valid `SSHKRL` magic, and sshd then fails *closed* on
    # every key it checks ("incomplete message"), locking the host out
    # entirely. Consumers only check the magic, so the check has to happen
    # here.
    unless ( $self->_krlIsValid($krlData) ) {
        $self->logger->error(
            "SSH CA: refusing to serve a corrupted KRL ($krlPath)");
        return $self->p->sendError( $req, 'Corrupted KRL', 500 );
    }

    $self->logger->debug('SSH CA: Serving KRL');

    return [
        200,
        [
            'Content-Type'  => 'application/octet-stream',
            'Cache-Control' => 'public, max-age=300',
        ],
        [$krlData]
    ];
}

# POST /ssh/sign - Sign user's SSH public key
# HELPER: decode the JSON body of a POST route, refusing what a cross-site
# form could produce (issue #62).
#
# The three POST routes used to call from_json on $req->content directly,
# bypassing the core's jsonBodyToObj and therefore its `Content-Type:
# application/json` requirement. That matters because an HTML form can only
# send application/x-www-form-urlencoded, multipart/form-data or text/plain —
# and a text/plain body containing JSON parsed cleanly. So a page on another
# origin could POST to /ssh/sign, /ssh/myrevoke and /ssh/revoke with the
# victim's cookie, whenever the SSO cookie is SameSite=None (which LLNG sets
# for SAML deployments).
#
# Nothing is disclosed that way: the certificate is only in a response body
# the attacker's page cannot read. The damage is a forced state change —
# re-signing a victim's (public) public key supersedes their live certificate
# and KRL-revokes the old serial, locking them out of SSH; a forced
# /ssh/myrevoke does the same in one step.
#
# The Origin check is the other half. Browsers attach Origin to every
# cross-origin POST, so a present-but-foreign Origin is refused outright.
# Non-browser callers — the ssh-ca CLI, curl, ob-* tooling — send none and are
# unaffected.
#
# Returns ($body, undef) or (undef, $response).
sub _jsonBodyOrReject {
    my ( $self, $req, $label ) = @_;

    if ( my $origin = $req->origin ) {
        unless ( $self->_isSelfOrigin( $req, $origin ) ) {
            $self->logger->warn(
                "$label: refused a cross-origin request from '$origin'");
            $self->p->auditLog(
                $req,
                code    => 'SSH_CA_CROSS_ORIGIN_REFUSED',
                message => "SSH CA: cross-origin $label refused",
                origin  => $origin,
            );
            return ( undef,
                $self->p->sendError( $req, 'Cross-origin request refused',
                    403 ) );
        }
    }

    my $body = $req->jsonBodyToObj;
    unless ( ref $body eq 'HASH' ) {
        my $err = $req->error || 'Invalid JSON';
        $self->logger->error("$label: $err");

        # $req->error is sticky (the setter ignores undef), and a leftover
        # "Data is not JSON" would surface in an unrelated later message.
        delete $req->{error};
        return ( undef, $self->p->sendError( $req, 'Invalid JSON', 400 ) );
    }

    return ( $body, undef );
}

# HELPER: does $origin designate this very portal?
# Same rule as the core's _checkSelfCors: scheme and host:port must match.
sub _isSelfOrigin {
    my ( $self, $req, $origin ) = @_;

    my $o = URI->new($origin);
    my $p = URI->new( $req->portal || $self->conf->{portal} || '' );
    return (  $o->scheme
          and $p->scheme
          and $o->scheme eq $p->scheme
          and $o->can('host_port')
          and $o->host_port
          and $p->can('host_port')
          and $o->host_port eq $p->host_port ) ? 1 : 0;
}

# HELPER: a configuration value that must be a non-negative integer.
# Anything else (unset, empty, "twenty", -1) falls back to $default, so a
# typo in the Manager cannot silently disable a limit.
sub _positiveIntConf {
    my ( $self, $key, $default ) = @_;

    my $v = $self->conf->{$key};
    return $default unless defined $v and $v =~ /\A[0-9]+\z/;
    return $v + 0;
}

# HELPER: per-user rate limit on /ssh/sign (issue #63).
#
# Why it matters here specifically: every signature forks ssh-keygen twice and
# rewrites the WHOLE KRL as a read-modify-write, and re-signing the same key
# appends the superseded serial — which /ssh/sign explicitly allows, so a loop
# grows the KRL without bound. The cost per call therefore grows with the KRL,
# and every appended serial is then loaded by every sshd on every backend. An
# authenticated user could turn that into a fleet-wide denial of service for
# the price of a shell loop.
#
# A fixed window (sshCaSignMaxPerHour, 20/hour, 0 = unlimited) counted in the
# user's own persistent session: the session store is already shared across
# nodes, so the count is cluster-wide with no new dependency. Two signatures
# racing can under-count by one — the store has no atomic increment — which is
# irrelevant for a limit whose purpose is to bound a loop, not to be exact.
#
# Returns a response when the caller is over the limit, undef otherwise.
sub _rateLimitSign {
    my ( $self, $req ) = @_;

    my $max = $self->_positiveIntConf( 'sshCaSignMaxPerHour', 20 );
    return undef unless $max;

    my $user = $req->user;
    unless ( defined $user and $user ne '' ) {

        # No identity to count against: /ssh/sign is an authenticated route,
        # so this should not happen. Refuse rather than hand out a free pass.
        $self->logger->error(
            'SSH CA sign: no user in session, refusing to sign unmetered');
        return $self->p->sendError( $req, 'Unauthorized', 403 );
    }

    my $now    = time();
    my $window = 3600;
    my $raw    = $req->userData->{_sshCaSignRate};
    my $state  = $raw ? eval { from_json($raw) } : undef;
    $state = undef unless ref $state eq 'HASH';

    my $start = $state->{start} || 0;
    my $count = $state->{count} || 0;
    if ( $now - $start >= $window ) {
        ( $start, $count ) = ( $now, 0 );
    }

    if ( $count >= $max ) {
        my $retry = $start + $window - $now;
        $retry = 1 if $retry < 1;
        $self->logger->warn( "SSH CA sign: rate limit reached for '$user' "
              . "($count/$max in the current hour)" );
        $self->p->auditLog(
            $req,
            code    => 'SSH_CA_SIGN_RATE_LIMITED',
            user    => $user,
            message => "SSH CA: /ssh/sign rate limit reached for '$user'",
            count   => $count,
            limit   => $max,
        );
        push @{ $req->respHeaders }, 'Retry-After' => $retry;
        return $self->p->sendJSONresponse(
            $req,
            {
                error       => 'Rate limit exceeded',
                limit       => $max,
                retry_after => $retry,
            },
            code => 429
        );
    }

    $self->p->updatePersistentSession( $req,
        { _sshCaSignRate => to_json( { start => $start, count => $count + 1 } ) }
    );

    return undef;
}

sub sshCaSign {
    my ( $self, $req ) = @_;

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH CA sign' );
    return $bail if $bail;

    # Rate limit before anything expensive: key validation, the policy check,
    # the ssh-keygen fork and the KRL rewrite all sit below this line, and the
    # point of the limit is that an abusive caller must not be able to make
    # the portal do that work (issue #63).
    #
    # The JSON body has already been decoded just above -- a refused caller
    # still pays that, deliberately: a malformed body must answer 400 whether
    # or not the caller is over its quota, otherwise the limit would turn a
    # client bug into a misleading 429.
    if ( my $limited = $self->_rateLimitSign($req) ) {
        return $limited;
    }

    my $userPubKey = $body->{public_key};
    unless ($userPubKey) {
        return $self->p->sendError( $req, 'public_key parameter required',
            400 );
    }

   # Validate SSH public key format: type, base64, optional comment, single line
   # Strict validation to prevent injection attacks. The `sk-*@openssh.com`
   # families are FIDO2/hardware-backed keys — they must be accepted here,
   # their `@` and `.` are not matched by \w.
    unless (
        $userPubKey =~ m{
            \A
            (?:
                 ssh-[\w-]+                       # ssh-ed25519, ssh-rsa, ...
               | ecdsa-sha2-\w+                   # ecdsa-sha2-nistp256, ...
               | sk-ssh-[\w-]+\@openssh\.com      # FIDO2 Ed25519
               | sk-ecdsa-sha2-\w+\@openssh\.com  # FIDO2 ECDSA
            )
            \s+ [A-Za-z0-9+/]+={0,2}
            (?: \s+ [^\r\n]* )?
            \z
        }x
      )
    {
        return $self->p->sendError( $req, 'Invalid SSH public key format',
            400 );
    }

    # Enforce the key type / key size policy. The verdict comes from the
    # DECODED wire-format blob, never from the textual prefix.
    my $policy = $self->_checkKeyPolicy($userPubKey);
    unless ( $policy->{ok} ) {
        $self->logger->warn( "SSH CA sign: rejected key for user "
              . ( $req->user || 'unknown' ) . ": "
              . $policy->{error} );
        return $self->p->sendError( $req, $policy->{error}, 400 );
    }

    # Label is mandatory (client-side also required). Fallback: extract from the
    # SSH public key's comment (third token) for backward-compat with records
    # signed before label support.
    my $label = $body->{label};
    $label = '' unless defined $label;
    $label =~ s/^\s+|\s+$//g;
    if ( $label eq '' && $userPubKey =~ /^\S+\s+\S+\s+(.+\S)\s*$/ ) {
        $label = $1;
    }
    if ( $label eq '' ) {
        return $self->p->sendError( $req, 'label parameter required', 400 );
    }
    if ( length($label) > 128 || $label =~ /[\r\n\t]/ ) {
        return $self->p->sendError( $req, 'Invalid label', 400 );
    }

    # Compute SSH key fingerprint (SHA256:...) — used for dedup and PAM lookup
    my $fingerprint = $self->_sshKeyFingerprint($userPubKey);
    unless ($fingerprint) {
        $self->logger->error('SSH CA sign: Cannot compute fingerprint');
        return $self->p->sendError( $req, 'Cannot compute key fingerprint',
            400 );
    }

    # Enforce label uniqueness within the user's (non-revoked, non-expired)
    # certificates — except when the same label is reused for the SAME key
    # (re-signing): in that case the old record is going to be replaced.
    my $existingCerts = $self->_certsFromData( $req->userData );
    my $now    = time();
    my $active = 0;
    my $resign = 0;
    for my $c (@$existingCerts) {
        next if $c->{revoked_at};
        next if $c->{expires_at} && $c->{expires_at} < $now;
        $active++;
        $resign = 1 if ( $c->{fingerprint} || '' ) eq $fingerprint;
        next unless ( $c->{label} || '' ) eq $label;
        next if ( $c->{fingerprint} || '' ) eq $fingerprint;
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Label already used for another key' },
            code => 409
        );
    }

    # Cap the number of live certificates a user may hold (issue #63). A
    # re-signature replaces an existing record, so it never grows the set and
    # is not counted. Users clear room with /ssh/myrevoke.
    my $maxCerts = $self->_positiveIntConf( 'sshCaMaxCertsPerUser', 20 );
    if ( $maxCerts and !$resign and $active >= $maxCerts ) {
        my $user = $req->user || 'unknown';
        $self->logger->warn(
            "SSH CA sign: '$user' already holds $active active certificates"
              . " (sshCaMaxCertsPerUser=$maxCerts)" );
        $self->p->auditLog(
            $req,
            code    => 'SSH_CA_CERT_QUOTA_EXCEEDED',
            user    => $user,
            message => "SSH CA: certificate quota reached for '$user'",
            active  => $active,
            limit   => $maxCerts,
        );
        return $self->p->sendJSONresponse(
            $req,
            {
                error => 'Certificate quota reached',
                limit => $maxCerts,
            },
            code => 409
        );
    }

    # Get validity from request (in days) or default to 30 days. It reaches
    # ssh-keygen as `-V +<n>m`, so a non-numeric value ("abc" -> 0) would
    # mint a sub-minute certificate and a negative one would make ssh-keygen
    # fail with a 500: only a positive integer is acceptable.
    my $validityDays = $body->{validity_days};
    $validityDays = 30 unless defined $validityDays && $validityDays ne '';
    unless ( !ref($validityDays)
        && $validityDays =~ /\A[0-9]+\z/
        && $validityDays > 0 )
    {
        return $self->p->sendError( $req,
            'validity_days must be a positive integer', 400 );
    }

    # Enforce maximum validity (in days, default 365)
    my $maxValidityDays = $self->conf->{sshCaCertMaxValidity} || 365;
    $validityDays = $maxValidityDays if $validityDays > $maxValidityDays;

    # Convert to minutes for ssh-keygen
    my $validityMinutes = $validityDays * 24 * 60;

 # SECURITY: Always derive principals from the authenticated user's session
 # Never trust principals from the request body to prevent impersonation attacks
    my @principals;

    # Evaluate principal sources from config (e.g., '$uid' or '$uid $mail')
    my $principalSources = $self->conf->{sshCaPrincipalSources} || '$uid';

    # Safe variable substitution without using /e to avoid eval-like behavior
    my $principal = '';
    my $template  = $principalSources;
    my $pos       = 0;

    while ( $template =~ /\$(\w+)/g ) {
        my $match_start = $-[0];
        my $match_end   = $+[0];

        # Append text before the match
        $principal .= substr( $template, $pos, $match_start - $pos );

        # Get value from userData or sessionInfo
        my $key = $1;
        my $val = $req->userData->{$key};
        $val = $req->sessionInfo->{$key} if !defined $val || $val eq '';
        $val = ''                        if !defined $val;

        # Strip characters that could turn a single attribute value into
        # multiple principals downstream: `,` is ssh-keygen -n's separator
        # (`-n alice,root` = two principals), and any whitespace is the
        # template's own separator (we split on /\s+/ below). CR/LF would
        # additionally poison audit logs and any file handed to ssh-keygen.
        # Each `$var` substitution must yield at most one principal token,
        # so match the same `\s` class the split uses — `tr///` cannot do
        # that, hence the regex.
        if ( $val =~ s/[\s,]//g ) {
            $self->logger->warn(
                "SSH CA sign: stripped separator chars from principal "
                  . "source \$$key for user "
                  . ( $req->user || 'unknown' ) );
        }

        $principal .= $val;
        $pos = $match_end;
    }

    # Append remaining text after last match
    $principal .= substr( $template, $pos ) if $pos < length($template);
    $principal =~ s/^\s+|\s+$//g;    # trim

    # Split on whitespace if multiple principals
    @principals = grep { $_ ne '' } split /\s+/, $principal;

  # Log warning if client tried to specify principals (potential attack attempt)
    if ( $body->{principals} && ref $body->{principals} eq 'ARRAY' ) {
        $self->logger->warn(
                "SSH CA sign: Ignoring 'principals' parameter from request "
              . "(user: "
              . ( $req->user || 'unknown' ) . "). "
              . "Principals are always derived from session for security." );
    }

    unless (@principals) {
        $self->logger->error('SSH CA sign: No principals available');
        return $self->p->sendError( $req, 'No principals available', 400 );
    }

    # Get user info for key_id
    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $user =
         $req->userData->{$whatToTrace}
      || $req->sessionInfo->{$whatToTrace}
      || $req->userData->{uid}
      || $req->sessionInfo->{uid}
      || $req->user
      || 'unknown';

    # Generate serial number
    my $serial = $self->_getNextSerial();

    # Generate key_id
    my $timestamp = time();
    my $keyId     = sprintf( "%s\@llng-%d-%06d", $user, $timestamp, $serial );

    # Sign the certificate
    my $result =
      $self->_signSshKey( $userPubKey, \@principals, $validityMinutes, $serial,
        $keyId );

    unless ( $result && $result->{certificate} ) {
        $self->logger->error('SSH CA sign: Failed to sign key');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to sign SSH key' },
            code => 500
        );
    }

    # Calculate expiration time
    my $validUntil    = time() + ( $validityMinutes * 60 );
    my @t             = gmtime($validUntil);
    my $validUntilISO = sprintf(
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900,
        $t[4] + 1,
        $t[3], $t[2], $t[1], $t[0]
    );

    $self->logger->info( "SSH CA: Certificate issued for user '$user', "
          . "principals: "
          . join( ',', @principals ) . ", "
          . "validity: ${validityMinutes}min, serial: $serial" );

    # Store certificate in persistent session for revocation tracking.
    # _storeCertificate replaces any existing record with the same fingerprint
    # and revokes the superseded serial in the KRL. Pass the already-decoded
    # $existingCerts so the helper doesn't re-run from_json on the same blob.
    $self->_storeCertificate(
        $req,
        existing    => $existingCerts,
        serial      => $serial,
        key_id      => $keyId,
        user        => $user,
        label       => $label,
        fingerprint => $fingerprint,
        principals  => \@principals,
        issued_at   => $timestamp,
        expires_at  => $validUntil,
    );

    # Audit log
    $self->p->auditLog(
        $req,
        code        => 'SSH_CERT_ISSUED',
        user        => $user,
        message     => "SSH certificate issued for user '$user'",
        principals  => \@principals,
        serial      => $serial,
        key_id      => $keyId,
        label       => $label,
        fingerprint => $fingerprint,
        validity    => $validityMinutes,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            certificate => $result->{certificate},
            serial      => $serial,
            valid_until => $validUntilISO,
            principals  => \@principals,
            key_id      => $keyId,
            label       => $label,
            fingerprint => $fingerprint,
        }
    );
}

# =============================================================================
# HELPER METHODS
# =============================================================================

# HELPER: Generate a unique certificate serial.
#
# Multi-portal deployments (issue #9) rule out a shared counter file: each
# node would increment its own and produce duplicates. Instead we derive the
# serial from the wall clock in microseconds plus a small random tail:
#   serial = seconds * 1_000_000_000 + microseconds * 1_000 + rand(0..999)
# That fits in an unsigned 63-bit integer (ssh-keygen accepts up to 2^64-1).
#
# Two safeguards on top of rand():
#   - per-process monotonic: we remember the last (s, us) and bump µs forward
#     if the clock tick hasn't advanced (or stepped backwards), which rules
#     out intra-process collisions even on coarse/NTP-adjusted clocks.
#   - cross-node collision probability within the same µs stays at 1/1000,
#     which is acceptable for SSH CA issuance rates. The KRL keys on serial,
#     so any clash would be caught there and can be retried.
{
    my ( $last_s, $last_us ) = ( 0, 0 );

    sub _getNextSerial {
        my ($self) = @_;
        my ( $s, $us ) = gettimeofday();
        if ( $s < $last_s || ( $s == $last_s && $us <= $last_us ) ) {
            ( $s, $us ) = ( $last_s, $last_us + 1 );
            if ( $us >= 1_000_000 ) { $s++; $us = 0; }
        }
        ( $last_s, $last_us ) = ( $s, $us );
        return $s * 1_000_000_000 + $us * 1_000 + int( rand(1000) );
    }
}

# HELPER: Sign SSH key using ssh-keygen
#
# $opts (optional hashref) lets callers other than the interactive /ssh/sign
# route (e.g. pam-access bastion-cert vouching) tighten the certificate:
#   - validity       : explicit ssh-keygen -V spec (e.g. "+120s"), overrides
#                      the $validityMinutes argument. Enables sub-minute TTLs.
#   - source_address : value for the `source-address` critical option. sshd
#                      itself then refuses the cert unless the connection comes
#                      from that address/CIDR. MUST be pre-validated by the
#                      caller (passed verbatim to ssh-keygen -O).
sub _signSshKey {
    my ( $self, $userPubKey, $principals, $validityMinutes, $serial, $keyId,
        $opts )
      = @_;
    $opts = {} unless ref $opts eq 'HASH';

    require File::Temp;

    # Create temp directory for key files.
    #
    # SECURITY: this directory holds the UNENCRYPTED CA private key, so it
    # must not outlive the signing operation. `File::Temp::tempdir(CLEANUP
    # => 1)` would only clean up at *program* exit — in a long-lived portal
    # worker (FastCGI/mod_perl) every /ssh/sign would then leave a copy of
    # the CA key in /tmp for the worker's whole lifetime, accumulating
    # without bound. `File::Temp->newdir` ties the removal to the object's
    # destruction instead, i.e. to this sub's scope, including every early
    # `return` and any `die` in between.
    my $tmpobj = File::Temp->newdir();
    my $tmpdir = "$tmpobj";

    # Write CA private key to temp file (convert PEM to OpenSSH format)
    my $caKeyFile = "$tmpdir/ca_key";
    open my $fh, '>', $caKeyFile or do {
        $self->logger->error("SSH CA: Cannot write CA key: $!");
        return undef;
    };
    print $fh $self->sshPrivKey;
    close $fh;
    chmod 0600, $caKeyFile;

    # Write user's public key to temp file
    my $userKeyFile = "$tmpdir/user_key.pub";
    open $fh, '>', $userKeyFile or do {
        $self->logger->error("SSH CA: Cannot write user key: $!");
        return undef;
    };
    print $fh $userPubKey;
    print $fh "\n" unless $userPubKey =~ /\n$/;
    close $fh;

    # Build ssh-keygen command
    my $validitySpec = $opts->{validity} || "+${validityMinutes}m";
    my @cmd = (
        'ssh-keygen',
        '-s', $caKeyFile,                   # CA key
        '-I', $keyId,                       # Key identity
        '-n', join( ',', @$principals ),    # Principals
        '-V', $validitySpec,                # Validity (override via $opts)
        '-z', $serial,                      # Serial number
    );

    # Optional `source-address` critical option: sshd refuses the cert unless
    # the connection originates from this address/CIDR. Used by bastion-cert
    # vouching to pin a cert to the vouching bastion's IP.
    push @cmd, '-O', "source-address=$opts->{source_address}"
      if defined $opts->{source_address} && $opts->{source_address} ne '';

    push @cmd, $userKeyFile;               # User's public key to sign (last)

    $self->logger->debug( "SSH CA: Running: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork: $!");
        return undef;
    }
    elsif ( $pid == 0 ) {

        # Child process
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 1;
    }
    else {
        # Parent process
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;

    # ssh-keygen is done with the CA key: drop it immediately rather than
    # waiting for $tmpobj's destructor, so the private key spends the
    # shortest possible time on disk.
    unlink $caKeyFile;

    if ( $exitCode != 0 ) {
        $self->logger->error(
            "SSH CA: ssh-keygen failed (exit $exitCode): $output");
        return undef;
    }

    # Read the generated certificate
    my $certFile = "$tmpdir/user_key-cert.pub";
    unless ( -f $certFile ) {
        $self->logger->error("SSH CA: Certificate file not created");
        return undef;
    }

    open $fh, '<', $certFile or do {
        $self->logger->error("SSH CA: Cannot read certificate: $!");
        return undef;
    };
    my $certificate = <$fh>;
    close $fh;
    chomp $certificate;

    return { certificate => $certificate };
}

# HELPER: Convert PEM private key to OpenSSH format
sub _pemToOpenSSHPrivateKey {
    my ( $self, $pemKey ) = @_;

    # First, try to detect if it's already in OpenSSH format
    if ( $pemKey =~ /^-----BEGIN OPENSSH PRIVATE KEY-----/ ) {
        return $pemKey;
    }

    # RSA keys in traditional format - ssh-keygen can read these directly
    if ( $pemKey =~ /BEGIN RSA PRIVATE KEY/ ) {
        return $pemKey;
    }

    # For Ed25519 PEM keys, we need to convert to OpenSSH format
    # because ssh-keygen cannot read Ed25519 PEM keys
    if (   $pemKey =~ /BEGIN PRIVATE KEY/
        || $pemKey =~ /BEGIN ED25519 PRIVATE KEY/ )
    {
        eval {
            require Crypt::PK::Ed25519;
            require MIME::Base64;

            my $pk = Crypt::PK::Ed25519->new( \$pemKey );

            # Get raw keys
            my $privRaw = $pk->export_key_raw('private');    # 32 bytes
            my $pubRaw  = $pk->export_key_raw('public');     # 32 bytes

            # Build OpenSSH private key format
            my $opensshKey =
              $self->_buildOpenSSHPrivateKey( $privRaw, $pubRaw, '' );
            return $opensshKey if $opensshKey;
        };
        if ($@) {
            $self->logger->error("SSH CA: Failed to convert Ed25519 key: $@");
        }
    }

    # EC keys - ssh-keygen can typically read these
    if ( $pemKey =~ /BEGIN EC PRIVATE KEY/ ) {
        return $pemKey;
    }

    # Fallback: return as-is and let ssh-keygen try
    return $pemKey;
}

# HELPER: Build OpenSSH private key format from raw Ed25519 key material
sub _buildOpenSSHPrivateKey {
    my ( $self, $privRaw, $pubRaw, $comment ) = @_;

    require MIME::Base64;

    # OpenSSH private key format for Ed25519 (unencrypted):
    # - Magic: "openssh-key-v1\0"
    # - Cipher name: "none" (string with length prefix)
    # - KDF name: "none" (string with length prefix)
    # - KDF options: empty string (length 0)
    # - Number of keys: 1 (uint32)
    # - Public key section (length-prefixed)
    # - Private/encrypted section (length-prefixed)

    my $keytype = 'ssh-ed25519';

    # Build public key blob
    my $pubBlob = pack( 'N', length($keytype) ) . $keytype;
    $pubBlob .= pack( 'N', length($pubRaw) ) . $pubRaw;

    # Build private section
    # Generate random check integers (must match)
    my $checkInt = int( rand(0xFFFFFFFF) );

    my $privSection = '';
    $privSection .= pack( 'N', $checkInt );    # check-int 1
    $privSection .= pack( 'N', $checkInt );    # check-int 2 (must match)

    # Key type
    $privSection .= pack( 'N', length($keytype) ) . $keytype;

    # Public key (32 bytes)
    $privSection .= pack( 'N', length($pubRaw) ) . $pubRaw;

    # Secret buffer: private key (32 bytes) + public key (32 bytes) = 64 bytes
    my $secretBuf = $privRaw . $pubRaw;
    $privSection .= pack( 'N', length($secretBuf) ) . $secretBuf;

    # Comment
    $comment //= '';
    $privSection .= pack( 'N', length($comment) ) . $comment;

    # Padding to 8-byte block size (for "none" cipher)
    my $blockSize = 8;
    my $padLen    = $blockSize - ( length($privSection) % $blockSize );
    $padLen = 0 if $padLen == $blockSize;
    for my $i ( 1 .. $padLen ) {
        $privSection .= chr($i);
    }

    # Build full key
    my $key = '';

    # Magic header
    $key .= "openssh-key-v1\0";

    # Cipher name: "none"
    my $cipher = 'none';
    $key .= pack( 'N', length($cipher) ) . $cipher;

    # KDF name: "none"
    my $kdf = 'none';
    $key .= pack( 'N', length($kdf) ) . $kdf;

    # KDF options: empty
    $key .= pack( 'N', 0 );

    # Number of keys
    $key .= pack( 'N', 1 );

    # Public key section
    $key .= pack( 'N', length($pubBlob) ) . $pubBlob;

    # Private section
    $key .= pack( 'N', length($privSection) ) . $privSection;

    # Encode as PEM
    my $b64    = MIME::Base64::encode_base64( $key, '' );
    my $pem    = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    my $offset = 0;
    while ( $offset < length($b64) ) {
        $pem .= substr( $b64, $offset, 70 ) . "\n";
        $offset += 70;
    }
    $pem .= "-----END OPENSSH PRIVATE KEY-----\n";

    return $pem;
}

# HELPER: Convert PEM public key to SSH format
sub _pemToSshPublicKey {
    my ( $self, $pemKey, $comment ) = @_;

    require MIME::Base64;

    my $sshKey;

    # Try Ed25519 first
    eval {
        require Crypt::PK::Ed25519;
        my $pk     = Crypt::PK::Ed25519->new( \$pemKey );
        my $rawKey = $pk->export_key_raw('public');

        # Build SSH format: string "ssh-ed25519" + string <32 bytes key>
        my $keyType = 'ssh-ed25519';
        my $blob =
            pack( 'N', length($keyType) )
          . $keyType
          . pack( 'N', length($rawKey) )
          . $rawKey;

        $sshKey = "$keyType " . MIME::Base64::encode_base64( $blob, '' );
    };

    # Try RSA if Ed25519 failed
    if ( $@ || !$sshKey ) {
        eval {
            require Crypt::PK::RSA;
            my $pk = Crypt::PK::RSA->new( \$pemKey );

            if ( $pk->can('export_key_openssh') ) {
                $sshKey = $pk->export_key_openssh;
            }
            else {
                # Fallback: use ssh-keygen to convert PEM public key
                # (`newdir` so the scratch dir dies with this scope, not
                # with the worker — see _signSshKey)
                require File::Temp;
                my $tmpobj  = File::Temp->newdir();
                my $keyFile = "$tmpobj/key.pub";
                open my $fh, '>', $keyFile or die "Cannot write: $!";
                print $fh $pemKey;
                close $fh;
                $sshKey = `ssh-keygen -i -m PKCS8 -f $keyFile 2>&1`;
                my $exit = $? >> 8;
                if ( $exit != 0 ) {
                    $self->logger->error(
                        "SSH CA: ssh-keygen -i failed (exit $exit): $sshKey");
                    $sshKey = undef;
                }
                else {
                    chomp $sshKey;
                    $sshKey = undef unless $sshKey;
                }
            }
        };
    }

    unless ($sshKey) {
        $self->logger->error("SSH CA: Failed to convert key to SSH format: $@");
        return undef;
    }

    # Add comment (SSH key has format: type base64 [comment])
    chomp($sshKey);
    my @parts = split /\s+/, $sshKey;
    if ( @parts == 2 ) {

        # No comment yet, add one
        $sshKey .= " LLNG-SSH-CA-$comment";
    }

    return "$sshKey\n";
}

# GET /ssh/mycerts - List current user's certificates
sub sshMyCerts {
    my ( $self, $req ) = @_;

    my $sshCerts = $self->_certsFromData( $req->userData );

    my $now = time();
    my @certs;
    for my $cert (@$sshCerts) {
        my $status = 'active';
        if ( $cert->{revoked_at} ) {
            $status = 'revoked';
        }
        elsif ( $cert->{expires_at} && $cert->{expires_at} < $now ) {
            $status = 'expired';
        }
        push @certs,
          {
            serial      => $cert->{serial},
            key_id      => $cert->{key_id},
            label       => $cert->{label},
            fingerprint => $cert->{fingerprint},
            principals  => $cert->{principals},
            issued_at   => $cert->{issued_at},
            expires_at  => $cert->{expires_at},
            status      => $status,
          };
    }

    # Sort by issued_at descending (newest first)
    @certs =
      sort { ( $b->{issued_at} || 0 ) <=> ( $a->{issued_at} || 0 ) } @certs;

    return $self->p->sendJSONresponse( $req, { certificates => \@certs } );
}

# POST /ssh/myrevoke - User revokes one of their own certificates.
# The certificate record is kept in the session with `revoked_at` set so the
# user's list keeps showing it; the serial is immediately published in the
# KRL. Note: re-signing the same key later supersedes and removes the record
# (see _storeCertificate); the KRL retains all revoked serials regardless.
sub sshMyCertRevoke {
    my ( $self, $req ) = @_;

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH myrevoke' );
    return $bail if $bail;
    my $serial = $body->{serial};
    unless ( defined $serial && $serial ne '' ) {
        return $self->p->sendError( $req, 'serial required', 400 );
    }

    # A corrupted legacy array would give us a partial view of the user's
    # certificates, and answering "not found" on it would look like a
    # successful no-op — refuse instead.
    unless ( defined $self->_legacyCerts( $req->userData ) ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Corrupted certificate data' },
            code => 500
        );
    }
    my $sshCerts = $self->_certsFromData( $req->userData );

    my $user =
         $req->userData->{ $self->conf->{whatToTrace} || 'uid' }
      || $req->userData->{uid}
      || $req->user
      || 'unknown';

    my $target;
    for my $cert (@$sshCerts) {
        if ( ( $cert->{serial} || '' ) eq $serial ) {
            if ( $cert->{revoked_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already revoked' },
                    code => 400
                );
            }
            $cert->{revoked_at}    = time();
            $cert->{revoked_by}    = $user;
            $cert->{revoke_reason} = 'self-revocation';
            $target                = $cert;
            last;
        }
    }
    unless ($target) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Certificate not found' },
            code => 404
        );
    }

    my %upd;
    $self->_drainLegacyCerts( $req->userData, \%upd );
    if ( my $k = $self->_certKey($target) ) {
        $upd{$k} = to_json($target);
    }
    $self->p->updatePersistentSession( $req, \%upd );
    my $krlOk = $self->_updateKrl($serial);
    $self->_publishRevoke( $req, $serial );

    $self->logger->info( "SSH CA: Self-revocation by '$user': "
          . "serial=$serial, key_id=$target->{key_id}" );

    $self->p->auditLog(
        $req,
        code       => 'SSH_CERT_SELF_REVOKED',
        user       => $user,
        message    => "SSH certificate self-revoked by '$user'",
        serial     => $serial,
        key_id     => $target->{key_id},
        label      => $target->{label},
        krl_update => $krlOk ? 'success' : 'failed',
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            result      => 1,
            serial      => $serial,
            key_id      => $target->{key_id},
            revoked_at  => $target->{revoked_at},
            krl_updated => $krlOk ? JSON::true : JSON::false,
        }
    );
}

# =============================================================================
# ADMIN INTERFACE METHODS
# =============================================================================

# HELPER: default-deny guard shared by the three administration endpoints.
#
# Returns a ready-to-return 403 response when the caller is not allowed to
# administrate the SSH CA, and undef when access is granted. `adminRule` is
# always a code ref (init() installs a constant-false sub when
# `sshCaAdminRule` is unset or fails to compile), so an unconfigured or
# misconfigured portal denies.
#
# sendError() already negotiates the representation: JSON for the
# XHR-driven /ssh/certs and /ssh/revoke, HTML for /ssh/admin.
sub _forbidNonAdmin {
    my ( $self, $req ) = @_;

    my $rule = $self->adminRule;
    return undef if $rule && $rule->( $req, $req->userData );

    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $user =
         $req->userData->{$whatToTrace}
      || $req->userData->{uid}
      || $req->user
      || 'unknown';
    my $uri = $req->env->{REQUEST_URI} // '';

    $self->userLogger->warn(
        "SSH CA: user '$user' is not allowed to administrate the SSH CA "
          . "(denied on $uri)" );
    $self->p->auditLog(
        $req,
        code    => 'SSH_CA_ADMIN_DENIED',
        user    => $user,
        message => "SSH CA administration denied for '$user'",
        uri     => $uri,
    );

    return $self->p->sendError( $req, 'Forbidden', 403 );
}

# GET /ssh/admin - Display the revocation interface
# Restricted by the sshCaAdminRule configuration parameter (default: deny)
sub sshAdminInterface {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    return $self->p->sendHtml( $req, 'sshcaadmin' );
}

# GET /ssh/certs - List/search certificates from persistent sessions
# Restricted by the sshCaAdminRule configuration parameter (default: deny)
sub sshCertsList {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    # Get search parameters
    my $userFilter   = $req->param('user')   || '';
    my $serialFilter = $req->param('serial') || '';
    my $keyIdFilter  = $req->param('key_id') || '';
    my $statusFilter = $req->param('status') || '';   # active, revoked, expired

    # Pagination: bound below as well as above. `int()` alone turned a
    # negative limit into a negative `splice` length (which silently drops
    # the tail of the list instead of the head) and a non-numeric value into
    # 0 results, so only a plain non-negative integer is honoured here.
    my $limit  = $req->param('limit');
    my $offset = $req->param('offset');
    $limit  = ( defined $limit  && $limit  =~ /\A[0-9]+\z/ ) ? $limit + 0 : 100;
    $offset = ( defined $offset && $offset =~ /\A[0-9]+\z/ ) ? $offset + 0 : 0;

    $limit = 1000 if $limit > 1000;

    # Search in persistent sessions
    my $moduleOptions = {
        backend => $self->conf->{persistentStorage}
          || $self->conf->{globalStorage},
        %{
                 $self->conf->{persistentStorageOptions}
              || $self->conf->{globalStorageOptions}
              || {}
        },
    };

    # No field restriction: certificates live one per key
    # ($CERT_PREFIX.<fingerprint>), whose names are not known in advance.
    #
    # The core loaded whole sessions for this search anyway (searchOnExpr
    # falls back to get_key_from_all_sessions); what changes is that the
    # result now RETAINS them for the length of the scan instead of a few
    # named fields. Fine at the scale this endpoint serves — an administrator
    # listing certificates — but it is the line to look at first if a large
    # fleet makes /ssh/certs heavy.
    my $res =
      Lemonldap::NG::Common::Apache::Session->searchOnExpr( $moduleOptions,
        '_session_kind', 'Persistent' );

    my @certs;
    my $now = time();

    for my $sessionId ( keys %{ $res || {} } ) {
        my $session = $res->{$sessionId};

        my $user     = $session->{_session_uid} || '';
        my $sshCerts = $self->_certsFromData($session);

        # Skip sessions holding no certificate at all
        next unless @$sshCerts;

        # Apply user filter at session level
        if ( $userFilter && $user !~ /\Q$userFilter\E/i ) {
            next;
        }

        for my $cert (@$sshCerts) {

            # Apply filters
            if ( $serialFilter && $cert->{serial} ne $serialFilter ) {
                next;
            }
            if ( $keyIdFilter
                && ( $cert->{key_id} || '' ) !~ /\Q$keyIdFilter\E/i )
            {
                next;
            }

            # Determine status
            my $certStatus = 'active';
            if ( $cert->{revoked_at} ) {
                $certStatus = 'revoked';
            }
            elsif ( $cert->{expires_at} && $cert->{expires_at} < $now ) {
                $certStatus = 'expired';
            }

            # Apply status filter
            if ( $statusFilter && $certStatus ne $statusFilter ) {
                next;
            }

            push @certs,
              {
                session_id    => $sessionId,
                serial        => $cert->{serial},
                key_id        => $cert->{key_id},
                user          => $user,
                principals    => $cert->{principals},
                issued_at     => $cert->{issued_at},
                expires_at    => $cert->{expires_at},
                revoked_at    => $cert->{revoked_at},
                revoked_by    => $cert->{revoked_by},
                revoke_reason => $cert->{revoke_reason},
                status        => $certStatus,
              };
        }
    }

    # Sort by issued_at descending (newest first)
    @certs =
      sort { ( $b->{issued_at} || 0 ) <=> ( $a->{issued_at} || 0 ) } @certs;

    my $total = scalar @certs;

    # Apply pagination
    if ( $offset > 0 || $limit < $total ) {
        @certs = splice( @certs, $offset, $limit );
    }

    return $self->p->sendJSONresponse(
        $req,
        {
            certificates => \@certs,
            total        => $total,
            limit        => $limit,
            offset       => $offset,
        }
    );
}

# POST /ssh/revoke - Revoke a certificate in persistent session
# Restricted by the sshCaAdminRule configuration parameter (default: deny).
# Users revoke their OWN certificates through /ssh/myrevoke, which needs no
# administration right.
sub sshCertRevoke {
    my ( $self, $req ) = @_;

    if ( my $denied = $self->_forbidNonAdmin($req) ) { return $denied }

    my ( $body, $bail ) = $self->_jsonBodyOrReject( $req, 'SSH revoke' );
    return $bail if $bail;

    my $sessionId = $body->{session_id};
    my $serial    = $body->{serial};

    unless ( $sessionId && $serial ) {
        return $self->p->sendError( $req, 'session_id and serial required',
            400 );
    }

    # The reason is stored in the session, echoed in logger->info and in the
    # audit log: filter it like `label` is filtered in sshCaSign, so it
    # cannot forge log lines or smuggle terminal escapes into an operator's
    # console. Rejecting the whole [:cntrl:] class also covers \r\n\t.
    my $reason = $body->{reason};
    $reason = '' unless defined $reason && !ref $reason;
    $reason =~ s/^\s+|\s+$//g;
    if ( length($reason) > 256 || $reason =~ /[[:cntrl:]]/ ) {
        return $self->p->sendError( $req, 'Invalid reason', 400 );
    }

    # Get current admin user
    my $adminUser =
         $req->userData->{ $self->conf->{whatToTrace} }
      || $req->userData->{uid}
      || $req->user
      || 'unknown';

    # Load the persistent session
    my $moduleOptions = {
        storageModule => $self->conf->{persistentStorage}
          || $self->conf->{globalStorage},
        storageModuleOptions => $self->conf->{persistentStorageOptions}
          || $self->conf->{globalStorageOptions}
          || {},
    };

    # Load the existing persistent session. `force => 1` would both skip
    # existence checks AND create a fresh session row if the id is unknown —
    # neither is wanted: admin revocation must only mutate a real persistent
    # session that already carries _sshCerts.
    my $psession = Lemonldap::NG::Common::Session->new(
        {
            %$moduleOptions,
            id => $sessionId,
        }
    );

    unless ( $psession && !$psession->error ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Session not found' },
            code => 404
        );
    }

    # Refuse sessions that are not persistent (SSO/PAMTOKEN/DEVA/... all
    # carry a different `_session_kind`). `sshCertsList` only ever exposes
    # persistent session ids to the admin UI, so anything else here is a
    # caller mistake or a forged request.
    unless ( ( $psession->data->{_session_kind} // '' ) eq 'Persistent' ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Session not found' },
            code => 404
        );
    }

    # Get SSH certs from session. As in sshMyCertRevoke, a corrupted legacy
    # array means we cannot honestly say a serial is absent.
    unless ( defined $self->_legacyCerts( $psession->data ) ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Corrupted certificate data' },
            code => 500
        );
    }
    my $sshCerts = $self->_certsFromData( $psession->data );

    # Find and update the certificate
    my $found = 0;
    my $user  = $psession->data->{_session_uid} || '';
    my $keyId;
    my $target;

    for my $cert (@$sshCerts) {
        if ( ( $cert->{serial} // '' ) eq $serial ) {
            if ( $cert->{revoked_at} ) {
                return $self->p->sendJSONresponse(
                    $req,
                    { error => 'Certificate already revoked' },
                    code => 400
                );
            }
            $cert->{revoked_at}    = time();
            $cert->{revoked_by}    = $adminUser;
            $cert->{revoke_reason} = $reason;
            $keyId                 = $cert->{key_id};
            $target                = $cert;
            $found                 = 1;
            last;
        }
    }

    unless ($found) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Certificate not found' },
            code => 404
        );
    }

    # Update session, one key for the revoked certificate only
    my %upd;
    $self->_drainLegacyCerts( $psession->data, \%upd );
    if ( my $k = $self->_certKey($target) ) {
        $upd{$k} = to_json($target);
    }
    $psession->update( \%upd );

    # Update the KRL file
    my $krlUpdated = $self->_updateKrl($serial);
    $self->_publishRevoke( $req, $serial );

    $self->logger->info( "SSH CA: Certificate revoked by '$adminUser': "
          . "serial=$serial, key_id=$keyId, user=$user, reason=$reason" );

    # Audit log
    $self->p->auditLog(
        $req,
        code    => 'SSH_CERT_REVOKED',
        user    => $user,
        admin   => $adminUser,
        message => "SSH certificate revoked for user '$user' by '$adminUser'",
        serial  => $serial,
        key_id  => $keyId,
        reason  => $reason,
        krl_update => $krlUpdated ? 'success' : 'failed',
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            result      => 1,
            serial      => $serial,
            key_id      => $keyId,
            user        => $user,
            revoked_at  => time(),
            revoked_by  => $adminUser,
            krl_updated => $krlUpdated ? JSON::true : JSON::false,
        }
    );
}

# HELPER: Store certificate in user's persistent session.
# If a record with the same fingerprint already exists, it is dropped and its
# serial revoked in the KRL: a given SSH key is represented by a single
# certificate record at a time (the most recent signature).
# HELPER: the per-certificate session key holding $cert.
#
# Keyed by fingerprint (see $CERT_PREFIX). Very old records may predate the
# fingerprint field; those fall back to the serial so they still migrate
# instead of being stranded in the legacy array.
sub _certKey {
    my ( $self, $cert ) = @_;

    return undef unless ref $cert eq 'HASH';
    return $CERT_PREFIX . $cert->{fingerprint}
      if ( $cert->{fingerprint} // '' ) ne '';
    return $CERT_PREFIX . 'serial:' . $cert->{serial}
      if ( $cert->{serial} // '' ) ne '';
    return undef;
}

# HELPER: decode the pre-upgrade `_sshCerts` array of a session hash.
# Returns [] when the session has none (already migrated, or never had one)
# and undef when it holds something that is not a JSON array — callers that
# must not silently act on a partial view check for that.
sub _legacyCerts {
    my ( $self, $data ) = @_;

    my $raw = $data->{_sshCerts};
    return [] unless defined $raw and $raw ne '';
    my $list = eval { from_json($raw) };
    if ( $@ or ref $list ne 'ARRAY' ) {
        $self->logger->error("SSH CA: Corrupted _sshCerts: $@");
        return undef;
    }
    return $list;
}

# HELPER: every certificate record a session hash holds — per-key records
# first, then whatever a not-yet-drained `_sshCerts` array still carries.
sub _certsFromData {
    my ( $self, $data ) = @_;

    my ( @certs, %seen );
    for my $k ( sort keys %$data ) {
        next unless index( $k, $CERT_PREFIX ) == 0;
        my $rec = eval { from_json( $data->{$k} // '' ) };
        if ( $@ or ref $rec ne 'HASH' ) {
            $self->logger->warn("SSH CA: Corrupted certificate record $k");
            next;
        }
        $seen{$k} = 1;
        push @certs, $rec;
    }
    for my $rec ( @{ $self->_legacyCerts($data) || [] } ) {
        next unless ref $rec eq 'HASH';
        my $k = $self->_certKey($rec);
        next if defined $k and $seen{$k};
        push @certs, $rec;
    }

    return \@certs;
}

# HELPER: schedule the migration of a session's `_sshCerts` array into the
# per-certificate keyspace. Every write path calls this, so the array drains
# on the first sign or revocation that touches the session.
sub _drainLegacyCerts {
    my ( $self, $data, $upd ) = @_;

    my $raw = $data->{_sshCerts};
    return unless defined $raw and $raw ne '';
    for my $rec ( @{ $self->_legacyCerts($data) || [] } ) {
        my $k = $self->_certKey($rec) or next;
        $upd->{$k} = to_json($rec) unless exists $upd->{$k};
    }
    $upd->{_sshCerts} = undef;
}

sub _storeCertificate {
    my ( $self, $req, %args ) = @_;

    my $certRecord = {
        serial      => $args{serial},
        key_id      => $args{key_id},
        label       => $args{label},
        fingerprint => $args{fingerprint},
        principals  => join( ',', @{ $args{principals} || [] } ),
        issued_at   => $args{issued_at},
        expires_at  => $args{expires_at},
    };

    # Reuse the decoded list from sshCaSign when it was passed in. Fall back
    # to re-reading the session so other internal callers don't have to
    # pre-parse.
    my $sshCerts =
      ref $args{existing} eq 'ARRAY'
      ? $args{existing}
      : $self->_certsFromData( $req->userData );

    # Only two keys are touched: this certificate's, and (when the same SSH
    # key is being re-signed under a record that predates the per-key layout)
    # the superseded record's. Everything else the user holds is left alone,
    # so a concurrent sign or revocation of another key cannot be lost.
    my $now = time();
    my %upd;
    $self->_drainLegacyCerts( $req->userData, \%upd );

    # Revoke the superseded serial in the KRL so the old certificate cannot be
    # used even if it is still within its validity window.
    for my $c (@$sshCerts) {
        next
          unless $args{fingerprint}
          && ( $c->{fingerprint} || '' ) eq $args{fingerprint};
        unless ( $c->{revoked_at}
            || ( $c->{expires_at} && $c->{expires_at} < $now ) )
        {
            if ( $c->{serial} ) {
                my $ok = $self->_updateKrl( $c->{serial} );
                $self->_publishRevoke( $req, $c->{serial} );
                $self->logger->info(
                    "SSH CA: Replaced certificate serial=$c->{serial} "
                      . "(superseded by $args{serial}); KRL update "
                      . ( $ok ? 'ok' : 'FAILED' ) );
            }
        }
        if ( my $k = $self->_certKey($c) ) { $upd{$k} = undef }
    }

    # Last, so it wins over the `undef` a superseded record with the same
    # fingerprint just scheduled on the very same key.
    my $key = $self->_certKey($certRecord);
    unless ($key) {
        $self->logger->error(
            'SSH CA: certificate record has neither fingerprint nor serial');
        return 0;
    }
    $upd{$key} = to_json($certRecord);

    $self->p->updatePersistentSession( $req, \%upd );

    $self->logger->debug(
        "SSH CA: Stored certificate serial=$args{serial} fp=$args{fingerprint} in persistent session"
    );
    return 1;
}

# HELPER: Compute the OpenSSH SHA256 fingerprint of an SSH public key.
# The canonical OpenSSH form is `SHA256:<base64(sha256(blob))>` with
# trailing `=` padding stripped (see sshkey_fingerprint_b64 in sshkey.c).
# The blob is the raw wire-format key, which is exactly what's base64-
# encoded as the second whitespace-separated token of the pubkey line —
# sshCaSign's public-key regex has already validated that shape upstream,
# so no fork to ssh-keygen is needed here.
sub _sshKeyFingerprint {
    my ( $self, $sshPubKey ) = @_;
    return undef unless defined $sshPubKey;

    my ($blob_b64) = $sshPubKey =~ /^\s*\S+\s+(\S+)/;
    unless ( defined $blob_b64 && length $blob_b64 ) {
        $self->logger->error("SSH CA: Cannot parse SSH pubkey for fingerprint");
        return undef;
    }

    my $blob = decode_base64($blob_b64);
    unless ( length $blob ) {
        $self->logger->error("SSH CA: Empty blob decoding pubkey base64");
        return undef;
    }

    my $b64 = encode_base64( sha256($blob), '' );
    $b64 =~ s/=+\z//;    # OpenSSH strips trailing '=' padding

    return "SHA256:$b64";
}

# HELPER: Validate a certificate serial.
# Serials are produced by _getNextSerial as plain decimal integers and are
# handed verbatim to ssh-keygen through the KRL spec file, one directive per
# line. Anything else (in particular anything containing a newline) would let
# a caller inject arbitrary KRL spec directives — `id:`, `key:`, `hash:` —
# and revoke certificates it has no business revoking (issue #65).
# ssh-keygen accepts serials up to 2^64-1, i.e. at most 20 digits.
sub _validSerial {
# HELPER: Bit length of an SSH "mpint" (RFC 4251 §5): a big-endian integer
# carrying a leading 0x00 byte whenever its top bit would otherwise be read
# as a sign bit. OpenSSH reports the significant bit count (a 2048-bit RSA
# modulus is 257 bytes on the wire, 2048 bits here).
sub _mpintBits {
    my ($mpint) = @_;
    return 0 unless defined $mpint;
    $mpint =~ s/\A\x00+//;
    return 0 unless length $mpint;
    my $first = ord( substr( $mpint, 0, 1 ) );
    my $bits  = ( length($mpint) - 1 ) * 8;
    while ($first) { $bits++; $first >>= 1; }
    return $bits;
}

# HELPER: Determine the real type and size of an SSH public key.
#
# The textual prefix of a pubkey line is just a label the client chose; it
# is NOT proof of what the key actually is. The truth is the base64 blob,
# which is the RFC 4253 wire format: a sequence of fields, each a uint32
# big-endian length followed by that many bytes. The first field is the key
# type; the rest depend on it (`ssh-rsa` => e, n ; `ssh-dss` => p, q, g, y ;
# `ssh-ed25519` => 32-byte point ; `sk-*` => point/curve then application).
#
# Returns undef if the blob is malformed, if the type is one we don't know
# how to size, or if the announced prefix disagrees with the blob.
# Otherwise a hashref { type, family, bits, sized }, where `family` is the
# token used in sshCaAllowedKeyTypes and `sized` says whether `bits` is a
# variable modulus size (RSA/DSA) that sshCaMinKeyBits may be compared to.
sub _parseSshPubKey {
    my ( $self, $sshPubKey ) = @_;
    return undef unless defined $sshPubKey;

    my ( $prefix, $blob_b64 ) = $sshPubKey =~ /^\s*(\S+)\s+(\S+)/;
    return undef unless defined $blob_b64 && length $blob_b64;

    my $blob = decode_base64($blob_b64);
    return undef unless length $blob;

    my @fields;
    my $pos = 0;
    my $len = length $blob;
    while ( $pos + 4 <= $len ) {
        my $flen = unpack( 'N', substr( $blob, $pos, 4 ) );
        $pos += 4;

        # Truncated or simply not a wire-format key: stop, don't guess.
        last if $flen > $len - $pos;
        push @fields, substr( $blob, $pos, $flen );
        $pos += $flen;

        # No key type we handle needs more than this (DSA has 5).
        last if @fields >= 5;
    }
    return undef unless @fields;

    my $type = $fields[0];
    return undef unless length $type;

    # A blob whose embedded type contradicts the announced prefix is either
    # corrupt or an attempt to have the policy check read one type while
    # ssh-keygen reads another.
    return undef unless $type eq $prefix;

    if ( my $fixed = $SSHCA_FIXED_KEY_TYPES{$type} ) {
        return {
            type   => $type,
            family => $fixed->[0],
            bits   => $fixed->[1],
            sized  => 0,
        };
    }

    if ( $type eq 'ssh-rsa' ) {

        # ssh-rsa: type, e, n — the modulus is the size that matters.
        return undef unless @fields >= 3;
        return {
            type   => $type,
            family => 'rsa',
            bits   => _mpintBits( $fields[2] ),
            sized  => 1,
        };
    }

    if ( $type eq 'ssh-dss' ) {

        # ssh-dss: type, p, q, g, y — p carries the key size.
        return undef unless @fields >= 2;
        return {
            type   => $type,
            family => 'dss',
            bits   => _mpintBits( $fields[1] ),
            sized  => 1,
        };
    }

    return undef;
}

# HELPER: Apply the configured key policy to a user-supplied public key.
# Returns { ok => 1, info => {...} } or { ok => 0, error => 'message' }.
sub _checkKeyPolicy {
    my ( $self, $sshPubKey ) = @_;

    my $info = $self->_parseSshPubKey($sshPubKey);
    return { ok => 0, error => 'Unsupported or malformed SSH public key' }
      unless $info;

    my $allowedConf = $self->conf->{sshCaAllowedKeyTypes};
    $allowedConf = SSHCA_DEFAULT_KEY_TYPES
      unless defined $allowedConf && $allowedConf =~ /\S/;
    my %allowed =
      map { lc($_) => 1 } grep { length } split /[\s,]+/, $allowedConf;

    unless ( $allowed{ $info->{family} } ) {
        return {
            ok    => 0,
            error => "SSH key type '$info->{type}' is not allowed",
        };
    }

    # A minimum bit count is only meaningful inside a variable-size family:
    # Ed25519 is always 256 bits and is stronger than RSA-3072, so comparing
    # the two numbers would reject the best keys available. Fixed-size
    # families are governed by the type allowlist alone.
    if ( $info->{sized} ) {
        my $min = $self->conf->{sshCaMinKeyBits};
        $min = SSHCA_DEFAULT_MIN_BITS
          unless defined $min && $min =~ /\A[0-9]+\z/;
        if ( $info->{bits} < $min ) {
            return {
                ok => 0,
                error =>
                  "SSH key is too small ($info->{bits} bits, minimum $min)",
            };
        }
    }

    return { ok => 1, info => $info };
}


    my ( $self, $serial ) = @_;
    return 0 unless defined $serial;
    return $serial =~ /\A[0-9]{1,20}\z/ ? 1 : 0;
}

# HELPER: Check that a blob is a structurally complete OpenSSH KRL.
#
# A KRL truncated mid-write still starts with the `SSHKRL` magic, so a magic
# check alone (which is all consumers do) accepts it — and sshd then rejects
# EVERY key with "incomplete message", i.e. fails closed and locks the host
# out. So walk the framing: fixed header, then the two length-prefixed
# strings that close it, then the section list (u8 type + u32-prefixed blob).
# Any length running past the end of the blob means the file is truncated.
#
# Layout (see krl_to_blob() in OpenSSH sshkrl.c):
#   "SSHKRL\n\0"      8 bytes
#   format version    u32 (1)
#   krl_version       u64
#   generated_date    u64
#   flags             u64
#   reserved          string
#   comment           string
#   sections          (u8 type + string)*
sub _krlIsValid {
    my ( $self, $data ) = @_;

    return 0 unless defined $data;
    my $len = length $data;

    # 36 bytes of fixed header + 2 empty strings = smallest legal KRL
    return 0 if $len < 44;
    return 0 unless substr( $data, 0, 8 ) eq "SSHKRL\n\0";
    return 0 unless unpack( 'N', substr( $data, 8, 4 ) ) == 1;

    my $pos = 36;

    # reserved + comment
    for ( 1 .. 2 ) {
        return 0 if $len - $pos < 4;
        my $l = unpack( 'N', substr( $data, $pos, 4 ) );
        $pos += 4;
        return 0 if $l > $len - $pos;
        $pos += $l;
    }

    # sections
    while ( $pos < $len ) {
        return 0 if $len - $pos < 5;    # u8 type + u32 length
        $pos += 1;
        my $l = unpack( 'N', substr( $data, $pos, 4 ) );
        $pos += 4;
        return 0 if $l > $len - $pos;
        $pos += $l;
    }

    return $pos == $len ? 1 : 0;
}

# HELPER: Take the node-wide KRL lock and return the locked filehandle.
# Callers hold the lock for as long as they keep the returned handle: it is
# released by close(), or implicitly when the lexical goes out of scope — on
# error paths included. There is a single lock, so exclusive (writers) and
# shared (readers) users cannot deadlock against each other.
# Returns undef when the lock cannot be taken.
sub _krlLock {
    my ( $self, $krlPath, $shared ) = @_;

    require Fcntl;
    my $lockPath = "$krlPath.lock";

    my $lockFh;
    unless ( open $lockFh, '>>', $lockPath ) {

        # Readers may legitimately lack write access to the KRL directory;
        # a read-only descriptor is enough for LOCK_SH.
        unless ( $shared and open $lockFh, '<', $lockPath ) {
            $self->logger->error(
                "SSH CA: Cannot open KRL lockfile $lockPath: $!");
            return undef;
        }
    }
    unless ( flock( $lockFh, $shared ? Fcntl::LOCK_SH() : Fcntl::LOCK_EX() ) ) {
        $self->logger->error("SSH CA: Cannot lock KRL: $!");
        close $lockFh;
        return undef;
    }
    return $lockFh;
}

# HELPER: (Re)write the KRL from an ssh-keygen spec file, atomically.
#
# `ssh-keygen -k` opens its -f target with O_TRUNC, so pointing it at the
# live KRL leaves a window where the file is empty or half-written while
# sshd and /ssh/revoked readers can see it (issue #59). Instead ssh-keygen
# writes to a temporary file in the KRL's own directory and we rename() it
# over the real one: readers always see either the whole old file or the
# whole new one.
#
# Everything runs under the exclusive KRL lock so that concurrent writers —
# portal workers handling a revocation, a broker event, and the
# sshca-rebuild-krl cron job, which all share this helper — do not lose each
# other's updates through interleaved read-modify-writes.
#
# %args:
#   spec   => path to the ssh-keygen KRL spec file (required)
#   update => merge into the existing KRL (ssh-keygen -u) instead of
#             replacing it
#
# Returns 1 on success, 0 on failure (the live KRL is then left untouched).
sub _writeKrl {
    my ( $self, $krlPath, %args ) = @_;

    my $specFile = $args{spec};
    unless ( defined $krlPath and length $krlPath and defined $specFile ) {
        $self->logger->error('SSH CA: _writeKrl called without KRL/spec path');
        return 0;
    }

    my $caPub = $self->sshPubKey;
    unless ($caPub) {
        $self->logger->error('SSH CA: No CA public key available for KRL');
        return 0;
    }

    # Ensure directory exists
    my $dir = $krlPath;
    $dir =~ s|/[^/]+$||;
    $dir = '.' unless length $dir;
    unless ( -d $dir ) {
        require File::Path;
        File::Path::make_path($dir);
    }

    my $lockFh = $self->_krlLock($krlPath);
    return 0 unless $lockFh;

    # Scratch dir for the KRL spec files. `newdir` (not `tempdir(CLEANUP
    # => 1)`) so it is removed when this sub returns — including on the
    # error paths below — instead of at worker exit.
    require File::Temp;
    my $tmpobj = File::Temp->newdir();
    my $tmpdir = "$tmpobj";

    # Write CA public key
    my $caPubFile = "$tmpdir/ca.pub";
    open my $fh, '>', $caPubFile or do {
        $self->logger->error("SSH CA: Cannot write CA public key: $!");
        return 0;
    };
    print $fh $caPub;
    close $fh;

    # Scratch KRL, in the target directory so rename() stays atomic
    my ( $tmpFh, $tmpKrl ) =
      eval { File::Temp::tempfile( '.krl.tmpXXXXXX', DIR => $dir, UNLINK => 0 ) };
    unless ( defined $tmpKrl ) {
        $self->logger->error("SSH CA: Cannot create temporary KRL in $dir: $@");
        return 0;
    }
    close $tmpFh;

    # Keep the current KRL's permissions; the KRL is public data served over
    # /ssh/revoked, and File::Temp would otherwise hand us a 0600 file.
    my $mode = ( stat $krlPath )[2];
    $mode = defined $mode ? $mode & 07777 : 0644;

    # `-u` is a read-modify-write: seed the scratch file with the current KRL
    # so ssh-keygen merges into a private copy, never into the live file.
    my $update = $args{update} && -s $krlPath;
    if ($update) {
        unless ( $self->_copyFile( $krlPath, $tmpKrl ) ) {
            unlink $tmpKrl;
            return 0;
        }

        # Refuse to merge into a KRL we cannot parse: ssh-keygen -u would
        # fail anyway, and rebuilding from this single spec would silently
        # drop every serial already revoked. Failing here is the safe side —
        # the sshca-rebuild-krl cron job repairs the file from the persistent
        # sessions, which are the source of truth.
        my $current = '';
        if ( open my $cfh, '<:raw', $tmpKrl ) {
            local $/;
            $current = <$cfh>;
            close $cfh;
        }
        unless ( $self->_krlIsValid($current) ) {
            $self->logger->error( "SSH CA: existing KRL $krlPath is corrupted; "
                  . "refusing to update it, run sshca-rebuild-krl to repair" );
            unlink $tmpKrl;
            return 0;
        }
    }

    # -k: Generate a KRL
    # -u: Update existing KRL
    # -s: CA public key
    # -f: KRL file
    my @cmd = ( 'ssh-keygen', '-k' );
    push @cmd, '-u' if $update;
    push @cmd, '-s', $caPubFile, '-f', $tmpKrl, $specFile;

    $self->logger->debug( "SSH CA: Writing KRL: " . join( ' ', @cmd ) );

    # Execute ssh-keygen
    my $output = '';
    my $pid    = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork for KRL update: $!");
        unlink $tmpKrl;
        return 0;
    }
    elsif ( $pid == 0 ) {
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 1;
    }
    else {
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;
    if ($exitCode) {
        $self->logger->error(
            "SSH CA: KRL update failed (exit $exitCode): $output");
        unlink $tmpKrl;
        return 0;
    }

    # Paranoia: never publish something we would refuse to serve
    my $newKrl = '';
    if ( open my $vfh, '<:raw', $tmpKrl ) {
        local $/;
        $newKrl = <$vfh>;
        eval { require IO::Handle; $vfh->sync };    # best effort durability
        close $vfh;
    }
    unless ( $self->_krlIsValid($newKrl) ) {
        $self->logger->error(
            'SSH CA: ssh-keygen produced an invalid KRL, keeping the old one');
        unlink $tmpKrl;
        return 0;
    }

    chmod $mode, $tmpKrl;
    unless ( rename $tmpKrl, $krlPath ) {
        $self->logger->error("SSH CA: Cannot install new KRL in $krlPath: $!");
        unlink $tmpKrl;
        return 0;
    }

    return 1;

    # $lockFh released here (and on every early return above)
}

# HELPER: byte copy, used to seed the scratch KRL for ssh-keygen -u
sub _copyFile {
    my ( $self, $from, $to ) = @_;

    open my $in, '<:raw', $from or do {
        $self->logger->error("SSH CA: Cannot read $from: $!");
        return 0;
    };
    open my $out, '>:raw', $to or do {
        $self->logger->error("SSH CA: Cannot write $to: $!");
        close $in;
        return 0;
    };
    my $buf;
    while (1) {
        my $n = read $in, $buf, 65536;
        unless ( defined $n ) {
            $self->logger->error("SSH CA: Cannot read $from: $!");
            close $in;
            close $out;
            return 0;
        }
        last unless $n;
        unless ( print $out $buf ) {
            $self->logger->error("SSH CA: Cannot write $to: $!");
            close $in;
            close $out;
            return 0;
        }
    }
    close $in;
    unless ( close $out ) {
        $self->logger->error("SSH CA: Cannot write $to: $!");
        return 0;
    }
    return 1;
}

# HELPER: make sure a parsable KRL exists, generating an empty one if needed.
# `ssh-keygen -k` with an empty spec produces a header-only KRL: the correct
# way to say "nothing is revoked" (issue #64). Returns 1 if a KRL is in place.
sub _ensureKrl {
    my ( $self, $krlPath ) = @_;

    return 0 unless defined $krlPath and length $krlPath;
    return 1 if -s $krlPath;

    require File::Temp;
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );
    my $specFile = "$tmpdir/empty_spec";
    open my $fh, '>', $specFile or do {
        $self->logger->error("SSH CA: Cannot write empty KRL spec: $!");
        return 0;
    };
    close $fh;

    my $ok = $self->_writeKrl( $krlPath, spec => $specFile, update => 0 );
    $self->logger->info("SSH CA: Generated an empty KRL in $krlPath") if $ok;
    return $ok;
}

# HELPER: Update KRL file with revoked serial.
# Serialized across workers on the same node, and made atomic, by _writeKrl:
# concurrent events (broker-driven + locally-triggered) can reach this helper
# in parallel, and ssh-keygen -u does a read-modify-write on the KRL file, so
# without the lock the last writer wins and earlier revocations get lost.
sub _updateKrl {
    my ( $self, $serial ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath}
      || '/var/lib/lemonldap-ng/ssh/revoked_keys';

    # Defence in depth (issue #65): the HTTP revocation routes only reach
    # this helper with a serial they matched against a stored certificate
    # record, but nothing structurally prevents another caller from passing
    # a crafted one straight into the ssh-keygen spec file.
    unless ( $self->_validSerial($serial) ) {
        $self->logger->error(
            'SSH CA: refusing to add a malformed serial to the KRL');
        return 0;
    }

    # Get CA public key for KRL
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured for KRL');
        return 0;
    }

    require File::Temp;
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );

    # Create KRL spec file with serial to revoke
    my $specFile = "$tmpdir/revoke_spec";
    open my $fh, '>', $specFile or do {
        $self->logger->error("SSH CA: Cannot write revoke spec: $!");
        return 0;
    };
    print $fh "serial: $serial\n";
    close $fh;

    my $ok = $self->_writeKrl( $krlPath, spec => $specFile, update => 1 );
    $self->logger->info("SSH CA: KRL updated with revoked serial $serial")
      if $ok;
    return $ok;
}

# HELPER: Broadcast a revocation to sibling portals through the LLNG message
# broker (issue #9). Peers subscribe to the 'sshCaRevoke' action in init() and
# call _updateKrl on their own local KRL file. Requires a real broker
# (::Redis / ::MQTT / ::Pg); with the default ::NoBroker the publish stays on
# the local node.
sub _publishRevoke {
    my ( $self, $req, $serial ) = @_;
    return unless defined $serial && $serial ne '';
    eval {
        $self->p->HANDLER->publishEvent( $req,
            { action => 'sshCaRevoke', serial => $serial } );
    };
    if ($@) {
        $self->logger->warn(
            "SSH CA: publishEvent(sshCaRevoke, $serial) failed: $@");
    }
    return 1;
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::SSHCA - SSH Certificate Authority plugin

=head1 SYNOPSIS

Enable this plugin in LemonLDAP::NG Manager:
General Parameters > Plugins > SSH CA > Activation

=head1 DESCRIPTION

This plugin provides SSH certificate signing functionality, allowing users
to obtain short-lived SSH certificates signed by a trusted Certificate Authority.

=head1 ENDPOINTS

=head2 GET /ssh

Displays the SSH certificate signing web interface.
Requires authentication. This interface allows users to:

=over

=item * Paste their SSH public key

=item * Choose certificate validity duration

=item * Obtain a signed certificate for SSH authentication

=back

=head2 GET /ssh/ca

Returns the SSH CA public key in OpenSSH format.
No authentication required.

=head2 GET /ssh/revoked

Returns the SSH Key Revocation List (KRL) if configured.
No authentication required.

=head2 POST /ssh/sign

Signs a user's SSH public key and returns a certificate.
Requires authentication.

Request body (JSON):

    {
        "public_key": "ssh-ed25519 AAAA... user@host",
        "label": "laptop-pro",        # optional, falls back to the key comment
        "validity_days": 30           # optional, positive integer
    }

C<validity_days> must be a positive integer and is clamped to
C<sshCaCertMaxValidity>. Principals are always derived from the session; a
C<principals> field in the request is ignored.

The public key must satisfy the configured key policy (see
C<sshCaAllowedKeyTypes> and C<sshCaMinKeyBits>); the key type and size are
read from the decoded key blob, not from the textual prefix.

Response:

    {
        "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
        "serial": 1,
        "valid_until": "2025-01-01T12:00:00Z",
        "principals": ["user1"],
        "key_id": "user1@llng-1234567890-000001"
    }

=head2 GET /ssh/admin

Displays the SSH CA administration interface for searching and revoking
certificates. Restricted by C<sshCaAdminRule> (see L</CONFIGURATION>);
returns 403 when the rule is unset or does not match.

=head2 GET /ssh/certs

Lists/searches issued certificates from persistent sessions, across every
user. Restricted by C<sshCaAdminRule>; returns 403 when the rule is unset
or does not match.

Parameters:

=over

=item * user - Filter by user name (partial match)

=item * serial - Filter by certificate serial number (exact match)

=item * key_id - Filter by key ID (partial match)

=item * status - Filter by status: active, revoked, expired

=item * limit - Maximum number of results (default: 100, max: 1000). Must be
a non-negative integer; anything else falls back to the default.

=item * offset - Offset for pagination (default: 0). Must be a non-negative
integer; anything else falls back to 0.

=back

=head2 POST /ssh/revoke

Revokes any user's certificate. Restricted by C<sshCaAdminRule>; returns
403 when the rule is unset or does not match. Users revoke their B<own>
certificates through C</ssh/myrevoke>, which requires no administration
right.

Request body (JSON):

    {
        "session_id": "persistent-session-id",
        "serial": "123",
        "reason": "Key compromised"     # optional, <= 256 chars, no controls
    }

=head1 CONFIGURATION

=over

=item sshCaActivation

Enable/disable the SSH CA plugin (default: 0)

=item portalDisplaySshCa

Display the SSH CA tab in the portal menu (default: 0).
When enabled, authenticated users will see an "SSH CA" tab in the portal
allowing them to sign their SSH keys through the web interface.

=item sshCaAdminRule

Rule (boolOrExpr) deciding who may use the administration endpoints
C</ssh/admin>, C</ssh/certs> and C</ssh/revoke> (default: B<empty, which
denies everyone>).

The rule is evaluated against the caller's session, like any LLNG rule:

    $uid eq 'admin'
    inGroup('ssh-admins')
    1                       # any authenticated user (NOT recommended)

There is deliberately no permissive default: these endpoints list every
user's certificates and can revoke any of them, so a portal that has not
been configured must not expose them. Leaving the parameter empty simply
disables the administration UI; the per-user endpoints (C</ssh/sign>,
C</ssh/mycerts>, C</ssh/myrevoke>) are unaffected.

Configuring C<locationRules> on the portal vhost on top of this rule is
still supported and still recommended as defence in depth.

=item sshCaKeyRef

Reference to the SSH CA key in the LLNG keys store (required)

=item sshCaCertMaxValidity

Maximum certificate validity in days (default: 365). A request asking for
more is clamped to this value. Certificates are requested in days; the
default when C<validity_days> is omitted is 30 days.

=item sshCaAllowedKeyTypes

Comma- or space-separated list of key families users may submit for signing
(default: C<ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa>). Recognised tokens:

=over

=item * C<ed25519> — C<ssh-ed25519>

=item * C<sk-ed25519> — C<sk-ssh-ed25519@openssh.com> (FIDO2)

=item * C<ecdsa> — C<ecdsa-sha2-nistp256/384/521>

=item * C<sk-ecdsa> — C<sk-ecdsa-sha2-nistp256@openssh.com> (FIDO2)

=item * C<rsa> — C<ssh-rsa>

=item * C<dss> — C<ssh-dss>, B<not allowed by default>: DSA is limited to
1024-bit keys and SHA-1 signatures, and has been disabled then removed in
recent OpenSSH releases.

=back

The family is determined by decoding the key blob, so a key cannot slip
through by mislabelling its textual prefix.

=item sshCaMinKeyBits

Minimum key size in bits (default: 2048). Only applies to families whose
size varies, i.e. RSA and DSA: an Ed25519 key is always 256 bits and is
stronger than RSA-3072, so comparing the two counts would be meaningless.
Fixed-size families are governed by C<sshCaAllowedKeyTypes> alone.

=item sshCaPrincipalSources

Expression to derive principals from session, e.g., '$uid' (default: '$uid')

=item sshCaKrlPath

Path to the Key Revocation List file (optional)

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::PamAccess> for PAM authentication/authorization

=head1 AUTHORS

=over

=item Xavier Guimard L<yadd@debian.org>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
