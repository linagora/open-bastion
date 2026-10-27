package Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization;

# OAuth 2.0 Device Authorization Grant - RFC 8628
# https://datatracker.ietf.org/doc/html/rfc8628
#
# With PKCE extension (RFC 7636) for additional security

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
  PE_NOTOKEN
  PE_TOKENEXPIRED
  PE_UNAUTHORIZEDPARTNER
);
use JSON qw(from_json to_json);
use Crypt::URandom;
use Digest::SHA qw(sha256_hex hmac_sha256_hex);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Lib::OIDCPlugin';

use constant hook => {

    # Hook called by OpenIDConnect.pm token method before grant type dispatch
    oidcGotTokenRequest => 'deviceCodeGrantHook',
};

# Character set for user_code (RFC 8628 section 6.1)
# Base-20 without vowels to avoid offensive words, easy to type on mobile
use constant USER_CODE_CHARS => 'BCDFGHJKLMNPQRSTVWXZ';

# Lower bound for the generated user_code length. RFC 8628 section 6.1 asks
# for at least 20 bits of entropy; 8 characters of the base-20 alphabet give
# ~34.6 bits. Anything shorter is both brute-forceable inside the code TTL and
# unsubmittable (submitVerification rejects codes shorter than 6).
use constant MIN_USER_CODE_LENGTH => 8;

# Session kind for device authorization storage
use constant sessionKind => 'DEVA';

# Lazy access to CrowdSecAgent plugin (optional, for abuse reporting)
has crowdsec => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::CrowdSecAgent'};
    }
);

# One-time token for CSRF protection
has ott => (
    is      => 'rw',
    lazy    => 1,
    default => sub {
        # OneTimeToken was renamed StateToken in LLNG >= 3.0
        my $lib =
          eval { require Lemonldap::NG::Portal::Lib::StateToken; 1 }
          ? 'Lemonldap::NG::Portal::Lib::StateToken'
          : 'Lemonldap::NG::Portal::Lib::OneTimeToken';
        my $ott = $_[0]->{p}->loadModule($lib);
        $ott->timeout( $_[0]->conf->{formTimeout} );
        return $ott;
    }
);

# INITIALIZATION

sub init {
    my ($self) = @_;

    return unless $self->SUPER::init;

    # Device Authorization endpoint (RFC 8628 section 3.1)
    # POST /oauth2/device - for devices to request authorization
    my $oidc_path = $self->conf->{issuerDBOpenIDConnectPath} || '^/oauth2/';
    $oidc_path =~ s/^.*?(\w+).*?$/$1/;    # Extract path name (e.g., "oauth2")
    $self->addUnauthRoute(
        $oidc_path => { 'device' => 'deviceAuthorizationEndpoint' },
        ['POST']
      )

      # Duplication in case of virtual device inside the browser
      ->addAuthRoute(
        $oidc_path => { 'device' => 'deviceAuthorizationEndpoint' },
        ['POST']
      )

      # Device verification endpoint (for users) - /device
      ->addAuthRouteWithRedirect(
        device => 'displayVerification',
        ['GET']
      )->addAuthRoute(
        device => 'submitVerification',
        ['POST']
      );

    # Warn if CrowdSec is not configured (RFC 8628 recommends IP-based lockout)
    # Check config rather than loadedModules since init order is not guaranteed
    unless ($self->conf->{crowdsec}
        and $self->conf->{crowdsecAgent} )
    {
        $self->logger->warn(
"CrowdSecAgent plugin not configured. RFC 8628 recommends IP-based rate limiting for device authorization. Consider enabling CrowdSec for better security."
        );
    }

    $self->logger->debug("Device Authorization Grant (RFC 8628) initialized");
    return 1;
}

# Device Authorization endpoint (RFC 8628 section 3.1)
# Called directly via route POST /oauth2/device
sub deviceAuthorizationEndpoint {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device Authorization endpoint called");

    # Client authentication: try full credentials first, fall back to
    # client_id only for public clients
    my $client_authenticated = 0;
    my ( $rp, $auth_method ) =
      $self->oidc->checkEndPointAuthenticationCredentials($req);

    if ($rp) {

        # "none" means only client_id was provided (no real authentication)
        $client_authenticated = 1
          if ( $auth_method && $auth_method ne 'none' );
    }
    else {
        # Fall back to client_id for public clients
        my $client_id = $req->param('client_id');
        unless ($client_id) {
            return $self->_sendDeviceError( $req, 'invalid_request',
                'client_id is required' );
        }

        $rp = $self->oidc->getRP($client_id);
        unless ($rp) {
            return $self->_sendDeviceError( $req, 'invalid_client' );
        }

        # Only public clients may skip client authentication
        unless ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsPublic} )
        {
            $self->logger->warn(
                "Confidential client $client_id must authenticate");
            return $self->_sendDeviceError( $req, 'invalid_client',
                'Client authentication required' );
        }
    }

    my $client_id =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    # Check if this RP allows device authorization grant
    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorization} )
    {
        $self->logger->warn(
            "Device authorization grant not allowed for RP $rp");
        return $self->_sendDeviceError( $req, 'unauthorized_client' );
    }

    # Get requested scope
    my $scope = $req->param('scope') || 'openid';

    # PKCE support (RFC 7636)
    my $code_challenge        = $req->param('code_challenge');
    my $code_challenge_method = $req->param('code_challenge_method') || 'plain';

    # Check if PKCE is required for this RP
    # requirePKCE=1: always required
    # requirePKCE=2: required only if client did not authenticate
    my $require_pkce =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRequirePKCE} || 0;
    if ( $require_pkce == 1
        or ( $require_pkce == 2 and !$client_authenticated ) )
    {
        unless ($code_challenge) {
            $self->logger->warn(
                "PKCE required but no code_challenge provided for RP $rp");
            return $self->_sendDeviceError( $req, 'invalid_request',
                'code_challenge is required' );
        }
    }

    # Validate code_challenge_method if PKCE is used
    if ($code_challenge) {
        unless ( $code_challenge_method eq 'plain'
            or $code_challenge_method eq 'S256' )
        {
            $self->logger->warn(
                "Invalid code_challenge_method: $code_challenge_method");
            return $self->_sendDeviceError( $req, 'invalid_request',
                'code_challenge_method must be plain or S256' );
        }
        $self->logger->debug(
"PKCE enabled for device authorization (method=$code_challenge_method)"
        );
    }

    # Generate device_code (secret, used for polling)
    my $device_code = $self->_generateDeviceCode();

    # Store device authorization request
    my $expiration =
      $self->conf->{oidcServiceDeviceAuthorizationExpiration} || 600;
    my $interval = $self->_pollingInterval;

    # Generate user_code with collision detection
    # Retry up to 10 times if collision occurs
    my $user_code;
    my $user_code_hash;
    my $max_retries = 10;

    for my $attempt ( 1 .. $max_retries ) {
        $user_code      = $self->_generateUserCode();
        $user_code_hash = $self->_userCodeIndex($user_code);

        # Check if this user_code already exists
        my $existing = $self->p->getApacheSession(
            $user_code_hash,
            kind   => sessionKind,
            noInfo => 1,

            # These device-authorization sessions are stored under a fixed id
            # (the SHA-256 of the code), created with hashStore => 0; every
            # lookup must opt out of hashedSessionStore too, or it would search
            # under sha256_hex(id) and never find them.
            hashStore => 0,
        );

        if ( !$existing ) {

            # No collision, we can use this user_code
            last;
        }

        # Check if the existing session is expired
        if ( time() > ( $existing->data->{expires_at} || 0 ) ) {

            # Expired, remove it and use this user_code
            $existing->remove;
            last;
        }

        $self->logger->debug(
            "User code collision detected (attempt $attempt), regenerating");

        if ( $attempt == $max_retries ) {
            $self->logger->error(
"Failed to generate unique user_code after $max_retries attempts"
            );
            return $self->_sendDeviceError( $req, 'server_error' );
        }
    }

    # Create session with device_code hash as ID (for polling lookup)
    my $device_code_hash = sha256_hex($device_code);

    # NOTE: the plaintext user_code is deliberately NOT persisted. Anyone able
    # to read the session backend would otherwise list every pending code and
    # approve (or deny) an enrolment in the device's place. Only its SHA-256 is
    # kept, which is exactly what the lookup session is already keyed on, so it
    # discloses nothing new; _deleteDeviceAuth uses it to drop that lookup
    # session.
    my $session_data = {
        _type          => 'deviceauth',
        _utime         => time() - $self->conf->{timeout} + $expiration,
        user_code_hash => $user_code_hash,
        client_id      => $client_id,
        rp             => $rp,
        scope          => $scope,
        status         => 'pending',              # pending, approved, denied
        created_at     => time(),
        expires_at     => time() + $expiration,
        code_challenge => $code_challenge,
        code_challenge_method => $code_challenge_method,
    };

    # Store the device authorization using getApacheSession with fixed ID
    my $session = $self->p->getApacheSession(
        $device_code_hash,
        kind      => sessionKind,
        info      => $session_data,
        force     => 1,
        hashStore => 0,
    );

    unless ( $session && $session->id ) {
        $self->logger->error("Failed to create device authorization session");
        return $self->_sendDeviceError( $req, 'server_error' );
    }

    # Create session indexed by user_code for verification lookup
    my $user_code_session = $self->p->getApacheSession(
        $user_code_hash,
        kind => sessionKind,
        info => {
            _type            => 'deviceauth_usercode',
            _utime           => time() - $self->conf->{timeout} + $expiration,
            device_code_hash => $device_code_hash,

            # No plaintext user_code here either: this session is *keyed* on
            # sha256_hex(user_code), so the field was pure duplication.
            expires_at => time() + $expiration,
        },
        force     => 1,
        hashStore => 0,
    );

    unless ( $user_code_session && $user_code_session->id ) {
        $self->logger->error("Failed to create user_code lookup session");

        # Clean up the device_code session
        $session->remove;
        return $self->_sendDeviceError( $req, 'server_error' );
    }

    # Build verification URI
    my $portal           = $self->p->HANDLER->tsv->{portal}->();
    my $verification_uri = "$portal/device";
    my $formatted_code   = $self->_formatUserCode($user_code);
    my $verification_uri_complete =
      "$portal/device?user_code=" . ( $user_code =~ s/-//gr );

    # RFC 8628 section 3.2 - Device Authorization Response
    my $response = {
        device_code               => $device_code,
        user_code                 => $formatted_code,
        verification_uri          => $verification_uri,
        verification_uri_complete => $verification_uri_complete,
        expires_in                => $expiration + 0,
        interval                  => $interval + 0,
    };

    # Log the digest, never the code itself: the debug log is not a place to
    # publish a live approval credential.
    $self->logger->debug(
        "Device authorization created: user_code_hash=$user_code_hash, client=$client_id"
    );
    $self->userLogger->info(
        "Device authorization initiated for client $client_id");

    $self->auditLog(
        $req,
        code => "ISSUER_OIDC_DEVICE_AUTH_INITIATED",
        rp   => $rp,

        # The index, not the code: at this point the code is live for the
        # whole TTL, and the audit trail is usually shipped further than the
        # session store this plugin already stopped writing it to (issue #84).
        user_code_hash => $user_code_hash,
        message        => "Device authorization initiated for RP $rp",
    );

    return $self->p->sendJSONresponse( $req, $response );
}

# HOOK: Token endpoint handler for device_code grant
# Called by OpenIDConnect.pm via processHook('oidcGotTokenRequest')
sub deviceCodeGrantHook {
    my ( $self, $req, $rp, $grant_type ) = @_;

    return PE_OK
      unless $grant_type eq 'urn:ietf:params:oauth:grant-type:device_code';

    $self->logger->debug("Device code grant hook called for RP $rp");

    my $device_code = $req->param('device_code');
    my $client_id   = $req->param('client_id')
      || $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsClientID};

    unless ($device_code) {
        return $self->_sendTokenError( $req, 'invalid_request',
            'device_code is required' );
    }

    # Check if this RP allows device authorization grant
    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorization} )
    {
        $self->logger->warn(
            "Device authorization grant not allowed for RP $rp");
        return $self->_sendTokenError( $req, 'unauthorized_client' );
    }

    # Find the device authorization
    my $device_auth = $self->_findByDeviceCode($device_code);

    unless ($device_auth) {

        # Token expired or invalid
        return $self->_sendTokenError( $req, 'expired_token' );
    }

    # Verify RP matches
    if ( $device_auth->{rp} ne $rp ) {
        $self->logger->warn( "RP mismatch in device_code grant: expected "
              . $device_auth->{rp}
              . ", got $rp" );
        return $self->_sendTokenError( $req, 'invalid_grant' );
    }

    # Check authorization status
    my $status = $device_auth->{status} || 'pending';

    if ( $status eq 'pending' ) {

        # RFC 8628 section 3.5 - Rate limiting with slow_down
        # Use poll count approach which is more resilient to race conditions
        my $interval   = $self->_pollingInterval;
        my $created_at = $device_auth->{created_at} || time();
        my $poll_count = ( $device_auth->{poll_count} || 0 ) + 1;
        my $now        = time();

        my $elapsed          = $now - $created_at;
        my $slow_down_margin = $device_auth->{slow_down_count} || 0;

        # If client has polled more than expected, return slow_down
        # Each slow_down increases the effective interval
        my $effective_max =
          int( $elapsed / ( $interval + $slow_down_margin * 5 ) ) + 1;

        # These two writes must NEVER carry `status => 'pending'`: the status
        # read above is a snapshot, an admin approval or denial can land
        # between that read and this write, and the session update merges
        # rather than replaces (Common/Session.pm). Writing `pending` back
        # would silently revert the decision while keeping the approval fields
        # it wrote, and a reverted denial would let a second approver grant
        # what an admin refused. Only the poll bookkeeping is written.
        if ( $poll_count > $effective_max + 1 ) {

            # Increment slow_down counter (increases effective interval)
            $self->_updateDeviceAuthFields(
                $device_auth,
                {
                    poll_count      => $poll_count,
                    slow_down_count => $slow_down_margin + 1,
                }
            );
            $self->logger->debug(
"Client polling too fast (poll $poll_count, max $effective_max), returning slow_down"
            );
            return $self->_sendTokenError( $req, 'slow_down' );
        }

        # Update poll count
        $self->_updateDeviceAuthFields( $device_auth,
            { poll_count => $poll_count, } );

        # RFC 8628 section 3.5 - authorization_pending
        return $self->_sendTokenError( $req, 'authorization_pending' );
    }
    elsif ( $status eq 'denied' ) {

        # RFC 8628 section 3.5 - access_denied
        $self->_deleteDeviceAuth( $req, $device_auth );
        return $self->_sendTokenError( $req, 'access_denied' );
    }
    elsif ( $status eq 'approved' ) {

        # Generate tokens!
        return $self->_generateTokens( $req, $device_auth, $rp );
    }
    else {
        $self->logger->error("Unknown device auth status: $status");
        return $self->_sendTokenError( $req, 'server_error' );
    }
}

# DEVICE VERIFICATION PAGE (for authenticated users)
sub displayVerification {
    my ( $self, $req ) = @_;

    $self->logger->debug("Display device verification page");

    # Pre-fill user_code if provided in URL
    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Clean up

    # Create CSRF token
    my $store = $self->ott->can('storeState') ? 'storeState' : 'createToken';
    my $token = $self->ott->$store();

    # Set template parameters
    $req->data->{activeTimer} = 0;
    $req->{user_code} = $user_code;

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $user_code,
            TOKEN     => $token,
            MSG       => '',
        }
    );
}

# DEVICE VERIFICATION SUBMIT
sub submitVerification {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device verification submitted");

    # Verify CSRF token
    my $token = $req->param('token');
    unless ($token) {
        $self->userLogger->error('Device verification called without token');
        return $self->p->do( $req, [ sub { PE_NOTOKEN } ] );
    }
    my $get = $self->ott->can('getState') ? 'getState' : 'getToken';
    unless ( $self->ott->$get($token) ) {
        $self->userLogger->error(
            'Device verification called with invalid/expired token');
        return $self->p->do( $req, [ sub { PE_TOKENEXPIRED } ] );
    }

    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Remove formatting (dashes, spaces)
    $user_code = uc($user_code);

    # Per-session lockout: brute-forcing the user_code space needs many
    # submissions from an authenticated session, and CrowdSec (IP based, and
    # optional) is not always there to stop them. Count the failures in the
    # SSO session itself and refuse once the budget is spent.
    if ( $self->_userCodeLockout($req) ) {
        my $user = $req->userData->{ $self->conf->{whatToTrace} };
        $self->userLogger->warn(
            "Too many invalid device user_code attempts for $user");
        $self->auditLog(
            $req,
            code    => "ISSUER_OIDC_DEVICE_AUTH_LOCKED",
            user    => $user,
            message => "Device verification locked after too many"
              . " invalid codes submitted by $user",
        );
        return $self->_showVerificationError( $req, 'deviceTooManyAttempts' );
    }

    unless ( $user_code && length($user_code) >= 6 ) {
        $self->_countUserCodeFailure($req);
        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Find the device authorization by user_code
    my $device_auth = $self->_findByUserCode($user_code);
    unless ($device_auth) {

        # Log the digest, not the code: a submitted code may well be a *valid*
        # one (a typo away, or probed by someone else), and this line is at
        # info level, i.e. on in production.
        $self->logger->info(
            "Invalid or expired user_code: "
              . $self->_userCodeIndex($user_code) );

        # Report to CrowdSec if available (potential bruteforce)
        $self->_reportInvalidUserCode( $req, $user_code );
        $self->_countUserCodeFailure($req);

        my $user = $req->userData->{ $self->conf->{whatToTrace} };
        $self->auditLog(
            $req,
            code => "ISSUER_OIDC_DEVICE_AUTH_INVALID_CODE",

            # A submitted code may well be a *valid* one -- a typo away from
            # its owner's, or probed by someone else -- so this record gets
            # the index too (issue #84).
            user_code_hash => $self->_userCodeIndex($user_code),
            user           => $user,
            message   => "Invalid or expired user_code submitted by $user",
        );

        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Valid code: clear the failure budget of this session
    $self->_resetUserCodeFailures($req);

    # Check if already processed
    if ( $device_auth->{status} ne 'pending' ) {
        $self->logger->info(
            "User code already processed: "
              . $self->_userCodeIndex($user_code) );
        return $self->_showVerificationError( $req, 'codeAlreadyUsed' );
    }

    # Check RP-specific device authorization rule (boolOrExpr)
    my $rp            = $device_auth->{rp};
    my $rp_activation = $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAllowDeviceAuthorization};
    if ( $rp_activation && $rp_activation ne '1' ) {
        my $rule =
          $self->p->buildRule( $rp_activation, 'deviceAuthorizationRule' );
        unless ( $rule && $rule->( $req, $req->userData ) ) {
            my $user = $req->userData->{ $self->conf->{whatToTrace} };
            $self->userLogger->warn(
                "User $user not authorized to register devices for RP $rp");
            $self->auditLog(
                $req,
                code      => "ISSUER_OIDC_DEVICE_AUTH_RULE_DENIED",
                rp        => $rp,
                user_code => $user_code,
                user      => $user,
                message   =>
                  "Device authorization denied by rule for $user on RP $rp",
            );
            return $self->p->do( $req, [ sub { PE_UNAUTHORIZEDPARTNER } ] );
        }
    }

    # Check action (approve or deny)
    my $action = $req->param('action') || 'approve';

    if ( $action eq 'deny' ) {

        # User denied the authorization
        $self->_updateDeviceAuthStatus( $device_auth, 'denied' );
        my $user = $req->userData->{ $self->conf->{whatToTrace} };
        $self->userLogger->notice(
            "Device authorization denied by user $user for client "
              . $device_auth->{client_id} );

        $self->auditLog(
            $req,
            code      => "ISSUER_OIDC_DEVICE_AUTH_DENIED",
            rp        => $device_auth->{rp},
            user_code => $user_code,
            user      => $user,
            message   =>
              "Device authorization denied by $user for RP $device_auth->{rp}",
        );

        return $self->p->sendHtml(
            $req, 'device',
            params => {
                DEVICE_DENIED => 1,
                MSG           => 'deviceDenied',
            }
        );
    }

    # Approve the authorization
    # Store user info for token generation
    my $user_session_id = $req->id || $req->userData->{_session_id};
    my $user            = $req->userData->{ $self->conf->{whatToTrace} };

    # Resolve the granted scope through the core gate now that we have the
    # consenting user's context ($req->userData). The device endpoint is
    # pre-auth, so the scope requested there is unfiltered; resolving it here
    # applies declared-scope filtering (oidcServiceAllowOnlyDeclaredScopes) and
    # the per-user dynamic scope rules (rpScopeRules) exactly like the
    # authorization-code flow, so a device cannot obtain a privileged scope the
    # approving user is not entitled to. offline_access is intentionally kept
    # (it is the offline refresh-token marker, stripped later at token minting).
    my $granted_scope =
      $self->oidc->getScope( $req, $rp, $device_auth->{scope} );

    $self->_updateDeviceAuthStatus(
        $device_auth,
        'approved',
        {
            user_session_id => $user_session_id,
            user            => $user,
            approved_at     => time(),
            scope           => $granted_scope,
        }
    );

    $self->userLogger->notice(
        "Device authorization approved by user $user for client "
          . $device_auth->{client_id} );

    $self->auditLog(
        $req,
        code      => "ISSUER_OIDC_DEVICE_AUTH_APPROVED",
        rp        => $device_auth->{rp},
        user_code => $user_code,
        user      => $user,
        message   =>
          "Device authorization approved by $user for RP $device_auth->{rp}",
    );

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            DEVICE_APPROVED => 1,
            CLIENT_ID       => $device_auth->{client_id},
            SCOPE           => $granted_scope,
            MSG             => 'deviceApproved',
        }
    );
}

# PRIVATE METHODS

sub _generateDeviceCode {
    my ($self) = @_;

    # 32 bytes of random data, hex encoded
    return unpack( 'H*', Crypt::URandom::urandom(32) );
}

# Configured polling interval, floored at 1 second: the manager now refuses
# anything below that, but an old or hand-edited configuration must not be able
# to push a zero or negative value into the slow_down divisor below.
sub _pollingInterval {
    my ($self) = @_;
    my $interval =
      $self->conf->{oidcServiceDeviceAuthorizationPollingInterval} || 5;
    return $interval < 1 ? 1 : $interval;
}

sub _generateUserCode {
    my ($self) = @_;
    my $length =
      $self->conf->{oidcServiceDeviceAuthorizationUserCodeLength} || 8;

    # Never generate a code weaker than RFC 8628 section 6.1 asks for, whatever
    # the configuration says (see MIN_USER_CODE_LENGTH).
    if ( $length < MIN_USER_CODE_LENGTH ) {
        $self->logger->warn( "Configured user_code length $length is below "
              . MIN_USER_CODE_LENGTH
              . ", using "
              . MIN_USER_CODE_LENGTH );
        $length = MIN_USER_CODE_LENGTH;
    }
    my $chars     = USER_CODE_CHARS;
    my $chars_len = length($chars);
    my $code      = '';

    # Use rejection sampling to avoid modulo bias
    # For chars_len=20, largest multiple fitting in a byte is 240 (12*20)
    my $max_valid = int( 256 / $chars_len ) * $chars_len;

    while ( length($code) < $length ) {

        # Get a batch of random bytes (request extra to reduce iterations)
        my $bytes = Crypt::URandom::urandom( ( $length - length($code) ) * 2 );
        foreach my $b ( split //, $bytes ) {
            my $val = ord($b);

            # Reject values that would cause modulo bias
            next if $val >= $max_valid;

            $code .= substr( $chars, $val % $chars_len, 1 );
            last if length($code) >= $length;
        }
    }
    return $code;
}

sub _formatUserCode {
    my ( $self, $code ) = @_;

    # Format as XXXX-XXXX for readability
    if ( length($code) == 8 ) {
        return substr( $code, 0, 4 ) . '-' . substr( $code, 4, 4 );
    }
    return $code;
}

# Index under which the user_code lookup session is stored, and the only
# representation of the code this plugin writes to a log or an audit record.
#
# A bare sha256_hex(user_code) is invertible by anyone who can list session
# ids: the code space is 20^8, about 2^34.6, which is seconds on a GPU, and a
# pending code is a live approval credential (issue #83). Keying the digest
# with the portal secret leaves the lookup a single direct read while making
# the id useless to a reader of the session backend.
#
# Without `key` configured there is nothing to key with; the bare digest is
# kept so the plugin still works, and says once that it is doing so.
sub _userCodeIndex {
    my ( $self, $user_code ) = @_;

    my $key = $self->conf->{key};
    unless ( defined $key and length $key ) {
        $self->logger->warn( "No `key` configured: the device user_code index"
              . " falls back to an unkeyed digest, enumerable from the session"
              . " backend (issue #83)" )
          unless $self->{_unkeyedIndexWarned}++;
        return sha256_hex($user_code);
    }

    return hmac_sha256_hex( $user_code, $key );
}

sub _findByUserCode {
    my ( $self, $user_code ) = @_;

    # Look up the user_code session to get the device_code_hash
    my $user_code_hash = $self->_userCodeIndex($user_code);

    my $user_code_session =
      $self->p->getApacheSession( $user_code_hash, kind => sessionKind,
        hashStore => 0, );

    # Authorizations created before the index was keyed (issue #83) live under
    # the bare digest. They expire within one code TTL, so this fallback is
    # here to carry an upgrade across that window, not forever.
    unless ( $user_code_session && $user_code_session->data ) {
        my $legacy = sha256_hex($user_code);
        if ( $legacy ne $user_code_hash ) {
            $user_code_session =
              $self->p->getApacheSession( $legacy, kind => sessionKind,
                hashStore => 0, );
            if ( $user_code_session && $user_code_session->data ) {
                $self->logger->debug(
                    "User code found under the legacy unkeyed index");
                $user_code_hash = $legacy;
            }
        }
    }

    unless ( $user_code_session && $user_code_session->data ) {
        $self->logger->debug("User code session not found: $user_code_hash");
        return undef;
    }

    # Check expiration
    if ( time() > ( $user_code_session->data->{expires_at} || 0 ) ) {
        $self->logger->debug("User code expired: $user_code_hash");
        $user_code_session->remove;
        return undef;
    }

    my $device_code_hash = $user_code_session->data->{device_code_hash};
    return $self->_getDeviceAuthByHash($device_code_hash);
}

sub _findByDeviceCode {
    my ( $self, $device_code ) = @_;

    my $device_code_hash = sha256_hex($device_code);
    return $self->_getDeviceAuthByHash($device_code_hash);
}

sub _getDeviceAuthByHash {
    my ( $self, $device_code_hash ) = @_;

    my $session =
      $self->p->getApacheSession( $device_code_hash, kind => sessionKind,
        hashStore => 0, );

    unless ( $session && $session->data ) {
        $self->logger->debug("Device auth session not found");
        return undef;
    }

    # Check expiration
    if ( time() > ( $session->data->{expires_at} || 0 ) ) {
        $self->logger->debug("Device auth session expired");
        $session->remove;
        return undef;
    }

    # Return session data with session reference for updates
    my $data = { %{ $session->data } };
    $data->{_session}          = $session;
    $data->{_device_code_hash} = $device_code_hash;

    return $data;
}

# Write a decision (approved/denied/...) plus its companion fields.
sub _updateDeviceAuthStatus {
    my ( $self, $device_auth, $status, $extra ) = @_;

    return $self->_updateDeviceAuthFields( $device_auth,
        { %{ $extra || {} }, status => $status } );
}

# Write only the given fields into the device authorization session. The
# session update merges, so keys left out — `status` in particular — keep
# whatever value another request has stored meanwhile.
sub _updateDeviceAuthFields {
    my ( $self, $device_auth, $info ) = @_;

    my $session = $device_auth->{_session};
    return unless $session;
    return unless ( ref $info eq 'HASH' and %$info );

    $self->p->getApacheSession(
        $session->id,
        kind      => sessionKind,
        info      => $info,
        hashStore => 0,
    );
}

# Consume a device authorization: drop the device_code session and its
# user_code lookup session, on every node.
#
# Returns true when THIS caller deleted the device_code session, false when it
# was already gone (a concurrent token request won it) or the store refused.
# Callers that are about to mint credentials must check it: the device_code is
# single-use, and without a conditional consumption two token requests holding
# the same code (and, under PKCE, the same verifier) both minted a full token
# set, so the theft left the legitimate device's exchange succeeding and
# nothing to notice (issue #68).
#
# `noCache => 1` makes the delete re-read the backend instead of the
# node-local session cache. And each removal is followed by an `unlog` event,
# because Common::Apache::Session::Store->remove only evicts the cache of the
# node performing the write (its `#TODO: remove cache on all LL::NG
# instances`): without the event, another node kept serving a deleted
# device_auth from cache for the whole code TTL, turning a millisecond race
# into a window that needs no timing skill at all.
# Returns whether THIS call won the device_code delete. Only the token
# exchange looks at that; the paths that expire or deny a code do not race for
# anything.
#
# As in /pam/verify, the loser is detected by the re-tie inside
# Common::Session->remove, not by the delete: deleting an absent record is a
# silent success in the store layer, so it is `noCache => 1` -- forcing that
# re-tie to go to the backend instead of the node-local cache -- that makes
# the verdict mean anything. It assumes the backend fails to retrieve a
# missing id rather than handing back an empty record.
#
# Note for later: on the exchange path the grant hook has already run by the
# time we get here, so a losing exchange has executed its side effects (the
# synthetic-session work in oidc-device-organization, for one) before being
# refused. That is idempotent today. Moving this delete ahead of the hook
# would change what the existing error paths do, so it is left where it is
# deliberately.
sub _deleteDeviceAuth {
    my ( $self, $req, $device_auth ) = @_;

    my $won = 0;

    # Delete the device_code session
    if ( my $session = $device_auth->{_session} ) {
        $won = $session->remove( { noCache => 1 } ) ? 1 : 0;
        $self->logger->info( 'Device authorization already consumed elsewhere: '
              . ( $session->error // 'unknown' ) )
          unless $won;
        $self->_unlogEverywhere( $req, $session );
    }

    # Also delete the user_code lookup session (keyed on the code digest,
    # which is all the record keeps of the code)
    if ( my $user_code_hash = $device_auth->{user_code_hash} ) {
        my $user_code_session =
          $self->p->getApacheSession( $user_code_hash, kind => sessionKind,
            hashStore => 0, );
        if ($user_code_session) {
            $user_code_session->remove( { noCache => 1 } );
            $self->_unlogEverywhere( $req, $user_code_session );
        }
    }

    return $won;
}

# HELPER: evict a just-removed session from every node's local session cache.
#
# Portal::Main::Run does this for the sessions it deletes itself
# (`publishEvent 'unlog'`); the device grant deletes its sessions directly, so
# it has to publish the event itself. The cache is keyed on the STORAGE id,
# which is the session id here (device sessions use hashStore => 0).
sub _unlogEverywhere {
    my ( $self, $req, $session ) = @_;

    my $id = $session->storageId || $session->id or return;
    eval {
        $self->p->HANDLER->publishEvent( $req,
            { action => 'unlog', id => $id } );
    };
    $self->logger->warn("Could not publish the unlog event for $id: $@") if $@;
}

sub _generateTokens {
    my ( $self, $req, $device_auth, $rp ) = @_;

    # Validate PKCE if it was used
    my $code_challenge        = $device_auth->{code_challenge};
    my $code_challenge_method = $device_auth->{code_challenge_method};

    if ($code_challenge) {
        my $code_verifier = $req->param('code_verifier');

        # Verify code_verifier is provided when code_challenge exists
        unless ($code_verifier) {
            $self->logger->error(
                "code_verifier is required when code_challenge was provided");
            return $self->_sendTokenError( $req, 'invalid_grant',
                'code_verifier is required' );
        }

        # Use the OIDC issuer's validatePKCEChallenge method
        unless (
            $self->oidc->validatePKCEChallenge(
                $code_verifier, $code_challenge, $code_challenge_method
            )
          )
        {
            $self->logger->error(
                "PKCE validation failed for device code grant");
            return $self->_sendTokenError( $req, 'invalid_grant',
                'PKCE validation failed' );
        }
        $self->logger->debug("PKCE validation successful");
    }

    my $scope = $device_auth->{scope};
    my $user  = $device_auth->{user};

    # Verify user session is still valid
    my $user_session_id = $device_auth->{user_session_id};
    my $session =
      $self->p->getApacheSession( $user_session_id, kind => 'SSO' );

    unless ($session) {
        $self->logger->error("User session not found for device authorization");
        $self->_deleteDeviceAuth( $req, $device_auth );
        return $self->_sendTokenError( $req, 'access_denied',
            'User session no longer valid' );
    }

    my $session_data = $session->data;
    my $timeout      = $self->conf->{timeout};
    my $utime        = $session_data->{_utime} || 0;

    if ( time() > $utime + $timeout ) {
        $self->logger->error("User session expired for device authorization");
        $self->_deleteDeviceAuth( $req, $device_auth );
        return $self->_sendTokenError( $req, 'access_denied',
            'User session expired' );
    }

    # Hook: allows plugins to modify session data before token creation
    # (e.g. replace with synthetic session for organizational devices).
    # The hook may also update $device_auth->{user_session_id} to point
    # to a different (e.g. synthetic) session.
    my $h = $self->p->processHook( $req, 'oidcDeviceCodeGrant',
        $device_auth, $rp, $session_data );
    if ( $h != PE_OK ) {
        $self->_deleteDeviceAuth( $req, $device_auth );

        # PE_ERROR from a grant hook is an internal failure (a hook could not
        # build the identity it is responsible for), not a policy denial.
        # Report it as such: a device told `access_denied` would look like a
        # revoked enrolment, while `server_error` says "retry the enrolment".
        # Either way the exchange fails closed — it never falls back to the
        # approving admin's identity.
        if ( $h == PE_ERROR ) {
            $self->logger->error(
                "Device code grant hook failed for RP $rp, refusing to mint"
                  . " tokens with a fallback identity" );
            return $self->_sendTokenError( $req, 'server_error',
                'Device grant hook failed' );
        }
        return $self->_sendTokenError( $req, 'access_denied' );
    }

    # Re-read values in case the hook changed them
    $user_session_id = $device_auth->{user_session_id};
    $scope           = $device_auth->{scope};

    # Single-use enforcement: consume the device authorization now that every
    # terminal check (PKCE, live user session, grant hook) has passed. Doing it
    # here rather than after the tokens are minted stops a second poll — at the
    # normal RFC 8628 5s cadence — from exchanging the same approved code twice
    # and getting a duplicate token set. The in-memory $device_auth copy is kept
    # for the refresh-token data and audit log below.
    #
    # The verdict is conditional on having actually won the delete: whoever
    # loses mints nothing (issue #68).
    unless ( $self->_deleteDeviceAuth( $req, $device_auth ) ) {
        $self->logger->error(
            "Device code already consumed by a concurrent token request"
              . " (RP $rp), refusing to mint a second token set" );
        $self->p->auditLog(
            $req,
            code    => 'ISSUER_OIDC_DEVICE_AUTH_DOUBLE_EXCHANGE',
            message => 'Device code exchange refused: already consumed',
            rp      => $rp,
            user    => $user,
        );
        return $self->_sendTokenError( $req, 'invalid_grant',
            'Device code already used' );
    }

    # Decide offline-ness BEFORE stripping offline_access, then drop it from the
    # granted scope so it is not advertised in the access token, the response
    # `scope`, the ID token or the refresh token. Mirrors the core token
    # endpoint (Issuer/OpenIDConnect.pm:891-924), where offline_access is a
    # request marker, not a granted scope.
    my $is_offline =
      (      $self->oidc->_hasScope( 'offline_access', $scope )
          && $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsAllowOffline} )
      ? 1
      : 0;
    $scope = join ' ', grep { $_ ne 'offline_access' } split /\s+/, $scope;

    # Generate access token
    my $access_token_extra = {
        scope      => $scope,
        rp         => $rp,
        grant_type => "device_code",
    };
    $access_token_extra->{user_session_id} = $user_session_id
      if $user_session_id;

    # Propagate a per-device identifier set by the grant hook (e.g.
    # oidc-device-organization stamps the synthetic session id as _deviceId) into
    # the access token session, so consumers can identify the individual enrolled
    # device. newAccessToken() only persists $access_token_extra, not arbitrary
    # $session_data keys, hence this explicit forward.
    $access_token_extra->{_deviceId} = $session_data->{_deviceId}
      if $session_data->{_deviceId};

    my $access_token =
      $self->oidc->newAccessToken( $req, $rp, $scope, $session_data,
        $access_token_extra );

    unless ($access_token) {
        $self->logger->error("Failed to create access token");
        return $self->_sendTokenError( $req, 'server_error' );
    }

    my $expires_in =
      $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsAccessTokenExpiration}
      || $self->conf->{oidcServiceAccessTokenExpiration}
      || 3600;

    my $response = {
        access_token => "$access_token",
        token_type   => 'Bearer',
        expires_in   => $expires_in + 0,
        scope        => $scope,
    };

    # Generate ID token if openid scope is requested
    if ( $scope =~ /\bopenid\b/ ) {
        my $id_token =
          $self->oidc->_generateIDToken( $req, $rp, $scope, $session_data, 0 );
        if ($id_token) {
            $response->{id_token} = $id_token;
        }
    }

    # Decide whether to issue a refresh token. Mirror the core token endpoint
    # (Issuer/OpenIDConnect.pm): an *offline* refresh token ($is_offline,
    # computed above) is gated by the offline_access scope +
    # oidcRPMetaDataOptionsAllowOffline, while an *online* refresh token is
    # gated by oidcRPMetaDataOptionsRefreshToken. These are two independent
    # gates: AllowOffline alone must be enough to get an offline refresh token,
    # even when RefreshToken (online) is off.
    if (   $is_offline
        || $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRefreshToken} )
    {
        my $refresh_token_data = {
            scope        => $scope,
            client_id    => $device_auth->{client_id},
            _session_uid => $session_data->{_user},
            auth_time    => $session_data->{_lastAuthnUTime},
            grant_type   => "device_code",
            %$session_data,
        };

        # Online refresh tokens are tied to the user's SSO session; offline
        # ones are standalone (the refresh token carries the user info, e.g.
        # the synthetic organization identity injected by the
        # oidc-device-organization plugin via $session_data).
        $refresh_token_data->{user_session_id} = $user_session_id
          unless $is_offline;

        my $refresh_token =
          $self->oidc->newRefreshToken( $rp, $refresh_token_data, $is_offline );

        if ($refresh_token) {
            $response->{refresh_token} = $refresh_token->id;
        }
    }

    # (device authorization already consumed above, before token minting)

    $self->logger->debug("Device code grant completed for RP $rp");

    $self->auditLog(
        $req,
        code => "ISSUER_OIDC_DEVICE_AUTH_TOKEN_GRANTED",
        rp   => $rp,

        # This path only ever sees the device_code; the plaintext user_code is
        # no longer persisted, so the audit trail carries its digest here. The
        # approve/deny records above still log the code itself, which is what
        # correlates an enrolment with the admin who authorized it.
        user_code_hash => $device_auth->{user_code_hash},
        user           => $user,
        message => "Device code exchanged for tokens by $user for RP $rp",
    );

    $req->response( $self->p->sendJSONresponse( $req, $response ) );
    return PE_SENDRESPONSE;
}

sub _sendDeviceError {
    my ( $self, $req, $error, $description ) = @_;

    my $response = { error => $error };
    $response->{error_description} = $description if $description;

    # Return PSGI response directly (used by deviceAuthorizationEndpoint route)
    return $self->p->sendJSONresponse( $req, $response, code => 400 );
}

sub _sendTokenError {
    my ( $self, $req, $error, $description ) = @_;

    my $response = { error => $error };
    $response->{error_description} = $description if $description;

    # authorization_pending and slow_down should return 400
    # expired_token and access_denied should return 400
    $req->response(
        $self->p->sendJSONresponse( $req, $response, code => 400 ) );
    return PE_SENDRESPONSE;
}

sub _showVerificationError {
    my ( $self, $req, $msg ) = @_;

    # Same sanitisation as displayVerification/submitVerification. The template
    # escapes with ESCAPE="HTML", so this is defence in depth rather than a
    # live XSS fix — but the reflected value should not be the only thing
    # standing between a crafted parameter and the page.
    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $user_code,
            MSG       => $msg,
            ERROR     => 1,
        }
    );
}

# INVALID user_code BUDGET (per SSO session)
#
# CrowdSec, when deployed, rate-limits by IP and needs a bouncer this plugin
# cannot verify. These three helpers add a lockout the plugin owns: N invalid
# codes inside the lockout window and the session may not submit any more
# until the window elapses. Disabled by setting MaxFailures to 0.

sub _maxUserCodeFailures {
    my ($self) = @_;
    my $max = $self->conf->{oidcServiceDeviceAuthorizationMaxFailures};
    $max = 5 unless defined $max and $max =~ /^\d+$/;
    return $max;
}

sub _userCodeLockoutDelay {
    my ($self) = @_;
    my $delay = $self->conf->{oidcServiceDeviceAuthorizationLockoutDelay};
    $delay = 300 unless defined $delay and $delay =~ /^\d+$/ and $delay > 0;
    return $delay;
}

# True when the current session has spent its budget and the window is still
# open.
sub _userCodeLockout {
    my ( $self, $req ) = @_;

    my $max = $self->_maxUserCodeFailures or return 0;
    my $failures = $req->userData->{_deviceAuthFailures} || 0;
    return 0 if $failures < $max;

    my $last = $req->userData->{_deviceAuthLastFailure} || 0;
    return 1 if ( time() - $last ) < $self->_userCodeLockoutDelay;

    # Window elapsed: forgive and let this attempt through
    $self->_resetUserCodeFailures($req);
    return 0;
}

sub _countUserCodeFailure {
    my ( $self, $req ) = @_;

    return unless $self->_maxUserCodeFailures;
    my $failures = ( $req->userData->{_deviceAuthFailures} || 0 ) + 1;
    $req->userData->{_deviceAuthFailures}    = $failures;
    $req->userData->{_deviceAuthLastFailure} = time();
    $self->p->updateSession(
        $req,
        {
            _deviceAuthFailures    => $failures,
            _deviceAuthLastFailure => time(),
        }
    );
    return $failures;
}

sub _resetUserCodeFailures {
    my ( $self, $req ) = @_;

    return unless $req->userData->{_deviceAuthFailures};
    $req->userData->{_deviceAuthFailures}    = 0;
    $req->userData->{_deviceAuthLastFailure} = 0;
    $self->p->updateSession( $req,
        { _deviceAuthFailures => 0, _deviceAuthLastFailure => 0 } );
    return;
}

# CrowdSec integration methods

sub _reportInvalidUserCode {
    my ( $self, $req, $user_code ) = @_;

    my $crowdsec = $self->crowdsec;
    return unless $crowdsec && $crowdsec->can('alert');

    my $ip  = $req->address;
    my $msg = "RFC 8628: Invalid user_code attempt from $ip (code: $user_code)";

    $crowdsec->alert(
        $ip, $msg,
        {
            scenario => 'llng/device-auth-bruteforce',
            reason   => $msg,
        }
    );
    $self->logger->debug("Reported invalid user_code attempt to CrowdSec");
}

1;
