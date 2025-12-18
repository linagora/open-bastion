package Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization;

# OAuth 2.0 Device Authorization Grant - RFC 8628
# https://datatracker.ietf.org/doc/html/rfc8628
#
# With PKCE extension (RFC 7636) for additional security

use strict;
use Mouse;
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_ERROR
  PE_SENDRESPONSE
);
use Crypt::URandom;
use Digest::SHA qw(sha256_hex);

our $VERSION = '2.23.0';

extends qw(
  Lemonldap::NG::Portal::Main::Plugin
);

# Hooks declaration - following OIDCNativeSso pattern
use constant hook => {

    # Hook called by OpenIDConnect.pm token method for device_code grant
    oidcGotDeviceCodeGrant => 'deviceCodeGrantHook',
};

# Character set for user_code (RFC 8628 section 6.1)
# Excludes vowels to avoid offensive words, excludes 0/O, 1/I/L for readability
use constant USER_CODE_CHARS => 'BCDFGHJKLMNPQRSTVWXZ23456789';

# Session kind for device authorization storage
use constant sessionKind => 'DEVA';

# Lazy access to OIDC issuer - following OIDCNativeSso pattern
has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

has rule => (
    is      => 'rw',
    default => sub {
        sub { 1 }
    }
);

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check if OIDC issuer is enabled
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            "OIDC issuer not enabled, Device Authorization plugin disabled");
        return 0;
    }

    # Parse activation rule
    if ( my $rule = $self->conf->{deviceAuthorizationRule} ) {
        $self->rule( $self->p->buildRule( $rule, 'deviceAuthorizationRule' ) );
        return 0 unless $self->rule;
    }

    # Device Authorization endpoint (RFC 8628 section 3.1)
    # POST /oauth2/device - for devices to request authorization
    my $oidc_path = $self->conf->{issuerDBOpenIDConnectPath} || '^/oauth2/';
    $oidc_path =~ s/^.*?(\w+).*?$/$1/;    # Extract path name (e.g., "oauth2")
    $self->addUnauthRoute(
        $oidc_path => { 'device' => 'deviceAuthorizationEndpoint' },
        ['POST']
    );

    # Device verification endpoint (for users) - /device
    $self->addAuthRouteWithRedirect(
        device => 'displayVerification',
        ['GET']
    );
    $self->addAuthRoute(
        device => 'submitVerification',
        ['POST']
    );

    $self->logger->debug("Device Authorization Grant (RFC 8628) enabled");
    return 1;
}

# Device Authorization endpoint (RFC 8628 section 3.1)
# Called directly via route POST /oauth2/device
sub deviceAuthorizationEndpoint {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device Authorization endpoint called");

    my $client_id = $req->param('client_id');

    unless ($client_id) {
        $self->logger->error(
            "Missing client_id in device authorization request");
        return $self->_sendDeviceError( $req, 'invalid_request',
            'client_id is required' );
    }

    # Get RP from client_id
    my $rp = $self->oidc->getRP($client_id);

    unless ($rp) {
        $self->logger->warn("Unknown client_id: $client_id");
        return $self->_sendDeviceError( $req, 'invalid_client' );
    }

    # Check if this RP allows device authorization grant
    unless ( $self->oidc->rpOptions->{$rp}
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorizationGrant} )
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
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRequirePKCE}
        and !$code_challenge )
    {
        $self->logger->warn(
            "PKCE required but no code_challenge provided for RP $rp");
        return $self->_sendDeviceError( $req, 'invalid_request',
            'code_challenge is required' );
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

    # Generate user_code (shown to user)
    my $user_code = $self->_generateUserCode();

    # Store device authorization request
    my $expiration =
      $self->conf->{oidcServiceDeviceAuthorizationExpiration} || 600;
    my $interval =
      $self->conf->{oidcServiceDeviceAuthorizationPollingInterval} || 5;

    # Create session with device_code hash as ID (for polling lookup)
    my $device_code_hash = sha256_hex($device_code);

    my $session_data = {
        _type          => 'deviceauth',
        _utime         => time() - $self->conf->{timeout} + $expiration,
        device_code    => $device_code,
        user_code      => $user_code,
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

    # Also create a session indexed by user_code for verification lookup
    my $user_code_hash    = sha256_hex($user_code);
    my $user_code_session = $self->p->getApacheSession(
        $user_code_hash,
        kind => sessionKind,
        info => {
            _type            => 'deviceauth_usercode',
            _utime           => time() - $self->conf->{timeout} + $expiration,
            device_code_hash => $device_code_hash,
            user_code        => $user_code,
            expires_at       => time() + $expiration,
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

    $self->logger->debug(
        "Device authorization created: user_code=$user_code, client=$client_id"
    );
    $self->userLogger->info(
        "Device authorization initiated for client $client_id");

    return $self->p->sendJSONresponse( $req, $response );
}

# HOOK: Token endpoint handler for device_code grant
# Called by OpenIDConnect.pm via processHook('oidcGotDeviceCodeGrant')
sub deviceCodeGrantHook {
    my ( $self, $req, $rp ) = @_;

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
        ->{oidcRPMetaDataOptionsAllowDeviceAuthorizationGrant} )
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

        # RFC 8628 section 3.5 - authorization_pending
        return $self->_sendTokenError( $req, 'authorization_pending' );
    }
    elsif ( $status eq 'denied' ) {

        # RFC 8628 section 3.5 - access_denied
        $self->_deleteDeviceAuth($device_auth);
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

    # Check rule
    unless ( $self->rule->( $req, $req->userData ) ) {
        $self->userLogger->warn(
            "User not allowed to verify device authorizations");
        return $self->p->do( $req, [ sub { PE_ERROR } ] );
    }

    # Pre-fill user_code if provided in URL
    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Clean up

    # Set template parameters
    $req->data->{activeTimer} = 0;
    $req->{user_code} = $user_code;

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $user_code,
            MSG       => '',
        }
    );
}

# DEVICE VERIFICATION SUBMIT
sub submitVerification {
    my ( $self, $req ) = @_;

    $self->logger->debug("Device verification submitted");

    # Check rule
    unless ( $self->rule->( $req, $req->userData ) ) {
        return $self->p->do( $req, [ sub { PE_ERROR } ] );
    }

    my $user_code = $req->param('user_code') || '';
    $user_code =~ s/[^A-Z0-9]//gi;    # Remove formatting (dashes, spaces)
    $user_code = uc($user_code);

    unless ( $user_code && length($user_code) >= 6 ) {
        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Find the device authorization by user_code
    my $device_auth = $self->_findByUserCode($user_code);
    unless ($device_auth) {
        $self->logger->info("Invalid or expired user_code: $user_code");
        return $self->_showVerificationError( $req, 'invalidUserCode' );
    }

    # Check if already processed
    if ( $device_auth->{status} ne 'pending' ) {
        $self->logger->info("User code already processed: $user_code");
        return $self->_showVerificationError( $req, 'codeAlreadyUsed' );
    }

    # Check action (approve or deny)
    my $action = $req->param('action') || 'approve';

    if ( $action eq 'deny' ) {

        # User denied the authorization
        $self->_updateDeviceAuthStatus( $device_auth, 'denied' );
        $self->userLogger->notice( "Device authorization denied by user "
              . $req->userData->{ $self->conf->{whatToTrace} }
              . " for client "
              . $device_auth->{client_id} );

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
    $self->_updateDeviceAuthStatus(
        $device_auth,
        'approved',
        {
            user_session_id => $user_session_id,
            user            => $req->userData->{ $self->conf->{whatToTrace} },
            approved_at     => time(),
        }
    );

    $self->userLogger->notice( "Device authorization approved by user "
          . $req->userData->{ $self->conf->{whatToTrace} }
          . " for client "
          . $device_auth->{client_id} );

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            DEVICE_APPROVED => 1,
            CLIENT_ID       => $device_auth->{client_id},
            SCOPE           => $device_auth->{scope},
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

sub _generateUserCode {
    my ($self) = @_;
    my $length =
      $self->conf->{oidcServiceDeviceAuthorizationUserCodeLength} || 8;
    my $chars     = USER_CODE_CHARS;
    my $chars_len = length($chars);
    my $code      = '';

    # Use cryptographically secure random bytes to generate the user code
    my $bytes = Crypt::URandom::urandom($length);
    foreach my $b ( split //, $bytes ) {
        my $idx = ord($b) % $chars_len;
        $code .= substr( $chars, $idx, 1 );
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

sub _findByUserCode {
    my ( $self, $user_code ) = @_;

    # Look up the user_code session to get the device_code_hash
    my $user_code_hash = sha256_hex($user_code);

    my $user_code_session =
      $self->p->getApacheSession( $user_code_hash, kind => sessionKind, );

    unless ( $user_code_session && $user_code_session->data ) {
        $self->logger->debug("User code session not found: $user_code");
        return undef;
    }

    # Check expiration
    if ( time() > ( $user_code_session->data->{expires_at} || 0 ) ) {
        $self->logger->debug("User code expired: $user_code");
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
      $self->p->getApacheSession( $device_code_hash, kind => sessionKind, );

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

sub _updateDeviceAuthStatus {
    my ( $self, $device_auth, $status, $extra ) = @_;

    my $session = $device_auth->{_session};
    return unless $session;

    # Update status
    my $info = { status => $status };

    # Add extra fields
    if ($extra) {
        for my $key ( keys %$extra ) {
            $info->{$key} = $extra->{$key};
        }
    }

    # Update session
    $self->p->getApacheSession(
        $session->id,
        kind => sessionKind,
        info => $info,
    );
}

sub _deleteDeviceAuth {
    my ( $self, $device_auth ) = @_;

    # Delete the device_code session
    if ( my $session = $device_auth->{_session} ) {
        $session->remove;
    }

    # Also delete the user_code lookup session
    if ( my $user_code = $device_auth->{user_code} ) {
        my $user_code_hash = sha256_hex($user_code);
        my $user_code_session =
          $self->p->getApacheSession( $user_code_hash, kind => sessionKind, );
        $user_code_session->remove if $user_code_session;
    }
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

    # Get the user's session
    my $user_session_id = $device_auth->{user_session_id};
    my $session         = $self->p->getApacheSession($user_session_id);

    unless ($session) {
        $self->logger->error("User session not found for device authorization");
        return $self->_sendTokenError( $req, 'server_error' );
    }

    # Generate access token
    my $access_token = $self->oidc->newAccessToken(
        $req, $rp, $scope,
        $session->data,
        {
            scope           => $scope,
            rp              => $rp,
            user_session_id => $user_session_id,
            grant_type      => "device_code",
        }
    );

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
          $self->oidc->_generateIDToken( $req, $rp, $scope, $session->data, 0 );
        if ($id_token) {
            $response->{id_token} = $id_token;
        }
    }

    # Generate refresh token if allowed
    if ( $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsRefreshToken} ) {
        my $refresh_token = $self->oidc->newRefreshToken(
            $rp,
            {
                scope           => $scope,
                client_id       => $device_auth->{client_id},
                _session_uid    => $session->data->{_user},
                auth_time       => $session->data->{_lastAuthnUTime},
                grant_type      => "device_code",
                user_session_id => $user_session_id,
                %{ $session->data },
            }
        );

        if ($refresh_token) {
            $response->{refresh_token} = $refresh_token->id;
        }
    }

    # Clean up the device authorization
    $self->_deleteDeviceAuth($device_auth);

    $self->logger->debug("Device code grant completed for RP $rp");

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

    return $self->p->sendHtml(
        $req, 'device',
        params => {
            USER_CODE => $req->param('user_code') || '',
            MSG       => $msg,
            ERROR     => 1,
        }
    );
}

1;
