# Desktop Login plugin for LemonLDAP::NG
#
# This plugin provides:
# - /desktop/login : Iframe-optimized login endpoint for LightDM greeter
# - /desktop/callback : OAuth2 callback that returns token to parent window
# - /desktop/token : Server-to-server endpoint to exchange auth code for token
#
# Used for desktop SSO via LightDM webkit greeter, where the user authenticates
# in an iframe and receives an OAuth2 access token for PAM authentication.

package Lemonldap::NG::Portal::Plugins::DesktopLogin;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Digest::SHA qw(sha256_hex);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
  PE_BADCREDENTIALS
);

our $VERSION = '1.0.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'DesktopLogin';

# Access to OIDC module for token generation
has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

# RP name for desktop login tokens
has rpName => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->conf->{desktopLoginRp} || 'desktop-sso' },
);

# Token duration for desktop sessions (default 8 hours)
has tokenDuration => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->conf->{desktopLoginTokenDuration} || 28800 },
);

# Allow insecure CSRF fallback when /dev/urandom is unavailable (default: false)
has allowInsecureCsrf => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->conf->{desktopLoginAllowInsecureCsrf} || 0 },
);

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check that OIDC issuer is enabled
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'DesktopLogin plugin requires OIDC issuer to be enabled');
        return 0;
    }

    # Route for iframe login page (displays login form optimized for greeter)
    $self->addUnauthRoute(
        desktop => { login => 'loginPage' },
        ['GET']
    );

    # Route for login form submission
    $self->addUnauthRoute(
        desktop => { login => 'doLogin' },
        ['POST']
    );

    # Route for authenticated callback (user has session)
    $self->addAuthRoute(
        desktop => { callback => 'authCallback' },
        ['GET']
    );

    # Route for server-to-server token exchange
    $self->addUnauthRoute(
        desktop => { token => 'tokenExchange' },
        ['POST']
    );

    # Route for token refresh (extends desktop session)
    $self->addUnauthRoute(
        desktop => { refresh => 'refreshToken' },
        ['POST']
    );

    $self->logger->info('DesktopLogin plugin initialized');
    return 1;
}

# ROUTE HANDLERS

# GET /desktop/login - Display iframe-optimized login page
sub loginPage {
    my ( $self, $req ) = @_;

    # Check for callback_url parameter (where to send the token)
    my $callback = $req->param('callback_url') || '';
    my $state    = $req->param('state')        || '';

    # Generate CSRF token for form protection
    my $csrf_token = $self->_generateCsrfToken($req);
    $req->pdata->{desktopCsrfToken} = $csrf_token;

    # Store in session for after authentication
    $req->pdata->{desktopCallback} = $callback if $callback;
    $req->pdata->{desktopState}    = $state    if $state;

    # Return the login template optimized for iframe
    return $self->p->sendHtml(
        $req,
        'desktopLogin',
        params => {
            CALLBACK_URL => $callback,
            STATE        => $state,
            PORTAL_URL   => $self->conf->{portal},
            CSRF_TOKEN   => $csrf_token,
        }
    );
}

# POST /desktop/login - Handle login form submission
sub doLogin {
    my ( $self, $req ) = @_;

    my $user       = $req->param('user')       || '';
    my $password   = $req->param('password')   || '';
    my $csrf_token = $req->param('csrf_token') || '';
    my $callback   = $req->param('callback_url') || $req->pdata->{desktopCallback} || '';
    my $state      = $req->param('state') || $req->pdata->{desktopState} || '';

    # Input length validation to prevent DoS and log injection
    # Username: max 256 chars (reasonable for LDAP/AD usernames)
    # Password: max 1024 chars (allows for long passphrases)
    if ( length($user) > 256 ) {
        $self->logger->warn("Desktop login: username too long");
        return $self->_loginError( $req, 'Invalid credentials', $callback, $state );
    }
    if ( length($password) > 1024 ) {
        $self->logger->warn("Desktop login: password too long");
        return $self->_loginError( $req, 'Invalid credentials', $callback, $state );
    }

    # Verify CSRF token to prevent cross-site request forgery
    my $stored_token = $req->pdata->{desktopCsrfToken} || '';
    unless ( $csrf_token && $stored_token && $csrf_token eq $stored_token ) {
        $self->logger->warn("Desktop login CSRF token mismatch");
        return $self->_loginError( $req, 'Invalid request', $callback, $state );
    }

    # Clear CSRF token after use (one-time use)
    delete $req->pdata->{desktopCsrfToken};

    unless ( $user && $password ) {
        return $self->_loginError( $req, 'Missing credentials', $callback, $state );
    }

    # Set credentials for authentication
    $req->user($user);
    $req->data->{password} = $password;

    # Run authentication process
    $req->steps( [
            'controlUrl', @{ $self->p->beforeAuth },
            'getUser',    'authenticate',
            @{ $self->p->betweenAuthAndData },
            'setSessionInfo', $self->p->groupsAndMacros,
            'setLocalGroups', 'store',
            @{ $self->p->afterData },
        ]
    );

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->info("Desktop login failed for user '$user': error $error");

        # Audit log for failed authentication
        $self->p->auditLog(
            $req,
            code    => 'DESKTOP_LOGIN_FAILED',
            user    => $user,
            message => "Desktop login failed for user $user",
            error   => $error,
        );

        return $self->_loginError( $req, 'Authentication failed', $callback, $state );
    }

    $self->logger->info("Desktop login successful for user '$user'");

    # Audit log for successful authentication
    $self->p->auditLog(
        $req,
        code    => 'DESKTOP_LOGIN_SUCCESS',
        user    => $user,
        message => "Desktop login successful for user $user",
    );

    # Generate access token for the user
    return $self->_generateAndReturnToken( $req, $callback, $state );
}

# GET /desktop/callback - Handle callback after successful authentication
sub authCallback {
    my ( $self, $req ) = @_;

    my $callback = $req->param('callback_url') || $req->pdata->{desktopCallback} || '';
    my $state    = $req->param('state') || $req->pdata->{desktopState} || '';

    # Verify state parameter matches stored value to prevent CSRF token generation
    my $stored_state = $req->pdata->{desktopState} || '';
    if ( $state && $stored_state && $state ne $stored_state ) {
        $self->logger->warn("Desktop callback: state parameter mismatch");
        return $self->_loginError( $req, 'Invalid state', $callback, $state );
    }

    # Clear stored state after use (one-time)
    delete $req->pdata->{desktopState};

    return $self->_generateAndReturnToken( $req, $callback, $state );
}

# POST /desktop/token - Server-to-server token exchange (code → token)
sub tokenExchange {
    my ( $self, $req ) = @_;

    my $body = eval { from_json( $req->content ) };
    if ($@) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Invalid JSON' },
            code => 400
        );
    }

    my $grant_type = $body->{grant_type} || '';
    my $code       = $body->{code}       || '';
    my $client_id  = $body->{client_id}  || '';

    unless ( $grant_type eq 'authorization_code' && $code ) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Invalid grant type or missing code' },
            code => 400
        );
    }

    # Lookup the authorization code session
    my $codeSession = $self->p->getApacheSession( $code, kind => 'DESKTOPCODE' );
    unless ($codeSession) {
        $self->logger->warn("Desktop token exchange: Invalid or expired code");
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Invalid or expired authorization code' },
            code => 400
        );
    }

    my $user = $codeSession->data->{_desktopUser};

    # Delete the code (one-time use)
    $codeSession->remove;

    # Generate access token
    my $token = $self->_createAccessToken($user);
    unless ($token) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Token generation failed' },
            code => 500
        );
    }

    $self->logger->info("Desktop token exchange successful for user '$user'");

    return $self->p->sendJSONresponse(
        $req,
        {
            access_token => $token->{access_token},
            token_type   => 'Bearer',
            expires_in   => $token->{expires_in},
            user         => $user,
        }
    );
}

# POST /desktop/refresh - Refresh access token
sub refreshToken {
    my ( $self, $req ) = @_;

    my $body = eval { from_json( $req->content ) };
    if ($@) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Invalid JSON' },
            code => 400
        );
    }

    my $refresh_token = $body->{refresh_token} || '';

    unless ($refresh_token) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Missing refresh_token' },
            code => 400
        );
    }

    # Lookup the refresh token session
    my $refreshSession = $self->p->getApacheSession( $refresh_token, kind => 'DESKTOPREFRESH' );
    unless ($refreshSession) {
        $self->logger->warn("Desktop refresh: Invalid or expired refresh token");
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Invalid or expired refresh token' },
            code => 401
        );
    }

    my $user = $refreshSession->data->{_desktopUser};

    # Generate new access token
    my $token = $self->_createAccessToken($user);
    unless ($token) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Token generation failed' },
            code => 500
        );
    }

    $self->logger->info("Desktop token refresh successful for user '$user'");

    return $self->p->sendJSONresponse(
        $req,
        {
            access_token => $token->{access_token},
            token_type   => 'Bearer',
            expires_in   => $token->{expires_in},
            user         => $user,
        }
    );
}

# INTERNAL HELPERS

# Generate CSRF token for form protection
sub _generateCsrfToken {
    my ( $self, $req ) = @_;

    # Generate random bytes from /dev/urandom (cryptographically secure)
    my $random = '';
    if ( open my $fh, '<', '/dev/urandom' ) {
        read $fh, $random, 32;
        close $fh;
    }
    else {
        unless ( $self->allowInsecureCsrf ) {
            $self->logger->error(
                "Cannot open /dev/urandom for CSRF token generation. "
                . "Set desktopLoginAllowInsecureCsrf to allow insecure fallback."
            );
            return;
        }
        $self->logger->warn(
            "Using insecure CSRF fallback (no /dev/urandom)");
        $random = time() . $$ . rand(1000000);
    }

    # Include request-specific data to bind token to this session
    my $token_data = $random . ( $req->env->{REMOTE_ADDR} || '' ) . time();
    return sha256_hex($token_data);
}

# Generate token and return to callback or as JSON
sub _generateAndReturnToken {
    my ( $self, $req, $callback, $state ) = @_;

    my $user = $req->userData->{ $self->conf->{whatToTrace} };
    unless ($user) {
        return $self->_loginError( $req, 'User not found', $callback, $state );
    }

    # Generate access token
    my $token = $self->_createAccessToken($user);
    unless ($token) {
        return $self->_loginError( $req, 'Token generation failed', $callback, $state );
    }

    # If callback URL provided, redirect with token in fragment (implicit flow)
    if ($callback) {
        # For security, validate callback URL against allowed patterns
        unless ( $self->_validateCallbackUrl($callback) ) {
            $self->logger->warn("Desktop login: Invalid callback URL: $callback");
            return $self->_loginError( $req, 'Invalid callback URL', '', $state );
        }

        # Build redirect URL with token in fragment (not query params for security)
        my $sep = $callback =~ /#/ ? '&' : '#';
        my $redirect_url = $callback
          . $sep
          . "access_token=$token->{access_token}"
          . "&token_type=Bearer"
          . "&expires_in=$token->{expires_in}"
          . "&user=$user";
        $redirect_url .= "&state=$state" if $state;

        # Return HTML page that sends message to parent window
        # Build JSON message with proper encoding to prevent XSS
        my $allowed_origin = $self->conf->{portal} || '';
        my $message_data = {
            access_token   => $token->{access_token},
            expires_in     => $token->{expires_in} + 0,  # Force numeric
            user           => $user,
            state          => $state,
            error          => undef,
            redirect_url   => $redirect_url,
            allowed_origin => $allowed_origin,
        };
        my $message_json = to_json($message_data, { allow_nonref => 1 });

        return $self->p->sendHtml(
            $req,
            'desktopCallback',
            params => {
                MESSAGE_JSON => $message_json,
                ACCESS_TOKEN => $token->{access_token},  # Keep for template conditionals
                USER         => $user,
            }
        );
    }

    # No callback, return JSON directly
    return $self->p->sendJSONresponse(
        $req,
        {
            access_token => $token->{access_token},
            token_type   => 'Bearer',
            expires_in   => $token->{expires_in},
            user         => $user,
        }
    );
}

# Create access token for desktop SSO
sub _createAccessToken {
    my ( $self, $user ) = @_;

    my $now      = time();
    my $duration = $self->tokenDuration;

    # Create access token session
    my $tokenInfo = {
        _type            => 'desktoptoken',
        _utime           => $now,
        _desktopUser     => $user,
        _desktopCreatedAt => $now,
        _desktopExpiresAt => $now + $duration,
        scope            => 'desktop pam',
        grant_type       => 'desktop_sso',
        client_id        => $self->rpName,
        sub              => $user,
    };

    my $tokenSession = $self->p->getApacheSession(
        undef,
        info => $tokenInfo,
        kind => 'DESKTOPTOKEN'
    );

    unless ( $tokenSession && $tokenSession->id ) {
        $self->logger->error('Failed to create desktop access token session');
        return;
    }

    $self->logger->info(
        "Desktop access token generated for user $user (TTL: ${duration}s)");

    return {
        access_token => $tokenSession->id,
        expires_in   => $duration,
    };
}

# Validate callback URL against allowed patterns
sub _validateCallbackUrl {
    my ( $self, $url ) = @_;

    # Must start with http:// or https://
    return 0 unless $url =~ m{^https?://};

    # Reject URLs with credentials (user:pass@ or user@ before host)
    # This prevents bypass attacks like http://localhost:fake@attacker.com/
    # where "localhost:fake" becomes credentials and attacker.com is the real host
    # Match @ that appears before the first / in the authority component,
    # accounting for optional port numbers (e.g., host:8080@attacker.com)
    return 0 if $url =~ m{^https?://[^/?#]*@};

    # Get allowed callback patterns from config
    my $allowed = $self->conf->{desktopLoginAllowedCallbacks} || [];

    # If no patterns configured, allow localhost only (for LightDM greeter)
    unless ( @$allowed ) {
        $allowed = [
            qr{^https?://localhost[:/]},
            qr{^https?://127\.0\.0\.1[:/]},
            qr{^https?://\[::1\][:/]},
        ];
    }

    for my $pattern (@$allowed) {
        if ( ref($pattern) eq 'Regexp' ) {
            return 1 if $url =~ $pattern;
        }
        else {
            return 1 if $url eq $pattern;
        }
    }

    return 0;
}

# Return error response for login
sub _loginError {
    my ( $self, $req, $message, $callback, $state ) = @_;

    # If callback provided, validate it before redirecting (prevent open redirect)
    if ($callback && $self->_validateCallbackUrl($callback)) {
        my $sep = $callback =~ /#/ ? '&' : '#';
        my $redirect_url = $callback . $sep . "error=" . uri_escape($message);
        $redirect_url .= "&state=$state" if $state;

        # Build JSON message with proper encoding to prevent XSS
        my $allowed_origin = $self->conf->{portal} || '';
        my $message_data = {
            access_token   => undef,
            expires_in     => undef,
            user           => undef,
            state          => $state,
            error          => $message,
            redirect_url   => $redirect_url,
            allowed_origin => $allowed_origin,
        };
        my $message_json = to_json($message_data, { allow_nonref => 1 });

        return $self->p->sendHtml(
            $req,
            'desktopCallback',
            params => {
                MESSAGE_JSON => $message_json,
                ERROR        => $message,  # Keep for template conditionals
            }
        );
    }

    # No callback, return JSON error
    return $self->p->sendJSONresponse(
        $req,
        { error => $message },
        code => 401
    );
}

# URI escape helper
sub uri_escape {
    my ($str) = @_;
    $str =~ s/([^A-Za-z0-9\-_.~])/sprintf("%%%02X", ord($1))/ge;
    return $str;
}

1;

__END__

=head1 NAME

Lemonldap::NG::Portal::Plugins::DesktopLogin - Desktop SSO via LightDM greeter

=head1 SYNOPSIS

Enable this plugin in lemonldap-ng.ini:

    [portal]
    plugins = DesktopLogin

Configure in Manager:

    desktopLoginRp = desktop-sso
    desktopLoginTokenDuration = 28800
    desktopLoginAllowedCallbacks = ["http://localhost:8080/callback"]

=head1 DESCRIPTION

This plugin provides endpoints for desktop SSO integration with LightDM
webkit greeter. Users authenticate through an iframe and receive an
OAuth2 access token that can be used with the PAM module.

=head1 ENDPOINTS

=over 4

=item GET /desktop/login

Display login form optimized for iframe embedding in LightDM greeter.

=item POST /desktop/login

Process login credentials and return access token.

=item GET /desktop/callback

Callback endpoint for authenticated users.

=item POST /desktop/token

Server-to-server token exchange (authorization code → access token).

=item POST /desktop/refresh

Refresh an existing access token.

=back

=head1 CONFIGURATION

=over 4

=item desktopLoginRp

Name of the OIDC Relying Party for desktop tokens (default: 'desktop-sso').

=item desktopLoginTokenDuration

Access token duration in seconds (default: 28800 = 8 hours).

=item desktopLoginAllowedCallbacks

Array of allowed callback URL patterns for token delivery.

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::PamAccess>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2025 Linagora

This is free software, licensed under AGPL-3.0.

=cut
