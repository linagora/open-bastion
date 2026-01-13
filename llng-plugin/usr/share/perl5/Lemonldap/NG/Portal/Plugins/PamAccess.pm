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
use JSON qw(from_json to_json);
use Lemonldap::NG::Portal::Main::Constants qw(
  PE_OK
  PE_ERROR
  PE_SENDRESPONSE
);

our $VERSION = '2.22.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'PamAccess';

# MenuTab configuration - rule for displaying the tab
has rule => (
    is      => 'ro',
    lazy    => 1,
    builder => sub { $_[0]->conf->{portalDisplayPamAccess} // 0 },
);
with 'Lemonldap::NG::Portal::MenuTab';

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

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check that OIDC issuer is enabled
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'PamAccess plugin requires OIDC issuer to be enabled');
        return 0;
    }

    # Routes for authenticated users (token generation interface)
    $self->addAuthRoute( pam => 'pamInterface', ['GET'] )
      ->addAuthRoute( pam => 'generateToken', ['POST'] );

    # Route for server-to-server authorization (Bearer token auth)
    $self->addUnauthRoute(
        pam => { authorize => 'authorize' },
        ['POST']
    );

    # Route for server heartbeat (refresh token based)
    $self->addUnauthRoute(
        pam => { heartbeat => 'heartbeat' },
        ['POST']
    );

    # Route for one-time token verification (server-to-server)
    $self->addUnauthRoute(
        pam => { verify => 'verifyToken' },
        ['POST']
    );

    # Route for NSS user info lookup (server-to-server)
    $self->addUnauthRoute(
        pam => { userinfo => 'userinfo' },
        ['POST']
    );

    # Route for bastion token generation (bastion -> LLNG)
    # Returns a JWT that proves the bastion has a valid session
    $self->addUnauthRoute(
        pam => { 'bastion-token' => 'bastionToken' },
        ['POST']
    );

    return 1;
}

# MENUTAB - Display method for the portal menu tab

sub display {
    my ( $self, $req ) = @_;

    return {
        logo => 'key',
        name => 'PamAccess',
        id   => 'pamaccess',
        html => $self->loadTemplate(
            $req,
            'pamaccess',
            params => {
                TOKEN => '',
                LOGIN => $req->userData->{ $self->conf->{whatToTrace} } || '',
                EXPIRES_IN       => '',
                SHOW_TOKEN       => 0,
                DEFAULT_DURATION => $self->conf->{pamAccessTokenDuration}
                  || 600,
                MAX_DURATION => $self->conf->{pamAccessMaxDuration} || 3600,
                js => "$self->{p}->{staticPrefix}/common/js/pamaccess.js",
            }
        ),
    };
}

# ROUTE HANDLERS

# GET /pam - Display the token generation interface
sub pamInterface {
    my ( $self, $req ) = @_;

    return $self->p->do( $req, [ sub { PE_OK } ] );
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

    # 1. Validate Bearer token from Authorization header
    my $access_token = $self->oidc->getEndPointAccessToken($req);
    unless ($access_token) {
        $self->logger->warn('PAM authorize: No Bearer token provided');
        return $self->_unauthorizedResponse( $req, 'Bearer token required' );
    }

    my $tokenSession = $self->oidc->getAccessToken($access_token);
    unless ($tokenSession) {
        $self->logger->warn('PAM authorize: Invalid or expired Bearer token');
        return $self->_unauthorizedResponse( $req, 'Invalid or expired token' );
    }

    # 2. Verify token was obtained via Device Authorization Grant
    my $grant_type = $tokenSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
                "PAM authorize: Token not from Device Authorization Grant "
              . "(grant_type: '$grant_type'). Server must enroll via /oauth2/device"
        );
        return $self->_forbiddenResponse( $req,
'Server not enrolled. Use Device Authorization Grant to register this server.'
        );
    }

    # 3. Verify token has correct scope (pam:server or pam)
    my $scope = $tokenSession->data->{scope} || '';
    unless ( $scope =~ /\bpam(?::server)?\b/ ) {
        $self->logger->warn("PAM authorize: Invalid token scope '$scope'");
        return $self->_forbiddenResponse( $req, 'Invalid token scope' );
    }

    # Log server identity from token
    my $server_id = $tokenSession->data->{client_id} || 'unknown';
    $self->logger->info(
        "PAM authorize request from enrolled server: $server_id");

    # 4. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM authorize: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user         = $body->{user};
    my $host         = $body->{host}         || '';
    my $service      = $body->{service}      || 'ssh';
    my $server_group = $body->{server_group} || 'default';

    unless ($user) {
        return $self->_badRequest( $req, 'Missing user parameter' );
    }

    $self->logger->debug(
"PAM authorize: checking user '$user' for host '$host', service '$service', server_group '$server_group'"
    );

    # 4. Lookup user (without active session)
    $req->user($user);
    $req->data->{_pamAuthorize} = 1;
    $req->steps( [
            'getUser',                 'setSessionInfo',
            $self->p->groupsAndMacros, 'setLocalGroups'
        ]
    );

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->info(
            "PAM authorize: User '$user' not found (error: $error)");

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

        return $self->p->sendJSONresponse(
            $req,
            {
                authorized => JSON::false,
                user       => $user,
                reason     => 'User not found',
            },
            code => 200
        );
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
    }
    else {
        $response->{reason} = 'Access denied by rule';
    }

    return $self->p->sendJSONresponse( $req, $response, code => 200 );
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

    # For other services, fall back to legacy rules
    else {
        $result->{authorized} =
          $self->_evaluateRule( $req, $server_group, 'legacy' );
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

        # Fallback to legacy rules if SSH rules not defined
        if ( !%$rules ) {
            $rules = $self->conf->{pamAccessServerGroups} || {};
        }
    }
    elsif ( $rule_type eq 'sudo' ) {
        $rules = $self->conf->{pamAccessSudoRules} || {};

        # No fallback for sudo - if not defined, sudo is denied
    }
    else {
        # Legacy mode
        $rules = $self->conf->{pamAccessServerGroups} || {};
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

    return $self->p->sendJSONresponse(
        $req,
        { error => $message },
        code    => 401,
        headers => [ 'WWW-Authenticate' => 'Bearer realm="pam"' ],
    );
}

sub _forbiddenResponse {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Forbidden';

    return $self->p->sendJSONresponse( $req, { error => $message },
        code => 403 );
}

sub _badRequest {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Bad Request';

    return $self->p->sendJSONresponse( $req, { error => $message },
        code => 400 );
}

# POST /pam/verify - Verify and consume a one-time PAM token
sub verifyToken {
    my ( $self, $req ) = @_;

    # 1. Validate server Bearer token from Authorization header
    my $server_token = $self->oidc->getEndPointAccessToken($req);
    unless ($server_token) {
        $self->logger->warn('PAM verify: No server Bearer token provided');
        return $self->_unauthorizedResponse( $req,
            'Server Bearer token required' );
    }

    my $serverSession = $self->oidc->getAccessToken($server_token);
    unless ($serverSession) {
        $self->logger->warn('PAM verify: Invalid or expired server token');
        return $self->_unauthorizedResponse( $req,
            'Invalid or expired server token' );
    }

    # Verify server token was obtained via Device Authorization Grant
    my $grant_type = $serverSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
                "PAM verify: Server token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')" );
        return $self->_forbiddenResponse( $req,
            'Server not enrolled. Use Device Authorization Grant.' );
    }

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

        return $self->p->sendJSONresponse(
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

        $tokenSession->remove;
        return $self->p->sendJSONresponse(
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

        $tokenSession->remove;
        return $self->p->sendJSONresponse(
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

    # 7. CRITICAL: Remove the session (one-time use!)
    $tokenSession->remove;

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
    return $self->p->sendJSONresponse(
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

    # 4. Verify token was obtained via Device Authorization Grant
    my $grant_type = $rtSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
                "PAM heartbeat: Token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')" );
        return $self->_forbiddenResponse( $req,
            'Token not from Device Authorization Grant' );
    }

    # 5. Update metadata in refresh_token session
    my $now      = time();
    my $hostname = $body->{hostname} || 'unknown';
    my $updates  = {
        _pamServer      => 1,
        _pamHostname    => $hostname,
        _pamServerGroup => $body->{server_group} || 'default',
        _pamVersion     => $body->{version}      || '',
        _pamLastSeen    => $now,
        _pamStatus      => 'active',
    };

    # Store stats as JSON string if provided
    if ( $body->{stats} ) {
        $updates->{_pamStats} = to_json( $body->{stats} );
    }

    # First heartbeat = enrollment timestamp
    unless ( $rtSession->data->{_pamEnrolledAt} ) {
        $updates->{_pamEnrolledAt} = $now;
    }

    # Update the refresh_token session
    $self->oidc->updateRefreshToken( $rtSession->id, $updates );

    $self->logger->debug("PAM heartbeat from $hostname");

    # 6. Respond with next heartbeat interval
    my $interval = $self->conf->{pamAccessHeartbeatInterval} || 300;
    return $self->p->sendJSONresponse(
        $req,
        {
            status         => 'ok',
            next_heartbeat => $interval,
            server_time    => $now,
        }
    );
}

# POST /pam/userinfo - Get user info for NSS module
sub userinfo {
    my ( $self, $req ) = @_;

    # 1. Validate server Bearer token from Authorization header
    my $server_token = $self->oidc->getEndPointAccessToken($req);
    unless ($server_token) {
        $self->logger->warn('PAM userinfo: No server Bearer token provided');
        return $self->_unauthorizedResponse( $req,
            'Server Bearer token required' );
    }

    my $serverSession = $self->oidc->getAccessToken($server_token);
    unless ($serverSession) {
        $self->logger->warn('PAM userinfo: Invalid or expired server token');
        return $self->_unauthorizedResponse( $req,
            'Invalid or expired server token' );
    }

    # Verify server token was obtained via Device Authorization Grant
    my $grant_type = $serverSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
            "PAM userinfo: Server token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')" );
        return $self->_forbiddenResponse( $req,
            'Server not enrolled. Use Device Authorization Grant.' );
    }

    # 2. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM userinfo: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user = $body->{user};
    unless ($user) {
        return $self->_badRequest( $req, 'user parameter required' );
    }

    # 3. Lookup user in backend
    $req->user($user);
    $req->data->{_pamUserinfo} = 1;
    $req->steps( [
            'getUser',                 'setSessionInfo',
            $self->p->groupsAndMacros, 'setLocalGroups'
        ]
    );

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->debug(
            "PAM userinfo: User '$user' not found (error: $error)");
        return $self->p->sendJSONresponse(
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

    $self->logger->debug("PAM userinfo: Found user '$user'");

    return $self->p->sendJSONresponse(
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

# POST /pam/bastion-token - Generate JWT for bastion-to-backend authentication
#
# This endpoint allows a bastion server to obtain a signed JWT that proves:
# 1. The bastion has a valid server token (enrolled via Device Authorization Grant)
# 2. The bastion is in a "bastion" server group
# 3. The user has been authenticated on this bastion
#
# The backend server can verify this JWT to ensure connections only come from
# authorized bastions, not direct connections bypassing the bastion.
#
# Request:
# {
#   "user": "dwho",                      # User being proxied
#   "target_host": "backend.example.com", # Target backend server
#   "target_group": "production"          # Target server group (optional)
# }
#
# Response:
# {
#   "bastion_jwt": "eyJhbGciOiJSUzI1NiI...",  # Signed JWT
#   "expires_in": 300                          # JWT validity in seconds
# }
sub bastionToken {
    my ( $self, $req ) = @_;

    # 1. Validate Bearer token from Authorization header
    my $access_token = $self->oidc->getEndPointAccessToken($req);
    unless ($access_token) {
        $self->logger->warn('PAM bastion-token: No Bearer token provided');
        return $self->_unauthorizedResponse( $req, 'Bearer token required' );
    }

    my $tokenSession = $self->oidc->getAccessToken($access_token);
    unless ($tokenSession) {
        $self->logger->warn('PAM bastion-token: Invalid or expired Bearer token');
        return $self->_unauthorizedResponse( $req, 'Invalid or expired token' );
    }

    # 2. Verify token was obtained via Device Authorization Grant
    my $grant_type = $tokenSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
                "PAM bastion-token: Token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')" );
        return $self->_forbiddenResponse( $req,
            'Server not enrolled. Use Device Authorization Grant.' );
    }

    # 3. Verify token has correct scope
    my $scope = $tokenSession->data->{scope} || '';
    unless ( $scope =~ /\bpam(?::server)?\b/ ) {
        $self->logger->warn("PAM bastion-token: Invalid token scope '$scope'");
        return $self->_forbiddenResponse( $req, 'Invalid token scope' );
    }

    # 4. Verify server is in a bastion group
    my $server_group = $tokenSession->data->{server_group} || 'default';
    my $bastion_groups = $self->conf->{pamAccessBastionGroups} || 'bastion';
    my @allowed_groups = split /[,;\s]+/, $bastion_groups;

    my $is_bastion = 0;
    for my $allowed (@allowed_groups) {
        if ( $server_group eq $allowed ) {
            $is_bastion = 1;
            last;
        }
    }

    unless ($is_bastion) {
        $self->logger->warn(
            "PAM bastion-token: Server group '$server_group' is not a bastion group"
        );
        return $self->_forbiddenResponse( $req,
            "Server is not an authorized bastion (group: $server_group)" );
    }

    # 5. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM bastion-token: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user         = $body->{user};
    my $target_host  = $body->{target_host}  || '';
    my $target_group = $body->{target_group} || 'default';

    unless ($user) {
        return $self->_badRequest( $req, 'Missing user parameter' );
    }

    # 6. Get bastion identity
    my $bastion_id = $tokenSession->data->{client_id} || 'unknown';

    $self->logger->info(
        "PAM bastion-token: Generating JWT for bastion '$bastion_id' "
          . "proxying user '$user' to '$target_host'" );

    # 7. Generate JWT
    my $jwt_ttl = $self->conf->{pamAccessBastionJwtTtl} || 300;  # 5 minutes default
    my $now     = time();
    my $exp     = $now + $jwt_ttl;

    # Generate unique JWT ID (must be cryptographically secure)
    my $jti = $self->_generateUUID();
    unless ($jti) {
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to generate secure token ID' },
            code => 500
        );
    }

    # Build JWT claims
    my $claims = {
        iss          => $self->conf->{portal},                 # Issuer: LLNG portal URL
        sub          => $user,                                  # Subject: user being proxied
        aud          => 'pam:bastion-backend',                  # Audience
        exp          => $exp,                                   # Expiration
        iat          => $now,                                   # Issued at
        jti          => $jti,                                   # Unique ID
        bastion_id   => $bastion_id,                            # Bastion server ID
        bastion_group => $server_group,                         # Bastion server group
        target_host  => $target_host,                           # Target backend
        target_group => $target_group,                          # Target server group
        bastion_ip   => $req->address,                          # Bastion IP address
    };

    # Lookup user groups if available
    $req->user($user);
    $req->data->{_pamBastionToken} = 1;
    $req->steps( [
            'getUser',                 'setSessionInfo',
            $self->p->groupsAndMacros, 'setLocalGroups'
        ]
    );

    my $error = $self->p->process($req);
    if ( $error == PE_OK ) {
        my $groups = $req->sessionInfo->{groups} || '';
        my @groupList = split /[,;\s]+/, $groups;
        $claims->{user_groups} = \@groupList if @groupList;
    }
    else {
        $self->logger->warn(
            "PAM bastion-token: Failed to retrieve groups for user $user (error=$error), JWT will have no user_groups claim"
        );
    }

    # 8. Sign JWT using OIDC module's key
    my $jwt = $self->_signBastionJwt($claims);
    unless ($jwt) {
        $self->logger->error("PAM bastion-token: Failed to sign JWT");
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to generate token' },
            code => 500
        );
    }

    # 9. Audit log
    $self->p->auditLog(
        $req,
        code         => 'PAM_BASTION_TOKEN_GENERATED',
        user         => $user,
        message      => "Bastion JWT generated for user '$user' to '$target_host'",
        bastion_id   => $bastion_id,
        target_host  => $target_host,
        target_group => $target_group,
        ttl          => $jwt_ttl,
    );

    # 10. Return JWT
    return $self->p->sendJSONresponse(
        $req,
        {
            bastion_jwt => $jwt,
            expires_in  => $jwt_ttl,
        }
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
                'PAM bastion-token: Cannot open /dev/urandom for UUID generation'
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
            'PAM bastion-token: No cryptographically secure random source available '
              . '(install Crypt::URandom or ensure /dev/urandom is readable)'
        );
        return undef;
    }

    # Set version 4 (random)
    $bytes[6] = ( $bytes[6] & 0x0f ) | 0x40;
    # Set variant (RFC 4122)
    $bytes[8] = ( $bytes[8] & 0x3f ) | 0x80;

    return sprintf(
        '%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x',
        @bytes
    );
}

# Sign a JWT for bastion authentication using RS256
# Uses the OIDC module's signing key
sub _signBastionJwt {
    my ( $self, $claims ) = @_;

    # Try to use OIDC module's JWT signing capability
    my $oidc = $self->oidc;
    return undef unless $oidc;

    # Get the signing key from OIDC configuration
    my $key;
    my $kid;

    # Check if we have OIDC service private signing key
    # Note: We intentionally do NOT fallback to encryption key - signing keys
    # and encryption keys serve different cryptographic purposes and should
    # not be used interchangeably (per security best practices)
    if ( $self->conf->{oidcServicePrivateKeySig} ) {
        $key = $self->conf->{oidcServicePrivateKeySig};
        $kid = $self->conf->{oidcServiceKeyIdSig} || 'llng-sig';
    }
    else {
        $self->logger->error(
            'PAM bastion-token: No OIDC private signing key configured '
              . '(oidcServicePrivateKeySig required for JWT signing)'
        );
        return undef;
    }

    # Build JWT header
    my $header = {
        alg => 'RS256',
        typ => 'JWT',
        kid => $kid,
    };

    # Encode header and payload
    require MIME::Base64;
    require JSON;

    my $header_b64 = MIME::Base64::encode_base64url(
        JSON::encode_json($header), ''
    );
    my $payload_b64 = MIME::Base64::encode_base64url(
        JSON::encode_json($claims), ''
    );

    my $signing_input = "$header_b64.$payload_b64";

    # Sign with RSA-SHA256
    require Crypt::OpenSSL::RSA;

    my $rsa;
    eval {
        $rsa = Crypt::OpenSSL::RSA->new_private_key($key);
        $rsa->use_sha256_hash();
    };
    if ($@) {
        $self->logger->error("PAM bastion-token: RSA key error: $@");
        return undef;
    }

    my $signature;
    eval {
        $signature = $rsa->sign($signing_input);
    };
    if ($@) {
        $self->logger->error("PAM bastion-token: Signing error: $@");
        return undef;
    }

    my $sig_b64 = MIME::Base64::encode_base64url( $signature, '' );

    return "$signing_input.$sig_b64";
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

=item pamAccessServerGroups

Hash of server group names to authorization rules. Each PAM server can
specify its group via the C<server_group> parameter in the authorize request.
If a server's group is not found, the 'default' group rule is used.

Example:
  {
    "production" => '$hGroup->{ops}',
    "staging"    => '$hGroup->{ops} or $hGroup->{dev}',
    "dev"        => '$hGroup->{dev} or $uid eq "admin"',
    "default"    => '1'
  }

=item pamAccessRp

OIDC Relying Party name for tokens (default: 'pam-access')

=item pamAccessHeartbeatInterval

Expected interval between server heartbeats in seconds (default: 300)

=item pamAccessInactiveThreshold

Time in seconds after which a server is considered inactive if no heartbeat
received (default: 900)

=item pamAccessHeartbeatRequired

If enabled, servers must have a recent heartbeat to use /pam/authorize.
This ensures that the PAM module is still active on the server. (default: 0)

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::DeviceAuthorization> for server enrollment

=head1 AUTHORS

=over

=item LemonLDAP::NG team L<https://lemonldap-ng.org/team>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
