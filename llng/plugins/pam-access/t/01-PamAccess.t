use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';

    # Install plugin templates over LLNG's built-in templates
    # In production these are deployed by lemonldap-ng-store install;
    # in tests we copy them from the sibling plugin directories.
    use File::Find;
    use File::Copy;
    use File::Path qw(make_path);
    use FindBin;

    # Locate the plugins root: this test lives in plugins/<name>/t/
    my $plugins_root = "$FindBin::Bin/../../";
    for my $plugin (qw(oidc-device-authorization pam-access)) {
        my $tpl_dir = "$plugins_root/$plugin/portal-templates";
        next unless -d $tpl_dir;
        find(
            {
                wanted => sub {
                    return unless -f $_ && /\.tpl$/;
                    my $rel = $File::Find::name;
                    $rel =~ s{^\Q$tpl_dir/\E}{};
                    my $dst = "site/templates/$rel";
                    make_path( $dst =~ s{/[^/]+$}{}r );
                    File::Copy::copy( $File::Find::name, $dst );
                },
                no_chdir => 1,
            },
            $tpl_dir
        );
    }
}

my $debug = 'error';
my ( $op, $res );

# Initialization
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel                        => $debug,
                domain                          => 'op.com',
                portal                          => 'http://auth.op.com',
                authentication                  => 'Demo',
                userDB                          => 'Same',
                issuerDBOpenIDConnectActivation  => 1,
                issuerDBOpenIDConnectRule        => '$uid eq "french"',
                customPlugins                   => '::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization',
                oidcRPMetaDataExportedVars       => {
                    'pam-access' => {
                        email  => 'mail',
                        name   => 'cn',
                        groups => 'groups',
                    }
                },
                oidcServiceMetaDataAuthorizeURI       => 'authorize',
                oidcServiceMetaDataCheckSessionURI    => 'check_session',
                oidcServiceMetaDataJWKSURI            => 'jwks',
                oidcServiceMetaDataEndSessionURI      => 'logout',
                oidcServiceMetaDataRegistrationURI    => 'register',
                oidcServiceMetaDataTokenURI           => 'token',
                oidcServiceMetaDataUserInfoURI        => 'userinfo',
                oidcServiceMetaDataIntrospectionURI   => 'introspect',
                oidcServiceAllowAuthorizationCodeFlow => 1,
                oidcRPMetaDataOptions                 => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    }
                },
                oidcRPMetaDataScopeRules => {
                    'pam-access' => {
                        pam          => '1',
                        'pam:server' => '1',
                    }
                },
                oidcOPMetaDataOptions    => {},
                oidcOPMetaDataJSON       => {},
                oidcOPMetaDataJWKS       => {},
                oidcServicePrivateKeySig => oidc_key_op_private_sig(),
                oidcServicePublicKeySig  => oidc_cert_op_public_sig(),
                pamAccessActivation      => 1,
                portalDisplayPamAccess   => 1,
                pamAccessTokenDuration   => 600,
                pamAccessMaxDuration     => 3600,
                pamAccessExportedVars    => {
                    gecos => 'cn',
                    shell => 'uid',
                },
                pamAccessSshRules => {
                    default    => '1',
                    production => '$groups =~ /admins/',
                    dev        => '1',
                },
                pamAccessSudoRules => {
                    default    => '$groups =~ /admins/',
                    production => '$groups =~ /admins/',
                    dev        => '1',
                },
                pamAccessRp => 'pam-access',
            }
        }
    ),
    'OP with PamAccess initialized'
);

# ============================================
# PART 1: User token generation
# ============================================

my $query = 'user=french&password=french';
ok(
    $res = $op->_post(
        '/',
        IO::String->new($query),
        accept => 'text/html',
        length => length($query),
    ),
    'Auth query'
);
my $id = expectCookie($res);
ok( $id, 'Got session cookie' );

# GET /pam interface
ok(
    $res = $op->_get(
        '/pam',
        accept => 'text/html',
        cookie => "lemonldap=$id",
    ),
    'GET /pam interface'
);
expectOK($res);

# POST /pam - generate token
$query = 'duration=300';
ok(
    $res = $op->_post(
        '/pam',
        IO::String->new($query),
        accept => 'application/json',
        cookie => "lemonldap=$id",
        length => length($query),
    ),
    'POST /pam to generate token'
);
expectOK($res);
my $json = expectJSON($res);
ok( $json->{token},             'Got access token' );
is( $json->{login}, 'french',   'Correct login' );
is( $json->{expires_in}, 300,   'Correct expiration' );
count(3);

my $user_token = $json->{token};

# Max duration enforcement
$query = 'duration=9999';
ok(
    $res = $op->_post(
        '/pam',
        IO::String->new($query),
        accept => 'application/json',
        cookie => "lemonldap=$id",
        length => length($query),
    ),
    'POST /pam with excessive duration'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{expires_in} <= 3600, 'Duration capped at max' );
count(1);

# ============================================
# PART 2: Server enrollment via Device Authorization Grant
# ============================================

$query = 'client_id=pam-access&client_secret=pamsecret&scope=pam:server';
ok(
    $res = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    'POST /oauth2/device for server enrollment'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{device_code},      'Got device_code' );
ok( $json->{user_code},        'Got user_code' );
ok( $json->{verification_uri}, 'Got verification_uri' );
count(3);

my $device_code = $json->{device_code};
my $user_code   = $json->{user_code};
$user_code =~ s/-//g;

# Get device verification page to extract CSRF token
ok(
    $res = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    'GET /device verification page'
);
expectOK($res);

my ($csrf_token) =
  $res->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
ok( $csrf_token, 'Got CSRF token from device form' );
count(1);

# Approve device
$query = buildForm( {
        user_code => $user_code,
        action    => 'approve',
        token     => $csrf_token,
    }
);
ok(
    $res = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    'POST /device to approve'
);
expectOK($res);

# Server polls for token
$query =
    "grant_type=urn:ietf:params:oauth:grant-type:device_code"
  . "&device_code=$device_code"
  . "&client_id=pam-access"
  . "&client_secret=pamsecret";
ok(
    $res = $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    'POST /oauth2/token with device_code grant'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{access_token}, 'Got server access_token' );
count(1);

my $server_token = $json->{access_token};

# ============================================
# PART 3: Verify one-time user token
# ============================================

my $verify_body = to_json( { token => $user_token } );
ok(
    $res = $op->_post(
        '/pam/verify',
        IO::String->new($verify_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($verify_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/verify to validate user token'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{valid},            'Token is valid' );
is( $json->{user}, 'french',   'Correct user' );
is( ref $json->{groups}, 'ARRAY', 'Groups is an array' );
count(3);

# Exported attributes
ok( ref $json->{attrs} eq 'HASH', 'Attrs present' );
ok( $json->{attrs}->{gecos},      'gecos exported' );
ok( $json->{attrs}->{shell},      'shell exported' );
count(3);

# Second verify should fail (one-time use)
ok(
    $res = $op->_post(
        '/pam/verify',
        IO::String->new($verify_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($verify_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/verify again (consumed)'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{valid}, 'Token no longer valid (one-time use)' );
count(1);

# Losing the race for the token is a refusal, not a second success (#53).
# The token is consumed before any check runs; when that consumption fails —
# because a concurrent /pam/verify already deleted the session, or because the
# store is unreachable — nothing is validated.
{
    my $q = 'duration=300';
    my $fresh = expectJSON(
        $op->_post(
            '/pam',
            IO::String->new($q),
            accept => 'application/json',
            cookie => "lemonldap=$id",
            length => length($q),
        )
    )->{token};
    ok( $fresh, 'Generated a fresh one-time token' );

    my $orig = \&Lemonldap::NG::Common::Session::remove;
    my $lost = 0;
    no warnings 'redefine';
    local *Lemonldap::NG::Common::Session::remove = sub {
        my $self = shift;
        if ( ( $self->data->{_type} // '' ) eq 'pamtoken' and !$lost++ ) {
            $self->error('Object does not exist');
            return 0;
        }
        return $orig->( $self, @_ );
    };

    my $b = to_json( { token => $fresh } );
    $res = $op->_post(
        '/pam/verify',
        IO::String->new($b),
        accept => 'application/json',
        type   => 'application/json',
        length => length($b),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
    $json = expectJSON($res);
    ok( !$json->{valid}, '  -> a token we did not win is refused' );
    count(2);
}

# ============================================
# PART 4: Authorization checks
# ============================================

# Without Bearer token
my $auth_body = to_json( { user => 'french', host => 'server.example.com' } );
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
    ),
    'POST /pam/authorize without Bearer'
);
expectReject( $res, 401 );

# Missing user parameter
$auth_body = to_json( { host => 'server.example.com' } );
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize without user'
);
expectReject( $res, 400 );

# Invalid JSON
$auth_body = 'not valid json';
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize with invalid JSON'
);
expectReject( $res, 400 );

# Non-existent user
$auth_body = to_json( { user => 'nonexistent', host => 'server.example.com' } );
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize with non-existent user'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{authorized}, 'User not authorized (not found)' );
ok( $json->{reason},       'Reason provided' );
count(2);

# Default server group (SSH allowed for all)
$auth_body = to_json( {
        user         => 'french',
        host         => 'server.example.com',
        server_group => 'default',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize default group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'Authorized for default group' );
ok( $json->{permissions}, 'permissions present' );
ok( !$json->{permissions}->{sudo_allowed},
    'sudo NOT allowed (not in admins)' );
count(3);

# Dev group (SSH and sudo for all)
$auth_body = to_json( {
        user         => 'french',
        host         => 'dev.example.com',
        server_group => 'dev',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize dev group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'Authorized for dev group' );
ok( $json->{permissions}->{sudo_allowed}, 'sudo allowed in dev' );
count(2);

# Production group (french not in admins)
$auth_body = to_json( {
        user         => 'french',
        host         => 'prod.example.com',
        server_group => 'production',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize production group'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{authorized},
    'NOT authorized for production (not in admins)' );
ok( $json->{reason}, 'Reason provided for denial' );
count(2);

# Unknown group (should fallback to default)
$auth_body = to_json( {
        user         => 'french',
        host         => 'unknown.example.com',
        server_group => 'unknown_group',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize unknown group (fallback)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'Authorized via default fallback' );
count(1);

# ============================================
# PART 5: NSS userinfo
# ============================================

my $userinfo_body = to_json( { user => 'french' } );
ok(
    $res = $op->_post(
        '/pam/userinfo',
        IO::String->new($userinfo_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($userinfo_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/userinfo for existing user'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{found},            'User found' );
is( $json->{user}, 'french',   'Correct username' );
is( ref $json->{groups}, 'ARRAY', 'Groups is an array' );
ok( $json->{gecos}, 'gecos exported via pamAccessExportedVars' );
count(4);

# Non-existing user
$userinfo_body = to_json( { user => 'nonexistent' } );
ok(
    $res = $op->_post(
        '/pam/userinfo',
        IO::String->new($userinfo_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($userinfo_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/userinfo for non-existing user'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{found}, 'User not found' );
count(1);

# Without Bearer
ok(
    $res = $op->_post(
        '/pam/userinfo',
        IO::String->new($userinfo_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($userinfo_body),
    ),
    'POST /pam/userinfo without Bearer'
);
expectReject( $res, 401 );

clean_sessions();
done_testing();

__END__
