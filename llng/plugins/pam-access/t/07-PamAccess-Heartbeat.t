use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

my $debug = 'error';
my ( $op, $res );

# ---------------------------------------------------------------------------
# Build $op — start from pam_lib::base_config() and override oidcRPMetaDataOptions
# to enable offline_access for the pam-access RP.  The override key is listed
# AFTER pam_lib::base_config() so it wins the last-write-wins hash merge.
# ---------------------------------------------------------------------------
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules    => { default => '1' },
                pamAccessExportedVars => { gecos => 'cn' },
                # Override: enable offline for pam-access RP so we get a
                # refresh token back from the device flow.
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName          => 'PAM Access',
                        oidcRPMetaDataOptionsClientID             => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret         => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline              => 1,
                        oidcRPMetaDataOptionsOfflineSessionExpiration  => 2592000,
                    }
                },
            }
        }
    ),
    'OP with heartbeat / offline support'
);

# ---------------------------------------------------------------------------
# Helper: enroll a server requesting offline_access scope.
# Returns ($access_token, $refresh_token).
# ---------------------------------------------------------------------------
sub enroll_offline {
    my ($sid) = @_;

    # Initiate device authorization — include offline_access in scope
    my $query = buildForm( {
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
            scope         => 'pam:server offline_access',
        }
    );
    my $r = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "Device auth request failed: $r->[0]" unless $r->[0] == 200;

    my $json       = from_json( $r->[2]->[0] );
    my $device_code = $json->{device_code}
      or die 'no device_code';
    my $user_code = $json->{user_code}
      or die 'no user_code';
    $user_code =~ s/-//g;

    # Get verification page for CSRF token
    $r = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$sid",
        accept => 'text/html',
    );
    my ($csrf) = $r->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    die 'no CSRF token' unless $csrf;

    # Approve device
    $query = buildForm( {
            user_code => $user_code,
            action    => 'approve',
            token     => $csrf,
        }
    );
    $r = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$sid",
        accept => 'text/html',
        length => length($query),
    );
    die "Device approval failed: $r->[0]" unless $r->[0] == 200;

    # Exchange device_code for tokens
    $query = buildForm( {
            grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code   => $device_code,
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
        }
    );
    $r = $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "Token exchange failed: $r->[0]" unless $r->[0] == 200;

    $json = from_json( $r->[2]->[0] );
    return ( $json->{access_token}, $json->{refresh_token} );
}

# ===========================================================================
# Test 1: Enroll with offline_access — verify refresh_token is issued
# ===========================================================================

my $id = $op->login('dwho');
my ( $server_at, $rt ) = enroll_offline($id);
ok( $server_at, 'Got access_token from offline enroll' );
ok( $rt,        'Got refresh_token from offline enroll' );
count(2);

# ===========================================================================
# Test 2: POST /pam/heartbeat — happy path
# ===========================================================================

my $hb_body = to_json( {
        refresh_token => $rt,
        hostname      => 'srv1.example.com',
        server_group  => 'default',
        version       => '0.3.0',
        node_role     => 'bastion',
    }
);
ok(
    $res = $op->_post(
        '/pam/heartbeat',
        IO::String->new($hb_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($hb_body),
    ),
    'POST /pam/heartbeat happy path'
);
expectOK($res);
my $hb = expectJSON($res);
is( $hb->{status}, 'ok', 'heartbeat status is ok' );
ok( $hb->{access_token},       'heartbeat returned access_token' );
is( $hb->{expires_in}, 600, 'heartbeat expires_in matches AccessTokenExpiration' );
count(4);

my $minted_at = $hb->{access_token};

# ===========================================================================
# Test 3: minted access_token works for /pam/authorize
# ===========================================================================

my $auth_body = to_json( {
        user         => 'dwho',
        host         => 'srv1.example.com',
        service      => 'sshd',
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
        custom => { HTTP_AUTHORIZATION => "Bearer $minted_at" },
    ),
    'POST /pam/authorize with heartbeat-minted access_token'
);
expectOK($res);
my $auth = expectJSON($res);
ok( $auth->{authorized}, 'User authorized via minted access_token' );
count(2);

# ===========================================================================
# Test 4: _utime slide — refresh session must be pushed forward
#   Expected: _utime >= time() + OfflineSessionExpiration - timeout - small_slack
# ===========================================================================

my $oidc_mod = $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
my $rt_session = $oidc_mod->getRefreshToken($rt);
ok( $rt_session, 'Can read refresh token session after heartbeat' );
is( $rt_session->data->{_pamVersion},  '0.3.0',   'client version stored as _pamVersion' );
is( $rt_session->data->{_pamNodeRole}, 'bastion', 'node role stored as _pamNodeRole' );
count(3);

my $utime   = $rt_session->data->{_utime};
my $offline_exp = 2592000;
my $timeout     = $op->p->conf->{timeout};
my $min_utime   = time() + $offline_exp - $timeout - 10;

ok( $utime,             '_utime is set in refresh session' );
ok( $utime > time(),    '_utime is in the future' );
ok( $utime >= $min_utime,
    "_utime ($utime) slid forward by OfflineSessionExpiration ($min_utime expected minimum)" );
count(3);

# ===========================================================================
# Test 5a: Rejection — no refresh_token in body → 400
# ===========================================================================

my $bad_body = to_json( { hostname => 'x' } );
ok(
    $res = $op->_post(
        '/pam/heartbeat',
        IO::String->new($bad_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bad_body),
    ),
    'POST /pam/heartbeat without refresh_token'
);
is( $res->[0], 400, 'Missing refresh_token yields HTTP 400' );
count(2);

# ===========================================================================
# Test 5b: Rejection — nonexistent refresh_token → 401
# ===========================================================================

my $inv_body = to_json( { refresh_token => 'doesnotexist' } );
ok(
    $res = $op->_post(
        '/pam/heartbeat',
        IO::String->new($inv_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($inv_body),
    ),
    'POST /pam/heartbeat with invalid refresh_token'
);
is( $res->[0], 401, 'Invalid refresh_token yields HTTP 401' );
count(2);

# ===========================================================================
# Test 6: connected sessions are persisted into the refresh-token session
# ===========================================================================

my $sess_body = to_json( {
        refresh_token => $rt,
        hostname      => 'srv1.example.com',
        server_group  => 'default',
        sessions      => [
            { user => 'dwho', from => '10.0.0.5', tty => 'pts/0', since => 1700000000 },
            { user => 'rtyler', from => '', tty => 'tty1', since => 1700000100 },
        ],
    }
);
ok(
    $res = $op->_post(
        '/pam/heartbeat',
        IO::String->new($sess_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($sess_body),
    ),
    'POST /pam/heartbeat with sessions list'
);
expectOK($res);
count(1);

$rt_session = $oidc_mod->getRefreshToken($rt);
ok( $rt_session->data->{_pamSessions}, '_pamSessions stored in refresh session' );
is( $rt_session->data->{_pamSessionCount}, 2, '_pamSessionCount matches list length' );
my $stored = from_json( $rt_session->data->{_pamSessions} );
is( ref $stored,            'ARRAY', '_pamSessions decodes to a JSON array' );
is( $stored->[0]->{user},   'dwho',  'first session user persisted' );
is( $stored->[0]->{from},   '10.0.0.5', 'first session source host persisted' );
is( $stored->[1]->{tty},    'tty1',  'second session tty persisted' );
count(6);

# ===========================================================================
# Test 7: malformed "sessions" (not an array) is coerced to an empty list
# ===========================================================================

my $bad_sess_body = to_json( {
        refresh_token => $rt,
        hostname      => 'srv1.example.com',
        server_group  => 'default',
        sessions      => 'not-an-array',
    }
);
ok(
    $res = $op->_post(
        '/pam/heartbeat',
        IO::String->new($bad_sess_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($bad_sess_body),
    ),
    'POST /pam/heartbeat with malformed sessions'
);
expectOK($res);
count(1);

$rt_session = $oidc_mod->getRefreshToken($rt);
is( $rt_session->data->{_pamSessions}, '[]', 'malformed sessions coerced to empty JSON array' );
is( $rt_session->data->{_pamSessionCount}, 0, 'malformed sessions yields count 0' );
count(2);

clean_sessions();
done_testing();
