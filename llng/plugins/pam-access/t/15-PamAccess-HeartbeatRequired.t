# Issue #52 — pamAccessHeartbeatRequired / pamAccessInactiveThreshold used to
# be inert: an administrator could tick "Require heartbeat" in the Manager and
# nothing changed. They now gate /pam/authorize on the caller's liveness.
#
# /pam/heartbeat stamps _pamLastSeen on the refresh-token session AND on every
# access token it mints (plus _pamRtRef, a pointer to that refresh-token
# session), so /pam/authorize can tell how long ago the calling server last
# reported — even when its PAM module reuses one access token for a while.

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
my ( $op, $res, $json );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules          => { default => '1' },
                pamAccessHeartbeatRequired => 1,
                pamAccessInactiveThreshold => 900,

                # offline_access so the device flow returns a refresh token
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsOfflineSessionExpiration =>
                          2592000,
                    }
                },
            }
        }
    ),
    'OP with pamAccessHeartbeatRequired enabled'
);
count(1);

my $pam = $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
my $oidc =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
ok( $pam && $oidc, 'PamAccess and OIDC issuer loaded' );
count(1);

my $sid = $op->login('dwho');
my ( $enroll_at, $rt ) = enroll_offline($sid);
ok( $enroll_at, 'Got access_token from the device grant' );
ok( $rt,        'Got refresh_token from the device grant' );
count(2);

sub authorize_with {
    my ($token) = @_;
    my $body = to_json( {
            user         => 'dwho',
            host         => 'srv1.example.com',
            service      => 'sshd',
            server_group => 'default',
        }
    );
    return $op->_post(
        '/pam/authorize',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $token" },
    );
}

sub beat {
    my $body = to_json( {
            refresh_token => $rt,
            hostname      => 'srv1.example.com',
            server_group  => 'default',
        }
    );
    my $r = $op->_post(
        '/pam/heartbeat',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
    );
    die "heartbeat failed: $r->[0]" unless $r->[0] == 200;
    return from_json( $r->[2]->[0] )->{access_token};
}

# ===========================================================================
# A server that has never beaten cannot authorize anybody
# ===========================================================================

ok( $res = authorize_with($enroll_at),
    'POST /pam/authorize with the enrollment token (no heartbeat yet)' );
is( $res->[0], 403, '  -> HTTP 403' );
$json = from_json( $res->[2]->[0] );
is( $json->{error}, 'Server has not sent a heartbeat', '  -> explicit error' );
ok( !defined $json->{authorized}, '  -> no authorization verdict' );
count(4);

# ===========================================================================
# After a heartbeat, the minted token authorizes
# ===========================================================================

my $minted = beat();
ok( $minted, 'Heartbeat minted a fresh access token' );
ok( $res = authorize_with($minted), 'POST /pam/authorize with it' );
expectOK($res);
ok( from_json( $res->[2]->[0] )->{authorized}, '  -> user authorized' );
count(3);

my $atSession = $oidc->getAccessToken($minted);
ok( $atSession, 'Minted access-token session readable' );
ok( $atSession->data->{_pamLastSeen}, '  -> carries _pamLastSeen' );
ok( $atSession->data->{_pamRtRef},    '  -> carries _pamRtRef' );
my $rtBack = $oidc->getRefreshToken( $atSession->data->{_pamRtRef}, 1 );
ok( $rtBack && !$rtBack->error,
    '  -> _pamRtRef resolves the refresh-token session' );
ok( $rtBack->data->{_pamLastSeen}, '  -> which holds the live _pamLastSeen' );
count(5);

# ===========================================================================
# A stale *token* is fine as long as the server keeps beating: the live
# _pamLastSeen of the refresh-token session wins.
# ===========================================================================

my $old = time() - 5000;
my $update = $oidc->can('updateState') || $oidc->can('updateToken');
$oidc->$update( $atSession->id, { _pamLastSeen => $old } );
ok( $res = authorize_with($minted),
    'POST /pam/authorize with an old token but a live server' );
expectOK($res);
ok( from_json( $res->[2]->[0] )->{authorized},
    '  -> still authorized (live heartbeat wins)' );
count(2);

# ===========================================================================
# Server stopped beating: both markers age out -> rejected
# ===========================================================================

$oidc->updateRefreshToken( $rt, { _pamLastSeen => $old } );
ok( $res = authorize_with($minted),
    'POST /pam/authorize after the server stopped beating' );
is( $res->[0], 403, '  -> HTTP 403' );
is( from_json( $res->[2]->[0] )->{error},
    'Server heartbeat is stale', '  -> stale heartbeat' );
count(3);

# ===========================================================================
# pamAccessInactiveThreshold is what decides: widen it and the same caller
# passes again.
# ===========================================================================

$pam->conf->{pamAccessInactiveThreshold} = 10000;
ok( $res = authorize_with($minted),
    'POST /pam/authorize with a threshold wider than the gap' );
expectOK($res);
ok( from_json( $res->[2]->[0] )->{authorized},
    '  -> authorized: the threshold is honoured' );
$pam->conf->{pamAccessInactiveThreshold} = 900;
count(2);

# ===========================================================================
# Disabled (the default): liveness is not checked at all
# ===========================================================================

$pam->conf->{pamAccessHeartbeatRequired} = 0;

ok( $res = authorize_with($minted),
    'POST /pam/authorize with a stale server, gate disabled' );
expectOK($res);
ok( from_json( $res->[2]->[0] )->{authorized}, '  -> authorized' );
count(2);

ok( $res = authorize_with($enroll_at),
    'POST /pam/authorize with a never-beating server, gate disabled' );
expectOK($res);
ok( from_json( $res->[2]->[0] )->{authorized}, '  -> authorized' );
count(2);

$pam->conf->{pamAccessHeartbeatRequired} = 1;

clean_sessions();
done_testing();

# ---------------------------------------------------------------------------
# Device Authorization Grant with offline_access (same flow as
# 07-PamAccess-Heartbeat.t): returns ($access_token, $refresh_token).
# ---------------------------------------------------------------------------
sub enroll_offline {
    my ($id) = @_;

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

    my $j = from_json( $r->[2]->[0] );
    my $device_code = $j->{device_code} or die 'no device_code';
    my $user_code   = $j->{user_code}   or die 'no user_code';
    $user_code =~ s/-//g;

    $r = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    );
    my ($csrf) = $r->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    die 'no CSRF token' unless $csrf;

    $query = buildForm( {
            user_code => $user_code,
            action    => 'approve',
            token     => $csrf,
        }
    );
    $r = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    );
    die "Device approval failed: $r->[0]" unless $r->[0] == 200;

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

    $j = from_json( $r->[2]->[0] );
    return ( $j->{access_token}, $j->{refresh_token} );
}
