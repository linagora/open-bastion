# The three server-to-server endpoints must name the enrolled server that
# asked. Those lookups carry no client address, so without it a miss cannot
# be traced back to a host when several share an egress IP.

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

# Capturing logger, installed on the plugin instance ($self->logger is rw,
# inherited from Common::Module).
{

    package t::CaptureLogger;
    sub new { return bless { msgs => $_[1] }, $_[0] }

    foreach my $level (qw(error warn notice info debug)) {
        no strict 'refs';
        *{$level} = sub {
            push @{ $_[0]->{msgs} }, "$level|$_[1]";
            return 1;
        };
    }
}

my $debug = 'error';
my ( $op, $res, $json );
my @logs;

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules     => { default => '1' },
                pamAccessExportedVars => { gecos   => 'cn' },
            }
        }
    ),
    'OP with PamAccess'
);

my $pam =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
ok( $pam, 'PamAccess plugin loaded' );
$pam->logger( t::CaptureLogger->new( \@logs ) );
count(1);

my $sid = $op->login('dwho');
my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Got server token' );
count(1);

# The device id stamped at enrollment is what the log must carry
my $atSession = $op->p->loadedModules->{
    'Lemonldap::NG::Portal::Issuer::OpenIDConnect'}
  ->getAccessToken($server_token);
ok( $atSession, 'Server access token session readable' );
my $expected = $atSession->data->{_deviceId} || $atSession->data->{client_id};
ok( $expected, "Server identity resolved from the token ($expected)" );
count(2);

sub post_userinfo {
    my ($user) = @_;
    @logs = ();
    my $body = to_json( { user => $user } );
    return $op->_post(
        '/pam/userinfo',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

# Known user: the request line names the server
ok( $res = post_userinfo('dwho'), 'POST /pam/userinfo for a known user' );
expectOK($res);
$json = expectJSON($res);
ok( $json->{found}, 'User found' );
my @req_lines = grep { /^info\|PAM userinfo request from enrolled server/ } @logs;
is( scalar @req_lines, 1, 'Exactly one request log line' );
like( $req_lines[0], qr/\Q$expected\E/, 'Request line carries the device id' );
count(3);

# Unknown user: the miss is logged at notice and names the server
ok( $res = post_userinfo('nosuchuser'), 'POST /pam/userinfo for an unknown user' );
expectOK($res);
$json = expectJSON($res);
ok( !$json->{found}, 'User not found' );
my @miss = grep { /^notice\|PAM userinfo: User 'nosuchuser' not found/ } @logs;
is( scalar @miss, 1, 'Miss logged at notice level' );
like( $miss[0], qr/\Q$expected\E/, 'Miss names the server that asked' );
count(3);

# /pam/authorize names the server on a miss
@logs = ();
my $auth_body = to_json( {
        user         => 'nosuchuser',
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
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize for an unknown user'
);
my @amiss = grep { /^notice\|PAM authorize: User 'nosuchuser' not found/ } @logs;
is( scalar @amiss, 1, 'authorize miss logged at notice level' );
like( $amiss[0], qr/\Q$expected\E/, 'authorize miss names the server' );
count(3);

# ---------------------------------------------------------------------------
# Same, on an organization-owned RP: enrollment stamps a per-device synthetic
# session, and the log must carry that _deviceId rather than the shared
# client_id -- which is the whole point when several bastions share an RP.
# ---------------------------------------------------------------------------

my @logs2;
my $op2;
ok(
    $op2 = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                    }
                },
                pamAccessSshRules     => { default => '1' },
                pamAccessExportedVars => { gecos   => 'cn' },
            }
        }
    ),
    'OP with device-organization (org-owned RP)'
);

my $pam2 =
  $op2->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
$pam2->logger( t::CaptureLogger->new( \@logs2 ) );

my $sid2 = $op2->login('dwho');
my $tok2 = pam_lib::enroll_server( $op2, $sid2 );
ok( $tok2, 'Got server token on the org-owned RP' );

my $at2 = $op2->p->loadedModules->{
    'Lemonldap::NG::Portal::Issuer::OpenIDConnect'}->getAccessToken($tok2);
my $devId = $at2->data->{_deviceId};
ok( $devId, 'Enrollment stamped a _deviceId' );
isnt( $devId, 'pam-access', '_deviceId is not the shared client_id' );
count(4);

@logs2 = ();
my $body2 = to_json( { user => 'nosuchuser' } );
ok(
    $res = $op2->_post(
        '/pam/userinfo',
        IO::String->new($body2),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body2),
        custom => { HTTP_AUTHORIZATION => "Bearer $tok2" },
    ),
    'POST /pam/userinfo for an unknown user (org-owned RP)'
);
expectOK($res);
my @miss2 = grep { /^notice\|PAM userinfo: User 'nosuchuser' not found/ } @logs2;
is( scalar @miss2, 1, 'Miss logged at notice level' );
like( $miss2[0], qr/\Q$devId\E/, 'Miss names the per-device id, not client_id' );
count(3);

@logs2 = ();
ok(
    $res = $op2->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $tok2" },
    ),
    'POST /pam/authorize for an unknown user (org-owned RP)'
);
my @amiss2 = grep { /^notice\|PAM authorize: User 'nosuchuser' not found/ } @logs2;
is( scalar @amiss2, 1, 'authorize miss logged at notice level' );
like( $amiss2[0], qr/\Q$devId\E/,
    'authorize miss names the per-device id, not client_id' );
count(3);

clean_sessions();
done_testing();
