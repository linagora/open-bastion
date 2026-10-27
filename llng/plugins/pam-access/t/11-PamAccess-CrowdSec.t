# Machine endpoints must never make the calling server report itself to
# CrowdSec. Both halves of the contract are pinned here: no alert for our
# server-to-server lookups, agent still armed for everything else.

use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use POSIX 'strftime';
use LWP::UserAgent;
use LWP::Protocol::PSGI;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

my $debug = 'error';
my ( $op, $res, $json );

# CrowdSec LAPI mock

my $alerts = 0;
my $lastAlertLogin;

LWP::Protocol::PSGI->register(
    sub {
        my $req = Lemonldap::NG::Portal::Main::Request->new(@_);

        if ( $req->path_info eq '/v1/watchers/login' ) {
            return [
                200,
                [],
                [
                    to_json( {
                            expire =>
                              strftime( "%Y-%m-%dT%H:%M:%SZ", gmtime ),
                            token => 'aaabbb',
                        }
                    )
                ]
            ];
        }
        elsif ( $req->path_info eq '/v1/alerts' ) {

            # POST = alert pushed, GET = alert history lookup
            if ( $req->method eq 'POST' ) {
                $alerts++;
                $lastAlertLogin = undef;
                my $obj = $req->jsonBodyToObj;
                if (    $obj
                    and $obj->[0]
                    and $obj->[0]->{events}
                    and $obj->[0]->{events}->[0]
                    and $obj->[0]->{events}->[0]->{meta} )
                {
                    foreach my $m ( @{ $obj->[0]->{events}->[0]->{meta} } ) {
                        $lastAlertLogin = $m->{value}
                          if $m->{key} eq 'login';
                    }
                }
                return [ 200, [], [] ];
            }
            return [ 200, [], ['[]'] ];
        }
        elsif ( $req->path_info eq '/v1/decisions' ) {
            return [ 200, [], [''] ];
        }

        fail( 'Unexpected CrowdSec request ' . $req->path_info );
        return [ 500, [], [] ];
    }
);

# Portal: PamAccess + CrowdSec agent both enabled

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules     => { default => '1' },
                pamAccessExportedVars => { gecos   => 'cn' },
                crowdsecMachineId     => 'llng',
                crowdsecPassword      => 'llngpwd',
                crowdsecAgent         => 1,
                crowdsecMaxFailures   => 5,
            }
        }
    ),
    'OP with PamAccess and the CrowdSec agent enabled'
);

my $sid = $op->login('dwho');
my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Got server token' );
count(1);

# Control: without this, every "no alert" below could just mean CrowdSec was
# never active.

my $prev = $alerts;
my $query = 'user=dwho&password=bad';
ok(
    $res = $op->_post(
        '/', IO::String->new($query),
        length => length($query),
    ),
    'Interactive login with a bad password'
);
expectReject($res);
is( $alerts, $prev + 1, 'CrowdSec agent is armed: alert pushed' );
is( $lastAlertLogin, 'dwho', 'Login is carried in the alert metadata' );
count(3);

# /pam/userinfo — the NSS path, reached by sshd before any authentication

$prev = $alerts;
my $body = to_json( { user => 'nosuchuser' } );
ok(
    $res = $op->_post(
        '/pam/userinfo',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/userinfo for an unknown user'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{found}, 'Unknown user reported as not found' );
is( $alerts, $prev, 'No CrowdSec alert for an NSS lookup miss' );
count(3);

# A client retrying in a loop must not accumulate alerts
$prev = $alerts;
for my $i ( 1 .. 5 ) {
    $op->_post(
        '/pam/userinfo',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}
is( $alerts, $prev, 'Repeated NSS lookup misses never accumulate alerts' );
count(1);

# /pam/authorize — the PAM path

$prev = $alerts;
$body = to_json( {
        user         => 'nosuchuser',
        host         => 'srv1.example.com',
        service      => 'sshd',
        server_group => 'default',
    }
);
ok(
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/authorize for an unknown user'
);
$json = expectJSON($res);
ok( !$json->{authorized}, 'Unknown user is not authorized' );
is( $alerts, $prev, 'No CrowdSec alert for a PAM authorization miss' );
count(3);

# A successful machine lookup is untouched too

$prev = $alerts;
$body = to_json( { user => 'dwho' } );
ok(
    $res = $op->_post(
        '/pam/userinfo',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'POST /pam/userinfo for a known user'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{found}, 'Known user resolved' );
is( $alerts, $prev, 'No CrowdSec alert for a successful lookup' );
count(3);

# The wrapper must only short-circuit /pam lookups, never leave the agent
# disabled for regular traffic.

$prev  = $alerts;
$query = 'user=rtyler&password=bad';
ok(
    $res = $op->_post(
        '/', IO::String->new($query),
        length => length($query),
    ),
    'Interactive login with a bad password, after the /pam calls'
);
expectReject($res);
is( $alerts, $prev + 1, 'CrowdSec agent is still armed for regular traffic' );
is( $lastAlertLogin, 'rtyler', 'Login is carried in the alert metadata' );
count(3);

clean_sessions();
done_testing();
