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

# ============================================
# Test 1: Offline mode enabled (boolean)
# ============================================

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules      => { default => '1' },
                pamAccessOfflineEnabled => 1,
                pamAccessOfflineTtl     => 3600,
                pamAccessExportedVars   => { gecos => 'cn' },
            }
        }
    ),
    'OP with offline mode enabled'
);

my $id = $op->login('dwho');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token' );
count(1);

my $auth_body = to_json( {
        user         => 'dwho',
        host         => 'server.example.com',
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
    'Authorize with offline mode enabled'
);
expectOK($res);
my $json = expectJSON($res);
ok( $json->{authorized}, 'User authorized' );
ok( $json->{offline}, 'offline block present' );
ok( $json->{offline}->{enabled}, 'offline enabled' );
is( $json->{offline}->{ttl}, 3600, 'Offline TTL is 3600' );
ok( $json->{gecos}, 'Exported attr gecos present' );
count(5);

# ============================================
# Test 2: Offline mode disabled
# ============================================

my $op2;
ok(
    $op2 = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op2.com',
                portal   => 'http://auth.op2.com',
                pam_lib::base_config(),
                pamAccessSshRules       => { default => '1' },
                pamAccessOfflineEnabled => 0,
            }
        }
    ),
    'OP without offline mode'
);

$id = $op2->login('dwho');
$server_token = pam_lib::enroll_server( $op2, $id );
ok( $server_token, 'Got server token' );
count(1);

ok(
    $res = $op2->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'Authorize without offline mode'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'User authorized' );
ok( !$json->{offline}, 'No offline block' );
count(2);

# ============================================
# Test 3: Offline mode with expression rule
# ============================================

my $op3;
ok(
    $op3 = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op3.com',
                portal   => 'http://auth.op3.com',
                pam_lib::base_config(),
                pamAccessSshRules       => { default => '1' },
                pamAccessOfflineEnabled => '$uid eq "rtyler"',
                pamAccessOfflineTtl     => 7200,
            }
        }
    ),
    'OP with offline mode expression'
);

$id = $op3->login('dwho');
$server_token = pam_lib::enroll_server( $op3, $id );
ok( $server_token, 'Got server token' );
count(1);

# dwho should NOT have offline (rule is '$uid eq "rtyler"')
$auth_body = to_json( {
        user         => 'dwho',
        host         => 'server.example.com',
        service      => 'sshd',
        server_group => 'default',
    }
);
ok(
    $res = $op3->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'Authorize dwho (expression test)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'dwho authorized' );
ok( !$json->{offline}, 'dwho has NO offline (expression does not match)' );
count(2);

# rtyler SHOULD have offline
$auth_body = to_json( {
        user         => 'rtyler',
        host         => 'server.example.com',
        service      => 'sshd',
        server_group => 'default',
    }
);
ok(
    $res = $op3->_post(
        '/pam/authorize',
        IO::String->new($auth_body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($auth_body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    ),
    'Authorize rtyler (expression test)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'rtyler authorized' );
ok( $json->{offline}, 'rtyler HAS offline (expression matches)' );
is( $json->{offline}->{ttl}, 7200, 'Offline TTL is 7200' );
count(3);

clean_sessions();
done_testing();

__END__
