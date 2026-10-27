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

# Initialization with separate SSH and sudo rules per server group
ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules => {
                    default    => '1',                    # SSH for all
                    production => '$groups =~ /ops/',     # SSH only for ops
                    dev        => '1',                    # SSH for all
                },
                pamAccessSudoRules => {
                    default    => '$groups =~ /admins/',  # sudo for admins
                    production => '$groups =~ /ops/',     # sudo for ops
                    dev        => '1',                    # sudo for all
                },
            }
        }
    ),
    'OP with separate SSH and sudo rules'
);

# Enroll server
my $id = $op->login('dwho');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token' );
count(1);

# ============================================
# SSH rules tests
# ============================================

# Default group: SSH allowed (rule '1'), sudo denied (dwho not in admins)
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
    'SSH default group'
);
expectOK($res);
my $json = expectJSON($res);
ok( $json->{authorized}, 'SSH authorized for default' );
ok( $json->{permissions}, 'permissions present' );
ok( !$json->{permissions}->{sudo_allowed}, 'sudo denied (not in admins)' );
count(3);

# Dev group: SSH and sudo for all
$auth_body = to_json( {
        user         => 'dwho',
        host         => 'dev.example.com',
        service      => 'sshd',
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
    'SSH dev group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'SSH authorized for dev' );
ok( $json->{permissions}->{sudo_allowed}, 'sudo allowed in dev' );
count(2);

# Production group: dwho not in ops → SSH denied
$auth_body = to_json( {
        user         => 'dwho',
        host         => 'prod.example.com',
        service      => 'sshd',
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
    'SSH production group'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{authorized}, 'SSH denied for production (not in ops)' );
ok( $json->{reason}, 'Reason provided' );
ok( !$json->{permissions}, 'No permissions when denied' );
count(3);

# ============================================
# Sudo service tests
# ============================================

# sudo on dev: authorized (SSH + sudo both '1')
$auth_body = to_json( {
        user         => 'dwho',
        host         => 'dev.example.com',
        service      => 'sudo',
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
    'sudo dev group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'sudo authorized for dev' );
ok( $json->{permissions}->{sudo_allowed}, 'sudo_allowed flag true' );
count(2);

# sudo on default: SSH allowed but sudo denied (not in admins)
$auth_body = to_json( {
        user         => 'dwho',
        host         => 'server.example.com',
        service      => 'sudo',
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
    'sudo default group'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'authorized (SSH allowed)' );
ok( !$json->{permissions}->{sudo_allowed}, 'sudo denied (not in admins)' );
count(2);

# ============================================
# Fallback to default rule
# ============================================

$auth_body = to_json( {
        user         => 'dwho',
        host         => 'unknown.example.com',
        service      => 'sshd',
        server_group => 'nonexistent',
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
    'SSH unknown group (fallback to default)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{authorized}, 'Authorized via default fallback' );
count(1);

clean_sessions();
done_testing();

__END__
