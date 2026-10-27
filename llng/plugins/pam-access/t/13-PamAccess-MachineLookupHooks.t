# A server-to-server lookup must stay invisible to every plugin hooked on the
# steps it runs, not just the CrowdSec agent. This pins the mechanism itself
# with a plugin of our own, on both hook kinds.

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

# A stand-in for any alerting plugin: one aroundSub on getUser, one afterSub
# on setLocalGroups. loadModule() skips the require when the package is
# already in the namespace, so no file is needed.
{

    package Lemonldap::NG::Portal::Plugins::TestAlerter;
    use Mouse;
    extends 'Lemonldap::NG::Portal::Main::Plugin';

    our $around = 0;
    our $after  = 0;

    use constant aroundSub => { getUser        => 'countAround' };
    use constant afterSub  => { setLocalGroups => 'countAfter' };

    sub init { return 1 }

    sub countAround {
        my ( $self, $sub, $req ) = @_;
        $around++;
        return $sub->($req);
    }

    sub countAfter {
        my ( $self, $req ) = @_;
        $after++;
        return 0;
    }
}

sub counters {
    return ( $Lemonldap::NG::Portal::Plugins::TestAlerter::around,
        $Lemonldap::NG::Portal::Plugins::TestAlerter::after );
}

sub reset_counters {
    $Lemonldap::NG::Portal::Plugins::TestAlerter::around = 0;
    $Lemonldap::NG::Portal::Plugins::TestAlerter::after  = 0;
}

my $debug = 'error';
my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::TestAlerter',
                pamAccessSshRules     => { default => '1' },
                pamAccessExportedVars => { gecos   => 'cn' },
            }
        }
    ),
    'OP with a third-party plugin hooked on getUser and setLocalGroups'
);

# Control: the hooks really fire on an interactive authentication. Without
# this, every "not called" assertion below would be vacuous.
reset_counters();
my $sid = $op->login('dwho');
my ( $around, $after ) = counters();
ok( $around > 0, "aroundSub on getUser fires on a real login ($around)" );
ok( $after > 0,  "afterSub on setLocalGroups fires on a real login ($after)" );
count(2);

my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Got server token' );
count(1);

sub machine_post {
    my ( $path, $payload ) = @_;
    reset_counters();
    my $body = to_json($payload);
    return $op->_post(
        $path,
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

# /pam/userinfo, both outcomes
foreach my $user (qw(dwho nosuchuser)) {
    ok( $res = machine_post( '/pam/userinfo', { user => $user } ),
        "POST /pam/userinfo for '$user'" );
    expectOK($res);
    my ( $a, $b ) = counters();
    is( $a, 0, "  aroundSub not called for '$user'" );
    is( $b, 0, "  afterSub not called for '$user'" );
    count(3);
}

# /pam/authorize
ok(
    $res = machine_post(
        '/pam/authorize',
        {
            user         => 'dwho',
            host         => 'srv1.example.com',
            service      => 'sshd',
            server_group => 'default',
        }
    ),
    'POST /pam/authorize'
);
expectOK($res);
( $around, $after ) = counters();
is( $around, 0, '  aroundSub not called on /pam/authorize' );
is( $after,  0, '  afterSub not called on /pam/authorize' );
count(3);

# And the hooks are still armed for regular traffic afterwards
reset_counters();
$op->login('rtyler');
( $around, $after ) = counters();
ok( $around > 0, 'aroundSub still fires on a later login' );
ok( $after > 0,  'afterSub still fires on a later login' );
count(2);

clean_sessions();
done_testing();
