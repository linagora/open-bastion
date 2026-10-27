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

# ============================================================================
# Scenario 1: Choice auth + pamAccessChoice configured
# ----------------------------------------------------------------------------
# /pam/authorize must succeed in routing the getUser step through Lib::Choice
# (i.e. it must NOT fall through to the User-not-found path because Choice
# could not resolve the sub-module).
# ============================================================================

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel       => $debug,
                domain         => 'op.com',
                portal         => 'http://auth.op.com',
                pam_lib::base_config(),
                authentication => 'Choice',
                userDB         => 'Choice',
                authChoiceModules => {
                    '1_demo'  => 'Demo;Demo;Null;;;',
                    '2_other' => 'SSL;Demo;Null;;;',
                },
                pamAccessSshRules => { default => '1' },
                pamAccessChoice   => '1_demo',
            }
        }
    ),
    'OP with Choice auth + pamAccessChoice=1_demo initialized'
);

# Login the user through the chosen Demo sub-module
my $id;
{
    my $query = main::buildForm( {
            user     => 'french',
            password => 'french',
            lmAuth   => '1_demo',
        }
    );
    ok(
        $res = $op->_post(
            '/',
            IO::String->new($query),
            accept => 'text/html',
            length => length($query),
        ),
        'Auth query (Choice / 1_demo)'
    );
    $id = expectCookie($res);
    ok( $id, 'Got session cookie via Choice login' );
    count(2);
}

# Enroll a server via Device Authorization Grant
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token (Choice scenario)' );
count(1);

# /pam/authorize for the same user — the critical assertion is that
# Lib::Choice routes getUser correctly, so we get a structured JSON
# response with an `authorized` boolean (not a 500 nor a "User not found"
# fallback).
my $auth_body = to_json( {
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
    'POST /pam/authorize (pamAccessChoice=1_demo)'
);
expectOK($res);
$json = expectJSON($res);
ok( exists $json->{authorized},
    'authorized key present (getUser routed via Choice)' );
ok( $json->{authorized},
    'User authorized (Choice resolved + default rule matched)' );
isnt( $json->{reason} || '', 'User not found',
    'No "User not found" fallback when pamAccessChoice is set' );
count(3);

# /pam/userinfo for the same user — must also resolve through Choice
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
    'POST /pam/userinfo (pamAccessChoice=1_demo)'
);
expectOK($res);
$json = expectJSON($res);
ok( $json->{found}, 'User found via Choice on /pam/userinfo' );
is( $json->{user}, 'french', 'Correct user echoed back' );
count(2);

# ============================================================================
# Scenario 2: Choice auth without pamAccessChoice
# ----------------------------------------------------------------------------
# Reproduces the original failure mode: Lib::Choice cannot resolve which
# sub-module to use for a server-to-server getUser, so getUser fails and
# /pam/authorize returns authorized=false with reason "User not found".
# This guards against accidental removal of the new option.
# ============================================================================

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel       => $debug,
                domain         => 'op.com',
                portal         => 'http://auth.op.com',
                pam_lib::base_config(),
                authentication => 'Choice',
                userDB         => 'Choice',
                authChoiceModules => {
                    '1_demo'  => 'Demo;Demo;Null;;;',
                    '2_other' => 'SSL;Demo;Null;;;',
                },
                pamAccessSshRules => { default => '1' },

                # pamAccessChoice intentionally NOT set (default empty)
            }
        }
    ),
    'OP with Choice auth, pamAccessChoice unset'
);

{
    my $query = main::buildForm( {
            user     => 'french',
            password => 'french',
            lmAuth   => '1_demo',
        }
    );
    ok(
        $res = $op->_post(
            '/',
            IO::String->new($query),
            accept => 'text/html',
            length => length($query),
        ),
        'Auth query (Choice / 1_demo) — no pamAccessChoice'
    );
    $id = expectCookie($res);
    ok( $id, 'Got session cookie via Choice login (no override)' );
    count(2);
}

$server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got server token (no-override scenario)' );
count(1);

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
    'POST /pam/authorize without pamAccessChoice'
);
expectOK($res);
$json = expectJSON($res);
ok( !$json->{authorized},
    'NOT authorized when Choice cannot resolve sub-module' );
is( $json->{reason}, 'User not found',
    'Reason is the historical "User not found" fallback' );
count(2);

clean_sessions();
done_testing();

__END__
