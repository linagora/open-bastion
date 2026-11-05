# Malformed request bodies and non-string credential fields.
#
# from_json() accepts any JSON value, and the handlers used to index the
# result as a hashref: a list, a number or a boolean body died with "Not a
# HASH reference" (issue #440). A reference in refresh_token, token or user
# reached a helper that takes a session id or a byte string and died on its
# type constraint (issue #441). A user above U+00FF died in the persistent
# session lookup, which hashes the login as bytes (issue #438).
#
# All of these are client errors: they must answer 400 without dying.

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

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel => $debug,
            domain   => 'op.com',
            portal   => 'http://auth.op.com',
            pam_lib::base_config(),
            pamAccessSshRules => { default => '1' },
            oidcRPMetaDataOptions => {
                'pam-access' => {
                    oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                    oidcRPMetaDataOptionsClientID     => 'pam-access',
                    oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                    oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    oidcRPMetaDataOptionsAllowOffline             => 1,
                },
            },
        }
    }
);
ok( $op, 'Portal with pam-access' );

my $sid = $op->login('dwho');
my ($token) = pam_lib::enroll_server_tokens( $op, $sid,
    scope => 'pam:server offline_access' );
ok( $token, 'Server enrolled' );

sub post {
    my ( $endpoint, $body, $bearer ) = @_;
    return $op->_post(
        "/pam/$endpoint",
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        ( $bearer
            ? ( custom => { HTTP_AUTHORIZATION => "Bearer $bearer" } )
            : () ),
    );
}

sub check_400 {
    my ( $endpoint, $body, $bearer, $label ) = @_;

    my $res = eval { post( $endpoint, $body, $bearer ) };
    is( $@, '', "$label: does not die" );
    is( $res && $res->[0], 400, "$label: 400" );
}

# ===========================================================================
# Issue #440: a body that is not a JSON object
# ===========================================================================

# heartbeat reads its body before any credential check; the other endpoints
# need the server token, which is checked first.
for my $raw ( '[]', '[1,2]', '0', 'true', 'false', 'null' ) {
    for my $endpoint (qw(heartbeat authorize verify userinfo bastion-cert)) {
        my $bearer = $endpoint eq 'heartbeat' ? undef : $token;
        check_400( $endpoint, $raw, $bearer,
            "$endpoint with body $raw" );
    }
}

# ===========================================================================
# Issue #441: a credential field that is a reference
# ===========================================================================

for my $value ( '[]', '["a"]', '{}', '{"a":1}', 'true' ) {
    check_400( 'heartbeat', qq({"refresh_token":$value}), undef,
        "heartbeat with refresh_token $value" );
    check_400( 'verify', qq({"token":$value}), $token,
        "verify with token $value" );
}

# The issue also flagged `user`: authorize and userinfo forward it to
# $req->user, and bastion-cert hashes it as a session key.
for my $endpoint (qw(authorize userinfo bastion-cert)) {
    check_400( $endpoint, '{"user":[]}', $token,
        "$endpoint with a user array" );
}

# ===========================================================================
# Issue #438: characters that cannot be part of a unix login
# ===========================================================================

my $case = 0;
for my $user ( "\x{263a}", "\x{100}", "a\x00b", "a\tb" ) {
    my $body = to_json( { user => $user } );
    check_400( 'bastion-cert', $body, $token,
        'bastion-cert with a non-login user (' . ++$case . ')' );
}

# A plain ASCII login still reaches the voucher check, i.e. the new check does
# not reject valid requests: no voucher exists here, so the answer is 403.
my $res = post( 'bastion-cert',
    '{"user":"dwho","public_key":"ssh-ed25519 AAAA","voucher":"x"}',
    $token );
is( $res->[0], 403, 'an ASCII user still reaches the voucher check' );

done_testing();
