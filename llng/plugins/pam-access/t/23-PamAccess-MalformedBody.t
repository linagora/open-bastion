# Malformed request bodies, non-string fields and credentials that cannot be
# session keys.
#
# from_json() accepts any JSON value, and the handlers used to index the
# result as a hashref: a list, a number or a boolean body died with "Not a
# HASH reference" (issue #440). A reference in refresh_token, token or user
# reached a helper that takes a session id or a byte string and died on its
# type constraint; a plain string outside printable ASCII died the same way
# once the session store hashed it with Digest::SHA (issue #441). A user
# above U+00FF died in the persistent-session lookup, which hashes the login
# as bytes (issue #438).
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

sub portal_ini {
    my (%overrides) = @_;
    return {
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
        %overrides,
    };
}

my $op = LLNG::Manager::Test->new( { ini => portal_ini() } );
ok( $op, 'Portal with pam-access' );

my $sid = $op->login('dwho');
my ( $token, $rt ) = pam_lib::enroll_server_tokens( $op, $sid,
    scope => 'pam:server offline_access' );
ok( $token, 'Server enrolled' );

sub post {
    my ( $op, $endpoint, $body, $bearer ) = @_;
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
    my ( $op, $endpoint, $body, $bearer, $label ) = @_;

    my $res = post( $op, $endpoint, $body, $bearer );
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
        check_400( $op, $endpoint, $raw, $bearer,
            "$endpoint with body $raw" );
    }
}

# ===========================================================================
# Issue #441: a credential field that is a reference
# ===========================================================================

for my $value ( '[]', '["a"]', '{}', '{"a":1}', 'true' ) {
    check_400( $op, 'heartbeat', qq({"refresh_token":$value}), undef,
        "heartbeat with refresh_token $value" );
    check_400( $op, 'verify', qq({"token":$value}), $token,
        "verify with token $value" );
}

# The issue also flagged `user`: authorize and userinfo forward it to
# $req->user, and bastion-cert hashes it as a session key.
for my $endpoint (qw(authorize userinfo bastion-cert)) {
    check_400( $op, $endpoint, '{"user":[]}', $token,
        "$endpoint with a user array" );
}

# ===========================================================================
# The other body members the handlers read are strings too. A reference used
# to be stored as is in the refresh-token session, and in legacy mode (empty
# pamAccessServerGroups) a server_group object was read as a refusal whose
# message the caller had chosen.
# ===========================================================================

my $hb_body = encode_json( {
        refresh_token => $rt,
        hostname      => {},
        server_group  => [],
        version       => { evil => 1 },
        node_role     => ['x'],
    }
);
my $hb_res = post( $op, 'heartbeat', $hb_body, undef );
is( $hb_res->[0], 200, 'heartbeat accepts reference-valued metadata' );

my $oidc_mod =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
my $rt_session = $oidc_mod->getRefreshToken($rt);
ok( $rt_session, 'can read the refresh-token session' );
is( $rt_session->data->{_pamHostname},    'unknown', 'hostname defaults' );
is( $rt_session->data->{_pamServerGroup}, 'default', 'server_group defaults' );
is( $rt_session->data->{_pamVersion},     '',        'version defaults' );
is( $rt_session->data->{_pamNodeRole},    '',        'node_role defaults' );

my $evil = encode_json(
    { user => 'dwho', server_group => { rejected => 1, message => 'pwned' } } );
my $auth_res = post( $op, 'authorize', $evil, $token );
is( $auth_res->[0], 200, 'authorize accepts a non-string server_group' );
unlike( $auth_res->[2]->[0], qr/pwned/,
    'the caller-chosen refusal message is not returned' );

# ===========================================================================
# Issue #438: characters that cannot be part of a unix login
# ===========================================================================

my $case = 0;
for my $user ( "\x{263a}", "\x{100}", "a\x00b", "a\tb" ) {
    my $body = encode_json(
        { user => $user, public_key => 'ssh-ed25519 AAAA', voucher => 'x' } );
    check_400( $op, 'bastion-cert', $body, $token,
        'bastion-cert with a non-login user (' . ++$case . ')' );
}

# A plain ASCII login still reaches the voucher check, i.e. the new check does
# not reject valid requests: no voucher exists here, so the answer is 403.
my $res = post( $op, 'bastion-cert',
    '{"user":"dwho","public_key":"ssh-ed25519 AAAA","voucher":"x"}',
    $token );
is( $res->[0], 403, 'an ASCII user still reaches the voucher check' );

# ===========================================================================
# Issue #441 under hashedSessionStore: LLNG hashes a session id and a login
# with Digest::SHA before storage. A wide character makes sha256_hex() die
# with "Wide character in subroutine entry", still a 500 on the anonymous
# heartbeat. The value is a plain string, so the reference check alone does
# not catch it.
# ===========================================================================

my $op_hashed =
  LLNG::Manager::Test->new( { ini => portal_ini( hashedSessionStore => 1 ) } );
ok( $op_hashed, 'Portal with hashedSessionStore' );

my $hsid = $op_hashed->login('dwho');
my ($htoken) = pam_lib::enroll_server_tokens( $op_hashed, $hsid,
    scope => 'pam:server offline_access' );
ok( $htoken, 'Server enrolled under hashedSessionStore' );

my $wide = encode_json( { refresh_token => "\x{263a}" } );
check_400( $op_hashed, 'heartbeat', $wide, undef,
    'heartbeat with a wide-character refresh_token under hashedSessionStore' );

$wide = encode_json( { token => "\x{263a}" } );
check_400( $op_hashed, 'verify', $wide, $htoken,
    'verify with a wide-character token under hashedSessionStore' );

for my $endpoint (qw(authorize userinfo)) {
    $wide = encode_json( { user => "\x{263a}" } );
    check_400( $op_hashed, $endpoint, $wide, $htoken,
        "$endpoint with a wide-character user under hashedSessionStore" );
}

# Give bastion-cert a key and a voucher so the request really reaches the
# login check: without them the handler's 400 "Missing public_key parameter"
# would make the case pass whatever the login check does.
$wide = encode_json(
    { user => "\x{263a}", public_key => 'ssh-ed25519 AAAA', voucher => 'x' } );
check_400( $op_hashed, 'bastion-cert', $wide, $htoken,
    'bastion-cert with a wide-character user under hashedSessionStore' );

done_testing();
