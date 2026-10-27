# Issue #100 (linagora/open-bastion#339) — signed answers of the /pam/*
# endpoints.
#
# A host takes its access decisions from these answers, and nothing but TLS
# vouched for them. A caller sending `Accept: application/ob-pam-response+jwt`
# now gets a compact JWS signed with the key the portal publishes in its JWKS
# for the caller's client_id. This pins:
#
#   - the five signed endpoints, on success AND on every refusal path;
#   - the claims binding the answer to one request (req_nonce, req_sha256),
#     and `resp` being exactly the plain answer;
#   - verification against the published JWKS, kid included;
#   - nonce_required, before any work is done;
#   - no change at all without the Accept header, and none on bastion-cert;
#   - fail-closed signing: an unusable algorithm yields an UNSIGNED 500.

use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use Digest::SHA qw(sha256_hex hmac_sha256_hex);
use Crypt::JWT  qw(decode_jwt);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

my $debug  = 'error';
my $ACCEPT = 'application/ob-pam-response+jwt';
my $KID    = 'pam-sig-1';
my $secret = 's3cr3t';
my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                oidcServiceKeyIdSig   => $KID,
                pamAccessSshRules     => { default => '$uid ne "rtyler"' },
                pamAccessExportedVars => { gecos   => 'cn' },
                pamAccessRequestSigningSecret => $secret,
                pamAccessRequestSigningMode   => 'off',

                # Offline access, so that the device grant also returns the
                # refresh token /pam/heartbeat authenticates with.
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsIDTokenSignAlg => 'RS256',
                    }
                },
            }
        }
    ),
    'OP with PamAccess'
);
count(1);

my $conf = $op->p->conf;
my $oidc =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};

my $sid = $op->login('dwho');
my ( $token, $refresh ) =
  pam_lib::enroll_server_tokens( $op, $sid,
    scope => 'pam:server offline_access' );
ok( $token,   'Enrolled a server' );
ok( $refresh, '  -> with a refresh token' );
count(2);

# The issuer, as the discovery document announces it.
my $ISS = from_json(
    $op->_get( '/.well-known/openid-configuration',
        accept => 'application/json' )->[2]->[0]
)->{issuer};
ok( $ISS, "Issuer: $ISS" );
count(1);

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
my $nonce_seq = 0;

sub newNonce {
    $nonce_seq++;
    return sprintf( '%d-3f2a1b4c-9d8e-4f01-b2a3-%012d',
        int( time * 1000 ), $nonce_seq );
}

# POST $path with $body. Signed answer asked for unless plain => 1.
#   nonce  => X-Nonce to send (default: a fresh one; undef: none)
#   bearer => Bearer token (default: $token; undef: none)
#   accept => Accept header override
sub call {
    my ( $path, $body, %a ) = @_;
    $body = to_json($body) if ref $body;
    my %hdr;
    my $bearer = exists $a{bearer} ? $a{bearer} : $token;
    $hdr{HTTP_AUTHORIZATION} = "Bearer $bearer" if defined $bearer;
    my $nonce = exists $a{nonce} ? $a{nonce} : newNonce();
    $hdr{HTTP_X_NONCE} = $nonce if defined $nonce and !$a{plain};
    %hdr = ( %hdr, %{ $a{headers} || {} } );
    return $op->_post(
        $path,
        IO::String->new($body),
        accept => $a{accept}
          // ( $a{plain} ? 'application/json' : "application/json, $ACCEPT" ),
        type   => 'application/json',
        length => length($body),
        custom => \%hdr,
    );
}

sub header {
    my ( $res, $name ) = @_;
    my %h = @{ $res->[1] };
    my ($k) = grep { lc($_) eq lc($name) } keys %h;
    return defined $k ? $h{$k} : undef;
}

# The JWKS the portal publishes for the pam-access client: what a host is
# provisioned with.
sub publishedJwks {
    my $r = $op->_get(
        '/oauth2/jwks',
        query  => 'client_id=pam-access',
        accept => 'application/json',
    );
    die "jwks: $r->[0]" unless $r->[0] == 200;
    return from_json( $r->[2]->[0] );
}

# Verify a signed answer against the published JWKS, the way a host does.
# Returns ( $header, $claims ), dies on a bad signature.
sub verifySigned {
    my ($res) = @_;
    my $jwt = $res->[2]->[0];
    return decode_jwt(
        token         => $jwt,
        kid_keys      => publishedJwks(),
        decode_header => 1,
        accepted_alg  => qr/\A(?:RS|PS|ES)\d+\z/,
        verify_exp    => 1,
        verify_iat    => 1,
    );
}

# Common assertions on a signed answer. %want: status, endpoint, nonce,
# body (raw request body), aud (undef = must be absent).
sub checkSigned {
    my ( $res, $label, %want ) = @_;
    is( $res->[0], $want{status}, "$label: HTTP $want{status}" );
    is( header( $res, 'Content-Type' ), $ACCEPT,  "$label: JWS content type" );
    is( header( $res, 'Vary' ),         'Accept', "$label: Vary: Accept" );
    my ( $h, $c ) = eval { verifySigned($res) };
    ok( $c, "$label: verifies against the published JWKS" )
      or diag( $@, ' body: ', $res->[2]->[0] );
    count(4);
    return unless $c;
    is( $h->{typ}, 'ob-pam-response+jwt', "$label: dedicated typ" );
    is( $h->{kid}, $KID,                  "$label: kid of the signing key" );
    is( $c->{iss}, $ISS,                  "$label: iss is the issuer" );
    is( $c->{endpoint},    $want{endpoint},           "$label: endpoint" );
    is( $c->{http_status}, $want{status},             "$label: http_status" );
    is( $c->{req_nonce},   $want{nonce},              "$label: req_nonce" );
    is( $c->{req_sha256},  sha256_hex( $want{body} ), "$label: req_sha256" );
    is( $c->{exp} - $c->{iat}, 60,                    "$label: valid 60 s" );
    ok( abs( $c->{iat} - time ) < 30, "$label: iat is now" );

    if ( defined $want{aud} ) {
        is( $c->{aud}, $want{aud}, "$label: aud is the caller's client_id" );
    }
    else {
        ok( !exists $c->{aud}, "$label: no aud (caller not identified)" );
    }
    count(10);
    return $c;
}

# ===========================================================================
# The issuer actually publishes the key we expect to verify against
# ===========================================================================
{
    my $jwks = publishedJwks();
    ok( ( grep { ( $_->{kid} // '' ) eq $KID } @{ $jwks->{keys} } ),
        "The portal's JWKS publishes kid '$KID'" );
    count(1);
}

# ===========================================================================
# Success, endpoint by endpoint — and `resp` is the plain answer
# ===========================================================================

# /pam/whoami
{
    my $plain = call( '/pam/whoami', '{}', plain => 1 );
    is( $plain->[0], 200, 'whoami: plain answer' );
    count(1);

    my $n = newNonce();
    $res = call( '/pam/whoami', '{}', nonce => $n );
    my $c = checkSigned(
        $res, 'whoami',
        status   => 200,
        endpoint => 'whoami',
        nonce    => $n,
        body     => '{}',
        aud      => 'pam-access'
    );
    is_deeply(
        $c->{resp},
        from_json( $plain->[2]->[0] ),
        'whoami: resp is exactly the plain answer'
    );
    ok( !exists $c->{jwks}, 'whoami: no jwks claim' );
    count(2);
}

# /pam/authorize
{
    my $body  = to_json( { user => 'dwho', host => 'h1', service => 'sshd' } );
    my $plain = call( '/pam/authorize', $body, plain => 1 );
    is( $plain->[0], 200, 'authorize: plain answer' );
    ok( from_json( $plain->[2]->[0] )->{authorized}, '  -> granted' );
    count(2);

    my $n = newNonce();
    $res = call( '/pam/authorize', $body, nonce => $n );
    my $c = checkSigned(
        $res, 'authorize',
        status   => 200,
        endpoint => 'authorize',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is_deeply(
        $c->{resp},
        from_json( $plain->[2]->[0] ),
        'authorize: resp is exactly the plain answer'
    );
    ok( $c->{resp}->{authorized}, 'authorize: the signed answer grants' );
    count(2);
}

# /pam/userinfo
{
    my $body  = to_json( { user => 'dwho' } );
    my $plain = call( '/pam/userinfo', $body, plain => 1 );
    is( $plain->[0], 200, 'userinfo: plain answer' );
    count(1);

    my $n = newNonce();
    $res = call( '/pam/userinfo', $body, nonce => $n );
    my $c = checkSigned(
        $res, 'userinfo',
        status   => 200,
        endpoint => 'userinfo',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is_deeply(
        $c->{resp},
        from_json( $plain->[2]->[0] ),
        'userinfo: resp is exactly the plain answer'
    );
    count(1);
}

# /pam/verify — one-time tokens, so one per call.
sub pamToken {
    my $q = 'duration=300';
    my $r = $op->_post(
        '/pam',
        IO::String->new($q),
        accept => 'application/json',
        cookie => "lemonldap=$sid",
        length => length($q),
    );
    return from_json( $r->[2]->[0] )->{token};
}

{
    my $plainBody = to_json( { token => pamToken() } );
    my $plain     = call( '/pam/verify', $plainBody, plain => 1 );
    is( $plain->[0], 200, 'verify: plain answer' );
    ok( from_json( $plain->[2]->[0] )->{valid}, '  -> valid' );
    count(2);

    my $body = to_json( { token => pamToken() } );
    my $n    = newNonce();
    $res = call( '/pam/verify', $body, nonce => $n );
    my $c = checkSigned(
        $res, 'verify',
        status   => 200,
        endpoint => 'verify',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is_deeply(
        $c->{resp},
        from_json( $plain->[2]->[0] ),
        'verify: resp is exactly the plain answer (same user)'
    );
    ok( $c->{resp}->{valid}, 'verify: the signed answer is valid:true' );
    count(2);

    # The binding: the signed answer names this request, so it cannot be
    # replayed for another token. A second request, same nonce, other body,
    # gets another req_sha256.
    my $body2 = to_json( { token => pamToken() } );
    my ( undef, $c2 ) =
      verifySigned( call( '/pam/verify', $body2, nonce => $n ) );
    isnt( $c2->{req_sha256}, $c->{req_sha256},
        'verify: req_sha256 tells two requests apart' );
    count(1);
}

# /pam/heartbeat — authenticates with the refresh token in the body, and its
# signed answer also carries the current signature keys.
{
    my $body  = to_json( { refresh_token => $refresh, hostname => 'h1' } );
    my $plain = call( '/pam/heartbeat', $body, plain => 1, bearer => undef );
    is( $plain->[0], 200, 'heartbeat: plain answer' );
    my $pj = from_json( $plain->[2]->[0] );
    ok( !exists $pj->{jwks}, '  -> without jwks' );
    count(2);

    my $n = newNonce();
    $res = call( '/pam/heartbeat', $body, nonce => $n, bearer => undef );
    my $c = checkSigned(
        $res, 'heartbeat',
        status   => 200,
        endpoint => 'heartbeat',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    my %r = %{ $c->{resp} };
    my %p = %$pj;

    # A fresh access token and the time differ from call to call.
    delete @r{qw(access_token server_time)};
    delete @p{qw(access_token server_time)};
    is_deeply( \%r, \%p, 'heartbeat: resp has the plain answer shape' );
    ok( $c->{resp}->{access_token}, 'heartbeat: carries the access token' );
    is( ref $c->{jwks}, 'HASH', 'heartbeat: jwks claim present' );
    ok(
        ( grep { ( $_->{kid} // '' ) eq $KID } @{ $c->{jwks}->{keys} || [] } ),
        '  -> and it holds the signing kid'
    );
    ok( !( grep { ( $_->{use} // '' ) ne 'sig' } @{ $c->{jwks}->{keys} } ),
        '  -> signature keys only' );
    count(5);

    # The jwks claim is enough on its own to verify the next answer: this is
    # what a host keeps between beats.
    my ( undef, $again ) = decode_jwt(
        token         => call( '/pam/whoami', '{}' )->[2]->[0],
        kid_keys      => $c->{jwks},
        decode_header => 1,
    );
    is( $again->{endpoint}, 'whoami',
        'heartbeat: its jwks verifies the next signed answer' );
    count(1);
}

# ===========================================================================
# Refusals are signed too
# ===========================================================================

# 401 before identification: signed, no aud.
{
    my $n = newNonce();
    $res = call(
        '/pam/authorize', '{"user":"dwho"}',
        bearer => 'deadbeef',
        nonce  => $n
    );
    my $c = checkSigned(
        $res, 'bad bearer',
        status   => 401,
        endpoint => 'authorize',
        nonce    => $n,
        body     => '{"user":"dwho"}',
        aud      => undef
    );
    is(
        $c->{resp}->{error},
        'Invalid or expired token',
        'bad bearer: resp carries the plain error'
    );
    is(
        header( $res, 'WWW-Authenticate' ),
        'Bearer realm="pam"',
        'bad bearer: WWW-Authenticate kept'
    );
    count(2);

    $res = call( '/pam/whoami', '{}', bearer => undef );
    is( $res->[0], 401, 'no bearer: 401' );
    ok( eval { verifySigned($res) }, '  -> signed' );
    count(2);

    $res =
      call( '/pam/heartbeat', '{"refresh_token":"nope"}', bearer => undef );
    is( $res->[0], 401, 'heartbeat with a bad refresh token: 401' );
    my ( undef, $hc ) = eval { verifySigned($res) };
    ok( $hc && !exists $hc->{jwks}, '  -> signed, and no jwks on failure' );
    count(2);
}

# verify: valid:false is signed, and still says 200.
{
    my $body = to_json( { token => 'no-such-token' } );
    my $n    = newNonce();
    $res = call( '/pam/verify', $body, nonce => $n );
    my $c = checkSigned(
        $res, 'verify invalid',
        status   => 200,
        endpoint => 'verify',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is_deeply(
        $c->{resp},
        { valid => JSON::false, error => 'Invalid or expired token' },
        'verify invalid: resp is valid:false'
    );
    count(1);
}

# authorize: denied by rule (200) and refused by the liveness gate (403).
{
    my $body = to_json( { user => 'rtyler', host => 'h1', service => 'sshd' } );
    my $n    = newNonce();
    my $c    = checkSigned(
        call( '/pam/authorize', $body, nonce => $n ),
        'authorize denied',
        status   => 200,
        endpoint => 'authorize',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    ok( !$c->{resp}->{authorized}, 'authorize denied: authorized:false' );
    count(1);

    local $conf->{pamAccessHeartbeatRequired} = 1;
    $body = to_json( { user => 'dwho', host => 'h1', service => 'sshd' } );
    $n    = newNonce();
    $c    = checkSigned(
        call( '/pam/authorize', $body, nonce => $n ),
        'authorize 403',
        status   => 403,
        endpoint => 'authorize',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is(
        $c->{resp}->{error},
        'Server has not sent a heartbeat',
        'authorize 403: resp carries the plain error'
    );
    count(1);
}

# Malformed fingerprint: 400, signed, through _parseFingerprintOrReject.
{
    my $body = to_json( {
            user        => 'dwho',
            host        => 'h1',
            service     => 'sshd',
            fingerprint => 'not-a-fingerprint'
        }
    );
    my $n = newNonce();
    my $c = checkSigned(
        call( '/pam/authorize', $body, nonce => $n ),
        'malformed fingerprint',
        status   => 400,
        endpoint => 'authorize',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );
    is(
        $c->{resp}->{error},
        'Malformed SSH fingerprint',
        'malformed fingerprint: resp carries the plain error'
    );
    count(1);
}

# Bad JSON: 400 from _badRequest, signed.
{
    my $n = newNonce();
    my $c = checkSigned(
        call( '/pam/userinfo', 'not json', nonce => $n ),
        'bad json',
        status   => 400,
        endpoint => 'userinfo',
        nonce    => $n,
        body     => 'not json',
        aud      => 'pam-access'
    );
    is( $c->{resp}->{error}, 'Invalid JSON', 'bad json: resp error' );
    count(1);
}

# ===========================================================================
# nonce_required
# ===========================================================================
{
    my $body = to_json( { token => pamToken() } );
    for my $case ( [ 'no X-Nonce', undef ], [ 'a malformed X-Nonce', 'a b' ] ) {
        $res = call( '/pam/verify', $body, nonce => $case->[1] );
        my $c = checkSigned(
            $res, "nonce_required ($case->[0])",
            status   => 400,
            endpoint => 'verify',
            nonce    => undef,
            body     => $body,
            aud      => undef
        );
        is_deeply(
            $c->{resp},
            { error => 'nonce_required' },
            "nonce_required ($case->[0]): resp"
        );
        ok( !exists $c->{req_nonce}, '  -> and no req_nonce claim' );
        count(2);
    }

    # Refused before any work: the one-time token was not consumed.
    my ( undef, $c ) = verifySigned( call( '/pam/verify', $body ) );
    ok( $c->{resp}->{valid},
        'The same token, now with a nonce, is still valid: nothing was consumed'
    );
    count(1);

    # The nonce is only required for a signed answer.
    is( call( '/pam/whoami', '{}', plain => 1, nonce => undef )->[0],
        200, 'No nonce is needed for a plain answer' );
    count(1);
}

# ===========================================================================
# Accept negotiation
# ===========================================================================
{
    for my $accept (
        $ACCEPT,
        'APPLICATION/OB-PAM-RESPONSE+JWT',
        "text/plain;q=0.5, $ACCEPT;q=0.9",
        "application/json,$ACCEPT ; q=1",
      )
    {
        $res = call( '/pam/whoami', '{}', accept => $accept );
        is( header( $res, 'Content-Type' ),
            $ACCEPT, "Accept '$accept' -> signed" );
        count(1);
    }
    for my $accept (
        'application/json', 'application/ob-pam-response+jwt-not',
        'application/*',    '*/*',
      )
    {
        $res = call( '/pam/whoami', '{}', accept => $accept );
        like(
            header( $res, 'Content-Type' ),
            qr{^application/json},
            "Accept '$accept' -> plain JSON"
        );
        count(1);
    }
}

# ===========================================================================
# Non-regression: without the Accept header nothing changes
# ===========================================================================
{
    # Same request, sent with and without an X-Nonce: the plain path ignores
    # it, and the answer is plain JSON with the historical headers.
    for my $case (
        [ '/pam/whoami',    '{}' ],
        [ '/pam/userinfo',  to_json( { user => 'dwho' } ) ],
        [ '/pam/authorize', to_json( { user => 'dwho', host => 'h1' } ) ],
        [ '/pam/authorize', 'not json' ],
      )
    {
        my ( $path, $body ) = @$case;
        my $a = call( $path, $body, plain => 1 );
        my $b = call(
            $path, $body,
            plain   => 1,
            headers => { HTTP_X_NONCE => newNonce() }
        );
        is( $a->[0], $b->[0], "plain $path: same status" );
        is_deeply(
            from_json( $a->[2]->[0] ),
            from_json( $b->[2]->[0] ),
            "plain $path: same body"
        );
        like(
            header( $a, 'Content-Type' ),
            qr{^application/json},
            "plain $path: JSON content type"
        );
        ok( !defined header( $a, 'Vary' ), "plain $path: headers unchanged" );
        count(4);
    }
    $res = call( '/pam/whoami', '{}', plain => 1, bearer => 'deadbeef' );
    is( $res->[0], 401, 'plain 401 unchanged' );
    is_deeply(
        from_json( $res->[2]->[0] ),
        { error => 'Invalid or expired server token' },
        '  -> body unchanged'
    );
    count(2);
}

# ===========================================================================
# bastion-cert is not a signed endpoint
# ===========================================================================
{
    $res = call( '/pam/bastion-cert', '{}' );
    is( $res->[0], 400, 'bastion-cert with the Accept header: 400' );
    like( header( $res, 'Content-Type' ),
        qr{^application/json}, '  -> still plain JSON' );
    is(
        from_json( $res->[2]->[0] )->{error},
        'Missing user parameter',
        '  -> unchanged body'
    );

    $res = call( '/pam/bastion-cert', '{}', bearer => undef, nonce => undef );
    is( $res->[0], 401, 'bastion-cert without a bearer: 401' );
    like( header( $res, 'Content-Type' ),
        qr{^application/json}, '  -> plain JSON, and no nonce_required' );
    count(5);
}

# ===========================================================================
# Interplay with request signing (#81): both can claim the X-Nonce
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode} = 'required';
    my $body = to_json( { user => 'dwho' } );
    my $ts   = time;
    my $n    = newNonce();
    my $msg  = join '.', $ts, $n, 'POST', '/pam/userinfo', $body;
    $res = call(
        '/pam/userinfo',
        $body,
        nonce   => $n,
        headers => {
            HTTP_X_TIMESTAMP     => $ts,
            HTTP_X_SIGNATURE_256 => 'sha256='
              . hmac_sha256_hex( $msg, $secret ),
        }
    );
    checkSigned(
        $res, 'signed request + signed answer',
        status   => 200,
        endpoint => 'userinfo',
        nonce    => $n,
        body     => $body,
        aud      => 'pam-access'
    );

    # And a request-signature refusal is itself signed.
    $res = call( '/pam/userinfo', $body );
    is( $res->[0], 403, 'unsigned request in required mode: 403' );
    ok( eval { verifySigned($res) }, '  -> signed refusal' );
    count(2);
}

# ===========================================================================
# Key rotation: the RP's signing-key list is honoured, first key signs, every
# listed key is published — in the JWKS and in the heartbeat's jwks claim.
# ===========================================================================
{
    local $conf->{keys} = {
        'pam-new' => {
            keyPrivate => alt_oidc_key_op_private_sig(),
            keyPublic  => alt_oidc_cert_op_public_sig(),
            keyId      => 'pam-sig-2',
        }
    };
    local $oidc->rpOptions->{'pam-access'}->{oidcRPMetaDataOptionsSigningKey} =
      'pam-new, default-oidc-sig';

    my $body = to_json( { refresh_token => $refresh, hostname => 'h1' } );
    $res = call( '/pam/heartbeat', $body, bearer => undef );
    my ( $h, $c ) = eval { verifySigned($res) };
    ok( $c, 'rotation: the heartbeat verifies against the published JWKS' )
      or diag $@;
    is( $h && $h->{kid}, 'pam-sig-2', '  -> signed by the first listed key' );
    is_deeply(
        [ sort map { $_->{kid} } @{ $c->{jwks}->{keys} } ],
        [ 'pam-sig-1', 'pam-sig-2' ],
        '  -> and its jwks lists both keys'
    );
    count(3);
}

# ===========================================================================
# Fail closed: no symmetric or `none` signature, no typ-less token
# ===========================================================================
{
    for my $alg (qw(HS256 none)) {
        local $conf->{pamAccessResponseSigningAlg} = $alg;
        $res = call( '/pam/whoami', '{}' );
        is( $res->[0], 500, "pamAccessResponseSigningAlg=$alg: 500" );
        like( header( $res, 'Content-Type' ),
            qr{^application/json}, '  -> unsigned' );
        is_deeply(
            from_json( $res->[2]->[0] ),
            { error => 'response_signing_unavailable' },
            '  -> response_signing_unavailable, never the plain answer'
        );
        count(3);
    }

    {
        local $conf->{pamAccessResponseSigningAlg} = 'PS256';
        my ( $h, $c ) = verifySigned( call( '/pam/whoami', '{}' ) );
        is( $h->{alg}, 'PS256', 'pamAccessResponseSigningAlg=PS256 is used' );
        count(1);
    }

    {
        local $oidc->rpOptions->{'pam-access'}
          ->{oidcRPMetaDataOptionsNoJwtHeader} = 1;
        $res = call( '/pam/whoami', '{}' );
        is( $res->[0], 500, 'RP with NoJwtHeader: 500' );
        is(
            from_json( $res->[2]->[0] )->{error},
            'response_signing_unavailable',
            '  -> response_signing_unavailable'
        );
        count(2);
    }

    # A plain caller is not affected by any of this.
    local $conf->{pamAccessResponseSigningAlg} = 'HS256';
    is( call( '/pam/whoami', '{}', plain => 1 )->[0],
        200, 'A broken signing setup does not touch plain answers' );
    count(1);
}

# ===========================================================================
# CORS: the signed answer carries the CORS headers of the plain one, both in
# the configured-policy case and in the portal's own cross-vhost AJAX case
# ===========================================================================
{
    my $cors = sub {
        my ($res) = @_;
        my @h = @{ $res->[1] };
        my %c;
        while ( my ( $k, $v ) = splice @h, 0, 2 ) {
            push @{ $c{ lc $k } }, $v if $k =~ /^Access-Control-/i;
        }
        return \%c;
    };
    for my $case (
        [ 'configured policy', {} ],
        [ 'same-origin AJAX',  { HTTP_ORIGIN => 'http://auth.op.com' } ],
      )
    {
        my ( $label, $hdr ) = @$case;
        my $plain  = call( '/pam/whoami', '{}', plain => 1, headers => $hdr );
        my $signed = call( '/pam/whoami', '{}', headers => $hdr );
        is( header( $signed, 'Content-Type' ),
            $ACCEPT, "CORS ($label): signed" );
        ok( scalar keys %{ $cors->($plain) },
            "CORS ($label): the plain answer has CORS headers" );
        is_deeply( $cors->($signed), $cors->($plain),
            "CORS ($label): the signed answer has the same ones" );
        count(3);
    }
    is(
        $cors->(
            call(
                '/pam/whoami', '{}',
                headers => { HTTP_ORIGIN => 'http://auth.op.com' }
            )
        )->{'access-control-allow-origin'}[0],
        'http://auth.op.com',
        '  -> self-CORS echoes the portal origin'
    );
    count(1);
}

# ===========================================================================
# The fail-closed guard: a handler answering outside _respond must never hand
# an unsigned answer to a caller that asked for a signed one
# ===========================================================================
{
    no warnings qw(redefine once);
    local *Lemonldap::NG::Portal::Plugins::PamAccess::whoami = sub {
        my ( $self, $req ) = @_;
        return $self->p->sendJSONresponse( $req, { escaped => 1 } );
    };

    $res = call( '/pam/whoami', '{}' );
    is( $res->[0], 500, 'A plain answer escaping a signed handler: 500' );
    like( header( $res, 'Content-Type' ),
        qr{^application/json}, '  -> unsigned' );
    is_deeply(
        from_json( $res->[2]->[0] ),
        { error => 'response_signing_unavailable' },
        '  -> response_signing_unavailable, not the escaped body'
    );

    $res = call( '/pam/whoami', '{}', plain => 1 );
    is( $res->[0], 200, '  -> a plain caller is not affected' );
    is_deeply(
        from_json( $res->[2]->[0] ),
        { escaped => 1 },
        '  -> and gets the handler answer as is'
    );

    # The wrapper is the single point of entry: nonce_required still holds
    # for a handler that would never call _startSignedEndpoint itself.
    $res = call( '/pam/whoami', '{}', nonce => undef );
    is( $res->[0], 400, '  -> nonce_required is enforced by the route' );
    count(6);
}

clean_sessions();
done_testing();
