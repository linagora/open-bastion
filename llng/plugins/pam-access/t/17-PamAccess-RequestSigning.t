# Issue #81 (linagora/open-bastion#188) — open-bastion's PAM/NSS client signs
# every call to the portal when `request_signing_secret` is set, and nothing on
# this side ever read the headers. The client signed, nothing checked: the
# replay-protection chain was a no-op that cost bandwidth and bought nothing.
#
# This pins the verifier against the wire format settled by open-bastion#188,
# including the worked example from the issue.

use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use Digest::SHA qw(hmac_sha256_hex);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

my $debug  = 'error';
my $secret = 's3cr3t';
my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules             => { default => '1' },
                pamAccessRequestSigningSecret => $secret,
                pamAccessRequestSigningWindow => 300,

                # Off by default; each block turns it on for itself.
                pamAccessRequestSigningMode => 'off',
            }
        }
    ),
    'OP with PamAccess'
);
count(1);

my $sid   = $op->login('dwho');
my $token = pam_lib::enroll_server( $op, $sid );
ok( $token, 'Enrolled a server' );
count(1);

# ---------------------------------------------------------------------------
# The exact message construction from the issue:
#   <timestamp>.<nonce>.<method>.<path>.<body>
# ---------------------------------------------------------------------------
my $nonce_seq = 0;

sub newNonce {
    $nonce_seq++;
    return sprintf( '%d-3f2a1b4c-9d8e-4f01-b2a3-%012d',
        int( time * 1000 ), $nonce_seq );
}

sub signedPost {
    my (%a) = @_;
    my $path = $a{path} // '/pam/authorize';
    my $body = $a{body}
      // to_json( { user => 'dwho', host => 'h1', service => 'sshd' } );
    my $ts    = $a{ts}    // time;
    my $nonce = $a{nonce} // newNonce();

    my %hdr = ( HTTP_AUTHORIZATION => "Bearer $token" );
    unless ( $a{unsigned} ) {
        my $msg = join '.', $ts, $nonce, 'POST', $path, $body;
        my $sig = $a{sig} // 'sha256=' . hmac_sha256_hex( $msg, $secret );
        %hdr = (
            %hdr,
            HTTP_X_TIMESTAMP     => $ts,
            HTTP_X_NONCE         => $nonce,
            HTTP_X_SIGNATURE_256 => $sig,
        );
    }
    %hdr = ( %hdr, %{ $a{headers} || {} } );

    return $op->_post(
        $path,
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => \%hdr,
    );
}

# ===========================================================================
# The worked example from the issue must produce the documented digest
# ===========================================================================
{
    my $msg = join '.',
      '1757068800',
      '1757068800123-3f2a1b4c-9d8e-4f01-b2a3-5c6d7e8f9a0b',
      'POST', '/pam/authorize', '{"user":"dwho"}';
    is(
        $msg,
'1757068800.1757068800123-3f2a1b4c-9d8e-4f01-b2a3-5c6d7e8f9a0b.POST./pam/authorize.{"user":"dwho"}',
        'The signed message is built as documented'
    );
    is( length hmac_sha256_hex( $msg, $secret ),
        64, '  -> and hashes to 64 hex characters' );
    count(2);
}

# ===========================================================================
# mode = off: the headers are ignored entirely
# ===========================================================================
is( signedPost( unsigned => 1 )->[0], 200, 'off: an unsigned call is served' );
is( signedPost( sig => 'sha256=' . ( '0' x 64 ) )->[0],
    200, 'off: even a wrong signature is ignored' );
count(2);

my $conf = $op->p->conf;

# ===========================================================================
# mode = optional: unsigned passes, badly signed does not
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode} = 'optional';

    is( signedPost( unsigned => 1 )->[0],
        200, 'optional: an unsigned call is still served' );
    is( signedPost()->[0], 200, 'optional: a correctly signed call is served' );

    $res = signedPost( sig => 'sha256=' . ( '0' x 64 ) );
    is( $res->[0], 403, 'optional: a WRONG signature is still refused' );
    is( from_json( $res->[2]->[0] )->{error},
        'Invalid request signature', '  -> and says so' );
    count(4);

    # Half-signed is malformed, not "an old client".
    $res = signedPost( headers => { HTTP_X_NONCE => '' } );
    is( $res->[0], 403, 'optional: a partially signed call is refused' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/Malformed/, '  -> as malformed' );
    count(2);
}

# ===========================================================================
# mode = required
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode} = 'required';

    is( signedPost()->[0], 200, 'required: a correctly signed call is served' );

    $res = signedPost( unsigned => 1 );
    is( $res->[0], 403, 'required: an unsigned call is refused' );
    is( from_json( $res->[2]->[0] )->{error},
        'Request signature required', '  -> and told why' );
    count(3);

    # The timestamp window, checked before the HMAC.
    $res = signedPost( ts => time - 3600 );
    is( $res->[0], 403, 'required: a stale timestamp is refused' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/timestamp/, '  -> as a timestamp problem' );
    $res = signedPost( ts => time + 3600 );
    is( $res->[0], 403, '  -> and so is one from the future' );
    count(3);

    # The nonce is single use.
    my $reused = newNonce();
    is( signedPost( nonce => $reused )->[0],
        200, 'required: a fresh nonce is accepted' );
    $res = signedPost( nonce => $reused );
    is( $res->[0], 403, '  -> replaying it is refused' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/nonce/, '  -> as a nonce problem' );
    count(3);

    # The signature covers the body: same headers, different body.
    {
        my $ts    = time;
        my $n     = newNonce();
        my $body  = to_json( { user => 'dwho', host => 'h1', service => 'sshd' } );
        my $msg   = join '.', $ts, $n, 'POST', '/pam/authorize', $body;
        my $sig   = 'sha256=' . hmac_sha256_hex( $msg, $secret );
        my $other = to_json( { user => 'rtyler', host => 'h1', service => 'sshd' } );
        $res = $op->_post(
            '/pam/authorize',
            IO::String->new($other),
            accept => 'application/json',
            type   => 'application/json',
            length => length($other),
            custom => {
                HTTP_AUTHORIZATION   => "Bearer $token",
                HTTP_X_TIMESTAMP     => $ts,
                HTTP_X_NONCE         => $n,
                HTTP_X_SIGNATURE_256 => $sig,
            },
        );
        is( $res->[0], 403, 'required: swapping the body breaks the signature' );
        count(1);
    }

    # And the path.
    $res = signedPost(
        path => '/pam/userinfo',
        body => to_json( { user => 'dwho' } ),
    );
    is( $res->[0], 200, 'required: another endpoint signs its own path' );
    count(1);

    {
        my $ts   = time;
        my $n    = newNonce();
        my $body = to_json( { user => 'dwho' } );
        my $msg  = join '.', $ts, $n, 'POST', '/pam/authorize', $body;
        $res = $op->_post(
            '/pam/userinfo',
            IO::String->new($body),
            accept => 'application/json',
            type   => 'application/json',
            length => length($body),
            custom => {
                HTTP_AUTHORIZATION   => "Bearer $token",
                HTTP_X_TIMESTAMP     => $ts,
                HTTP_X_NONCE         => $n,
                HTTP_X_SIGNATURE_256 => 'sha256='
                  . hmac_sha256_hex( $msg, $secret ),
            },
        );
        is( $res->[0], 403,
            '  -> a signature for another path does not transfer' );
        count(1);
    }

    # Malformed headers.
    for my $bad (
        [ 'not-hex',            'HTTP_X_SIGNATURE_256' ],
        [ 'sha256=deadbeef',    'HTTP_X_SIGNATURE_256' ],
        [ 'SHA256=' . ( 'a' x 64 ), 'HTTP_X_SIGNATURE_256' ],
      )
    {
        $res = signedPost( headers => { $bad->[1] => $bad->[0] } );
        is( $res->[0], 403, "required: $bad->[1] '$bad->[0]' is refused" );
        count(1);
    }
    $res = signedPost( ts => 'yesterday' );
    is( $res->[0], 403, 'required: a non-numeric timestamp is refused' );
    count(1);
}

# ===========================================================================
# A configured mode with no secret must fail closed, not silently pass
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode}   = 'required';
    local $conf->{pamAccessRequestSigningSecret} = '';
    $res = signedPost();
    is( $res->[0], 403, 'A missing secret refuses instead of waving through' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/misconfigured/, '  -> and says it is a misconfiguration' );
    count(2);
}

# ===========================================================================
# A bad signature must not burn the nonce
#
# _claimNonce WRITES to the shared session store. Claiming before verifying
# the HMAC meant any unauthenticated caller could create one record per
# request — the headers and the timestamp are entirely attacker-controlled —
# and could also invalidate a captured request before its legitimate retry.
# Order is timestamp -> HMAC -> nonce claim.
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode} = 'required';

    my $n = newNonce();

    $res = signedPost( nonce => $n, sig => 'sha256=' . ( 'b' x 64 ) );
    is( $res->[0], 403, 'A wrong signature is refused' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/signature/, '  -> as a signature problem, not a nonce one' );
    count(2);

    # ...and the legitimate holder of the secret can still use that nonce.
    is( signedPost( nonce => $n )->[0],
        200, '  -> and the nonce was not burned by the forgery' );
    count(1);

    # Same for a request that never gets as far as the HMAC.
    my $n2 = newNonce();
    $res = signedPost(
        nonce   => $n2,
        headers => { HTTP_X_SIGNATURE_256 => 'not-hex' }
    );
    is( $res->[0], 403, 'Malformed headers are refused' );
    is( signedPost( nonce => $n2 )->[0],
        200, '  -> without burning the nonce either' );
    count(2);
}

# ===========================================================================
# An unrecognised mode is treated as 'required' (fail closed), loudly
# ===========================================================================
{
    local $conf->{pamAccessRequestSigningMode} = 'optionnal';

    is( signedPost( unsigned => 1 )->[0],
        403, 'A typo in the mode does not wave unsigned requests through' );
    is( signedPost()->[0], 200, '  -> and a signed request still works' );
    count(2);
}

clean_sessions();
done_testing();
