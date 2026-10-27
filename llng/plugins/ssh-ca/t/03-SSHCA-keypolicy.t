use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use MIME::Base64;
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempdir);

# Private scratch root for every File::Temp call made in this process, so
# PART 0 can assert that signing leaves nothing behind. It must be set
# before anything calls File::Spec->tmpdir (which caches its answer), hence
# a BEGIN block placed before test-lib is loaded, and a path computed
# textually rather than through File::Spec.
my $TMPHOME;

BEGIN {
    $TMPHOME = ( $ENV{TMPDIR} || '/tmp' ) . "/sshca-policy-t-$$";
    make_path($TMPHOME);
    $ENV{TMPDIR} = $TMPHOME;
}

END {
    remove_tree($TMPHOME) if $TMPHOME && -d $TMPHOME;
}

BEGIN {
    require 't/test-lib.pm';
}

system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';

# ============================================
# Fixtures
# ============================================

# CA key (RSA in PEM, like the other SSHCA test files)
my ( $ca_private_key, $ca_public_key );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmpdir/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system(
        "openssl rsa -in $tmpdir/ca.key -pubout -out $tmpdir/ca.pub 2>/dev/null")
      == 0
      or plan skip_all => "openssl pubkey extraction failed";

    local $/;
    open my $fh, '<', "$tmpdir/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmpdir/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# User keys of every family the policy has an opinion about
my $keydir = tempdir( CLEANUP => 1 );

sub gen_key {
    my ( $name, @args ) = @_;
    system( "ssh-keygen", @args, '-f', "$keydir/$name", '-N', '', '-q' ) == 0
      or plan skip_all => "ssh-keygen key generation failed ($name)";
    open my $fh, '<', "$keydir/$name.pub" or die;
    my $pub = <$fh>;
    close $fh;
    chomp $pub;
    return $pub;
}

my $ed25519 = gen_key( 'ed', '-t', 'ed25519' );
my $rsa1024 = gen_key( 'r1024', '-t', 'rsa', '-b', '1024' );
my $rsa2048 = gen_key( 'r2048', '-t', 'rsa', '-b', '2048' );
my $ecdsa   = gen_key( 'e256',  '-t', 'ecdsa', '-b', '256' );

# SSH wire format helpers: a key blob is a sequence of length-prefixed
# fields (uint32 big-endian length + payload).
sub _s { return pack( 'N', length( $_[0] ) ) . $_[0] }

sub _fields {
    my ($pubkeyLine) = @_;
    my ($b64) = $pubkeyLine =~ /^\s*\S+\s+(\S+)/;
    my $blob = decode_base64($b64);
    my @f  = ();
    my $pos = 0;
    my $len = length $blob;
    while ( $pos + 4 <= $len ) {
        my $n = unpack( 'N', substr( $blob, $pos, 4 ) );
        $pos += 4;
        last if $n > $len - $pos;
        push @f, substr( $blob, $pos, $n );
        $pos += $n;
    }
    return @f;
}

# FIDO2 keys cannot be generated without a security key, but their public
# half is just a blob: build one from real key material so ssh-keygen can
# actually sign it. sk-ssh-ed25519 = type, point, application.
my $sk_ed25519;
{
    my @f = _fields($ed25519);
    my $t = 'sk-ssh-ed25519@openssh.com';
    $sk_ed25519 =
      "$t " . encode_base64( _s($t) . _s( $f[1] ) . _s('ssh:'), '' ) . " fido-ed";
}

# sk-ecdsa-sha2-nistp256 = type, curve name, point, application
my $sk_ecdsa;
{
    my @f = _fields($ecdsa);
    my $t = 'sk-ecdsa-sha2-nistp256@openssh.com';
    $sk_ecdsa =
        "$t "
      . encode_base64( _s($t) . _s( $f[1] ) . _s( $f[2] ) . _s('ssh:'), '' )
      . " fido-ecdsa";
}

# ssh-dss = type, p, q, g, y. Modern ssh-keygen refuses to generate DSA
# keys, and the policy rejects the type before ssh-keygen ever sees it, so
# a structurally valid blob with dummy numbers is enough here.
my $dss;
{
    my $t = 'ssh-dss';
    my $p = "\x80" . ( "\x42" x 127 );    # 1024-bit
    my $q = "\x80" . ( "\x11" x 19 );     # 160-bit
    my $g = "\x02" . ( "\x33" x 127 );
    my $y = "\x7f" . ( "\x55" x 127 );
    $dss =
        "$t "
      . encode_base64( _s($t) . _s($p) . _s($q) . _s($g) . _s($y), '' )
      . " legacy-dsa";
}

# A key whose textual prefix lies about what the blob contains: the policy
# must trust the blob, not the label.
my $mislabelled;
{
    my ($b64) = $ed25519 =~ /^\s*\S+\s+(\S+)/;
    $mislabelled = "ssh-rsa $b64 liar";
}

my $tmpdir  = tempdir( CLEANUP => 1 );
my $krlPath = "$tmpdir/krl";

sub new_portal {
    my (%extra) = @_;
    return LLNG::Manager::Test->new( {
            ini => {
                logLevel       => $debug,
                domain         => 'example.com',
                portal         => 'http://auth.example.com/',
                authentication => 'Demo',
                userDB         => 'Same',
                customPlugins  => '::Plugins::SSHCA',
                sshCaKeyRef    => 'sshca',
                keys           => {
                    sshca => {
                        keyPrivate => $ca_private_key,
                        keyPublic  => $ca_public_key,
                    },
                },
                sshCaKrlPath          => $krlPath,
                sshCaCertMaxValidity  => 30,
                sshCaPrincipalSources => '$uid',

                # /ssh/certs and /ssh/revoke default-deny since the
                # sshCaAdminRule of PR #76 (issue #58): the admin parts of this
                # file need a rule that dwho matches.
                sshCaAdminRule => q{$uid eq "dwho"},
                %extra,
            }
        }
    );
}

my ( $portal, $id, $res, $payload );

sub sign_req {
    my ($body) = @_;
    my $raw = to_json($body);
    return $portal->_post(
        '/ssh/sign',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
    );
}

sub error_of {
    my ($r) = @_;
    my $j = eval { JSON::from_json( $r->[2]->[0] ) };
    return $@ ? '' : ( $j->{error} // '' );
}

$portal = new_portal();
$id     = $portal->login('dwho');

# ============================================
# PART 0: the CA private key must not survive the signing operation
#
# The portal is a long-lived process: File::Temp::tempdir(CLEANUP => 1)
# would only remove the scratch directory at *program* exit, leaving one
# copy of the unencrypted CA key in TMPDIR per /ssh/sign for the worker's
# whole lifetime. Count the scratch root before and after a few signatures.
# ============================================

sub tmp_entries {
    opendir my $dh, $TMPHOME or die "Cannot read $TMPHOME: $!";
    my @e = grep { !/\A\.\.?\z/ } readdir $dh;
    closedir $dh;
    return @e;
}

my $before = scalar tmp_entries();
for my $i ( 1 .. 3 ) {
    my $k = gen_key( "leak$i", '-t', 'ed25519' );
    $res = sign_req( { public_key => $k, label => "leak$i" } );
    is( $res->[0], 200, "leak-check signature $i succeeded" );
}
my @after = tmp_entries();
is( scalar @after, $before,
    'No scratch directory left behind after signing (CA key not leaked)' )
  or diag( "leftover entries: " . join( ', ', @after ) );
count(4);

# ============================================
# PART 1: default policy
#   ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa @ >= 2048 bits
# ============================================

for my $case (
    [ 'ed25519',    $ed25519,    'ssh-ed25519-cert' ],
    [ 'rsa2048',    $rsa2048,    'ssh-rsa-cert' ],
    [ 'ecdsa256',   $ecdsa,      'ecdsa-sha2-nistp256-cert' ],
    [ 'sk-ed25519', $sk_ed25519, 'sk-ssh-ed25519-cert' ],
    [ 'sk-ecdsa',   $sk_ecdsa,   'sk-ecdsa-sha2-nistp256-cert' ],
  )
{
    my ( $label, $key, $certType ) = @$case;
    ok( $res = sign_req( { public_key => $key, label => $label } ),
        "sign $label (allowed by default policy)" );
    $payload = expectJSON($res);
    like( $payload->{certificate}, qr/^\Q$certType\E/,
        "$label certificate is a $certType" );
    count(1);
}

# RSA-1024 is syntactically fine but below the 2048-bit floor
ok(
    $res = sign_req( { public_key => $rsa1024, label => 'weak-rsa' } ),
    'sign RSA-1024'
);
expectReject( $res, 400 );
like( error_of($res), qr/1024 bits/, 'RSA-1024 rejected for its size' );
count(1);

# DSA is not in the default allowlist
ok( $res = sign_req( { public_key => $dss, label => 'dsa' } ), 'sign ssh-dss' );
expectReject( $res, 400 );
like( error_of($res), qr/ssh-dss.*not allowed/,
    'ssh-dss rejected as a disallowed type' );
count(1);

# The blob wins over the announced prefix
ok(
    $res = sign_req( { public_key => $mislabelled, label => 'mislabelled' } ),
    'sign key whose prefix contradicts its blob'
);
expectReject( $res, 400 );
like( error_of($res), qr/Unsupported or malformed/,
    'Prefix/blob mismatch rejected' );
count(1);

# ============================================
# PART 2: validity_days validation
# ============================================

my $vkey = gen_key( 'v', '-t', 'ed25519' );

for my $bad ( 'abc', -5, 0, '3.5', '' ) {
    ok(
        $res = sign_req(
            { public_key => $vkey, label => "v-$bad", validity_days => $bad }
        ),
        "sign with validity_days='$bad'"
    );
    if ( $bad eq '' ) {

        # empty means "unset": the 30-day default applies
        expectJSON($res);
    }
    else {
        expectReject( $res, 400 );
        like( error_of($res), qr/validity_days/,
            "validity_days='$bad' rejected" );
        count(1);
    }
}

# Above the configured maximum (30 days) the request is clamped, not refused
ok(
    $res = sign_req(
        { public_key => $vkey, label => 'v-clamped', validity_days => 3650 }
    ),
    'sign with validity_days=3650 (max is 30)'
);
$payload = expectJSON($res);
ok(
    $payload->{valid_until} =~ /\A\d{4}-\d{2}-\d{2}T/,
    'valid_until is an ISO timestamp'
);
count(1);

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts to check the clamped expiry'
);
$payload = expectJSON($res);
my ($clamped) =
  grep { ( $_->{label} || '' ) eq 'v-clamped' } @{ $payload->{certificates} };
ok( $clamped, 'Clamped certificate present' );
cmp_ok( $clamped->{expires_at} - time(), '<=', 30 * 86400 + 60,
    'validity_days clamped to sshCaCertMaxValidity' );
cmp_ok( $clamped->{expires_at} - time(), '>', 29 * 86400,
    'clamped certificate still lasts ~30 days' );
count(3);

# ============================================
# PART 3: /ssh/certs limit & offset bounds
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/certs (baseline)'
);
$payload = expectJSON($res);
my $total = $payload->{total};
cmp_ok( $total, '>', 1, 'Several certificates issued so far' );
count(1);

for my $q ( 'limit=-1', 'limit=abc', 'limit=-1&offset=-3' ) {
    ok(
        $res = $portal->_get(
            '/ssh/certs',
            cookie => "lemonldap=$id",
            accept => 'application/json',
            query  => $q,
        ),
        "GET /ssh/certs?$q"
    );
    $payload = expectJSON($res);
    is( $payload->{limit}, 100, "$q: limit falls back to 100" );
    is( $payload->{offset}, 0, "$q: offset is never negative" );
    is( scalar @{ $payload->{certificates} },
        $total, "$q: no certificate silently dropped" );
    count(3);
}

# A valid pagination request still works
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id",
        accept => 'application/json',
        query  => 'limit=1&offset=1',
    ),
    'GET /ssh/certs?limit=1&offset=1'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 1, 'limit=1 returns one row' );
is( $payload->{offset}, 1, 'offset echoed back' );
count(2);

# ============================================
# PART 4: revocation reason filtering
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id",
        accept => 'application/json',
        query  => 'status=active',
    ),
    'GET /ssh/certs to pick a revocation target'
);
$payload = expectJSON($res);
my $victim = $payload->{certificates}->[0];
ok( $victim && $victim->{session_id}, 'Got a certificate to revoke' );
count(1);

sub revoke_req {
    my ($body) = @_;
    my $raw = to_json($body);
    return $portal->_post(
        '/ssh/revoke',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
    );
}

for my $bad (
    "compromised\nSSH_CERT_REVOKED fake log line",
    "escape\x1b[31m",
    "x" x 257,
  )
{
    ok(
        $res = revoke_req( {
                session_id => $victim->{session_id},
                serial     => $victim->{serial},
                reason     => $bad,
            }
        ),
        'POST /ssh/revoke with an unsafe reason'
    );
    expectReject( $res, 400 );
    like( error_of($res), qr/Invalid reason/, 'Unsafe reason rejected' );
    count(1);
}

ok(
    $res = revoke_req( {
            session_id => $victim->{session_id},
            serial     => $victim->{serial},
            reason     => '  Key compromised  ',
        }
    ),
    'POST /ssh/revoke with a clean reason'
);
$payload = expectJSON($res);
ok( $payload->{result}, 'Revocation accepted' );
count(1);

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id",
        accept => 'application/json',
        query  => "serial=$victim->{serial}",
    ),
    'GET /ssh/certs for the revoked serial'
);
$payload = expectJSON($res);
is( $payload->{certificates}->[0]->{revoke_reason},
    'Key compromised', 'Reason stored trimmed' );
count(1);

# ============================================
# PART 5: configurable policy
# ============================================

$portal = new_portal(
    sshCaAllowedKeyTypes => 'ed25519, rsa',
    sshCaMinKeyBits      => 1024,
);
$id = $portal->login('french');

ok(
    $res = sign_req( { public_key => $rsa1024, label => 'weak-but-allowed' } ),
    'sign RSA-1024 with sshCaMinKeyBits=1024'
);
expectJSON($res);

ok(
    $res = sign_req( { public_key => $ed25519, label => 'ed-allowed' } ),
    'sign ed25519 with a restricted allowlist'
);
expectJSON($res);

ok(
    $res = sign_req( { public_key => $ecdsa, label => 'ecdsa-blocked' } ),
    'sign ecdsa with an allowlist that excludes it'
);
expectReject( $res, 400 );
like( error_of($res), qr/ecdsa-sha2-nistp256.*not allowed/,
    'ecdsa rejected by the configured allowlist' );
count(1);

ok(
    $res = sign_req( { public_key => $sk_ed25519, label => 'sk-blocked' } ),
    'sign sk-ed25519 with an allowlist that excludes it'
);
expectReject( $res, 400 );
like( error_of($res), qr/sk-ssh-ed25519\@openssh\.com.*not allowed/,
    'sk-ed25519 rejected by the configured allowlist' );
count(1);

clean_sessions();
done_testing();
