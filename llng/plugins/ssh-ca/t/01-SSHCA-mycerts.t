use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

# Check ssh-keygen and openssl are available
system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';

# Generate RSA key pair in PEM format for SSH CA
my ( $ca_private_key, $ca_public_key );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmpdir/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system("openssl rsa -in $tmpdir/ca.key -pubout -out $tmpdir/ca.pub 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl pubkey extraction failed";

    local $/;
    open my $fh, '<', "$tmpdir/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmpdir/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# Generate three user SSH keys (ed25519) to cover dedup and uniqueness tests
my ( @user_pubkeys, @user_fps );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    for my $i ( 1 .. 3 ) {
        system("ssh-keygen -t ed25519 -f $tmpdir/k$i -N '' -q -C host$i") == 0
          or plan skip_all => "ssh-keygen key generation failed";
        open my $fh, '<', "$tmpdir/k$i.pub" or die;
        my $pub = <$fh>;
        close $fh;
        chomp $pub;
        push @user_pubkeys, $pub;

        my $fp_line = `ssh-keygen -l -E sha256 -f $tmpdir/k$i.pub`;
        my ($fp) = $fp_line =~ /\b(SHA256:\S+)/;
        push @user_fps, $fp;
    }
}

my $tmpdir = tempdir( CLEANUP => 1 );
my $krlPath = "$tmpdir/krl";

my $portal = LLNG::Manager::Test->new( {
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
        }
    }
);

my $res;

# ============================================
# PART 1: Public endpoints (no auth required)
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/ca',
        accept => 'text/plain',
    ),
    'GET /ssh/ca'
);
expectOK($res);

my $sshPubKey = $res->[2]->[0];
ok( $sshPubKey, 'Got SSH public key' );
like( $sshPubKey, qr/^ssh-rsa\s+/, 'Public key is in SSH RSA format' );
like( $sshPubKey, qr/LLNG-SSH-CA/, 'Public key has LLNG comment' );
count(3);

ok(
    $res = $portal->_get(
        '/ssh/revoked',
        accept => 'application/octet-stream',
    ),
    'GET /ssh/revoked (no revocation yet)'
);
expectOK($res);

# An empty KRL must still be a *valid* KRL (issue #64): sshd cannot parse an
# empty RevokedKeys file as a KRL and silently falls back to the flat key
# file format, which means revocations are not enforced.
like( $res->[2]->[0], qr/\ASSHKRL\n\0/, 'Empty KRL carries the KRL magic' );
is( length( $res->[2]->[0] ), 44, 'Empty KRL is a bare KRL header' );
count(2);

# ============================================
# PART 2: Label validation
# ============================================

my $id = $portal->login('dwho');

# GET /ssh/mycerts before signing - empty
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts before signing'
);
my $payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 0, 'No certificates before signing' );
count(1);

# POST /ssh/sign - missing public_key
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

ok( $res = sign_req( { validity_days => 1 } ), 'sign without public_key' );
expectReject( $res, 400 );

ok(
    $res = sign_req( { public_key => 'not-a-valid-key', label => 'x' } ),
    'sign with invalid public_key'
);
expectReject( $res, 400 );

# Label is mandatory, but falls back to SSH comment: this key has comment "host1",
# so signing WITHOUT an explicit label must succeed (fallback populated).
ok(
    $res = sign_req(
        { public_key => $user_pubkeys[0], validity_days => 1 }
    ),
    'sign without label (falls back to comment)'
);
$payload = expectJSON($res);
is( $payload->{label}, 'host1', 'Label auto-extracted from SSH comment' );
ok( $payload->{fingerprint}, 'Fingerprint returned' );
is( $payload->{fingerprint}, $user_fps[0], 'Returned fingerprint matches computed' );
count(3);

# Sign a key whose comment was stripped and NO label → must fail 400
my $nocomment = $user_pubkeys[1];
$nocomment =~ s/\s+host2$//;
ok(
    $res = sign_req(
        { public_key => $nocomment, validity_days => 1 }
    ),
    'sign without label and no SSH comment'
);
expectReject( $res, 400 );

# ============================================
# PART 3: Label uniqueness (409)
# ============================================

# Sign key #2 with an explicit label
ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[1],
            validity_days => 1,
            label         => 'laptop-alpha',
        }
    ),
    'sign key2 with label laptop-alpha'
);
$payload = expectJSON($res);
is( $payload->{label},       'laptop-alpha', 'Label stored' );
is( $payload->{fingerprint}, $user_fps[1],    'Fingerprint for key2 stored' );
count(2);

# Trying to sign key #3 with the SAME label must fail with 409
ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[2],
            validity_days => 1,
            label         => 'laptop-alpha',
        }
    ),
    'sign key3 with duplicate label rejected'
);
is( $res->[0], 409, 'Duplicate label returns 409' );
count(1);

# Signing key #3 with a different label works
ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[2],
            validity_days => 1,
            label         => 'laptop-beta',
        }
    ),
    'sign key3 with distinct label'
);
$payload = expectJSON($res);
is( $payload->{label}, 'laptop-beta', 'Distinct label stored' );
count(1);

# ============================================
# PART 4: Re-signature dedup (same key → replaces)
# ============================================

# At this point, session contains: host1 (key1), laptop-alpha (key2), laptop-beta (key3)
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts after 3 distinct keys'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 3, 'Three distinct keys stored' );
count(1);

# Re-sign key2 with the SAME label — old serial must be replaced in session
my $prev_serial_key2;
for my $c ( @{ $payload->{certificates} } ) {
    $prev_serial_key2 = $c->{serial} if ( $c->{label} || '' ) eq 'laptop-alpha';
}
ok( $prev_serial_key2, 'Previous serial for laptop-alpha captured' );
count(1);

ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[1],
            validity_days => 1,
            label         => 'laptop-alpha',
        }
    ),
    're-sign key2 with same label (allowed)'
);
my $new_payload = expectJSON($res);
isnt( $new_payload->{serial}, $prev_serial_key2,
    'Re-signature produces a new serial' );
count(1);

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts after re-signature'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 3,
    'Still three records (re-signature replaced, not appended)' );
my @key2_certs =
  grep { ( $_->{fingerprint} || '' ) eq $user_fps[1] } @{ $payload->{certificates} };
is( scalar @key2_certs, 1, 'Exactly one record for key2 fingerprint' );
is( $key2_certs[0]->{serial}, $new_payload->{serial},
    'Record holds the new serial' );
count(3);

# Re-sign key2 yet again, but with a DIFFERENT label — allowed, label updates
ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[1],
            validity_days => 1,
            label         => 'laptop-alpha-renamed',
        }
    ),
    're-sign key2 with renamed label'
);
$payload = expectJSON($res);
is( $payload->{label}, 'laptop-alpha-renamed', 'Label renamed on re-signature' );
count(1);

# KRL must now carry the 2 superseded serials for key2 — sanity check file size grew
ok( -f $krlPath, 'KRL file exists on disk' );
ok( -s $krlPath > 0, 'KRL file is non-empty' );
count(2);

# ============================================
# PART 5: Self-revocation
# ============================================

# Pick the current laptop-alpha-renamed record to self-revoke
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts before self-revoke'
);
$payload = expectJSON($res);
my $target;
for my $c ( @{ $payload->{certificates} } ) {
    $target = $c if ( $c->{label} || '' ) eq 'laptop-alpha-renamed';
}
ok( $target, 'Target record found' );
count(1);

sub myrevoke_req {
    my ($body) = @_;
    my $raw = to_json($body);
    return $portal->_post(
        '/ssh/myrevoke',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
    );
}

ok( $res = myrevoke_req( { serial => $target->{serial} } ),
    'POST /ssh/myrevoke' );
$payload = expectJSON($res);
ok( $payload->{result},     'Self-revocation succeeded' );
ok( $payload->{revoked_at}, 'revoked_at timestamp returned' );
count(2);

# Revoking again must fail with 400
ok(
    $res = myrevoke_req( { serial => $target->{serial} } ),
    're-revoke same serial'
);
is( $res->[0], 400, 'Already-revoked returns 400' );
count(1);

# Revoking non-existent serial → 404
ok(
    $res = myrevoke_req( { serial => '999999' } ),
    'revoke non-existent serial'
);
is( $res->[0], 404, 'Non-existent serial returns 404' );
count(1);

# mycerts must now expose the revoked status
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts after self-revoke'
);
$payload = expectJSON($res);
my ($revoked) =
  grep { ( $_->{serial} || '' ) eq $target->{serial} }
  @{ $payload->{certificates} };
ok( $revoked,                          'Revoked record still present' );
is( $revoked->{status}, 'revoked',     'Status is revoked' );
count(2);

# Revoked labels can be reused for a brand-new key (no longer in the "active"
# uniqueness set). Sign key1 again with the freed-up label.
# Note: key1 was signed in part 2 with label 'host1' (from comment).
# We first drop key1's current session entry by revoking it:
my ($k1) =
  grep { ( $_->{fingerprint} || '' ) eq $user_fps[0] } @{ $payload->{certificates} };
if ( $k1 && !$k1->{revoked_at} ) {
    $res = myrevoke_req( { serial => $k1->{serial} } );
    expectOK($res);
}

# Now reuse the revoked label 'laptop-alpha-renamed' for key1 (different fp)
ok(
    $res = sign_req(
        {
            public_key    => $user_pubkeys[0],
            validity_days => 1,
            label         => 'laptop-alpha-renamed',
        }
    ),
    'reuse revoked label for a different key'
);
$payload = expectJSON($res);
is( $payload->{label}, 'laptop-alpha-renamed',
    'Label accepted after prior revocation' );
count(1);

# ============================================
# PART 6: Cross-session persistence
# ============================================

my $id2 = $portal->login('dwho');
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id2",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts with a fresh SSO session'
);
$payload = expectJSON($res);
ok( scalar @{ $payload->{certificates} } > 0,
    'Certificates persist across SSO sessions' );
count(1);

# ============================================
# PART 7: Isolation between users
# ============================================

my $id3 = $portal->login('french');
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id3",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts as a different user'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 0,
    'Different user has no certificates' );
count(1);

# French signs the SAME key with the same label as dwho — allowed (per-user)
my $body = to_json(
    {
        public_key    => $user_pubkeys[1],
        validity_days => 7,
        label         => 'laptop-alpha',
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id3",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign as french with dwho-style label'
);
$payload = expectJSON($res);
like( $payload->{key_id}, qr/french\@llng-/, 'Key ID contains french username' );
ok( grep( { $_ eq 'french' } @{ $payload->{principals} } ),
    'Principal is french' );
count(2);

# ============================================
# PART 8: Unauthenticated access is rejected
# ============================================

$body = to_json(
    { public_key => $user_pubkeys[0], label => 'x' }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/sign without cookie'
);
ok( $res->[0] != 200, 'Unauthenticated sign request is rejected' );
count(1);

# ============================================
# PART 9: certificates are stored one per key (issue #66)
# ============================================

my $CP = $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_PREFIX;

# Both the SSO session (what /ssh/* reads through $req->userData) and the
# persistent session (what the admin endpoints and pam-access read) hold the
# records; patch them together when simulating a pre-upgrade session.
sub dwho_sessions {
    return (
        $portal->p->getApacheSession( $id, kind => 'SSO' ),
        $portal->p->getPersistentSession('dwho'),
    );
}

{
    my ( $sso, $ps ) = dwho_sessions();
    my @keys = grep { index( $_, $CP ) == 0 } keys %{ $ps->data };
    ok( @keys >= 2, 'certificates live one per key, not in a shared array' );
    ok( !defined $ps->data->{_sshCerts},
        'no _sshCerts array is written any more' );
    ok( ( grep { index( $_, $CP ) == 0 } keys %{ $sso->data } ),
        'the SSO session carries the same per-key records' );
    count(3);
}

# A session written before the upgrade still lists and still revokes, and the
# first write drains its array into per-certificate keys.
{
    my ( $sso, $ps ) = dwho_sessions();

    my ( @legacy, %upd );
    for my $k ( keys %{ $ps->data } ) {
        next unless index( $k, $CP ) == 0;
        push @legacy, from_json( $ps->data->{$k} );
        $upd{$k} = undef;
    }
    my %downgrade = ( %upd, _sshCerts => to_json( \@legacy ) );
    $_->update( {%downgrade} ) for ( $sso, $ps );

    ok(
        $res = $portal->_get(
            '/ssh/mycerts',
            cookie => "lemonldap=$id",
            accept => 'application/json',
        ),
        'GET /ssh/mycerts on a pre-upgrade session'
    );
    my $legacyPayload = expectJSON($res);
    is( scalar @{ $legacyPayload->{certificates} },
        scalar @legacy, '  -> the legacy array is still listed in full' );
    count(1);

    # Any write drains it.
    my ($victim) =
      grep { ( $_->{status} || '' ) eq 'active' }
      @{ $legacyPayload->{certificates} };
    ok( $victim, '  -> found an active certificate to self-revoke' );
    $res = myrevoke_req( { serial => $victim->{serial} } );
    is( $res->[0], 200, '  -> self-revoke on a pre-upgrade session works' );
    count(2);

    my ( undef, $after ) = dwho_sessions();
    ok( !defined $after->data->{_sshCerts},
        '  -> and the legacy array is drained' );
    is(
        scalar( grep { index( $_, $CP ) == 0 } keys %{ $after->data } ),
        scalar @legacy,
        '  -> every record was republished under its own key'
    );
    count(2);

    my $rec = from_json( $after->data->{ $CP . $victim->{fingerprint} } );
    ok( $rec->{revoked_at}, '  -> the revocation was recorded per key' );
    count(1);
}

# ============================================
# PART 10: cross-site POSTs are refused (issue #62)
# ============================================

# What a cross-site HTML form can actually send. A form cannot set
# Content-Type: application/json — only urlencoded, multipart or text/plain —
# and from_json used to swallow all three, so a page on another origin could
# re-sign a victim's public key and KRL-revoke their live certificate.
{
    my $raw = to_json(
        { public_key => $user_pubkeys[0], label => 'csrf', validity_days => 1 }
    );

    for my $ct ( 'text/plain', 'application/x-www-form-urlencoded' ) {
        $res = $portal->_post(
            '/ssh/sign',
            IO::String->new($raw),
            cookie => "lemonldap=$id",
            type   => $ct,
            length => length($raw),
        );
        is( $res->[0], 400, "POST /ssh/sign with Content-Type $ct is refused" );
        count(1);
    }

    # And a JSON body from a foreign Origin, which is what a fetch() from an
    # attacker page looks like once it sets the content type.
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
        custom => { HTTP_ORIGIN => 'https://evil.example.net' },
    );
    is( $res->[0], 403, 'POST /ssh/sign from a foreign Origin is refused' );
    count(1);

    # The portal's own origin still works (the /ssh page posts from there).
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
        custom => { HTTP_ORIGIN => 'http://auth.example.com' },
    );
    is( $res->[0], 200, 'POST /ssh/sign from the portal origin still works' );
    count(1);

    # Same gate on the two revocation routes.
    my $rev = to_json( { serial => '404404' } );
    $res = $portal->_post(
        '/ssh/myrevoke',
        IO::String->new($rev),
        cookie => "lemonldap=$id",
        type   => 'text/plain',
        length => length($rev),
    );
    is( $res->[0], 400, 'POST /ssh/myrevoke with a form content type is refused' );
    count(1);
}

clean_sessions();
done_testing();
