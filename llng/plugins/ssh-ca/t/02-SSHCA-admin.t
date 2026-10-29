use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

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

# Generate two distinct user SSH public keys — dedup by fingerprint means the
# same key signed twice yields a single session record, so we need two keys
# to produce two dwho certs.
my ( $user_pub_key, $user_pub_key2 );
{
    my $tmpdir = tempdir( CLEANUP => 1 );
    for my $i ( 1 .. 2 ) {
        system("ssh-keygen -t ed25519 -f $tmpdir/user_key$i -N '' -q") == 0
          or plan skip_all => "ssh-keygen key generation failed";
    }
    open my $fh, '<', "$tmpdir/user_key1.pub" or die;
    $user_pub_key = <$fh>;
    close $fh;
    chomp $user_pub_key;
    open $fh, '<', "$tmpdir/user_key2.pub" or die;
    $user_pub_key2 = <$fh>;
    close $fh;
    chomp $user_pub_key2;
}

my $tmpdir = tempdir( CLEANUP => 1 );
my $krlPath = "$tmpdir/krl";

# Shared portal configuration. `sshCaAdminRule` is deliberately NOT part of
# it: the last part of this file reuses the same base without a rule to check
# that the administration endpoints default to DENY (issue #58).
my %baseConf = (
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
    sshCaCertMaxValidity  => 365,
    sshCaPrincipalSources => '$uid',
);

# ============================================
# Initialization
# ============================================

# rtyler is the SSH CA administrator here; dwho and french are ordinary
# users (rtyler owns no certificate, so it never appears in the listings).
my $portal = LLNG::Manager::Test->new( {
        ini => {
            %baseConf,
            sshCaAdminRule => q{$uid eq "rtyler"},
        }
    }
);

my $res;

# ============================================
# PART 1: Sign certificates as two different users
# ============================================

# User dwho signs 2 certs
my $id_dwho = $portal->login('dwho');

my @dwho_keys = ( $user_pub_key, $user_pub_key2 );
for my $i ( 1 .. 2 ) {
    my $body = to_json( {
            public_key    => $dwho_keys[ $i - 1 ],
            validity_days => 30,
            label         => "dwho-host$i",
        }
    );
    ok(
        $res = $portal->_post(
            '/ssh/sign',
            IO::String->new($body),
            cookie => "lemonldap=$id_dwho",
            type   => 'application/json',
            length => length($body),
        ),
        "dwho signs cert $i"
    );
    expectJSON($res);
}

# User french signs 1 cert
my $id_french = $portal->login('french');

my $body = to_json( {
        public_key    => $user_pub_key,
        validity_days => 7,
        label         => 'french-host',
    }
);
ok(
    $res = $portal->_post(
        '/ssh/sign',
        IO::String->new($body),
        cookie => "lemonldap=$id_french",
        type   => 'application/json',
        length => length($body),
    ),
    'french signs cert'
);
my $french_cert = expectJSON($res);

# ============================================
# PART 2: A non-admin user is REJECTED by the admin endpoints (issue #58)
#
# dwho is authenticated and owns certificates, but does not match
# sshCaAdminRule. Before the fix, dwho could list every user's certificates
# and revoke french's.
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_dwho",
        accept => 'application/json',
    ),
    'GET /ssh/certs as non-admin dwho'
);
expectReject( $res, 403 );

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_dwho",
        accept => 'application/json',
        query  => 'user=french',
    ),
    'GET /ssh/certs?user=french as non-admin dwho'
);
expectReject( $res, 403 );

# A well-formed revocation of french's certificate must be refused before
# anything is looked up: the answer is 403, not 404/400.
$body = to_json( {
        session_id => 'whatever',
        serial     => $french_cert->{serial},
        reason     => 'pwned',
    }
);
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_dwho",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke as non-admin dwho'
);
expectReject( $res, 403 );

ok(
    $res = $portal->_get(
        '/ssh/admin',
        cookie => "lemonldap=$id_dwho",
        accept => 'text/html',
    ),
    'GET /ssh/admin as non-admin dwho'
);
is( $res->[0], 403, 'Admin interface refused with 403' );
unlike( $res->[2]->[0], qr/sshCaAdminTitle/,
    'Admin interface HTML not rendered' );
count(2);

# The per-user endpoints keep working for the very same non-admin user
ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id_dwho",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts still allowed for non-admin dwho'
);
my $payload = expectJSON($res);
is( scalar @{ $payload->{certificates} },
    2, 'dwho still sees its own 2 certificates' );
count(1);

# ============================================
# PART 3: Admin endpoint - GET /ssh/certs
# ============================================

my $id_admin = $portal->login('rtyler');

# List all certs (no filter)
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
    ),
    'GET /ssh/certs (all) as admin'
);
$payload = expectJSON($res);
ok( exists $payload->{certificates}, 'certificates field exists' );
ok( exists $payload->{total},        'total field exists' );
is( $payload->{total}, 3, 'Total is 3 certificates' );
count(3);

# Filter by user
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'user=dwho',
    ),
    'GET /ssh/certs filtered by user=dwho'
);
$payload = expectJSON($res);
is( $payload->{total}, 2, 'dwho has 2 certificates' );
count(1);

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'user=french',
    ),
    'GET /ssh/certs filtered by user=french'
);
$payload = expectJSON($res);
is( $payload->{total}, 1, 'french has 1 certificate' );
count(1);

# Filter by status
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'status=active',
    ),
    'GET /ssh/certs filtered by status=active'
);
$payload = expectJSON($res);
is( $payload->{total}, 3, 'All 3 are active' );
count(1);

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'status=revoked',
    ),
    'GET /ssh/certs filtered by status=revoked'
);
$payload = expectJSON($res);
is( $payload->{total}, 0, 'None revoked yet' );
count(1);

# Filter by serial
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => "serial=$french_cert->{serial}",
    ),
    'GET /ssh/certs filtered by serial'
);
$payload = expectJSON($res);
is( $payload->{total}, 1, 'Found 1 cert by serial' );
is( $payload->{certificates}->[0]->{user}, 'french',
    'Correct user for serial filter' );
count(2);

# Check cert record fields
my $cert = $payload->{certificates}->[0];
ok( $cert->{session_id}, 'session_id present' );
ok( $cert->{serial},     'serial present' );
ok( $cert->{key_id},     'key_id present' );
ok( $cert->{user},       'user present' );
ok( $cert->{principals}, 'principals present' );
ok( $cert->{issued_at},  'issued_at present' );
ok( $cert->{expires_at}, 'expires_at present' );
is( $cert->{status}, 'active', 'status is active' );
count(8);

# Pagination (limit/offset)
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'limit=2&offset=0',
    ),
    'GET /ssh/certs with limit=2'
);
$payload = expectJSON($res);
is( $payload->{total}, 3, 'Total still 3' );
is( scalar @{ $payload->{certificates} }, 2, 'Got 2 results with limit=2' );
count(2);

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'limit=2&offset=2',
    ),
    'GET /ssh/certs with offset=2'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 1, 'Got 1 result with offset=2' );
count(1);

# ============================================
# PART 4: Revocation
# ============================================

# Get session_id for french's cert
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => "serial=$french_cert->{serial}",
    ),
    'Get french cert session_id'
);
$payload = expectJSON($res);
my $session_id    = $payload->{certificates}->[0]->{session_id};
my $revoke_serial = $french_cert->{serial};

# Revoke - missing parameters
$body = to_json( { serial => $revoke_serial } );
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke without session_id'
);
expectReject( $res, 400 );

$body = to_json( { session_id => $session_id } );
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke without serial'
);
expectReject( $res, 400 );

# Revoke - invalid session
$body = to_json( { session_id => 'nonexistent', serial => '999' } );
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke with invalid session_id'
);
expectReject( $res, 404 );

# Revoke - invalid serial in valid session
$body = to_json( { session_id => $session_id, serial => '999999' } );
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke with invalid serial'
);
expectReject( $res, 404 );

# Revoke - valid revocation
$body = to_json( {
        session_id => $session_id,
        serial     => $revoke_serial,
        reason     => 'Key compromised',
    }
);
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke (valid)'
);
$payload = expectJSON($res);
ok( $payload->{result},      'Revocation successful' );
is( $payload->{serial}, $revoke_serial, 'Revoked correct serial' );
is( $payload->{user},   'french',       'Revoked correct user' );
ok( $payload->{revoked_at},  'revoked_at returned' );
is( $payload->{revoked_by}, 'rtyler', 'revoked_by is the admin rtyler' );
count(5);

# Revoke - already revoked
ok(
    $res = $portal->_post(
        '/ssh/revoke',
        IO::String->new($body),
        cookie => "lemonldap=$id_admin",
        type   => 'application/json',
        length => length($body),
    ),
    'POST /ssh/revoke (already revoked)'
);
expectReject( $res, 400 );

# ============================================
# PART 5: Verify revocation is reflected
# ============================================

# Check certs listing shows revoked status
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => "serial=$revoke_serial",
    ),
    'GET /ssh/certs after revocation'
);
$payload = expectJSON($res);
$cert    = $payload->{certificates}->[0];
is( $cert->{status}, 'revoked', 'Status is revoked' );
ok( $cert->{revoked_at},                 'revoked_at present' );
is( $cert->{revoked_by}, 'rtyler',       'revoked_by is rtyler' );
is( $cert->{revoke_reason}, 'Key compromised', 'Revocation reason preserved' );
count(4);

# Filter by status=revoked
ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'status=revoked',
    ),
    'GET /ssh/certs status=revoked'
);
$payload = expectJSON($res);
is( $payload->{total}, 1, '1 revoked certificate' );
count(1);

ok(
    $res = $portal->_get(
        '/ssh/certs',
        cookie => "lemonldap=$id_admin",
        accept => 'application/json',
        query  => 'status=active',
    ),
    'GET /ssh/certs status=active after revocation'
);
$payload = expectJSON($res);
is( $payload->{total}, 2, '2 active certificates remain' );
count(1);

# Check mycerts for french after re-login shows revoked status
# Revocation updates the persistent session, which is merged into
# the SSO session at login time via setPersistentSessionInfo
my $id_french2 = $portal->login('french');

ok(
    $res = $portal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id_french2",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts as french after re-login'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} }, 1,
    'french still has 1 certificate' );
is( $payload->{certificates}->[0]->{status}, 'revoked',
    'french cert shows as revoked after re-login' );
count(2);

# ============================================
# PART 6: KRL file was updated
# ============================================

ok( -f $krlPath, 'KRL file was created after revocation' );
count(1);

my $krl_size = -s $krlPath;
ok( $krl_size > 0, 'KRL file is not empty' );
count(1);

# GET /ssh/revoked should return the KRL
ok(
    $res = $portal->_get(
        '/ssh/revoked',
        accept => 'application/octet-stream',
    ),
    'GET /ssh/revoked after revocation'
);
expectOK($res);
is( length( $res->[2]->[0] ), $krl_size,
    'KRL response matches file size' );
count(1);

# ============================================
# PART 7: Admin interface
# ============================================

ok(
    $res = $portal->_get(
        '/ssh/admin',
        cookie => "lemonldap=$id_admin",
        accept => 'text/html',
    ),
    'GET /ssh/admin as admin'
);
expectOK($res);
like( $res->[2]->[0], qr/sshCaAdminTitle|SSH Certificate/,
    'Admin interface HTML rendered' );
count(1);

# ============================================
# PART 7b: /ssh/revoke is behind the same cross-site gate (issue #62)
#
# The two self-service routes are covered in 01-SSHCA-mycerts.t; this one
# needs an administrator, so it is pinned here. The point is that the
# refusals below come from the CSRF gate and not from _forbidNonAdmin:
# rtyler IS the administrator in this portal.
# ============================================

{
    my $raw = to_json( { session_id => 'nosuchsession', serial => '404404' } );

    # A cross-site HTML form cannot send application/json, and from_json used
    # to swallow the three content types a form can send.
    ok(
        $res = $portal->_post(
            '/ssh/revoke',
            IO::String->new($raw),
            cookie => "lemonldap=$id_admin",
            type   => 'text/plain',
            length => length($raw),
        ),
        'POST /ssh/revoke with a form content type'
    );
    is( $res->[0], 400, ' ...is refused' );
    count(1);

    # A fetch() from an attacker page, which does set the content type.
    ok(
        $res = $portal->_post(
            '/ssh/revoke',
            IO::String->new($raw),
            cookie => "lemonldap=$id_admin",
            type   => 'application/json',
            length => length($raw),
            custom => { HTTP_ORIGIN => 'https://evil.example.net' },
        ),
        'POST /ssh/revoke from a foreign Origin'
    );
    expectReject( $res, 403, 'Cross-origin request refused' );

    # The portal's own origin passes the gate and reaches the handler, which
    # then fails on the unknown session — a 404, not a 403.
    ok(
        $res = $portal->_post(
            '/ssh/revoke',
            IO::String->new($raw),
            cookie => "lemonldap=$id_admin",
            type   => 'application/json',
            length => length($raw),
            custom => { HTTP_ORIGIN => 'http://auth.example.com' },
        ),
        'POST /ssh/revoke from the portal origin'
    );
    isnt( $res->[0], 403, ' ...passes the cross-site gate' );
    count(1);
}

# ============================================
# PART 8: default DENY when sshCaAdminRule is unset (issue #58)
#
# Same configuration, minus the rule. The endpoints must refuse EVERYONE —
# including rtyler, who is the administrator as soon as the rule is set.
# This is the regression guard: the plugin must never fall back to "any
# authenticated user" just because nothing has been configured.
# ============================================

my $noRulePortal = LLNG::Manager::Test->new( { ini => {%baseConf} } );

for my $who ( [ 'dwho', $id_dwho ], [ 'rtyler', $id_admin ] ) {
    my ( $name, $id ) = @$who;

    ok(
        $res = $noRulePortal->_get(
            '/ssh/certs',
            cookie => "lemonldap=$id",
            accept => 'application/json',
        ),
        "GET /ssh/certs as $name, sshCaAdminRule unset"
    );
    expectReject( $res, 403 );

    $body = to_json( { session_id => $session_id, serial => $revoke_serial } );
    ok(
        $res = $noRulePortal->_post(
            '/ssh/revoke',
            IO::String->new($body),
            cookie => "lemonldap=$id",
            type   => 'application/json',
            length => length($body),
        ),
        "POST /ssh/revoke as $name, sshCaAdminRule unset"
    );
    expectReject( $res, 403 );

    ok(
        $res = $noRulePortal->_get(
            '/ssh/admin',
            cookie => "lemonldap=$id",
            accept => 'text/html',
        ),
        "GET /ssh/admin as $name, sshCaAdminRule unset"
    );
    is( $res->[0], 403, "Admin interface refused with 403 for $name" );
    count(1);
}

# ...while signing and self-service listing still work without any rule
ok(
    $res = $noRulePortal->_get(
        '/ssh/mycerts',
        cookie => "lemonldap=$id_dwho",
        accept => 'application/json',
    ),
    'GET /ssh/mycerts unaffected by sshCaAdminRule'
);
$payload = expectJSON($res);
is( scalar @{ $payload->{certificates} },
    2, 'dwho still sees its own 2 certificates' );
count(1);

clean_sessions();
done_testing();
