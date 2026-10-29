use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

# Issue #63: /ssh/sign had no rate limit and nothing capped how many
# certificates a user could hold. Every signature forks ssh-keygen twice and
# rewrites the WHOLE KRL, and re-signing the same key appends the superseded
# serial — which the plugin explicitly allows. So a shell loop grew the KRL
# without bound, at a cost per call that grows with the KRL, and every
# appended serial is loaded by every sshd on every backend: a cheap
# authenticated denial of service against the whole fleet.
#
# Two bounds now: sshCaSignMaxPerHour and sshCaMaxCertsPerUser. The KRL is
# bounded by them, without ever refusing to record a revocation (dropping one
# would be a silent fail-open).

system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';

# --- CA keypair --------------------------------------------------------------
my ( $ca_private_key, $ca_public_key );
{
    my $d = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $d/ca.key 2>/dev/null"
    ) == 0
      or plan skip_all => "openssl key generation failed";
    system("openssl rsa -in $d/ca.key -pubout -out $d/ca.pub 2>/dev/null") == 0
      or plan skip_all => "openssl pubkey extraction failed";
    local $/;
    open my $fh, '<', "$d/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$d/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}

# --- a pool of user keys -----------------------------------------------------
my @pub;
{
    my $d = tempdir( CLEANUP => 1 );
    for my $i ( 0 .. 7 ) {
        system("ssh-keygen -t ed25519 -f $d/k$i -N '' -q -C user$i") == 0
          or plan skip_all => "ssh-keygen key generation failed";
        open my $fh, '<', "$d/k$i.pub" or die;
        my $l = <$fh>;
        close $fh;
        chomp $l;
        push @pub, $l;
    }
}

my $krlPath = tempdir( CLEANUP => 1 ) . '/krl';

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

            # Small enough to exercise both bounds in a few calls.
            sshCaSignMaxPerHour  => 4,
            sshCaMaxCertsPerUser => 2,
        }
    }
);

my $id = $portal->login('dwho');

sub sign {
    my ( $key, $label ) = @_;
    my $raw = to_json(
        { public_key => $key, label => $label, validity_days => 1 } );
    return $portal->_post(
        '/ssh/sign',
        IO::String->new($raw),
        cookie => "lemonldap=$id",
        type   => 'application/json',
        length => length($raw),
    );
}

# ============================================================================
# The per-user certificate quota
# ============================================================================

is( sign( $pub[0], 'k0' )->[0], 200, 'first certificate signed' );
is( sign( $pub[1], 'k1' )->[0], 200, 'second certificate signed' );

my $res = sign( $pub[2], 'k2' );
is( $res->[0], 409, 'a third distinct key is refused (quota of 2)' );
my $err = from_json( $res->[2]->[0] );
is( $err->{error}, 'Certificate quota reached', '  -> says why' );
is( $err->{limit}, 2,                           '  -> and reports the limit' );

# A re-signature REPLACES a record, so it never grows the set and must stay
# allowed even at the quota — otherwise a user at the cap could not rotate.
is( sign( $pub[0], 'k0' )->[0],
    200, 'a re-signature of a held key is still allowed at the quota' );

# Revoking frees a slot.
{
    my $raw = to_json( { serial => '' } );
    my $list = expectJSON(
        $portal->_get(
            '/ssh/mycerts',
            cookie => "lemonldap=$id",
            accept => 'application/json',
        )
    );
    my ($victim) =
      grep { ( $_->{status} || '' ) eq 'active' } @{ $list->{certificates} };
    ok( $victim, 'found an active certificate to revoke' );
    $raw = to_json( { serial => $victim->{serial} } );
    is(
        $portal->_post(
            '/ssh/myrevoke',
            IO::String->new($raw),
            cookie => "lemonldap=$id",
            type   => 'application/json',
            length => length($raw),
        )->[0],
        200,
        'revoked one certificate'
    );
}

# ============================================================================
# The per-user hourly rate limit
# ============================================================================

# Four signatures were accepted above (k0, k1, the refused k2 does NOT count
# against the limit only if it was rejected before the counter — it is not:
# the limit is charged first, deliberately, so an abusive caller cannot make
# the portal do the work. So the budget of 4 is already spent.
$res = sign( $pub[3], 'k3' );
is( $res->[0], 429, 'the fifth call in the window is rate limited' );
$err = from_json( $res->[2]->[0] );
is( $err->{error}, 'Rate limit exceeded', '  -> says why' );
is( $err->{limit}, 4,                     '  -> and reports the limit' );
cmp_ok( $err->{retry_after}, '>', 0, '  -> with a usable retry_after' );

my %h = @{ $res->[1] };
ok( $h{'Retry-After'}, '  -> and a Retry-After header' );

# The window is per user: another user still has their own budget.
{
    my $other = $portal->login('french');
    my $raw   = to_json(
        { public_key => $pub[4], label => 'other', validity_days => 1 } );
    is(
        $portal->_post(
            '/ssh/sign',
            IO::String->new($raw),
            cookie => "lemonldap=$other",
            type   => 'application/json',
            length => length($raw),
        )->[0],
        200,
        'the limit is per user, not global'
    );
}

# The counter lives in the user's own session, so it is shared across nodes
# with no extra storage. Both copies (SSO + persistent) carry it, because
# updatePersistentSession writes both and /ssh/sign reads $req->userData.
sub setRate {
    my (%state) = @_;
    my $json = to_json( \%state );
    $_->update( { _sshCaSignRate => $json } )
      for (
        $portal->p->getApacheSession( $id, kind => 'SSO' ),
        $portal->p->getPersistentSession('dwho'),
      );
}

{
    my $ps = $portal->p->getPersistentSession('dwho');
    my $st = from_json( $ps->data->{_sshCaSignRate} );
    is( $st->{count}, 4, 'the counter is kept in the user session' );

    # Roll the window over; the certificate quota is out of the way here.
    setRate( start => time - 3601, count => 4 );
    my $conf = $portal->p->conf;
    local $conf->{sshCaMaxCertsPerUser} = 0;
    is( sign( $pub[0], 'k0' )->[0], 200, 'a new window restores the budget' );
}

# ============================================================================
# 0 disables each bound
# ============================================================================
{
    my $conf = $portal->p->conf;
    local $conf->{sshCaSignMaxPerHour}  = 0;
    local $conf->{sshCaMaxCertsPerUser} = 0;
    is( sign( $pub[5], 'k5' )->[0], 200, '0 disables both bounds' );
    is( sign( $pub[6], 'k6' )->[0], 200, '  -> and keeps disabling them' );
}

# A non-numeric value must not silently disable a limit.
{
    my $conf = $portal->p->conf;
    local $conf->{sshCaSignMaxPerHour}  = 'twenty';
    local $conf->{sshCaMaxCertsPerUser} = 0;
    setRate( start => time, count => 9999 );
    is( sign( $pub[7], 'k7' )->[0],
        429, 'a malformed limit falls back to the default, not to unlimited' );
}

clean_sessions();
done_testing();
