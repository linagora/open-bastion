use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
}

# Issue #455: the administration page shows each certificate's last use, can
# filter and sort on it, and keeps the certificates a re-signature replaced
# (status `superseded`) instead of dropping them. sshca-rebuild-krl collects
# serials through _krlSerialsFromData, which must see the per-key records and
# the superseded ones.

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

# --- user keys ---------------------------------------------------------------
my @pub;
{
    my $d = tempdir( CLEANUP => 1 );
    for my $i ( 0 .. 2 ) {
        system("ssh-keygen -t ed25519 -f $d/k$i -N '' -q -C user$i") == 0
          or plan skip_all => "ssh-keygen key generation failed";
        open my $fh, '<', "$d/k$i.pub" or die;
        my $l = <$fh>;
        close $fh;
        chomp $l;
        push @pub, $l;
    }
}

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
            sshCaKrlPath          => tempdir( CLEANUP => 1 ) . '/krl',
            sshCaCertMaxValidity  => 30,
            sshCaPrincipalSources => '$uid',
            sshCaAdminRule        => q{$uid eq "rtyler"},
            sshCaSignMaxPerHour   => 0,
            sshCaMaxCertsPerUser  => 2,
            sshCaCertHistoryMax   => 2,
        }
    }
);
my $conf   = $portal->p->conf;
my $plugin = $portal->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
ok( $plugin, 'SSH CA plugin loaded' );

no warnings 'once';
my $USE = $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_USE_PREFIX;
my $OLD = $Lemonldap::NG::Portal::Plugins::SSHCA::CERT_OLD_PREFIX;
use warnings 'once';

my $id    = $portal->login('dwho');
my $admin = $portal->login('rtyler');

sub post {
    my ( $path, $data, $cookie ) = @_;
    my $raw = to_json($data);
    return $portal->_post(
        $path,
        IO::String->new($raw),
        cookie => "lemonldap=" . ( $cookie // $id ),
        type   => 'application/json',
        length => length($raw),
    );
}

sub sign {
    my ( $key, $label ) = @_;
    my $res =
      post( '/ssh/sign',
        { public_key => $key, label => $label, validity_days => 1 } );
    return $res->[0] == 200 ? from_json( $res->[2]->[0] ) : $res;
}

sub mycerts {
    return expectJSON(
        $portal->_get(
            '/ssh/mycerts',
            cookie => "lemonldap=$id",
            accept => 'application/json',
        )
    )->{certificates};
}

sub certs {
    my ($query) = @_;
    return $portal->_get(
        '/ssh/certs',
        query  => $query,
        cookie => "lemonldap=$admin",
        accept => 'application/json',
    );
}

sub bySerial { my %h = map { ( $_->{serial} => $_ ) } @{ $_[0] }; \%h }

sub persistent { $portal->p->getPersistentSession('dwho') }


# ============================================================================
# A re-signature keeps the superseded certificate
# ============================================================================

my $c1 = sign( $pub[0], 'k0' );
my $c2 = sign( $pub[0], 'k0' );
ok( $c1->{serial} && $c2->{serial}, 'the same key signed twice' );
my $fp0 = mycerts()->[0]->{fingerprint};

{
    my $l = bySerial( mycerts() );
    is( scalar keys %$l, 2, 'both certificates are listed' );
    is( $l->{ $c2->{serial} }->{status}, 'active', '  -> the new one active' );
    is( $l->{ $c1->{serial} }->{status},
        'superseded', '  -> the old one superseded' );
    is( $l->{ $c1->{serial} }->{superseded_by},
        $c2->{serial}, '  -> by the new serial' );
    ok( $l->{ $c1->{serial} }->{superseded_at}, '  -> with a date' );
    ok( defined persistent()->data->{ $OLD . $c1->{serial} },
        '  -> stored under its serial' );
}

is_deeply( [ $plugin->_krlSerialsFromData( persistent()->data ) ],
    [ $c1->{serial} ], 'the KRL rebuild sees the superseded serial' );

# A superseded record no longer counts against the quota: k0 and k1 are the
# two active certificates, the third key is refused.
is( ref sign( $pub[1], 'k1' ), 'HASH',
    'the superseded certificate does not count against the quota' );
is( sign( $pub[2], 'k2' )->[0], 409, '  -> two active ones do' );

{
    my $res = post( '/ssh/myrevoke', { serial => $c1->{serial} } );
    is( $res->[0], 400, 'a superseded certificate cannot be revoked' );
    is( from_json( $res->[2]->[0] )->{error},
        'Certificate already superseded', '  -> says why' );
}

# ============================================================================
# Bounds of the history
# ============================================================================

my @serials = ( $c1->{serial}, $c2->{serial} );
push @serials, sign( $pub[0], 'k0' )->{serial} for 1 .. 3;
{
    my @old = sort map { $_->{serial} } grep { $_->{status} eq 'superseded' }
      @{ mycerts() };
    is_deeply( \@old, [ sort @serials[ 2, 3 ] ],
        'sshCaCertHistoryMax keeps the most recently superseded' );
    ok( !defined persistent()->data->{ $OLD . $c1->{serial} },
        '  -> and deletes the others' );
}

# A record that expired more than sshCaCertHistoryRetention days ago goes.
# Written in the persistent session only, as another SSO session of the same
# user would: the history is read from there, not from this session's copy.
persistent()->update( {
        $OLD . '77' => to_json( {
                serial        => '77',
                fingerprint   => 'SHA256:old',
                issued_at     => time - 50 * 86400,
                expires_at    => time - 31 * 86400,
                superseded_at => time - 40 * 86400,
                superseded_by => '78',
            }
        )
    }
);
ok( persistent()->data->{ $OLD . '77' }, 'an old superseded record' );
{
    # Room to spare, so that only the retention can drop it.
    local $conf->{sshCaCertHistoryMax} = 50;
    sign( $pub[0], 'k0' );
}
ok( !defined persistent()->data->{ $OLD . '77' },
    '  -> is dropped after the retention period' );

{
    local $conf->{sshCaCertHistoryMax} = 0;
    sign( $pub[0], 'k0' );
    is( scalar( grep { $_->{status} eq 'superseded' } @{ mycerts() } ),
        0, 'sshCaCertHistoryMax = 0 keeps no history' );
}

# ============================================================================
# Last use
# ============================================================================

my ($k1) = grep { $_->{label} eq 'k1' } @{ mycerts() };
my $now = time;

# pam-access writes the stamp in the persistent session only.
persistent()->update( {
        $USE . $k1->{fingerprint} => to_json(
            { serial => $k1->{serial}, at => $now - 100, host => 'srv1' }
        )
    }
);
{
    my $l = bySerial( mycerts() );
    is( $l->{ $k1->{serial} }->{last_used_at},
        $now - 100, 'mycerts shows the last use from the persistent session' );
    is( $l->{ $k1->{serial} }->{last_used_host}, 'srv1', '  -> and where' );
}

# A stamp naming another serial describes another certificate of that key.
persistent()->update( {
        $USE . $k1->{fingerprint} =>
          to_json( { serial => '1', at => $now - 100, host => 'srv1' } )
    }
);
ok( !defined bySerial( mycerts() )->{ $k1->{serial} }->{last_used_at},
    'a stamp for another serial is ignored' );

persistent()->update( {
        $USE . $k1->{fingerprint} => to_json(
            { serial => $k1->{serial}, at => $now - 7200, host => 'srv2' }
        )
    }
);
my $k1b = sign( $pub[1], 'k1' );
{
    my $l = bySerial( mycerts() );
    is( $l->{ $k1->{serial} }->{last_used_at},
        $now - 7200, 'the superseded record keeps its last use' );
    is( $l->{ $k1->{serial} }->{last_used_host}, 'srv2', '  -> and where' );
    ok( !defined $l->{ $k1b->{serial} }->{last_used_at},
        '  -> the new certificate has none' );
}

# ============================================================================
# Administration: filters and sort
# ============================================================================

# One active certificate used 30 s ago, the other (k1, re-signed) never.
my ($k0) = grep { $_->{label} eq 'k0' && $_->{status} eq 'active' }
  @{ mycerts() };
persistent()->update( {
        $USE . $k0->{fingerprint} =>
          to_json( { serial => $k0->{serial}, at => $now - 30, host => 'h0' } )
    }
);

sub serialsOf {
    my ($query) = @_;
    my $res = expectJSON( certs($query) );
    return [ map { $_->{serial} } @{ $res->{certificates} } ];
}

is_deeply(
    serialsOf('status=active&activity=never'),
    [ $k1b->{serial} ],
    'activity=never lists the unused certificate'
);
is_deeply(
    serialsOf('status=active&activity=within:3600'),
    [ $k0->{serial} ],
    'activity=within:3600 lists the one used 30 s ago'
);
is_deeply( serialsOf('status=active&activity=within:10'),
    [], 'activity=within:10 lists nothing' );
is_deeply( serialsOf('status=active&activity=idle:3600'),
    [], 'activity=idle: a certificate issued just now is not idle' );
is_deeply(
    serialsOf('status=superseded&activity=idle:3600'),
    [ $k1->{serial} ],
    'activity=idle lists a certificate last used 2 h ago'
);
is_deeply(
    serialsOf('status=active&sort=last_used'),
    [ $k0->{serial}, $k1b->{serial} ],
    'sort=last_used puts the used certificate first'
);
{
    my $res = expectJSON( certs('status=active') );
    my ($v) = grep { $_->{serial} eq $k0->{serial} } @{ $res->{certificates} };
    is( $v->{last_used_host}, 'h0', 'the listing carries the last use' );
    is( $v->{user},           'dwho', '  -> and the user' );
}

for my $bad (qw(activity=foo activity=idle:abc activity=within: sort=bogus)) {
    is( certs($bad)->[0], 400, "$bad is refused" );
}

done_testing();
