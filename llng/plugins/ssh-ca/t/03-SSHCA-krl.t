#
# KRL integrity tests for the SSH CA plugin.
#
#   - issue #59: the KRL was rewritten in place (ssh-keygen opens -f with
#     O_TRUNC) with no lock shared between the portal workers and the
#     sshca-rebuild-krl cron job. A KRL truncated mid-write keeps a valid
#     `SSHKRL` magic, and sshd then fails CLOSED on every key it checks
#     ("incomplete message") — a full SSH lockout of the host.
#   - issue #64: a missing KRL was served as an empty body, and the file was
#     served without ever checking the magic.
#   - issue #65: the broker revocation handler passed its serial straight into
#     the ssh-keygen KRL spec file, where a newline injects extra directives.
#
use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use POSIX ();
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

my $tmpdir  = tempdir( CLEANUP => 1 );
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

my $plugin =
  $portal->p->_loadedPlugins->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
ok( $plugin, 'SSHCA plugin instance retrieved' );
count(1);

my $res;

sub slurp {
    my ($path) = @_;
    open my $fh, '<:raw', $path or return undef;
    local $/;
    my $d = <$fh>;
    close $fh;
    return $d;
}

sub spew {
    my ( $path, $data ) = @_;
    open my $fh, '>:raw', $path or die "cannot write $path: $!";
    print $fh $data;
    close $fh;
}

sub getKrl {
    return $portal->_get( '/ssh/revoked', accept => 'application/octet-stream' );
}

# `ssh-keygen -Q -l -f` is the authoritative parser: it is what tells us
# whether sshd would accept the file. Available since OpenSSH 8.2.
sub krlSerials {
    my ($path) = @_;
    my $out = `ssh-keygen -Q -l -f "$path" 2>&1`;
    return undef if $?;
    my %s;

    # Contiguous serials are stored (and printed) as a range
    while ( $out =~ /^serial:\s*(\d+)(?:-(\d+))?\s*$/mg ) {
        my ( $from, $to ) = ( $1, defined $2 ? $2 : $1 );
        $s{$_} = 1 for $from .. $to;
    }
    return \%s;
}

my $canListKrl = defined krlSerials($krlPath);

# =============================================================================
# PART 1: a valid, empty KRL exists from the start (issue #64)
# =============================================================================

ok( -f $krlPath, 'KRL file generated at plugin init' );
my $empty = slurp($krlPath);
is( substr( $empty, 0, 8 ), "SSHKRL\n\0", 'Generated KRL carries the magic' );
is( length($empty), 44, 'Generated KRL is a bare header' );
count(3);

ok( $res = getKrl(), 'GET /ssh/revoked with no revocation' );
expectOK($res);
is( $res->[2]->[0], $empty, 'Empty KRL served verbatim, not as an empty body' );
count(1);

SKIP: {
    skip 'ssh-keygen -Q -l not supported', 1 unless $canListKrl;
    my $serials = krlSerials($krlPath);
    ok( $serials && !%$serials, 'ssh-keygen parses the empty KRL, 0 serials' );
    count(1);
}

# =============================================================================
# PART 2: serial validation (issue #65)
# =============================================================================

ok( $plugin->_validSerial('1'),                    'serial "1" accepted' );
ok( $plugin->_validSerial('18446744073709551615'), 'max uint64 accepted' );
ok( !$plugin->_validSerial(undef),                 'undef serial rejected' );
ok( !$plugin->_validSerial(''),                    'empty serial rejected' );
ok( !$plugin->_validSerial('12a'),                 'non-decimal rejected' );
ok( !$plugin->_validSerial(' 12'),                 'padded serial rejected' );
ok( !$plugin->_validSerial('123456789012345678901'), 'over-long rejected' );
ok( !$plugin->_validSerial("12\nid: root"),  'newline injection rejected' );
ok( !$plugin->_validSerial("12\nkey: ssh-ed25519 AAAA"),
    'key directive injection rejected' );
count(9);

# The injection payload must never reach the ssh-keygen spec file.
my $before = slurp($krlPath);
ok( !$plugin->_updateKrl("42\nid: injected\nhash: SHA256:x"),
    '_updateKrl refuses a serial carrying KRL directives' );
is( slurp($krlPath), $before, 'KRL untouched by the rejected update' );
count(2);

# Same through the broker handler, which is the one path that does not match
# the serial against a stored certificate record first.
my $action = Lemonldap::NG::Handler::Main::MsgActions::msgActions()
  ->{sshCaRevoke};
ok( $action, 'sshCaRevoke broker action registered' );
$action->( 'Lemonldap::NG::Handler::Main', { serial => "7\nid: everyone" },
    undef );
is( slurp($krlPath), $before, 'KRL untouched by a poisoned broker event' );
count(2);

# ... while a well-formed broker event still works.
$action->( 'Lemonldap::NG::Handler::Main', { serial => '4242' }, undef );
isnt( slurp($krlPath), $before, 'Legitimate broker event updates the KRL' );
count(1);

SKIP: {
    skip 'ssh-keygen -Q -l not supported', 2 unless $canListKrl;
    my $serials = krlSerials($krlPath);
    ok( $serials, 'KRL still parses after the broker events' );
    is_deeply( [ sort keys %$serials ], ['4242'],
        'Only the legitimate serial was revoked' );
    count(2);
}

# =============================================================================
# PART 3: a corrupted KRL is never served (issue #59)
# =============================================================================

# Build a KRL with a few serials so it has real sections to truncate.
ok( $plugin->_updateKrl($_), "revoke serial $_" ) for qw(1001 1002 1003);
count(3);

my $good = slurp($krlPath);
ok( length($good) > 44, 'KRL grew past the bare header' );
count(1);

ok( $res = getKrl(), 'GET /ssh/revoked with revoked serials' );
expectOK($res);
is( $res->[2]->[0], $good, 'Valid KRL served byte for byte' );
count(1);

# A KRL truncated mid-write: the magic is intact, so the consumer-side
# `head -c 6 | grep SSHKRL` gate lets it through — and sshd then refuses
# EVERY key with "incomplete message".
my $truncated = substr( $good, 0, 60 );
is( substr( $truncated, 0, 6 ), 'SSHKRL',
    'Truncated KRL still passes a magic-only check' );
count(1);

SKIP: {
    skip 'ssh-keygen -Q -l not supported', 1 unless $canListKrl;
    spew( "$tmpdir/probe", $truncated );
    ok( !defined krlSerials("$tmpdir/probe"),
        'ssh-keygen rejects the truncated KRL (this is what locks sshd out)' );
    count(1);
}

spew( $krlPath, $truncated );
ok( $res = getKrl(), 'GET /ssh/revoked with a truncated KRL' );
is( $res->[0], 500, 'Truncated KRL is not served' );
count(2);

# Header intact, body garbage
spew( $krlPath, "SSHKRL\n\0" . ( "\xff" x 100 ) );
ok( $res = getKrl(), 'GET /ssh/revoked with a corrupted KRL body' );
is( $res->[0], 500, 'Corrupted KRL is not served' );
count(2);

# A corrupted KRL must not be merged into either: `ssh-keygen -u` cannot read
# it, and rebuilding from the single spec would silently drop every serial
# already revoked. Repair goes through sshca-rebuild-krl (update => 0).
my $corrupted = slurp($krlPath);
ok( !$plugin->_updateKrl('1234'), '_updateKrl refuses to merge into a corrupted KRL' );
is( slurp($krlPath), $corrupted, 'Corrupted KRL left untouched' );
count(2);

{
    my $spec = "$tmpdir/repair_spec";
    spew( $spec, "serial: 1001\nserial: 1002\n" );
    ok( $plugin->_writeKrl( $krlPath, spec => $spec, update => 0 ),
        'A full rewrite repairs a corrupted KRL' );
    ok( $plugin->_krlIsValid( slurp($krlPath) ), 'Repaired KRL is valid' );
    count(2);
}

# A zero-length KRL is regenerated rather than served as an empty body
spew( $krlPath, '' );
ok( $res = getKrl(), 'GET /ssh/revoked with a zero-length KRL' );
expectOK($res);
is( length( $res->[2]->[0] ), 44, 'Zero-length KRL regenerated as empty KRL' );
count(1);

# Put the good KRL back and check the endpoint recovers
spew( $krlPath, $good );
ok( $res = getKrl(), 'GET /ssh/revoked after restoring the KRL' );
expectOK($res);
is( $res->[2]->[0], $good, 'Endpoint serves the KRL again' );
count(1);

# =============================================================================
# PART 4: the live KRL is replaced atomically (issue #59)
# =============================================================================

my $inodeBefore = ( stat $krlPath )[1];
ok( $plugin->_updateKrl('2001'), 'revoke serial 2001' );
my $inodeAfter = ( stat $krlPath )[1];
isnt( $inodeAfter, $inodeBefore,
    'KRL is replaced by rename(), not truncated in place' );
count(2);

opendir my $dh, $tmpdir or die $!;
my @leftovers = grep { /^\.krl\.tmp/ } readdir $dh;
closedir $dh;
is( scalar @leftovers, 0, 'No scratch KRL left behind' );
count(1);

# =============================================================================
# PART 5: concurrent writers do not lose revocations, and readers never
#         observe a half-written KRL (issue #59)
# =============================================================================

SKIP: {
    skip 'ssh-keygen -Q -l not supported', 3 unless $canListKrl;

    # Non-contiguous, so that each one shows up as its own KRL entry
    my @serials = map { 3000 + $_ * 7 } ( 1 .. 8 );
    my @pids;
    for my $s (@serials) {
        my $pid = fork();
        die "fork failed: $!" unless defined $pid;
        unless ($pid) {

            # Child: only touches the KRL file, never the session store.
            $plugin->_updateKrl($s);
            POSIX::_exit(0);
        }
        push @pids, $pid;
    }

    # While the children write, keep reading the live file: with the
    # temp-file + rename install, every single read must be a complete KRL.
    my ( $reads, $torn ) = ( 0, 0 );
    while ( waitpid( -1, POSIX::WNOHANG() ) >= 0 ) {
        my $data = slurp($krlPath);
        $reads++;
        $torn++ unless $plugin->_krlIsValid($data);
        last if $reads > 20000;
    }
    waitpid( $_, 0 ) for @pids;

    ok( $reads > 0, "read the live KRL $reads time(s) during the writes" );
    is( $torn, 0, 'Never observed a partially written KRL' );

    my $serials = krlSerials($krlPath);
    my @missing = grep { !$serials->{$_} } @serials;
    is_deeply( \@missing, [],
        'No revocation lost by concurrent _updateKrl calls' );
    count(3);
}

clean_sessions();
done_testing();
