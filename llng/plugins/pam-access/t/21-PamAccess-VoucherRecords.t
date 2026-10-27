# A bastion voucher lives in its own session record, not in a key of the
# user's persistent session.
#
# The move is not a tidy-up. Both previous shapes -- one shared
# `_pamBastionVouchers` map, then one key per bastion (issue #54) -- made
# minting a read-modify-write on a hash the store rewrites wholesale, and no
# plugin can make that atomic: Apache::Session::Lock::Null is installed
# everywhere. Per-key narrowed the losing window; it could not close it, and
# the sweep that kept the keyspace bounded decided from a snapshot, so it
# could delete a nonce another bastion had just refreshed.
#
# What one record per voucher buys, and what this file pins:
#
#   PART 1  nothing is written alongside a voucher, so minting for one bastion
#           does not touch another's record -- there is no shared hash left to
#           lose a write to, and no sweep to get wrong.
#   PART 2  the TTL rides in _utime, so the store's own purge bounds the
#           keyspace instead of the plugin sweeping it.
#   PART 3  a voucher no longer depends on the persistent session: it survives
#           losing it, end to end through /pam/bastion-cert.
#   PART 4  vouchers written before the upgrade are still honoured, and are
#           left where they are (a cluster upgrades node by node).

use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Temp qw(tempdir);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();

    use File::Find;
    use File::Copy;
    use File::Path qw(make_path);
    my $tpl_dir = "$FindBin::Bin/../../ssh-ca/portal-templates";
    if ( -d $tpl_dir ) {
        find(
            {
                wanted => sub {
                    return unless -f $_ && /\.tpl$/;
                    my $rel = $File::Find::name;
                    $rel =~ s{^\Q$tpl_dir/\E}{};
                    my $dst = "site/templates/$rel";
                    make_path( $dst =~ s{/[^/]+$}{}r );
                    File::Copy::copy( $File::Find::name, $dst );
                },
                no_chdir => 1,
            },
            $tpl_dir
        );
    }
}

system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";

my $debug = 'error';
my ( $op, $res );

my ( $ca_priv, $ca_pub );
{
    my $t = tempdir( CLEANUP => 1 );
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $t/ca.key 2>/dev/null"
    ) == 0 or plan skip_all => "openssl genrsa failed";
    system("openssl rsa -in $t/ca.key -pubout -out $t/ca.pub 2>/dev/null") == 0
      or plan skip_all => "openssl rsa -pubout failed";
    local $/;
    open my $fh, '<', "$t/ca.key" or die;
    $ca_priv = <$fh>;
    close $fh;
    open $fh, '<', "$t/ca.pub" or die;
    $ca_pub = <$fh>;
    close $fh;
}

my $eph_pub;
{
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/eph -N '' -q -C hop") == 0
      or plan skip_all => "ssh-keygen failed";
    open my $fh, '<', "$t/eph.pub" or die;
    $eph_pub = <$fh>;
    close $fh;
    chomp $eph_pub;
}

my $krl = tempdir( CLEANUP => 1 ) . "/revoked_keys";

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),

                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::SSHCA',

                sshCaKeyRef  => 'ssh-ca',
                sshCaKrlPath => $krl,
                keys         => {
                    'ssh-ca' => {
                        keyPublic  => $ca_pub,
                        keyPrivate => $ca_priv,
                        keyComment => 'test ssh ca',
                    }
                },

                pamAccessBastionGroups => 'bastion',
                pamAccessSshRules      => { default => '1', bastion => '1' },
            }
        }
    ),
    'OP with pam-access + ssh-ca'
);
count(1);

my $sid          = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Bastion enrolled' );
count(1);

my $BASTION_ID = 'pam-access';    # no organization ownership: the client_id

my $plugin =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
ok( $plugin, 'PamAccess plugin loaded' );
count(1);

sub bastion_post {
    my ( $path, $hash ) = @_;
    my $body = to_json($hash);
    return $op->_post(
        $path,
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $server_token" },
    );
}

sub record { return pam_lib::voucher_session( $op, 'french', $_[0] ) }

# ===========================================================================
# PART 1: one record per (user, bastion) -- minting for one leaves the others
#         untouched
# ===========================================================================

# Minted through the helper directly: what matters here is the storage shape,
# and going through /pam/authorize would only let this test reach one
# bastion_id (the caller's own).
my ( $nonceA, $expA ) = $plugin->_mintBastionVoucher( undef, 'french', 'bA' );
ok( $nonceA, 'a voucher is minted for bastion bA' );

my $beforeB = record('bA')->data;
my %snapshot = map { $_ => $beforeB->{$_} } qw(nonce exp _utime);

my ( $nonceB, $expB ) = $plugin->_mintBastionVoucher( undef, 'french', 'bB' );
ok( $nonceB, 'a voucher is minted for bastion bB' );
isnt( $nonceB, $nonceA, '  -> with its own nonce' );
count(3);

my $afterB = record('bA')->data;
is_deeply(
    { map { $_ => $afterB->{$_} } qw(nonce exp _utime) },
    \%snapshot,
    "minting for another bastion does not write to bA's record"
);
count(1);

# The sweep that could delete a live nonce is gone with the shared hash: an
# expired voucher is simply left for the store's purge, and a mint for another
# bastion never has to decide anything about it.
record('bA')->update( { exp => time - 10 } );
$plugin->_mintBastionVoucher( undef, 'french', 'bB' );
ok( record('bA')->data->{nonce},
    'an expired voucher is not swept by another bastion\'s mint' );
is( $plugin->_checkBastionVoucher(
        $op->p->getPersistentSession('french'), 'french', 'bA', $nonceA
    )->{reason},
    'voucher_expired',
    '  -> it is refused on its own expiry instead'
);
count(2);

# ===========================================================================
# PART 2: the TTL rides in _utime, for the store's purge
# ===========================================================================

{
    my $data    = record('bB')->data;
    my $timeout = $op->p->conf->{timeout} || 72000;
    is( $data->{_utime} + $timeout,
        $data->{exp}, 'the record carries its TTL in _utime for purgeCentralCache' );
    is( $data->{_type}, 'pam_bastion_voucher', '  -> and is typed' );
    is( $data->{_session_kind}, 'PAMVOUCHER', '  -> under its own kind' );
    count(3);
}

# ===========================================================================
# PART 3: the voucher outlives the persistent session it used to live in
# ===========================================================================

$res = bastion_post( '/pam/authorize',
    { user => 'french', host => 'b1', service => 'ssh',
        server_group => 'bastion' } );
is( $res->[0], 200, '/pam/authorize 200' );
my $voucher = from_json( $res->[2]->[0] )->{bastion_voucher};
ok( $voucher, '  -> and mints a voucher' );
count(2);

# Wipe everything the voucher used to depend on.
$op->p->getPersistentSession('french')->remove;
my $wiped = $op->p->getPersistentSession('french');
ok( !( grep { /^_pamVoucher::|^_pamBastionVouchers$/ } keys %{ $wiped->data } ),
    'the persistent session no longer holds anything voucher-shaped' );
count(1);

$res = bastion_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'backend1',
        public_key  => $eph_pub,
        voucher     => $voucher,
    }
);
is( $res->[0], 200, '  -> and the voucher is still honoured' );
ok( from_json( $res->[2]->[0] )->{certificate}, '  -> the hop cert is issued' );
count(2);

# ===========================================================================
# PART 4: pre-upgrade vouchers are read, and left alone
# ===========================================================================

{
    # A session as an older node would have written it: no record, one
    # per-bastion key.
    record($BASTION_ID)->remove;
    my $legacy_nonce = 'legacy-nonce-0001';
    $op->p->getPersistentSession('french')->update( {
            '_pamVoucher::' . $BASTION_ID =>
              to_json( { nonce => $legacy_nonce, exp => time + 3600 } ),
        }
    );

    $res = bastion_post(
        '/pam/bastion-cert',
        {
            user        => 'french',
            target_host => 'backend2',
            public_key  => $eph_pub,
            voucher     => $legacy_nonce,
        }
    );
    is( $res->[0], 200, 'a pre-upgrade voucher is still honoured' );

    # The next mint carries the nonce into a record without disturbing the old
    # key: another node may still be minting into it during a rolling upgrade.
    $res = bastion_post( '/pam/authorize',
        { user => 'french', host => 'b1', service => 'ssh',
            server_group => 'bastion' } );
    is( from_json( $res->[2]->[0] )->{bastion_voucher},
        $legacy_nonce, '  -> and carried forward, not rotated' );
    is( record($BASTION_ID)->data->{nonce},
        $legacy_nonce, '  -> into its own record' );
    ok(
        defined $op->p->getPersistentSession('french')
          ->data->{ '_pamVoucher::' . $BASTION_ID },
        '  -> while the pre-upgrade key is left where it is'
    );
    count(4);
}

clean_sessions();
done_testing();
