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

    # The OpenBao mock lives with the ssh-ca tests.
    our $MOCK = "$FindBin::Bin/../../ssh-ca/t/openbao-lib.pm";
    require $MOCK if -f $MOCK;
}

# Issue #476: /pam/bastion-cert with the ssh-ca signer `openbao`. There is no
# local CA private key then, so the endpoint must ask ssh-ca whether it can
# sign (canSign) rather than look for one, and it must record, log and return
# the serial OpenBao chose, not the one it generated.
#
# The OpenBao mock really signs with ssh-keygen, here with the RSA PEM CA key
# that is pinned in the LLNG configuration as keyPublic.

our $MOCK;
plan skip_all => "ssh-ca test library not found ($MOCK)"
  unless $INC{$MOCK};

system("which ssh-keygen >/dev/null 2>&1") == 0
  or plan skip_all => "ssh-keygen not available";
system("which openssl >/dev/null 2>&1") == 0
  or plan skip_all => "openssl not available";
openbao_lib::deps_ok()
  or plan skip_all => "LWP::Protocol::PSGI / Plack::Request required";
openbao_lib::setup()
  or plan skip_all => "ssh-keygen key generation failed";

my $debug = 'error';
my ( $op, $res );

# --- CA keypair (PEM), held by the mock; only the public half is in LLNG ------
my ( $ca_private_key, $ca_public_key );
my $tmp = tempdir( CLEANUP => 1 );
{
    system(
"openssl genrsa 2048 2>/dev/null | openssl rsa -traditional -out $tmp/ca.key 2>/dev/null"
      ) == 0
      or plan skip_all => "openssl key generation failed";
    system("openssl rsa -in $tmp/ca.key -pubout -out $tmp/ca.pub 2>/dev/null")
      == 0
      or plan skip_all => "openssl pubkey extraction failed";
    local $/;
    open my $fh, '<', "$tmp/ca.key" or die;
    $ca_private_key = <$fh>;
    close $fh;
    open $fh, '<', "$tmp/ca.pub" or die;
    $ca_public_key = <$fh>;
    close $fh;
}
openbao_lib::use_ca_key($ca_private_key);

my $eph_pubkey;
{
    system("ssh-keygen -t ed25519 -f $tmp/eph -N '' -q -C ephemeral-hop") == 0
      or plan skip_all => "ssh-keygen key generation failed";
    open my $fh, '<', "$tmp/eph.pub" or die;
    $eph_pubkey = <$fh>;
    close $fh;
    chomp $eph_pubkey;
}

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
                sshCaKrlPath => "$tmp/revoked_keys",
                keys         => { 'ssh-ca' => { keyPublic => $ca_public_key } },
                sshCaSigner  => 'openbao',
                sshCaOpenBaoUrl      => $openbao_lib::URL,
                sshCaOpenBaoRole     => 'llng-portal',
                sshCaOpenBaoRoleId   => 'portal-role',
                sshCaOpenBaoSecretId => 's3cret-id',

                pamAccessBastionGroups => 'bastion',
                pamAccessSshRules      => { default => '1', bastion => '1' },
                pamAccessBastionCertPinSourceAddress => 1,
                pamAccessBastionCertTtl              => 120,
            }
        }
    ),
    'OP with pam-access + ssh-ca signing through OpenBao'
);

my $sshca = $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::SSHCA'};
ok( $sshca && !$sshca->sshPrivKey, 'ssh-ca loaded without a private key' );
ok( $sshca->canSign,               '  -> but can sign' );

my $id           = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $id );
ok( $server_token, 'Got bastion server token' );

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

$res = bastion_post(
    '/pam/authorize',
    {
        user         => 'french',
        server_group => 'bastion',
        host         => 'b1',
        service      => 'ssh'
    }
);
is( $res->[0], 200, '/pam/authorize 200' );
my $voucher = from_json( $res->[2]->[0] )->{bastion_voucher};
ok( $voucher, '  -> bastion_voucher present' );

my %hop = (
    user         => 'french',
    target_host  => 'backend1.op.com',
    target_group => 'production',
    public_key   => $eph_pubkey,
    voucher      => $voucher,
);

# Audit events, to check which serial is recorded.
my @audit;
{
    no warnings 'redefine';
    my $orig = \&Lemonldap::NG::Common::PSGI::auditLog;
    *Lemonldap::NG::Common::PSGI::auditLog = sub {
        my ( $self, $req, %info ) = @_;
        push @audit, \%info;
        return $orig->( $self, $req, %info );
    };
}

# ============================================================================
# Nominal hop
# ============================================================================
openbao_lib::clear_requests();
my $t_sign = time;
$res = bastion_post( '/pam/bastion-cert', \%hop );
is( $res->[0], 200, 'bastion-cert through OpenBao -> 200' );
my $cert   = from_json( $res->[2]->[0] );
my $signed = $openbao_lib::S{signed}[-1];
ok( $signed, '  -> OpenBao signed it' );
is( $cert->{serial}, $signed->{serial},
    '  -> the response carries the serial OpenBao chose' );
is( $cert->{expires_in}, 120, '  -> expires_in' );
is(
    $cert->{key_id},
    'bastion=pam-access;user=french;target=backend1.op.com',
    '  -> key_id unchanged'
);

my $req = ( grep { $_->{path} =~ m{/sign/} } openbao_lib::requests() )[-1];
is( $req->{body}{ttl},              '120s',          '  -> ttl in seconds' );
is( $req->{body}{valid_principals}, 'french',        '  -> principal' );
is( $req->{body}{key_id},           $cert->{key_id}, '  -> key_id sent' );
is_deeply(
    $req->{body}{critical_options},
    { 'source-address' => '127.0.0.1' },
    '  -> source-address pinned to the bastion'
);

{
    open my $fh, '>', "$tmp/hop-cert.pub" or die;
    print $fh "$cert->{certificate}\n";
    close $fh;
    my $L = `ssh-keygen -L -f $tmp/hop-cert.pub 2>&1`;
    like( $L, qr/Serial: \Q$cert->{serial}\E\n/, '  -> cert carries it' );
    like( $L, qr/source-address\s+127\.0\.0\.1/, '  -> pinned' );
    my $p = $sshca->_parseSshCert(
        MIME::Base64::decode_base64( ( split / /, $cert->{certificate} )[1] ) );
    my $end = $p->{valid_before} - $t_sign;
    ok( $end >= 115 && $end <= 125,
        "  -> expires ~120s after signing (${end}s)" );
}

{
    my $fp  = $sshca->_sshKeyFingerprint($eph_pubkey);
    my $ps  = $op->p->getPersistentSession('french');
    my $rec = from_json( $ps->data->{ "_pamEphCert::" . $fp } // '{}' );
    is( $rec->{serial}, $signed->{serial},
        '  -> the hop record holds the OpenBao serial' );
    my ($ev) =
      grep { ( $_->{code} // '' ) eq 'PAM_BASTION_CERT_ISSUED' } @audit;
    is( $ev && $ev->{serial},
        $signed->{serial}, '  -> and so does the audit event' );
}

# ============================================================================
# Failures: 500, never a locally signed certificate
# ============================================================================
{
    local $openbao_lib::S{fail_sign} =
      [ 503, { errors => ['Vault is sealed'] } ];
    $res = bastion_post( '/pam/bastion-cert', \%hop );
    is( $res->[0], 500, 'OpenBao sealed -> 500' );
    is(
        from_json( $res->[2]->[0] )->{error},
        'Failed to sign certificate',
        '  -> error'
    );
}
{
    local $openbao_lib::S{tamper} = { ca => 'other' };
    $res = bastion_post( '/pam/bastion-cert', \%hop );
    is( $res->[0], 500, 'certificate signed by another CA -> 500' );
}
{
    local $openbao_lib::S{tamper} = { source => '' };
    $res = bastion_post( '/pam/bastion-cert', \%hop );
    is( $res->[0], 500, 'source-address dropped by OpenBao -> 500' );
}
{
    local $openbao_lib::S{tamper} = { ttl => '+1d' };
    $res = bastion_post( '/pam/bastion-cert', \%hop );
    is( $res->[0], 500, 'certificate longer than the hop TTL -> 500' );
}

# The guard is canSign, not the presence of a private key.
{
    no warnings qw(redefine once);
    local *Lemonldap::NG::Portal::Plugins::SSHCA::canSign = sub { 0 };
    $res = bastion_post( '/pam/bastion-cert', \%hop );
    is( $res->[0], 500, 'canSign false -> 500' );
    is(
        from_json( $res->[2]->[0] )->{error},
        'SSH CA not available',
        '  -> SSH CA not available'
    );
}

$res = bastion_post( '/pam/bastion-cert', \%hop );
is( $res->[0], 200, 'back to normal -> 200' );

clean_sessions();
done_testing();
