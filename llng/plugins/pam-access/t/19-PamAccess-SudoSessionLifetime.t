# Realistic workstation/backend session: several sudo over hours, each paying
# with a fresh one-time PAM token.
#
# pam_openbastion always demands a real token for the sudo services, even
# where authorize_only is set for sshd ("Mode E guarantee that sudo requires a
# fresh LLNG token"). So a user working for a few hours runs, several times:
#
#     POST /pam            -> mint a one-time token (their SSO session)
#     POST /pam/verify     -> the machine burns it (single use, #53/#68)
#     POST /pam/authorize  -> service 'sudo', permissions.sudo_allowed
#
# Two shapes of machine, and the second is where the traps are:
#
#   PART A  an isolated machine / backend reached directly. No SSH
#           certificate is in play, so nothing is bound and nothing expires
#           except the tokens themselves.
#
#   PART B  a backend reached THROUGH a bastion. sshd accepted an ephemeral
#           hop certificate whose own validity is ~2 minutes, and every later
#           sudo in that still-open session re-presents its fingerprint.
#           Acceptance must therefore be gated on the binding window
#           (pamAccessBastionBindingTtl, 24h), not on the certificate's
#           expires_at — gating on the latter broke sudo two minutes into
#           every backend session. t/08 pins that unit-side by editing the
#           stored record; here it is the real flow, over real elapsed time.
#
#   PART C  the token economics the two parts above rely on: single use, and
#           dead once its own duration has passed.

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

# The ephemeral hop key ob-ssh would mint for one connection to backend1.
my ( $eph_pub, $eph_fp );
{
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/eph -N '' -q -C hop") == 0
      or plan skip_all => "ssh-keygen failed";
    open my $fh, '<', "$t/eph.pub" or die;
    $eph_pub = <$fh>;
    close $fh;
    chomp $eph_pub;
    my $out = `ssh-keygen -lf $t/eph.pub 2>/dev/null`;
    ($eph_fp) = $out =~ /(SHA256:[A-Za-z0-9+\/=]+)/;
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
                pamAccessSshRules  => { default => '1', bastion => '1' },
                pamAccessSudoRules => { default => '1', bastion => '1' },

                # A sudo three hours in still mints a token from the user's
                # own SSO session, and the machine still holds its Bearer.
                # Neither is what this file is about, so give both headroom
                # (a real deployment renews them: browser session, and
                # /pam/heartbeat for the machine).
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 604800,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    },
                },
                timeout => 604800,
            }
        }
    ),
    'OP with pam-access + ssh-ca'
);
count(1);

my $sid = $op->login('french');
my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Machine enrolled' );
count(1);

# --- the three calls one sudo makes ------------------------------------------

# The user asks the portal for a one-time token (web UI or `llng pam_token`).
sub mint_token {
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

sub server_post {
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

sub verify_token {
    my ( $token, $fp ) = @_;
    return server_post( '/pam/verify',
        { token => $token, ( defined $fp ? ( fingerprint => $fp ) : () ) } );
}

sub authorize_sudo {
    my ($fp) = @_;
    return server_post(
        '/pam/authorize',
        {
            user         => 'french',
            host         => 'backend1',
            service      => 'sudo',
            server_group => 'default',
            ( defined $fp ? ( fingerprint => $fp ) : () ),
        }
    );
}

# One complete sudo. Returns the three status codes so a failure says which
# of the three calls broke.
sub one_sudo {
    my ($fp) = @_;
    my $token = mint_token();
    return ( 'no-token', 0, 0 ) unless $token;
    my $v = verify_token( $token, $fp );
    my $a = authorize_sudo($fp);
    my $aj = eval { from_json( $a->[2]->[0] ) } || {};
    return (
        $v->[0],
        ( eval { from_json( $v->[2]->[0] )->{valid} } ? 1 : 0 ),
        ( $aj->{authorized} && $aj->{permissions}{sudo_allowed} ) ? 1 : 0,
    );
}

# ===========================================================================
# PART A: isolated machine — sudo every so often, for a working day
# ===========================================================================

for my $h ( 0, 1, 3, 6, 9 ) {
    Time::Fake->offset( $h ? "+${h}h" : "+0s" );
    my ( $vcode, $valid, $sudo ) = one_sudo();
    is( $vcode, 200, "T+${h}h: /pam/verify answers 200" );
    ok( $valid,      "  -> the fresh token is valid" );
    ok( $sudo,       "  -> and sudo is authorized" );
    count(3);
}
Time::Fake->reset();

# ===========================================================================
# PART B: backend behind a bastion — the same, presenting the hop certificate
# ===========================================================================

# The bastion vouches for french and mints the hop certificate. This is the
# ob-ssh flow of t/18, reduced to what registers the ephemeral fingerprint.
$res = server_post(
    '/pam/authorize',
    {
        user         => 'french',
        host         => 'bastion1',
        service      => 'ssh',
        server_group => 'bastion',
    }
);
my $voucher = from_json( $res->[2]->[0] )->{bastion_voucher};
ok( $voucher, 'Bastion login mints a voucher' );

$res = server_post(
    '/pam/bastion-cert',
    {
        user        => 'french',
        target_host => 'backend1',
        public_key  => $eph_pub,
        voucher     => $voucher,
    }
);
is( $res->[0], 200, 'The hop certificate is issued' );
count(2);

# The certificate itself is deliberately short-lived: well under an hour.
my $cert_ttl = from_json( $res->[2]->[0] )->{expires_in};
cmp_ok( $cert_ttl, '<', 3600,
    '  -> and is short-lived, as sshd only needs it at connect time' );
count(1);

# The SSH session it opened, however, lasts. Every sudo in it re-presents the
# same fingerprint, long after the certificate itself has lapsed.
for my $h ( 0, 2, 5, 20 ) {
    Time::Fake->offset( $h ? "+${h}h" : "+0s" );
    my ( $vcode, $valid, $sudo ) = one_sudo($eph_fp);
    is( $vcode, 200, "T+${h}h on the backend: /pam/verify answers 200" );
    ok( $valid, "  -> the hop fingerprint is still accepted" );
    ok( $sudo,  "  -> and sudo is authorized" );
    count(3);
}

# Past pamAccessBastionBindingTtl (24h) the binding is over: the fingerprint
# is no longer known, and the user has to reconnect through the bastion.
Time::Fake->offset("+25h");
{
    my $token = mint_token();
    $res = verify_token( $token, $eph_fp );
    ok( !from_json( $res->[2]->[0] )->{valid},
        'T+25h: the hop binding has lapsed, the fingerprint is refused' );
    count(1);
}
Time::Fake->reset();

# ===========================================================================
# PART C: what makes the loop above safe
# ===========================================================================

# Single use: the token PART A and B burned cannot pay for a second sudo.
{
    my $token = mint_token();
    ok( from_json( verify_token($token)->[2]->[0] )->{valid},
        'A fresh token verifies once' );
    ok( !from_json( verify_token($token)->[2]->[0] )->{valid},
        '  -> and never twice (#53/#68)' );
    count(2);
}

# And a token left unused for longer than its own duration is dead, so
# hoarding tokens at the start of a session is not a way around the loop.
{
    my $token = mint_token();    # duration=300
    Time::Fake->offset("+10m");
    ok( !from_json( verify_token($token)->[2]->[0] )->{valid},
        'A token older than its duration is refused' );
    count(1);
    Time::Fake->reset();
}

clean_sessions();
done_testing();
