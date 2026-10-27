# Realistic bastion session: one login, several ob-ssh hops over hours.
#
# In Open Bastion the voucher is minted ONCE, at bastion login, by
# pam_openbastion's /pam/authorize call, and exported into the PAM environment
# (LLNG_BASTION_VOUCHER). It is never refreshed afterwards: ob-ssh and
# ob-cert-daemon go straight to /pam/bastion-cert and never call
# /pam/authorize again. So the voucher's TTL is, in practice, the maximum
# duration of a usable bastion session.
#
# Issue #55 capped the voucher when NOTHING binds it to the user's SSO
# certificate — pamAccessBastionVoucherUnboundTtl, 15 minutes. That cap must
# not touch the nominal flow, where the user reached the bastion with an
# SSO-issued SSH certificate and the bastion forwards its fingerprint: there
# the voucher is bound to the certificate's own expiry and a multi-hour
# session must keep working.
#
# This file pins both halves with Time::Fake:
#   PART 1  bound voucher   -> hops at +1h, +3h, +7h, +11h all succeed
#   PART 2  the 12h ceiling -> and the hop at +13h does not
#   PART 3  unbound voucher -> 15 minutes, the deliberate #55 trade-off
#   PART 4  the operational escape hatch for fingerprint-less deployments

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

    # ssh-ca ships its own templates; /ssh/sign needs them.
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

# --- SSH CA keypair (PEM) ----------------------------------------------------
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

# --- The user's own SSH key (what they log into the bastion with) ------------
my ( $user_pub, $user_fp );
{
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/user -N '' -q -C french\@laptop") == 0
      or plan skip_all => "ssh-keygen failed";
    open my $fh, '<', "$t/user.pub" or die;
    $user_pub = <$fh>;
    close $fh;
    chomp $user_pub;
    my $out = `ssh-keygen -lf $t/user.pub 2>/dev/null`;
    ($user_fp) = $out =~ /(SHA256:[A-Za-z0-9+\/=]+)/;
}

# --- The ephemeral key a bastion mints per hop -------------------------------
# ob-ssh generates a fresh one for every hop, so the test does too.
sub new_ephemeral_key {
    my $t = tempdir( CLEANUP => 1 );
    system("ssh-keygen -t ed25519 -f $t/eph -N '' -q -C hop") == 0
      or die "ssh-keygen failed";
    open my $fh, '<', "$t/eph.pub" or die;
    my $k = <$fh>;
    close $fh;
    chomp $k;
    return $k;
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

                sshCaKeyRef           => 'ssh-ca',
                sshCaKrlPath          => $krl,
                sshCaCertMaxValidity  => 365,
                sshCaPrincipalSources => '$uid',
                keys                  => {
                    'ssh-ca' => {
                        keyPublic  => $ca_pub,
                        keyPrivate => $ca_priv,
                        keyComment => 'test ssh ca',
                    }
                },

                pamAccessBastionGroups => 'bastion',
                pamAccessSshRules      => { default => '1', bastion => '1' },

                # The bastion's own Bearer token must outlive the scenario:
                # a real bastion keeps it alive with /pam/heartbeat, and the
                # PAM module refreshes it on a 401. Neither is what this file
                # is about — the voucher is. 2 days of headroom isolates it.
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 172800,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    },
                },

                # Same reason: the user's SSO session must not be what expires.
                timeout => 172800,
            }
        }
    ),
    'OP with pam-access + ssh-ca'
);
count(1);

# ---------------------------------------------------------------------------
# The user logs in and holds an SSO-issued SSH certificate, valid 7 days.
# This is what they authenticate to the bastion with.
# ---------------------------------------------------------------------------
my $sid = $op->login('french');

my $signBody =
  to_json(
    { public_key => $user_pub, validity_days => 7, label => 'laptop' } );
ok(
    $res = $op->_post(
        '/ssh/sign',
        IO::String->new($signBody),
        cookie => "lemonldap=$sid",
        type   => 'application/json',
        length => length($signBody),
    ),
    'User signs an SSH certificate (7 days)'
);
is( from_json( $res->[2]->[0] )->{fingerprint},
    $user_fp, '  -> with the expected fingerprint' );
count(2);

my $server_token = pam_lib::enroll_server( $op, $sid );
ok( $server_token, 'Bastion enrolled' );
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

# One ob-ssh hop: fresh ephemeral key, present the login voucher.
# The voucher map lives in the USER's persistent session, keyed by bastion id,
# so each part below uses its own user to start from a clean map.
sub hop {
    my ( $voucher, $user ) = @_;
    return bastion_post(
        '/pam/bastion-cert',
        {
            user        => $user || 'french',
            target_host => 'backend1',
            public_key  => new_ephemeral_key(),
            voucher     => $voucher,
        }
    );
}

sub bastion_login {
    my ( $user, %extra ) = @_;
    return bastion_post(
        '/pam/authorize',
        {
            user         => $user,
            host         => 'bastion1',
            service      => 'ssh',
            server_group => 'bastion',
            %extra,
        }
    );
}

# ===========================================================================
# PART 1: the nominal flow — bastion login with an SSO certificate
# ===========================================================================

$res = bastion_post(
    '/pam/authorize',
    {
        user         => 'french',
        host         => 'bastion1',
        service      => 'ssh',
        server_group => 'bastion',
        fingerprint  => $user_fp,
    }
);
is( $res->[0], 200, 'Bastion login: /pam/authorize 200' );
my $authz = from_json( $res->[2]->[0] );
ok( $authz->{authorized}, '  -> authorized' );
my $voucher = $authz->{bastion_voucher};
ok( $voucher, '  -> a voucher was minted' );

# Bound to the SSO certificate, so the 15-minute unbound cap does NOT apply.
# The ceiling here is pamAccessBastionVoucherTtl (12h), the certificate being
# valid for 7 days.
cmp_ok( $authz->{bastion_voucher_expires_in},
    '>', 900, '  -> and is NOT capped at the unbound 15 minutes' );
cmp_ok( $authz->{bastion_voucher_expires_in},
    '<=', 43200, '  -> the ceiling is the 12h voucher TTL' );
count(5);

# The first hop, immediately after login.
is( hop($voucher)->[0], 200, 'ob-ssh hop at T+0 succeeds' );
count(1);

# ...and the same voucher, hours later, without any new /pam/authorize.
for my $h ( 1, 3, 7, 11 ) {
    Time::Fake->offset("+${h}h");
    my $r = hop($voucher);
    is( $r->[0], 200, "ob-ssh hop at T+${h}h still succeeds" );
    count(1);
}

# ===========================================================================
# PART 2: the 12h ceiling is real
#
# Past pamAccessBastionVoucherTtl the voucher is dead and the user has to
# reconnect to the bastion — which is the intended behaviour, not a
# regression: the voucher is a session-scoped capability, not a credential.
# ===========================================================================

Time::Fake->offset("+13h");
$res = hop($voucher);
is( $res->[0], 403, 'ob-ssh hop at T+13h is refused' );
is( from_json( $res->[2]->[0] )->{reason},
    'voucher_expired', '  -> as voucher_expired' );
count(2);

# A fresh bastion login mints a usable voucher again (same nonce or not, the
# caller only ever uses what /pam/authorize just returned).
$res = bastion_post(
    '/pam/authorize',
    {
        user         => 'french',
        host         => 'bastion1',
        service      => 'ssh',
        server_group => 'bastion',
        fingerprint  => $user_fp,
    }
);
my $voucher2 = from_json( $res->[2]->[0] )->{bastion_voucher};
ok( $voucher2, 'Reconnecting to the bastion mints a fresh voucher' );
is( hop($voucher2)->[0], 200, '  -> and hops work again' );
count(2);

Time::Fake->reset();

# ===========================================================================
# PART 2b: a later unbound login never SHORTENS a live bound voucher
#
# _mintBastionVoucher reuses the nonce already exported into the other live
# shells of the same user on the same bastion, and only ever extends its
# expiry. So a second /pam/authorize that carries no fingerprint does not
# retroactively cut an existing bound voucher down to 15 minutes — which
# would otherwise kill the sessions of a user who happens to reconnect
# without their certificate. The #55 property still holds through the reuse:
# the stored expiry is already <= the certificate's own.
# ===========================================================================

$res = bastion_login( 'french', fingerprint => $user_fp );
my $bound_exp = from_json( $res->[2]->[0] )->{bastion_voucher_expires_in};

$res = bastion_login('french');    # same bastion, no fingerprint this time
my $after = from_json( $res->[2]->[0] );
cmp_ok( $after->{bastion_voucher_expires_in},
    '>', 900, 'An unbound login does not shorten a live bound voucher' );
is( $after->{bastion_voucher}, $voucher2,
    '  -> and reuses the same nonce (other shells keep working)' );
count(2);

# ===========================================================================
# PART 3: no fingerprint — the #55 trade-off, stated explicitly
#
# When the bastion login carried no SSH certificate (token or password auth),
# nothing binds the voucher to an SSO lifetime, and #55 caps it at 15 minutes.
# A hop 20 minutes into such a session is refused where it used to work for
# 12 hours. That is deliberate, but it IS a behaviour change for those
# deployments, so it is pinned here rather than left to be discovered.
#
# dwho holds no SSO certificate and has never been vouched for, so its
# voucher map starts empty — PART 2b showed why that matters.
# ===========================================================================

$res = bastion_login('dwho');
my $unbound  = from_json( $res->[2]->[0] );
my $uvoucher = $unbound->{bastion_voucher};
ok( $uvoucher, 'Fingerprint-less login still mints a voucher' );
cmp_ok( $unbound->{bastion_voucher_expires_in},
    '<=', 900, '  -> capped at 15 minutes (#55)' );
count(2);

is( hop( $uvoucher, 'dwho' )->[0], 200, '  -> a hop at T+0 works' );
count(1);

Time::Fake->offset("+10m");
is( hop( $uvoucher, 'dwho' )->[0], 200, '  -> and at T+10m' );
count(1);

Time::Fake->offset("+20m");
$res = hop( $uvoucher, 'dwho' );
is( $res->[0], 403, '  -> but NOT at T+20m: the session is cut short' );
is( from_json( $res->[2]->[0] )->{reason},
    'voucher_expired', '  -> as voucher_expired' );
count(2);

Time::Fake->reset();

# ===========================================================================
# PART 4: the escape hatch
#
# A deployment that cannot bind fingerprints (no SSO certificates on the
# bastion) raises pamAccessBastionVoucherUnboundTtl. This is the documented
# answer to PART 3, so it is pinned too: the knob has to actually work.
# rtyler is this part's clean-slate user.
# ===========================================================================

{
    my $conf = $op->p->conf;
    local $conf->{pamAccessBastionVoucherUnboundTtl} = 28800;    # 8h

    $res = bastion_login('rtyler');
    my $long = from_json( $res->[2]->[0] );
    cmp_ok( $long->{bastion_voucher_expires_in},
        '>', 900, 'Raising the unbound TTL lifts the 15-minute cap' );
    count(1);

    Time::Fake->offset("+6h");
    is( hop( $long->{bastion_voucher}, 'rtyler' )->[0],
        200, '  -> a fingerprint-less session survives 6 hours' );
    count(1);
    Time::Fake->reset();
}

clean_sessions();
done_testing();
