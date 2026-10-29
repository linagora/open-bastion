# Issue #51 — every /pam/* server-to-server endpoint must check the caller's
# scope, not just four of them.
#
# /pam/verify and /pam/userinfo used to stop at the grant-type test, so any
# device-grant token — from any RP, with any scope — could enumerate users
# (groups + every pamAccessExportedVars attribute) through /pam/userinfo, or
# burn a stolen one-time token through /pam/verify.
#
# The token used below is a REAL device-grant token, obtained through the very
# same /oauth2/device flow by another RP of the same portal: only its scope
# differs, which is exactly what the missing gate ignored.

use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
    use FindBin;
    require "$FindBin::Bin/pam-lib.pm";
    pam_lib::install_plugin_templates();
}

my $debug = 'error';
my ( $op, $res, $json );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),
                pamAccessSshRules     => { default => '1' },
                pamAccessExportedVars => { gecos   => 'cn' },

                # A second RP, unrelated to PAM, also allowed to run the
                # device flow — a monitoring agent, a CLI tool, anything.
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    },
                    'other-app' => {
                        oidcRPMetaDataOptionsDisplayName  => 'Other App',
                        oidcRPMetaDataOptionsClientID     => 'other-app',
                        oidcRPMetaDataOptionsClientSecret => 'othersecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    },
                },
            }
        }
    ),
    'OP with PamAccess'
);
count(1);

my $sid = $op->login('dwho');

# Two enrolled servers, same portal, same grant: only the scope differs.
my $good = pam_lib::enroll_server( $op, $sid );
my $bad  = pam_lib::enroll_server(
    $op, $sid,
    client_id     => 'other-app',
    client_secret => 'othersecret',
    scope         => 'profile',
);
ok( $good, 'Enrolled a server with the pam:server scope' );
ok( $bad,  'Enrolled another RP with a non-pam scope' );
count(2);

my $oidc =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
my $badSession = $oidc->getAccessToken($bad);
ok( $badSession, 'Non-pam token session readable' );
my $badScope = $badSession->data->{scope} // '';
is( $badSession->data->{grant_type},
    'device_code', 'Non-pam token IS a device-grant token' );
ok( !( grep { $_ eq 'pam' or $_ eq 'pam:server' } split /\s+/, $badScope ),
    "Non-pam token carries no pam scope ('$badScope')" );
count(3);

# A fresh one-time user token to try to burn
sub new_user_token {
    my $q = 'duration=300';
    my $r = $op->_post(
        '/pam',
        IO::String->new($q),
        accept => 'application/json',
        cookie => "lemonldap=$sid",
        length => length($q),
    );
    die "token generation failed: $r->[0]" unless $r->[0] == 200;
    return from_json( $r->[2]->[0] )->{token};
}

sub post_pam {
    my ( $path, $body, $token ) = @_;
    my $content = to_json($body);
    return $op->_post(
        $path,
        IO::String->new($content),
        accept => 'application/json',
        type   => 'application/json',
        length => length($content),
        custom => { HTTP_AUTHORIZATION => "Bearer $token" },
    );
}

# ===========================================================================
# /pam/verify — a non-pam caller must be refused, and must NOT consume the
# one-time token it presented.
# ===========================================================================

my $user_token = new_user_token();
ok( $user_token, 'Generated a one-time user token' );

ok( $res = post_pam( '/pam/verify', { token => $user_token }, $bad ),
    'POST /pam/verify with a non-pam scoped token' );
is( $res->[0], 403, '  -> HTTP 403' );
$json = from_json( $res->[2]->[0] );
is( $json->{error}, 'Invalid token scope', '  -> Invalid token scope' );
ok( !defined $json->{valid}, '  -> no verdict returned' );
count(4);

# The token was not burned: a properly scoped caller still consumes it.
ok( $res = post_pam( '/pam/verify', { token => $user_token }, $good ),
    'POST /pam/verify with the pam-scoped token' );
expectOK($res);
$json = expectJSON($res);
ok( $json->{valid}, '  -> the one-time token survived the refused call' );
is( $json->{user}, 'dwho', '  -> and identifies the right user' );
count(3);

# ===========================================================================
# /pam/userinfo — a non-pam caller gets no NSS enumeration
# ===========================================================================

ok( $res = post_pam( '/pam/userinfo', { user => 'dwho' }, $bad ),
    'POST /pam/userinfo with a non-pam scoped token' );
is( $res->[0], 403, '  -> HTTP 403' );
$json = from_json( $res->[2]->[0] );
is( $json->{error}, 'Invalid token scope', '  -> Invalid token scope' );
ok( !defined $json->{found},  '  -> no lookup verdict leaked' );
ok( !defined $json->{groups}, '  -> no groups leaked' );
ok( !defined $json->{gecos},  '  -> no exported attribute leaked' );
count(6);

ok( $res = post_pam( '/pam/userinfo', { user => 'dwho' }, $good ),
    'POST /pam/userinfo with the pam-scoped token' );
expectOK($res);
$json = expectJSON($res);
ok( $json->{found}, '  -> the properly scoped caller still gets the user' );
count(2);

# ===========================================================================
# The four endpoints that already gated must keep gating (they now share the
# same helper).
# ===========================================================================

ok(
    $res = post_pam(
        '/pam/authorize',
        { user => 'dwho', host => 'srv1', service => 'sshd' }, $bad
    ),
    'POST /pam/authorize with a non-pam scoped token'
);
is( $res->[0], 403, '  -> HTTP 403' );
is( from_json( $res->[2]->[0] )->{error},
    'Invalid token scope', '  -> Invalid token scope' );
count(3);

ok(
    $res = post_pam(
        '/pam/bastion-cert',
        {
            user       => 'dwho',
            public_key => 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA test',
            voucher    => 'whatever',
        },
        $bad
    ),
    'POST /pam/bastion-cert with a non-pam scoped token'
);
is( $res->[0], 403, '  -> HTTP 403' );
is( from_json( $res->[2]->[0] )->{error},
    'Invalid token scope', '  -> Invalid token scope' );
count(3);

# ===========================================================================
# Scope matching is exact (RFC 6749 §3.3 whitespace-separated tokens). The
# previous /\bpam(?::server)?\b/ accepted 'pam-x' and 'x-pam'.
# ===========================================================================

my $pam = $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
ok( $pam, 'PamAccess plugin loaded' );
ok( $pam->_hasPamScope('pam'),                 "'pam' accepted" );
ok( $pam->_hasPamScope('pam:server'),          "'pam:server' accepted" );
ok( $pam->_hasPamScope('openid pam:server'),   "'pam:server' among others" );
ok( $pam->_hasPamScope("openid\tpam"),         'tab separated scope' );
ok( !$pam->_hasPamScope('pam-x'),              "'pam-x' rejected" );
ok( !$pam->_hasPamScope('x-pam'),              "'x-pam' rejected" );
ok( !$pam->_hasPamScope('pam:server:extra'),   "'pam:server:extra' rejected" );
ok( !$pam->_hasPamScope('pam_server'),         "'pam_server' rejected" );
ok( !$pam->_hasPamScope('openid profile'),     'unrelated scopes rejected' );
ok( !$pam->_hasPamScope(''),                   'empty scope rejected' );
ok( !$pam->_hasPamScope(undef),                'undef scope rejected' );
count(12);

clean_sessions();
done_testing();
