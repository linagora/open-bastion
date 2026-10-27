# Issue #50 — /pam/* accepted ANY device-grant token, and in the default
# configuration took server_group straight from the request body.
#
# `grant_type => device_code` is stamped for every RP using the device flow,
# not just PAM ones, and the core's getAccessToken performs no audience or RP
# check. So a token issued to an unrelated relying party — or, the cheap case,
# a token held by any compromised ordinary host of the same project — reached
# /pam/*. It could then POST {"server_group":"bastion"} to /pam/authorize and
# collect (bastion_id, user) vouchers for users it had never seen. The voucher
# binding is sound and that is exactly the problem: it binds to the ATTACKER's
# device id, which is what gets the hop certificates.
#
# Both halves are gated on pamAccessAllowedRps, which is empty by default so
# an upgrade changes nothing:
#   * the token must have been issued to a listed relying party;
#   * a bastion server_group may no longer be self-declared in the body.

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

                # A second RP of the same portal, also allowed to run the
                # device flow AND granted a pam scope — the shape of an
                # ordinary enrolled host in the same project.
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,

                        # /pam/heartbeat runs the same gate on a REFRESH
                        # token session, which is a different shape — see the
                        # last part of this file.
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsOfflineSessionExpiration => 2592000,
                    },
                    'other-app' => {
                        oidcRPMetaDataOptionsDisplayName  => 'Other App',
                        oidcRPMetaDataOptionsClientID     => 'other-app',
                        oidcRPMetaDataOptionsClientSecret => 'othersecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                    },
                },
                oidcRPMetaDataScopeRules => {
                    'pam-access' => { pam => '1', 'pam:server' => '1' },
                    'other-app'  => { pam => '1', 'pam:server' => '1' },
                },
            }
        }
    ),
    'OP with PamAccess and a second pam-scoped RP'
);
count(1);

my $sid = $op->login('dwho');

my $pam = pam_lib::enroll_server( $op, $sid );
my $other = pam_lib::enroll_server(
    $op, $sid,
    client_id     => 'other-app',
    client_secret => 'othersecret',
);
ok( $pam,   'Enrolled the PAM relying party' );
ok( $other, 'Enrolled an unrelated RP with the same pam scope' );
count(2);

sub authorize {
    my ( $token, %extra ) = @_;
    my $body = to_json(
        { user => 'dwho', host => 'h1', service => 'sshd', %extra } );
    return $op->_post(
        '/pam/authorize',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $token" },
    );
}

# ===========================================================================
# Default configuration: nothing changes
# ===========================================================================

is( authorize($pam)->[0],   200, 'Allowlist empty: the PAM RP is served' );
is( authorize($other)->[0], 200, '  -> and so is any other pam-scoped RP' );

# ... which is the hole: the unrelated RP can call itself a bastion.
$res = authorize( $other, server_group => 'bastion' );
is( $res->[0], 200, '  -> including declaring itself a bastion' );
ok( from_json( $res->[2]->[0] )->{bastion_voucher},
    '  -> and it gets a voucher (this is issue #50)' );
count(4);

# ===========================================================================
# With pamAccessAllowedRps set
# ===========================================================================

my $conf = $op->p->conf;

{
    local $conf->{pamAccessAllowedRps} = 'pam-access';

    is( authorize($pam)->[0], 200, 'Allowlist set: the listed RP is served' );

    $res = authorize($other);
    is( $res->[0], 403, '  -> a token from an unlisted RP is refused' );
    is( from_json( $res->[2]->[0] )->{error},
        'Token is not a PAM token', '  -> and told why' );
    count(3);

    # Every endpoint behind the same gate, not just /pam/authorize.
    my $body = to_json( { token => 'whatever' } );
    for my $path (qw(/pam/verify /pam/userinfo)) {
        $res = $op->_post(
            $path,
            IO::String->new($body),
            accept => 'application/json',
            type   => 'application/json',
            length => length($body),
            custom => { HTTP_AUTHORIZATION => "Bearer $other" },
        );
        is( $res->[0], 403, "  -> $path is behind the same gate" );
        count(1);
    }

    # Second half: with the allowlist on, a bastion group can no longer be
    # self-declared, even by a listed RP. pamAccessServerGroups is empty here,
    # so there is no authoritative source for it.
    $res = authorize( $pam, server_group => 'bastion' );
    is( $res->[0], 403, '  -> a self-declared bastion group is refused' );
    like( from_json( $res->[2]->[0] )->{error},
        qr/may not declare itself/, '  -> and told why' );
    count(2);

    # A non-bastion group is still taken from the body: the legacy path is
    # only closed for the group that grants vouchers.
    $res = authorize( $pam, server_group => 'webservers' );
    is( $res->[0], 200, '  -> an ordinary group is still accepted' );
    ok( !from_json( $res->[2]->[0] )->{bastion_voucher},
        '  -> with no voucher, as before' );
    count(2);
}

# With the map configured, a bastion is named by the portal and works.
{
    local $conf->{pamAccessAllowedRps} = 'pam-access';
    local $conf->{pamAccessServerGroups} = { 'pam-access' => 'bastion' };

    $res = authorize( $pam, server_group => 'bastion' );
    is( $res->[0], 200, 'A mapped bastion is served' );
    ok( from_json( $res->[2]->[0] )->{bastion_voucher},
        '  -> and still gets its voucher' );
    count(2);

    # The unlisted RP cannot borrow it: it is not in the map either.
    $res = authorize( $other, server_group => 'bastion' );
    is( $res->[0], 403, '  -> the unlisted RP still cannot' );
    count(1);
}

# The allowlist accepts the usual separators, and a hashref for programmatic
# configurations.
{
    local $conf->{pamAccessAllowedRps} = 'other-app, pam-access';
    is( authorize($other)->[0], 200, 'Comma-separated list is honoured' );
    count(1);
}
{
    local $conf->{pamAccessAllowedRps} = { 'other-app' => 1 };
    is( authorize($other)->[0], 200, 'A hashref is honoured too' );
    is( authorize($pam)->[0],   403, '  -> and still excludes the rest' );
    count(2);
}

# ===========================================================================
# /pam/heartbeat: the same gate, on a refresh-token session
#
# `rp` is stamped by the core's newAccessToken only. The refresh token the
# device flow mints carries no `rp` at all, and the synthetic session built
# by oidc-device-organization stamps `_clientConfKey` instead. A gate reading
# `rp` alone therefore refused EVERY heartbeat as soon as the allowlist was
# set — every enrolled device would have stopped refreshing at access-token
# expiry. _resolveRp is what the endpoint's own step 5 already used.
# ===========================================================================

my ( $pam_at, $pam_rt ) = pam_lib::enroll_server_tokens(
    $op, $sid,
    scope => 'pam:server offline_access',
);
ok( $pam_rt, 'Enrolled the PAM RP with a refresh token' );
count(1);

sub heartbeat {
    my ($rt) = @_;
    my $body = to_json( { refresh_token => $rt, hostname => 'h1' } );
    return $op->_post(
        '/pam/heartbeat',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
    );
}

is( heartbeat($pam_rt)->[0], 200, 'Heartbeat works with an empty allowlist' );
count(1);

{
    local $conf->{pamAccessAllowedRps} = 'pam-access';
    $res = heartbeat($pam_rt);
    is( $res->[0], 200, 'Heartbeat still works with the RP listed' );
    ok( from_json( $res->[2]->[0] )->{access_token},
        '  -> and returns a fresh access token' );
    count(2);
}

{
    local $conf->{pamAccessAllowedRps} = 'other-app';
    $res = heartbeat($pam_rt);
    is( $res->[0], 403, '  -> and is refused when the RP is not listed' );
    is( from_json( $res->[2]->[0] )->{error},
        'Token is not a PAM token', '  -> with the caller-gate message' );
    count(2);
}

clean_sessions();
done_testing();
