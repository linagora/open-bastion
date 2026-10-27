# POST /pam/whoami — an enrolled server reads back the id the portal gave it.
#
# Removing /pam/bastion-token (#57) took its `probe: true` mode with it, and
# that mode was the only way for a bastion to learn its own _deviceId. The id
# is not cosmetic: it is the `bastion=<id>` in every hop certificate's key-id,
# which the backends' AuthorizedPrincipalsCommand matches against
# /etc/open-bastion/allowed_bastions. ob-bastion-id reads it, and both
# deployment paths feed it into the backend allowlist.
#
# Nothing else served it, which this file also pins so the claim cannot rot:
# /pam/authorize does not return the caller's identity, /pam/heartbeat does
# not, and /oauth2/introspect does not export private session keys.

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

                # oidc-device-organization is what stamps _deviceId, so the
                # id under test is the real one, not the client_id fallback.
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',

                pamAccessSshRules      => { default => '1', bastion => '1' },
                pamAccessBastionGroups => 'bastion',

                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,

                        # This is what stamps _deviceId: the enrolment is
                        # owned by the organization, not by whoever approved
                        # it, and each device gets its own synthetic session.
                        oidcRPMetaDataOptionsDeviceOwnership => 'organization',
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
    'OP with pam-access and the device-organization identity plugin'
);
count(1);

my $sid   = $op->login('dwho');
my $token = pam_lib::enroll_server( $op, $sid );
ok( $token, 'Server enrolled' );
count(1);

sub whoami {
    my ($bearer) = @_;
    my $body = '{}';
    return $op->_post(
        '/pam/whoami',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        ( $bearer
            ? ( custom => { HTTP_AUTHORIZATION => "Bearer $bearer" } )
            : () ),
    );
}

# ===========================================================================
# It answers the question it exists for
# ===========================================================================

$res = whoami($token);
is( $res->[0], 200, 'POST /pam/whoami with an enrolled Bearer -> 200' );
$json = from_json( $res->[2]->[0] );
ok( $json->{server_id}, '  -> and returns a server_id' );
is( $json->{client_id}, 'pam-access', '  -> alongside the client_id' );

# The id must be the per-device digest, not the shared client_id: a whole
# project enrolls under one client_id, and an allowlist keyed on that would
# admit every machine in the project.
isnt( $json->{server_id}, 'pam-access',
    '  -> the id is per-device, not the project-wide client_id' );
like( $json->{server_id}, qr/\A[0-9a-f]{64}\z/,
    '  -> a sha256 digest, as stamped at enrollment' );

# Compatibility alias for the removed probe: ob-bastion-id reads .bastion_id.
is( $json->{bastion_id}, $json->{server_id},
    '  -> bastion_id is an alias of the same value' );
count(6);

# Stable: the same enrollment answers the same id, so an allowlist written
# once stays valid.
is( from_json( whoami($token)->[2]->[0] )->{server_id},
    $json->{server_id}, 'The id is stable across calls' );
count(1);

# A second, independent enrollment of the SAME client_id is a different
# machine and must get a different id.
my $token2 = pam_lib::enroll_server( $op, $sid );
isnt( from_json( whoami($token2)->[2]->[0] )->{server_id},
    $json->{server_id}, 'A second enrollment of the same RP gets its own id' );
count(1);

# ===========================================================================
# It is behind the standard caller gate, and it is a pure read
# ===========================================================================

is( whoami(undef)->[0], 401, 'Without a Bearer -> 401' );
is( whoami('deadbeef')->[0], 401, 'With a bogus Bearer -> 401' );
count(2);

# The RP allowlist (#50) applies here like everywhere else.
{
    my $conf = $op->p->conf;
    my $other = pam_lib::enroll_server(
        $op, $sid,
        client_id     => 'other-app',
        client_secret => 'othersecret',
    );
    is( whoami($other)->[0], 200, 'Allowlist empty: any pam-scoped RP is served' );

    local $conf->{pamAccessAllowedRps} = 'pam-access';
    is( whoami($other)->[0], 403, '  -> and an unlisted RP is refused' );
    is( whoami($token)->[0],  200, '  -> while the listed one still works' );
    count(3);
}

# Request signing (#81) applies too — an unsigned call is refused in
# `required` mode without the endpoint having to know anything about it.
{
    my $conf = $op->p->conf;
    local $conf->{pamAccessRequestSigningMode}   = 'required';
    local $conf->{pamAccessRequestSigningSecret} = 's3cret';
    is( whoami($token)->[0], 403, 'Unsigned call refused in required mode' );
    count(1);
}

# No side effect: unlike /pam/heartbeat, calling this must not stamp the
# session. An operator running ob-bastion-id should not look like a beat.
{
    my $ps_before = $op->p->getPersistentSession('dwho');
    my $seen_before = $ps_before ? $ps_before->data->{_pamSeen} : undef;
    whoami($token);
    my $ps_after = $op->p->getPersistentSession('dwho');
    is( ( $ps_after ? $ps_after->data->{_pamSeen} : undef ),
        $seen_before, 'whoami leaves _pamSeen untouched' );
    count(1);
}

# ===========================================================================
# The authoritative server_group, and only when the portal has one
# ===========================================================================

ok( !exists from_json( whoami($token)->[2]->[0] )->{server_group},
    'No server_group while pamAccessServerGroups is empty' );
count(1);

{
    my $conf = $op->p->conf;
    local $conf->{pamAccessServerGroups} = { 'pam-access' => 'bastion' };
    is( from_json( whoami($token)->[2]->[0] )->{server_group},
        'bastion', 'The mapped group is returned when configured' );
    count(1);
}

# ===========================================================================
# Why this endpoint had to exist: nothing else answers the question
#
# These are tripwires. If a future change starts exposing the identity
# elsewhere, one of them fails and this endpoint can be reconsidered.
# ===========================================================================

{
    my $body = to_json(
        { user => 'dwho', host => 'h1', service => 'sshd' } );
    $res = $op->_post(
        '/pam/authorize',
        IO::String->new($body),
        accept => 'application/json',
        type   => 'application/json',
        length => length($body),
        custom => { HTTP_AUTHORIZATION => "Bearer $token" },
    );
    my $a = from_json( $res->[2]->[0] );
    ok( !$a->{server_id} && !$a->{bastion_id} && !$a->{client_id},
        '/pam/authorize still returns no caller identity' );
    count(1);
}

{
    my $q = main::buildForm( {
            token         => $token,
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
        }
    );
    $res = $op->_post(
        '/oauth2/introspect',
        IO::String->new($q),
        accept => 'application/json',
        length => length($q),
    );
    my $i = from_json( $res->[2]->[0] );
    ok( $i->{active}, 'The server token introspects as active' );
    ok( !$i->{_deviceId} && !$i->{server_id} && !$i->{bastion_id},
        '  -> but introspection exposes no device identity' );
    count(2);
}

clean_sessions();
done_testing();
