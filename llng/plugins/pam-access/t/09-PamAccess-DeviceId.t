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

# With oidc-device-organization, each enrolled device gets its own synthetic
# session whose id is stamped as `_deviceId` into the tokens. PamAccess then uses
# that as the bastion_id — so a single project-wide client_id still yields a
# UNIQUE identifier per bastion (what a backend allowlist pins on). This test
# proves the device-id is present, distinct from the shared client_id, and unique
# per enrollment.

my $debug = 'error';
my ( $op, $res );

ok(
    $op = LLNG::Manager::Test->new( {
            ini => {
                logLevel => $debug,
                domain   => 'op.com',
                portal   => 'http://auth.op.com',
                pam_lib::base_config(),

                # Add device-organization on top of base_config's plugins.
                customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',

                # Make the RP organization-owned so enrollment stamps a per-device
                # synthetic session (full RP options: a hash key overrides
                # base_config's, so we restate the essentials + ownership).
                oidcRPMetaDataOptions => {
                    'pam-access' => {
                        oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                        oidcRPMetaDataOptionsClientID     => 'pam-access',
                        oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                        oidcRPMetaDataOptionsAccessTokenExpiration    => 600,
                        oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                        oidcRPMetaDataOptionsAllowOffline             => 1,
                        oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                    }
                },
                pamAccessSshRules      => { default => '1', bastion => '1' },
                pamAccessBastionGroups => 'bastion',
            }
        }
    ),
    'OP with pam-access + device-organization (org-owned RP)'
);

# The bastion id the plugin derives from a caller token. This used to be read
# back from /pam/bastion-token's probe mode; that endpoint is gone (issue #57),
# so ask the plugin for the identity directly -- which is all the probe did.
sub probe_bastion_id {
    my ( $token, $opx ) = @_;
    $opx ||= $op;
    my $plugin =
      $opx->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'};
    my $session = $plugin->oidc->getAccessToken($token);
    ok( $session, '  -> caller token resolves to a session' );
    return $plugin->_callerId($session);
}

my $sid = $op->login('french');

# Two separate enrollments → two distinct synthetic device sessions.
my $tok_a = pam_lib::enroll_server( $op, $sid );
ok( $tok_a, 'enrolled device A' );
my $tok_b = pam_lib::enroll_server( $op, $sid );
ok( $tok_b, 'enrolled device B' );

my $id_a = probe_bastion_id($tok_a);
my $id_b = probe_bastion_id($tok_b);

ok( $id_a, "device A bastion_id present ($id_a)" );
ok( $id_b, "device B bastion_id present ($id_b)" );
isnt( $id_a, 'pam-access',
    'bastion_id A is the per-device id, NOT the shared client_id' );
isnt( $id_b, 'pam-access', 'bastion_id B is the per-device id' );
isnt( $id_a, $id_b, 'two enrolled devices get DISTINCT device-ids' );

# The device-id is a SHA-256 digest of the synthetic session id, never the raw
# session id (which is a live credential replayable as a `lemonldap` cookie).
like( $id_a, qr/\A[0-9a-f]{64}\z/, 'device-id is a SHA-256 hex digest' );

# ---------------------------------------------------------------------------
# The device-id must SURVIVE a heartbeat refresh: in production the bastion's
# access token expires and is re-minted via /pam/heartbeat from the refresh
# token. newAccessToken() only persists its $info hash, so the heartbeat must
# carry _deviceId explicitly — otherwise bastion_id would revert to client_id.
# ---------------------------------------------------------------------------
sub enroll_offline {
    my ($s) = @_;
    my $q = main::buildForm( {
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
            scope         => 'pam:server offline_access',
        }
    );
    my $r = $op->_post( '/oauth2/device', IO::String->new($q),
        accept => 'application/json', length => length($q) );
    die "device auth failed: $r->[0]" unless $r->[0] == 200;
    my $j  = from_json( $r->[2]->[0] );
    my $dc = $j->{device_code};
    ( my $uc = $j->{user_code} ) =~ s/-//g;
    $r = $op->_get( '/device', query => "user_code=$uc",
        cookie => "lemonldap=$s", accept => 'text/html' );
    my ($csrf) = $r->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    $q = main::buildForm(
        { user_code => $uc, action => 'approve', token => $csrf } );
    $op->_post( '/device', IO::String->new($q),
        cookie => "lemonldap=$s", accept => 'text/html', length => length($q) );
    $q = main::buildForm( {
            grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code   => $dc,
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
        }
    );
    $r = $op->_post( '/oauth2/token', IO::String->new($q),
        accept => 'application/json', length => length($q) );
    die "token exchange failed: $r->[0]" unless $r->[0] == 200;
    $j = from_json( $r->[2]->[0] );
    return ( $j->{access_token}, $j->{refresh_token} );
}

my ( $tok_c, $rt_c ) = enroll_offline($sid);
ok( $rt_c, 'enrolled device C with a refresh token (offline_access)' );
my $id_c = probe_bastion_id($tok_c);
isnt( $id_c, 'pam-access', 'device C device-grant token carries the device-id' );

my $hb_body = to_json( {
        refresh_token => $rt_c,
        hostname      => 'bastionC.op.com',
        server_group  => 'bastion',
        version       => '0.4.1',
        node_role     => 'bastion',
    }
);
my $r = $op->_post(
    '/pam/heartbeat',
    IO::String->new($hb_body),
    accept => 'application/json',
    type   => 'application/json',
    length => length($hb_body),
);
is( $r->[0], 200, 'heartbeat returns 200' ) or diag explain $r;
my $tok_hb = from_json( $r->[2]->[0] )->{access_token};
ok( $tok_hb, 'heartbeat minted a fresh access token' );
my $id_hb = probe_bastion_id($tok_hb);
is( $id_hb, $id_c,
    'device-id SURVIVES the heartbeat refresh (not reverted to client_id)' );

# ---------------------------------------------------------------------------
# End-to-end under hashedSessionStore: the org-device bastion enrollment that
# first surfaced the device-authorization session-lookup bug must now work, and
# the device-id (derived from the cleartext session id, domain-separated) stays
# a valid per-device identifier in this storage mode.
# ---------------------------------------------------------------------------
{
    my $op2;
    ok(
        $op2 = LLNG::Manager::Test->new( {
                ini => {
                    logLevel           => $debug,
                    domain             => 'op.com',
                    portal             => 'http://auth.op.com',
                    hashedSessionStore => 1,
                    pam_lib::base_config(),
                    customPlugins =>
'::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',
                    oidcRPMetaDataOptions => {
                        'pam-access' => {
                            oidcRPMetaDataOptionsDisplayName  => 'PAM Access',
                            oidcRPMetaDataOptionsClientID     => 'pam-access',
                            oidcRPMetaDataOptionsClientSecret => 'pamsecret',
                            oidcRPMetaDataOptionsAccessTokenExpiration => 600,
                            oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                            oidcRPMetaDataOptionsAllowOffline             => 1,
                            oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                        }
                    },
                    pamAccessSshRules      => { default => '1', bastion => '1' },
                    pamAccessBastionGroups => 'bastion',
                }
            }
        ),
        'OP with hashedSessionStore enabled'
    );

    my $hsid  = $op2->login('french');
    my $tok_h = pam_lib::enroll_server( $op2, $hsid );
    ok( $tok_h, 'org-device enrollment succeeds under hashedSessionStore' );
    my $id_h = probe_bastion_id( $tok_h, $op2 );
    ok( $id_h, "device-id present under hashedSessionStore ($id_h)" );
    like( $id_h, qr/\A[0-9a-f]{64}\z/,
        'device-id is still a SHA-256 hex digest under hashedSessionStore' );
    isnt( $id_h, 'pam-access',
        'device-id is the per-device id, not the shared client_id' );
}

clean_sessions();
done_testing();
