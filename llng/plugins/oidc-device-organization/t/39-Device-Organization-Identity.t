use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# Issue #71: the plugin carries the most identity-critical code in the chain —
# it swaps the approving admin's session for a synthetic one and derives
# _deviceId, the value the whole bastion vouching chain keys on — and three
# things about it were pinned nowhere:
#
#   1. _deviceId stability across a refresh. It is documented as
#      "deterministic (stable across refreshes)", and PamAccess::_callerId
#      returns it as the bastion identity, so a device whose id changed at
#      refresh would silently lose its vouchers.
#   2. The AllowOffline=0 + ownership=organization combination, which yields
#      no refresh token at all.
#   3. The identity swap itself: the wholesale `%$session_data = %{...}` copy
#      and the user_session_id reassignment. Nothing checked that the admin's
#      attributes stop there, nor that the device outlives the admin's SSO
#      session — which is the entire point of organizational ownership.
#
# It also pins the constraint the plugin's own comment leans on: the core
# /oauth2/token refresh grant does NOT work for these tokens (it re-resolves
# the synthetic client_id in the UserDB and fails), which is why Open Bastion
# refreshes through /pam/heartbeat instead.

my $debug = 'error';

my %rpCommon = (
    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
    oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
    oidcRPMetaDataOptionsUserIDAttr            => "",
    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
    oidcRPMetaDataOptionsBypassConsent         => 1,
    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
);

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins                   => '::Plugins::PamAccess'
              . ' ::Plugins::OIDCDeviceAuthorization'
              . ' ::Plugins::OIDCDeviceOrganization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 0,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,
            pamAccessActivation                           => 1,
            pamAccessRp                                   => 'pam-access',
            pamAccessSshRules => { default => '1' },

            oidcRPMetaDataExportedVars => {
                'pam-access' => { email => 'mail', name => 'cn' },
                'personal'   => { email => 'mail', name => 'cn' },
            },
            oidcRPMetaDataScopeRules => {
                'pam-access' => { 'pam:server' => '1' },
            },
            oidcRPMetaDataOptions => {

                # The production shape: an organization device that also
                # refreshes through /pam/heartbeat.
                'pam-access' => {
                    %rpCommon,
                    oidcRPMetaDataOptionsDisplayName   => 'PAM Access',
                    oidcRPMetaDataOptionsClientID      => 'pam-access',
                    oidcRPMetaDataOptionsClientSecret  => 'pamsecret',
                    oidcRPMetaDataOptionsAllowOffline  => 1,
                    oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                    oidcRPMetaDataOptionsOfflineSessionExpiration => 2592000,
                },

                # Organization ownership with offline refusal AND no online
                # refresh token: the device gets an access token and nothing
                # to renew it with.
                'noffline' => {
                    %rpCommon,
                    oidcRPMetaDataOptionsDisplayName     => 'No offline',
                    oidcRPMetaDataOptionsClientID        => 'rp_nooff',
                    oidcRPMetaDataOptionsPublic          => 1,
                    oidcRPMetaDataOptionsAllowOffline    => 0,
                    oidcRPMetaDataOptionsRefreshToken    => 0,
                    oidcRPMetaDataOptionsDeviceOwnership => 'organization',
                },

                # No ownership at all: the hook must not fire.
                'personal' => {
                    %rpCommon,
                    oidcRPMetaDataOptionsDisplayName  => 'Personal',
                    oidcRPMetaDataOptionsClientID     => 'rp_perso',
                    oidcRPMetaDataOptionsPublic       => 1,
                    oidcRPMetaDataOptionsAllowOffline => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $oidc =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};

my $adminSid = login( $op, 'french' );

# The full RFC 8628 dance for one RP. Returns the decoded token response.
sub enroll {
    my (%a) = @_;
    my $client_id = $a{client_id};
    my $scope     = $a{scope} // 'openid profile offline_access';

    my $query = buildForm( {
            client_id => $client_id,
            ( $a{secret} ? ( client_secret => $a{secret} ) : () ),
            scope => $scope,
        }
    );
    my $r = $op->_post(
        '/oauth2/device', IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
    my $p         = expectJSON($r);
    my $dc        = $p->{device_code};
    my $user_code = $p->{user_code} =~ s/-//gr;

    $r = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$adminSid",
        accept => 'text/html'
    );
    my ($csrf) = $r->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    $query = buildForm(
        { user_code => $user_code, action => 'approve', token => $csrf } );
    expectOK(
        $op->_post(
            '/device', IO::String->new($query),
            cookie => "lemonldap=$adminSid",
            accept => 'text/html',
            length => length($query)
        )
    );

    $query = buildForm( {
            grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code => $dc,
            client_id   => $client_id,
            ( $a{secret} ? ( client_secret => $a{secret} ) : () ),
        }
    );
    $r = $op->_post(
        '/oauth2/token', IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
    return ( $r, expectJSON($r) );
}

# ===========================================================================
# 1. _deviceId is stable across a refresh (/pam/heartbeat)
# ===========================================================================

my ( $res, $tokens ) = enroll(
    client_id => 'pam-access',
    secret    => 'pamsecret',
    scope     => 'pam:server offline_access',
);
ok( $tokens->{access_token},  'Org device enrolled with an access token' );
ok( $tokens->{refresh_token}, '  -> and an offline refresh token' );
count(2);

my $firstId = $oidc->getAccessToken( $tokens->{access_token} )->data->{_deviceId};
like( $firstId, qr/^[0-9a-f]{64}$/, '  -> carrying a per-device id' );
count(1);

my $hb = to_json( {
        refresh_token => $tokens->{refresh_token},
        hostname      => 'srv1.op.com',
        server_group  => 'default',
        node_role     => 'bastion',
    }
);
$res = $op->_post(
    '/pam/heartbeat',
    IO::String->new($hb),
    accept => 'application/json',
    type   => 'application/json',
    length => length($hb),
);
is( $res->[0], 200, 'POST /pam/heartbeat renews the access token' );
my $renewed = from_json( $res->[2]->[0] )->{access_token};
ok( $renewed, '  -> a new access token came back' );
isnt( $renewed, $tokens->{access_token}, '  -> a different one' );
count(3);

my $renewedSession = $oidc->getAccessToken($renewed);
is( $renewedSession->data->{_deviceId},
    $firstId, '  -> with the SAME device id (stable across refresh)' );
count(1);

# The renewed token carries no user_session_id, by design: an OFFLINE refresh
# token is standalone (_generateTokens only stamps user_session_id when the
# token is online), so the synthetic identity travels in the refresh token's
# own data rather than through a session pointer. That is exactly why
# _deviceId has to be stable on its own — there is nothing else to key on.
ok( !$renewedSession->data->{user_session_id},
    '  -> the renewed token is standalone (offline refresh)' );
is( $renewedSession->data->{client_id},
    'pam-access', '  -> and still identifies the device' );
count(2);

# Two heartbeats in a row keep it stable.
$res = $op->_post(
    '/pam/heartbeat',
    IO::String->new($hb),
    accept => 'application/json',
    type   => 'application/json',
    length => length($hb),
);
is( $res->[0], 200, 'A second heartbeat also succeeds' );
is(
    $oidc->getAccessToken( from_json( $res->[2]->[0] )->{access_token} )
      ->data->{_deviceId},
    $firstId,
    '  -> device id still unchanged'
);
count(2);

# The core refresh grant is NOT a supported path for these tokens: it
# re-resolves the synthetic client_id in the UserDB. The plugin's design
# comment depends on this being true, so pin it.
{
    my $q = buildForm( {
            grant_type    => 'refresh_token',
            refresh_token => $tokens->{refresh_token},
            client_id     => 'pam-access',
            client_secret => 'pamsecret',
        }
    );
    my $r = $op->_post(
        '/oauth2/token', IO::String->new($q),
        accept => 'application/json',
        length => length($q)
    );
    is( $r->[0], 400,
        'The core refresh grant does not serve org device tokens' );
    is( from_json( $r->[2]->[0] )->{error},
        'invalid_grant', '  -> invalid_grant, as the design comment assumes' );
    count(2);
}

# ===========================================================================
# 2. AllowOffline=0 + ownership=organization
# ===========================================================================

( $res, $tokens ) = enroll(
    client_id => 'rp_nooff',
    scope     => 'openid profile offline_access',
);
ok( $tokens->{access_token}, 'AllowOffline=0: an access token is still issued' );
ok( !$tokens->{refresh_token},
    '  -> and NO refresh token, offline or online' );
count(2);

# The identity swap still happened — the device is the client, not the admin.
my $noffSession = $oidc->getAccessToken( $tokens->{access_token} );
like( $noffSession->data->{_deviceId},
    qr/^[0-9a-f]{64}$/, '  -> the device id is stamped all the same' );
isnt( $noffSession->data->{_deviceId},
    $firstId, '  -> and is distinct from the other device' );
count(2);

my $noffSynthetic = getSession( $noffSession->data->{user_session_id} )->data;
ok( $noffSynthetic->{_deviceOrg},
    '  -> behind a synthetic organization session' );
count(1);

# offline_access is stripped from the granted scope even when refused.
unlike( $noffSession->data->{scope} // '',
    qr/offline_access/, '  -> offline_access is not advertised as granted' );
count(1);

# ===========================================================================
# 3. The identity swap: what must NOT cross over
# ===========================================================================

my $adminSession = getSession($adminSid)->data;

( $res, $tokens ) = enroll(
    client_id => 'pam-access',
    secret    => 'pamsecret',
    scope     => 'pam:server offline_access',
);
my $devSession = $oidc->getAccessToken( $tokens->{access_token} );

isnt( $devSession->data->{user_session_id},
    $adminSid, 'The token points at the synthetic session, not the admin one' );
count(1);

my $synthetic = getSession( $devSession->data->{user_session_id} )->data;
is( $synthetic->{_user}, 'pam-access', 'Synthetic identity is the client' );
is( $synthetic->{_approved_by},
    'french', '  -> the admin is recorded, not impersonated' );
count(2);

# The wholesale `%$session_data = %{ $session->data }` copy replaces the
# admin's data outright. Nothing personal may survive it.
for my $leak (qw(mail cn uid _session_uid)) {
    next unless defined $adminSession->{$leak};
    isnt( $synthetic->{$leak} // '',
        $adminSession->{$leak},
        "  -> the admin's $leak does not leak into the device session" );
    count(1);
}

# userinfo answers as the device.
my $ui = expectJSON( getUserinfo( $op, $tokens->{access_token} ) );
is( $ui->{sub}, 'pam-access', 'userinfo subject is the device' );
ok( !$ui->{email}, '  -> and carries none of the admin attributes' );
count(2);

# The whole point of organizational ownership: the device survives the admin
# leaving. Kill the admin's SSO session and the device token must still work.
getSession($adminSid)->remove;
$ui = expectJSON( getUserinfo( $op, $tokens->{access_token} ) );
is( $ui->{sub}, 'pam-access',
    'The device token outlives the approving admin session' );
count(1);

# ===========================================================================
# 4. Without ownership=organization the hook must not fire
# ===========================================================================

$adminSid = login( $op, 'french' );
( $res, $tokens ) = enroll(
    client_id => 'rp_perso',
    scope     => 'openid profile offline_access',
);
my $perso = $oidc->getAccessToken( $tokens->{access_token} );
ok( !$perso->data->{_deviceId},
    'A personal-ownership RP gets no device id' );
count(1);

$ui = expectJSON( getUserinfo( $op, $tokens->{access_token} ) );
is( $ui->{sub}, 'french', '  -> and the token stays the admin identity' );
count(1);

clean_sessions();
done_testing();
