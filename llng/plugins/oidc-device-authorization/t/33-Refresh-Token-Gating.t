use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';

# Initialization — three public RPs to cover the refresh-token issuance matrix.
#
#   rp_offline : AllowOffline=1, RefreshToken=0
#                → offline_access scope must yield a refresh token
#   rp_online  : AllowOffline=0, RefreshToken=1
#                → any scope must yield a (non-offline) refresh token
#   rp_none    : AllowOffline=0, RefreshToken=0
#                → no refresh token under any scope

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                                      => $debug,
            domain                                        => 'op.com',
            portal                                        => 'http://auth.op.com/',
            authentication                                => 'Demo',
            userDB                                        => 'Same',
            issuerDBOpenIDConnectActivation               => 1,
            customPlugins                                 => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,
            oidcRPMetaDataExportedVars => {
                rp_offline => { preferred_username => 'uid', name => 'cn' },
                rp_online  => { preferred_username => 'uid', name => 'cn' },
                rp_none    => { preferred_username => 'uid', name => 'cn' },
            },
            oidcRPMetaDataOptions => {
                rp_offline => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP Offline',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientID              => 'rp_offline',
                    oidcRPMetaDataOptionsPublic                => 1,
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowOffline          => 1,
                    oidcRPMetaDataOptionsRefreshToken          => 0,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
                rp_online => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP Online',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientID              => 'rp_online',
                    oidcRPMetaDataOptionsPublic                => 1,
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowOffline          => 0,
                    oidcRPMetaDataOptionsRefreshToken          => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
                rp_none => {
                    oidcRPMetaDataOptionsDisplayName           => 'RP None',
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => 'RS256',
                    oidcRPMetaDataOptionsClientID              => 'rp_none',
                    oidcRPMetaDataOptionsPublic                => 1,
                    oidcRPMetaDataOptionsUserIDAttr            => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowOffline          => 0,
                    oidcRPMetaDataOptionsRefreshToken          => 0,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

# ---------------------------------------------------------------------------
# Helper: run the full device-authorization flow for a public client.
# Returns the decoded token JSON hashref on success, or dies.
# ---------------------------------------------------------------------------
sub device_flow {
    my ( $client_id, $scope, $sid ) = @_;

    # Step 1 — initiate device authorization
    my $query = buildForm( {
            client_id => $client_id,
            scope     => $scope,
        }
    );
    my $res = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "device auth request failed ($res->[0]) for $client_id"
      unless $res->[0] == 200;

    my $init   = from_json( $res->[2]->[0] );
    my $device_code = $init->{device_code}
      or die "no device_code for $client_id";
    my $user_code = $init->{user_code}
      or die "no user_code for $client_id";
    $user_code =~ s/-//g;

    # Step 2 — get verification page (to extract CSRF token)
    $res = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$sid",
        accept => 'text/html',
    );
    my ($csrf) = $res->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    die "no CSRF token for $client_id" unless $csrf;

    # Step 3 — approve device
    $query = buildForm( {
            user_code => $user_code,
            action    => 'approve',
            token     => $csrf,
        }
    );
    $res = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$sid",
        accept => 'text/html',
        length => length($query),
    );
    die "device approval failed ($res->[0]) for $client_id"
      unless $res->[0] == 200;

    # Step 4 — exchange device code for tokens (no client_secret for public)
    $query = buildForm( {
            grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code => $device_code,
            client_id   => $client_id,
        }
    );
    $res = $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "token exchange failed ($res->[0]) for $client_id"
      unless $res->[0] == 200;

    return from_json( $res->[2]->[0] );
}

# ---------------------------------------------------------------------------
# Log in once; reuse the session across all four flows.
# ---------------------------------------------------------------------------
my $sid = login( $op, 'french' );

# ===========================================================================
# Case 1: rp_offline + offline_access scope
#   AllowOffline=1, RefreshToken=0, scope includes offline_access
#   → access_token AND refresh_token expected
# ===========================================================================

my $tok;
ok(
    $tok = device_flow( 'rp_offline', 'openid offline_access', $sid ),
    'rp_offline offline_access flow completed'
);
ok( $tok->{access_token},  'rp_offline: access_token present' );
ok( $tok->{refresh_token}, 'rp_offline: refresh_token present (offline gate)' );

# M1: offline_access is a request marker, not a granted scope — it must be
# stripped from the advertised response scope even though it gated the
# refresh token above (mirrors the core token endpoint).
unlike( $tok->{scope} // '', qr/\boffline_access\b/,
    'rp_offline: response scope strips offline_access' );
like( $tok->{scope} // '', qr/\bopenid\b/,
    'rp_offline: response scope keeps openid' );
count(5);

# ===========================================================================
# Case 2: rp_online + openid scope only
#   AllowOffline=0, RefreshToken=1
#   → refresh_token expected (online gate, no offline_access needed)
# ===========================================================================

ok(
    $tok = device_flow( 'rp_online', 'openid', $sid ),
    'rp_online openid flow completed'
);
ok( $tok->{refresh_token}, 'rp_online: refresh_token present (online gate)' );
count(2);

# ===========================================================================
# Case 3: rp_none + offline_access scope
#   AllowOffline=0, RefreshToken=0 — offline gate closed
#   → access_token present, refresh_token ABSENT
# ===========================================================================

ok(
    $tok = device_flow( 'rp_none', 'openid offline_access', $sid ),
    'rp_none offline_access flow completed'
);
ok( $tok->{access_token},    'rp_none offline_access: access_token present' );
ok( !$tok->{refresh_token},  'rp_none offline_access: refresh_token absent' );
count(3);

# ===========================================================================
# Case 4: rp_none + openid scope only
#   AllowOffline=0, RefreshToken=0 — both gates closed
#   → refresh_token ABSENT
# ===========================================================================

ok(
    $tok = device_flow( 'rp_none', 'openid', $sid ),
    'rp_none openid-only flow completed'
);
ok( !$tok->{refresh_token}, 'rp_none openid-only: refresh_token absent' );
count(2);

# ===========================================================================
# Case 5: an approved device_code is single-use (M4)
#   The code is consumed before the tokens are minted, so a second exchange
#   with the same approved code must be rejected rather than minting a
#   duplicate token set.
# ===========================================================================
{
    my $query = buildForm( { client_id => 'rp_online', scope => 'openid' } );
    my $res = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    my $init = from_json( $res->[2]->[0] );
    my $device_code = $init->{device_code};
    ( my $user_code = $init->{user_code} ) =~ s/-//g;

    $res = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$sid",
        accept => 'text/html',
    );
    my ($csrf) = $res->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;

    $query = buildForm(
        { user_code => $user_code, action => 'approve', token => $csrf } );
    $res = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$sid",
        accept => 'text/html',
        length => length($query),
    );
    is( $res->[0], 200, 'M4: device approved' );

    my $exchange = sub {
        my $q = buildForm( {
                grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
                device_code => $device_code,
                client_id   => 'rp_online',
            }
        );
        return $op->_post(
            '/oauth2/token',
            IO::String->new($q),
            accept => 'application/json',
            length => length($q),
        );
    };

    my $r1 = $exchange->();
    is( $r1->[0], 200, 'M4: first exchange succeeds' );
    ok( from_json( $r1->[2]->[0] )->{access_token},
        '  -> access_token issued' );

    my $r2 = $exchange->();
    is( $r2->[0], 400, 'M4: second exchange with the same code is rejected' );
    my $err = from_json( $r2->[2]->[0] );
    like(
        $err->{error},
        qr/^(?:expired_token|invalid_grant)$/,
        "  -> error is expired_token/invalid_grant (got $err->{error})"
    );
    count(5);
}

clean_sessions();
done_testing();
