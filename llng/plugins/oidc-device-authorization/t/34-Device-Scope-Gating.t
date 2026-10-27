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

# The device endpoint is pre-auth, so the requested scope is unfiltered. The
# plugin must resolve it through the core getScope gate at approval time, so
# the per-user dynamic scope rules (rpScopeRules) decide which privileged
# scopes the *approving* user actually grants — exactly like the
# authorization-code flow. Here `pam` is granted only to dwho.

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,
            oidcRPMetaDataExportedVars => {
                rp_scoped => { preferred_username => 'uid', name => 'cn' },
            },
            oidcRPMetaDataScopeRules => {

                # `pam` is a dynamic scope granted only to dwho; `openid`
                # stays untouched (not a dynamic scope).
                rp_scoped => { pam => '$uid eq q{dwho}' },
            },
            oidcRPMetaDataOptions => {
                rp_scoped => {
                    oidcRPMetaDataOptionsDisplayName    => 'RP Scoped',
                    oidcRPMetaDataOptionsIDTokenExpiration  => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg     => 'RS256',
                    oidcRPMetaDataOptionsClientID           => 'rp_scoped',
                    oidcRPMetaDataOptionsPublic             => 1,
                    oidcRPMetaDataOptionsUserIDAttr         => '',
                    oidcRPMetaDataOptionsAccessTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsBypassConsent             => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization  => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

# ---------------------------------------------------------------------------
# Helper: full device-authorization flow for a public client, approved by the
# session $sid. Returns the decoded token JSON hashref, or dies.
# ---------------------------------------------------------------------------
sub device_flow {
    my ( $client_id, $scope, $sid ) = @_;

    my $query = buildForm( { client_id => $client_id, scope => $scope } );
    my $res = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "device auth request failed ($res->[0])" unless $res->[0] == 200;

    my $init = from_json( $res->[2]->[0] );
    my $device_code = $init->{device_code} or die "no device_code";
    ( my $user_code = $init->{user_code} ) =~ s/-//g;

    $res = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$sid",
        accept => 'text/html',
    );
    my ($csrf) = $res->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    die "no CSRF token" unless $csrf;

    $query = buildForm(
        { user_code => $user_code, action => 'approve', token => $csrf } );
    $res = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$sid",
        accept => 'text/html',
        length => length($query),
    );
    die "device approval failed ($res->[0])" unless $res->[0] == 200;

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
    die "token exchange failed ($res->[0])" unless $res->[0] == 200;

    return from_json( $res->[2]->[0] );
}

# ===========================================================================
# Case 1: french requests `openid pam` — french does NOT match the rule, so
#         `pam` must be stripped from the granted scope.
# ===========================================================================
my $sid_french = login( $op, 'french' );
my $tok;
ok( $tok = device_flow( 'rp_scoped', 'openid pam', $sid_french ),
    'french: device flow completed' );
ok( $tok->{access_token}, '  -> access_token present' );
like( $tok->{scope} // '', qr/\bopenid\b/, '  -> scope keeps openid' );
unlike( $tok->{scope} // '', qr/\bpam\b/,
    '  -> scope strips pam (french not entitled by rpScopeRules)' );
count(4);

# ===========================================================================
# Case 2: dwho requests `openid pam` — dwho matches the rule, so `pam` is
#         granted. Proves resolution is per-user, not a blanket strip.
# ===========================================================================
my $sid_dwho = login( $op, 'dwho' );
ok( $tok = device_flow( 'rp_scoped', 'openid pam', $sid_dwho ),
    'dwho: device flow completed' );
like( $tok->{scope} // '', qr/\bpam\b/,
    '  -> scope keeps pam (dwho entitled by rpScopeRules)' );
count(2);

clean_sessions();
done_testing();
