use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# Regression: the device-authorization user_code/device_code sessions are stored
# under a fixed id (the SHA-256 of the code) with hashStore => 0. The lookups
# used to omit hashStore => 0, so with hashedSessionStore enabled getApacheSession
# searched under sha256_hex(id) and never found them — the verification page
# could not resolve the user_code, approval silently failed, and the token
# exchange returned `expired_token`. This test runs the full RFC 8628 flow with
# hashedSessionStore on and asserts it succeeds end to end.

my $debug = 'error';

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins                   => '::Plugins::OIDCDeviceAuthorization',

            # The setting under test.
            hashedSessionStore => 1,

            oidcServiceDeviceAuthorizationExpiration       => 600,
            oidcServiceDeviceAuthorizationPollingInterval  => 5,
            oidcServiceDeviceAuthorizationUserCodeLength   => 8,
            oidcRPMetaDataOptions                          => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName              => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration        => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg           => "RS256",
                    oidcRPMetaDataOptionsClientID                 => "rpid",
                    oidcRPMetaDataOptionsPublic                   => 1,
                    oidcRPMetaDataOptionsUserIDAttr               => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration    => 3600,
                    oidcRPMetaDataOptionsBypassConsent            => 1,
                    oidcRPMetaDataOptionsRefreshToken             => 1,
                    oidcRPMetaDataOptionsAllowOffline             => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $res;

# 1. Device authorization request
my $query = buildForm( { client_id => 'rpid', scope => 'openid profile' } );
$res = $op->_post( "/oauth2/device", IO::String->new($query),
    accept => 'application/json', length => length($query) );
my $payload = expectJSON($res);
ok( $payload->{device_code}, "Got device_code (hashedSessionStore)" );
ok( $payload->{user_code},   "Got user_code (hashedSessionStore)" );
count(2);

my $device_code = $payload->{device_code};
my $user_code   = $payload->{user_code};

# 2. Login and open the verification page — this is the lookup that failed:
#    the user_code session must be found under hashedSessionStore.
my $id = login( $op, 'french' );
$res = $op->_get( "/device",
    query  => "user_code=" . ( $user_code =~ s/-//gr ),
    cookie => "lemonldap=$id", accept => 'text/html' );
expectOK($res);
like( $res->[2]->[0], qr/deviceform/,
    "Verification page resolves the user_code (session found)" );
count(1);

my ($csrf) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;
ok( $csrf, "Got CSRF token" );
count(1);

# 3. Approve the device.
$query = buildForm( {
        user_code => ( $user_code =~ s/-//gr ),
        action    => 'approve',
        token     => $csrf,
    }
);
$res = $op->_post( "/device", IO::String->new($query),
    cookie => "lemonldap=$id", accept => 'text/html', length => length($query) );
expectOK($res);
like( $res->[2]->[0], qr/deviceApproved|success/, "Device approved" );
count(1);

# 4. Exchange the device_code — the regression: this used to return
#    expired_token because the device_auth session could not be found.
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
        client_id   => 'rpid',
    }
);
$res = $op->_post( "/oauth2/token", IO::String->new($query),
    accept => 'application/json', length => length($query) );
$payload = expectJSON($res);
is( $res->[0], 200, "Token exchange succeeds under hashedSessionStore" );
ok( $payload->{access_token}, "Got access_token" );
ok( $payload->{id_token},     "Got id_token" );
count(3);

clean_sessions();
done_testing();
