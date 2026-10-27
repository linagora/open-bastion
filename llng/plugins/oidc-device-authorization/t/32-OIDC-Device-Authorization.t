use warnings;
use Test::More;
use strict;
use IO::String;
use MIME::Base64;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

my $debug = 'error';

# Initialization
my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                                 => $debug,
            domain                                   => 'op.com',
            portal                                   => 'http://auth.op.com/',
            authentication                           => 'Demo',
            userDB                                   => 'Same',
            issuerDBOpenIDConnectActivation          => 1,
            customPlugins                            => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,
            oidcRPMetaDataExportedVars                    => {
                rp => {
                    email              => "mail",
                    preferred_username => "uid",
                    name               => "cn",
                },
                rp_pkce_required => {
                    email              => "mail",
                    preferred_username => "uid",
                    name               => "cn",
                }
            },
            oidcRPMetaDataOptions => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName           => "RP",
                    oidcRPMetaDataOptionsIDTokenExpiration     => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg        => "RS256",
                    oidcRPMetaDataOptionsClientID              => "rpid",
                    oidcRPMetaDataOptionsPublic                => 1,
                    oidcRPMetaDataOptionsUserIDAttr            => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsRefreshToken          => 1,
                    oidcRPMetaDataOptionsAllowOffline          => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization       => 1,
                },
                rp_no_device => {
                    oidcRPMetaDataOptionsDisplayName       => "RP No Device",
                    oidcRPMetaDataOptionsIDTokenExpiration => 3600,
                    oidcRPMetaDataOptionsClientID          => "rpid_no_device",
                    oidcRPMetaDataOptionsClientSecret      => "rpsecret",
                    oidcRPMetaDataOptionsUserIDAttr        => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization       => 0,
                },
                rp_pkce_required => {
                    oidcRPMetaDataOptionsDisplayName => "RP PKCE Required",
                    oidcRPMetaDataOptionsIDTokenExpiration => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg    => "RS256",
                    oidcRPMetaDataOptionsClientID          => "rpid_pkce",
                    oidcRPMetaDataOptionsPublic            => 1,
                    oidcRPMetaDataOptionsUserIDAttr        => "",
                    oidcRPMetaDataOptionsAccessTokenExpiration => 3600,
                    oidcRPMetaDataOptionsBypassConsent         => 1,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization       => 1,
                    oidcRPMetaDataOptionsRequirePKCE           => 2,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $res;

# Test 1: Device Authorization Request
# RFC 8628 Section 3.1
my $query = buildForm( {
        client_id => 'rpid',
        scope     => 'openid profile email',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request"
);

my $payload = expectJSON($res);

ok( $payload->{device_code},               "Got device_code" );
ok( $payload->{user_code},                 "Got user_code" );
ok( $payload->{verification_uri},          "Got verification_uri" );
ok( $payload->{verification_uri_complete}, "Got verification_uri_complete" );
ok( $payload->{expires_in},                "Got expires_in" );
is( $payload->{interval}, 5, "Got expected polling interval" );
count(6);

my $device_code = $payload->{device_code};
my $user_code   = $payload->{user_code};

# Verify user_code format (8 chars, base-20 without vowels per RFC 8628)
like(
    $user_code,
    qr/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/,
    "User code has expected format (XXXX-XXXX, base-20)"
);
count(1);

# Test 2: Polling before user authorizes - should get authorization_pending
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint before authorization"
);

expectReject( $res, 400, "authorization_pending" );

# Test 3: User authenticates and enters user_code
# First, login
my $id = login( $op, 'french' );

# Access device verification page with user_code
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=" . ( $user_code =~ s/-//gr ),    # Remove hyphen
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page with user_code"
);
count(1);

expectOK($res);

# Verify form is displayed
like( $res->[2]->[0], qr/deviceform/, "Device authorization form displayed" );
count(1);

# Extract CSRF token from the form
my ($csrf_token) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;
ok( $csrf_token, "Got CSRF token from form" );
count(1);

# Test 4: User approves the device
my $user_code_clean = $user_code =~ s/-//gr;
$query = buildForm( {
        user_code => $user_code_clean,
        action    => 'approve',
        token     => $csrf_token,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval"
);
count(1);

expectOK($res);
like( $res->[2]->[0],
    qr/deviceApproved|success/, "Device approved message displayed" );
count(1);

# Test 5: Poll again - should now get tokens
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint after authorization"
);

$payload = expectJSON($res);
ok( $payload->{access_token},           "Got access_token" );
ok( $payload->{token_type} eq 'Bearer', "Got Bearer token type" );
ok( $payload->{id_token},               "Got id_token" );
count(3);

my $access_token = $payload->{access_token};

# Test 6: Verify access token works for userinfo
$res     = getUserinfo( $op, $access_token );
$payload = expectJSON($res);
is( $payload->{sub}, 'french', "Got correct sub claim" );
count(1);

# Test 7: Device code should no longer be usable (already exchanged)
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Try to reuse device_code"
);

expectReject( $res, 400, "expired_token" );

# Test 8: Invalid device_code should fail
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => 'invalid_device_code',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll with invalid device_code"
);

expectReject( $res, 400, "expired_token" );

# Test 9: Device authorization not allowed for RP
$query = buildForm( {
        client_id => 'rpid_no_device',
        scope     => 'openid',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization for RP without device grant"
);

expectReject( $res, 400, "invalid_client" );

# Test 10: User denies the device
# First create a new device authorization
$query = buildForm( {
        client_id => 'rpid',
        scope     => 'openid profile',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post new device authorization request"
);

$payload = expectJSON($res);
my $device_code2 = $payload->{device_code};
my $user_code2   = $payload->{user_code};
$user_code2 =~ s/-//g;

# Get device page to get CSRF token for denial
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code2",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for denial"
);
count(1);

my ($csrf_token2) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;
ok( $csrf_token2, "Got CSRF token from form for denial" );
count(1);

# User denies
$query = buildForm( {
        user_code => $user_code2,
        action    => 'deny',
        token     => $csrf_token2,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device denial"
);
count(1);

# Poll should get access_denied
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code2,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll after user denial"
);

expectReject( $res, 400, "access_denied" );

# Test 11: Expired device code
$query = buildForm( {
        client_id => 'rpid',
        scope     => 'openid',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization for expiration test"
);

$payload = expectJSON($res);
my $device_code3 = $payload->{device_code};

# Fast-forward time past expiration
Time::Fake->offset("+15m");

$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code3,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll with expired device_code"
);

expectReject( $res, 400, "expired_token" );

# Reset time
Time::Fake->reset();

# ===========================================================================
# PKCE Tests (RFC 7636 extension for Device Authorization Grant)
# ===========================================================================

# Example from https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
my $code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
my $code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

# Test 12: PKCE with S256 method - full flow
$query = buildForm( {
        client_id             => 'rpid',
        scope                 => 'openid profile',
        code_challenge        => $code_challenge,
        code_challenge_method => 'S256',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request with PKCE S256"
);

$payload = expectJSON($res);
ok( $payload->{device_code}, "Got device_code with PKCE" );
ok( $payload->{user_code},   "Got user_code with PKCE" );
count(2);

my $device_code_pkce = $payload->{device_code};
my $user_code_pkce   = $payload->{user_code};
$user_code_pkce =~ s/-//g;

# Get device page to get CSRF token
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code_pkce",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for PKCE test"
);
count(1);

my ($csrf_token_pkce) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;

# User approves the device
$query = buildForm( {
        user_code => $user_code_pkce,
        action    => 'approve',
        token     => $csrf_token_pkce,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval for PKCE test"
);
count(1);

# Poll with valid code_verifier
$query = buildForm( {
        grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code   => $device_code_pkce,
        code_verifier => $code_verifier,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint with valid code_verifier"
);

$payload = expectJSON($res);
ok( $payload->{access_token}, "Got access_token with PKCE S256" );
ok( $payload->{id_token},     "Got id_token with PKCE S256" );
count(2);

# Test 13: PKCE with plain method - full flow
$query = buildForm( {
        client_id             => 'rpid',
        scope                 => 'openid profile',
        code_challenge        => 'plain_challenge_value',
        code_challenge_method => 'plain',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request with PKCE plain"
);

$payload = expectJSON($res);
my $device_code_plain = $payload->{device_code};
my $user_code_plain   = $payload->{user_code};
$user_code_plain =~ s/-//g;

# Get device page to get CSRF token
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code_plain",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for PKCE plain test"
);
count(1);

my ($csrf_token_plain) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;

# User approves the device
$query = buildForm( {
        user_code => $user_code_plain,
        action    => 'approve',
        token     => $csrf_token_plain,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval for PKCE plain test"
);
count(1);

# Poll with valid code_verifier (for plain method, verifier = challenge)
$query = buildForm( {
        grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code   => $device_code_plain,
        code_verifier => 'plain_challenge_value',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint with valid code_verifier (plain)"
);

$payload = expectJSON($res);
ok( $payload->{access_token}, "Got access_token with PKCE plain" );
count(1);

# Test 14: PKCE - missing code_verifier when code_challenge was provided
$query = buildForm( {
        client_id             => 'rpid',
        scope                 => 'openid',
        code_challenge        => $code_challenge,
        code_challenge_method => 'S256',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request for missing code_verifier test"
);

$payload = expectJSON($res);
my $device_code_noverifier = $payload->{device_code};
my $user_code_noverifier   = $payload->{user_code};
$user_code_noverifier =~ s/-//g;

# Get device page to get CSRF token
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code_noverifier",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for missing code_verifier test"
);
count(1);

my ($csrf_token_noverifier) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;

# User approves
$query = buildForm( {
        user_code => $user_code_noverifier,
        action    => 'approve',
        token     => $csrf_token_noverifier,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval for missing code_verifier test"
);
count(1);

# Poll WITHOUT code_verifier - should fail
$query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code_noverifier,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint without code_verifier"
);

expectReject( $res, 400, "invalid_grant" );

# Test 15: PKCE - invalid code_verifier
$query = buildForm( {
        client_id             => 'rpid',
        scope                 => 'openid',
        code_challenge        => $code_challenge,
        code_challenge_method => 'S256',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request for invalid code_verifier test"
);

$payload = expectJSON($res);
my $device_code_invalid = $payload->{device_code};
my $user_code_invalid   = $payload->{user_code};
$user_code_invalid =~ s/-//g;

# Get device page to get CSRF token
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code_invalid",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for invalid code_verifier test"
);
count(1);

my ($csrf_token_invalid) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;

# User approves
$query = buildForm( {
        user_code => $user_code_invalid,
        action    => 'approve',
        token     => $csrf_token_invalid,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval for invalid code_verifier test"
);
count(1);

# Poll with INVALID code_verifier - should fail
$query = buildForm( {
        grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code   => $device_code_invalid,
        code_verifier => 'INVALID_VERIFIER',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid&$query"),
        accept => 'application/json',
        length => length("client_id=rpid&$query"),
    ),
    "Poll token endpoint with invalid code_verifier"
);

expectReject( $res, 400, "invalid_grant" );

# Test 16: Invalid code_challenge_method
$query = buildForm( {
        client_id             => 'rpid',
        scope                 => 'openid',
        code_challenge        => $code_challenge,
        code_challenge_method => 'invalid_method',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization request with invalid code_challenge_method"
);

expectReject( $res, 400, "invalid_request" );

# ===========================================================================
# PKCE Required Tests (RP configured with oidcRPMetaDataOptionsRequirePKCE)
# ===========================================================================

# Test 17: PKCE required - request WITHOUT PKCE should fail
$query = buildForm( {
        client_id => 'rpid_pkce',
        scope     => 'openid profile',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization without PKCE on PKCE-required RP"
);

expectReject( $res, 400, "invalid_request" );

# Test 18: PKCE required - request WITH PKCE should succeed (full flow)
$query = buildForm( {
        client_id             => 'rpid_pkce',
        scope                 => 'openid profile',
        code_challenge        => $code_challenge,
        code_challenge_method => 'S256',
    }
);

ok(
    $res = $op->_post(
        "/oauth2/device",
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    ),
    "Post device authorization with PKCE on PKCE-required RP"
);

$payload = expectJSON($res);
ok( $payload->{device_code}, "Got device_code on PKCE-required RP" );
ok( $payload->{user_code},   "Got user_code on PKCE-required RP" );
count(2);

my $device_code_req = $payload->{device_code};
my $user_code_req   = $payload->{user_code};
$user_code_req =~ s/-//g;

# Get device page to get CSRF token
ok(
    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code_req",
        cookie => "lemonldap=$id",
        accept => 'text/html',
    ),
    "Get device verification page for PKCE-required RP"
);
count(1);

my ($csrf_token_req) =
  $res->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;

# User approves the device
$query = buildForm( {
        user_code => $user_code_req,
        action    => 'approve',
        token     => $csrf_token_req,
    }
);

ok(
    $res = $op->_post(
        "/device",
        IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query),
    ),
    "Post device approval for PKCE-required RP"
);
count(1);

# Poll with valid code_verifier
$query = buildForm( {
        grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code   => $device_code_req,
        code_verifier => $code_verifier,
    }
);

ok(
    $res = $op->_post(
        "/oauth2/token",
        IO::String->new("client_id=rpid_pkce&$query"),
        accept => 'application/json',
        length => length("client_id=rpid_pkce&$query"),
    ),
    "Poll token endpoint with valid code_verifier on PKCE-required RP"
);

$payload = expectJSON($res);
ok( $payload->{access_token}, "Got access_token on PKCE-required RP" );
ok( $payload->{id_token},     "Got id_token on PKCE-required RP" );
count(2);

clean_sessions();
done_testing();
