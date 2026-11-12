use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# The invalid-code budget stops a logged-in user from brute-forcing the
# user_code space. A code the session can obtain by itself proves nothing
# about the codes it is guessing, so submitting it must not give the budget
# back: neither a fresh pending code (a public RP hands one to anyone through
# /oauth2/device) nor a code already approved earlier in the same window.

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => 'error',
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration   => 600,
            oidcServiceDeviceAuthorizationMaxFailures  => 3,
            oidcServiceDeviceAuthorizationLockoutDelay => 300,
            oidcRPMetaDataOptions                      => {
                rp => {
                    oidcRPMetaDataOptionsDisplayName              => 'RP',
                    oidcRPMetaDataOptionsIDTokenExpiration        => 3600,
                    oidcRPMetaDataOptionsIDTokenSignAlg           => 'RS256',
                    oidcRPMetaDataOptionsClientID                 => 'rpid',
                    oidcRPMetaDataOptionsPublic                   => 1,
                    oidcRPMetaDataOptionsAccessTokenExpiration    => 3600,
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);
ok( $op, 'OP with the device authorization plugin' );
count(1);

sub new_code {
    my $q = buildForm( { client_id => 'rpid', scope => 'openid' } );
    my $r = $op->_post(
        '/oauth2/device', IO::String->new($q),
        accept => 'application/json',
        length => length($q)
    );
    return expectJSON($r)->{user_code} =~ s/-//gr;
}

sub submit {
    my ( $id, $code ) = @_;
    my $page = $op->_get(
        '/device',
        cookie => "lemonldap=$id",
        accept => 'text/html'
    );
    my ($csrf) = $page->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;
    my $q =
      buildForm( { user_code => $code, action => 'approve', token => $csrf } );
    return $op->_post(
        '/device', IO::String->new($q),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($q)
    )->[2]->[0];
}

# --- 1. a fresh pending code does not restore the budget -------------------

my $id = login( $op, 'dwho' );
like( submit( $id, 'ZZZZZZZZ' ), qr/invalidUserCode/, 'First failure' );
like( submit( $id, 'ZZZZZZZY' ), qr/invalidUserCode/, 'Second failure' );
like( submit( $id, new_code() ), qr/deviceApproved/,
    'A fresh pending code is approved' );
like( submit( $id, 'ZZZZZZZX' ), qr/invalidUserCode/,
    'Third failure is still answered with the plain error' );
like( submit( $id, 'ZZZZZZZW' ), qr/deviceTooManyAttempts/,
    'The budget still counts the failures before the pending code' );
count(5);

# --- 2. a code already used does not restore the budget --------------------

my $id2  = login( $op, 'rtyler' );
my $used = new_code();
like( submit( $id2, $used ), qr/deviceApproved/, 'A code is approved' );
like( submit( $id2, 'ZZZZZZZZ' ), qr/invalidUserCode/, 'First failure' );
like( submit( $id2, 'ZZZZZZZY' ), qr/invalidUserCode/, 'Second failure' );
like( submit( $id2, $used ), qr/codeAlreadyUsed/, 'The code is already used' );
like( submit( $id2, 'ZZZZZZZX' ), qr/invalidUserCode/,
    'Third failure is still answered with the plain error' );
like( submit( $id2, 'ZZZZZZZW' ), qr/deviceTooManyAttempts/,
    'The budget still counts the failures before the used code' );
count(6);

clean_sessions();
done_testing();
