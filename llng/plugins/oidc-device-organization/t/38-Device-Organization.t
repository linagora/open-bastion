use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# First tests for oidc-device-organization.
#
# The plugin swaps the approving admin's identity for a synthetic, per-device
# one at token minting time. The regression it exists for: when the synthetic
# session could NOT be created, the hook used to return PE_OK, which let the
# enrollment complete against the *admin's* session — a token whose sub is the
# admin, dying with the admin's SSO session, and carrying no _deviceId at all.
# ob-enroll saw a 200 and the failure only surfaced hours later. It must now
# fail closed.

my $debug = 'error';

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins                   =>
              '::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,
            oidcRPMetaDataOptions                         => {
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
                    oidcRPMetaDataOptionsDeviceOwnership          => 'organization',

                    # Per-RP offline lifetime: the synthetic session must
                    # follow it, not the global setting
                    oidcRPMetaDataOptionsOfflineSessionExpiration => 86400,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

ok(
    $op->p->loadedModules->{
        'Lemonldap::NG::Portal::Plugins::OIDCDeviceOrganization'},
    'Device organization plugin loaded'
);
count(1);

my $id = login( $op, 'french' );

# Run the RFC 8628 dance up to (and including) the token exchange
sub enroll {
    my ($scope) = @_;
    $scope ||= 'openid profile offline_access';
    my $query = buildForm( { client_id => 'rpid', scope => $scope } );
    my $res   = $op->_post(
        "/oauth2/device", IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
    my $payload     = expectJSON($res);
    my $device_code = $payload->{device_code};
    my $user_code   = $payload->{user_code} =~ s/-//gr;

    $res = $op->_get(
        "/device",
        query  => "user_code=$user_code",
        cookie => "lemonldap=$id",
        accept => 'text/html'
    );
    my ($csrf) =
      $res->[2]->[0] =~
      m%<input type="hidden" name="token" value="([\d_]+?)" />%;
    $query = buildForm(
        { user_code => $user_code, action => 'approve', token => $csrf } );
    $res = $op->_post(
        "/device", IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query)
    );
    expectOK($res);

    $query = buildForm( {
            grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code => $device_code,
            client_id   => 'rpid',
        }
    );
    my $token = $op->_post(
        "/oauth2/token", IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
    return ( $token, $device_code );
}

# --- 1. nominal organization enrollment ------------------------------------

my ( $res, $device_code ) = enroll();
my $payload = expectJSON($res);
ok( $payload->{access_token},  "Got access_token" );
ok( $payload->{refresh_token}, "Got offline refresh_token" );
count(2);

# The token identifies the device, not the admin who approved it
$res = getUserinfo( $op, $payload->{access_token} );
my $userinfo = expectJSON($res);
is( $userinfo->{sub}, 'rpid', "Token subject is the client, not the admin" );
count(1);

my $oidc =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
my $atSession = $oidc->getAccessToken( $payload->{access_token} );
ok( $atSession, "Access token session readable" );
like( $atSession->data->{_deviceId},
    qr/^[0-9a-f]{64}$/, "Access token carries a per-device id" );
count(2);

# The synthetic session behind it
my $synthetic = getSession( $atSession->data->{user_session_id} )->data;
is( $synthetic->{_user}, 'rpid', "Synthetic session is the client identity" );
ok( $synthetic->{_deviceOrg}, "Synthetic session flagged as org device" );
is( $synthetic->{_approved_by},
    'french', "Synthetic session records the approving admin" );
count(3);

# _utime follows the core pattern `time + ttl - timeout` with the *per-RP*
# offline lifetime — not `time + ttl`, which reaped the session `timeout` late
my $expected = time + 86400 - $op->p->conf->{timeout};
cmp_ok( abs( $synthetic->{_utime} - $expected ),
    '<', 10, "Synthetic session _utime follows time + ttl - timeout" );
count(1);

# A second enrollment gets its own device id
( $res, undef ) = enroll();
$payload = expectJSON($res);
my $second = $oidc->getAccessToken( $payload->{access_token} );
isnt( $second->data->{_deviceId},
    $atSession->data->{_deviceId},
    "Each enrollment gets a distinct device id" );
count(1);

# --- 2. fail closed when the synthetic session cannot be created -----------

{
    no warnings 'redefine';
    my $orig = \&Lemonldap::NG::Portal::Main::getApacheSession;

    # Break exactly one thing: the creation of the synthetic org session
    local *Lemonldap::NG::Portal::Main::getApacheSession = sub {
        my ( $self, $sid, %args ) = @_;
        return undef
          if ( !defined $sid
            and ( $args{kind} // '' ) eq 'SSO'
            and ref $args{info} eq 'HASH'
            and $args{info}->{_deviceOrg} );
        return $orig->( $self, $sid, %args );
    };

    ( $res, $device_code ) = enroll();

    # No token, and an error that says "server side problem", not
    # "you are not allowed"
    expectReject( $res, 400, "server_error" );

    my $body = eval { from_json( $res->[2]->[0] ) } || {};
    ok( !$body->{access_token},
        "No token minted when the device identity cannot be built" );
    count(1);
}

# The device authorization was consumed: the enrollment must be restarted, it
# never silently falls back to the approving admin
my $query = buildForm( {
        grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
        device_code => $device_code,
        client_id   => 'rpid',
    }
);
$res = $op->_post(
    "/oauth2/token", IO::String->new($query),
    accept => 'application/json',
    length => length($query)
);
expectReject( $res, 400, "expired_token" );

# ... and the plugin still works once the store is healthy again
( $res, undef ) = enroll();
$payload = expectJSON($res);
ok( $payload->{access_token}, "Enrollment works again after the failure" );
count(1);

clean_sessions();
done_testing();
