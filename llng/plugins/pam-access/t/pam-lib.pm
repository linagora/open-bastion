# Helper functions for pam-access tests

package pam_lib;

use strict;
use warnings;
use IO::String;
use JSON;
use Lemonldap::NG::Common::Session;

# Install sibling plugin templates into LLNG site/templates/
sub install_plugin_templates {
    require File::Find;
    require File::Copy;
    require File::Path;
    require FindBin;

    my $plugins_root = "$FindBin::Bin/../../";
    for my $plugin (qw(oidc-device-authorization pam-access)) {
        my $tpl_dir = "$plugins_root/$plugin/portal-templates";
        next unless -d $tpl_dir;
        File::Find::find(
            {
                wanted => sub {
                    return unless -f $_ && /\.tpl$/;
                    my $rel = $File::Find::name;
                    $rel =~ s{^\Q$tpl_dir/\E}{};
                    my $dst = "site/templates/$rel";
                    File::Path::make_path( $dst =~ s{/[^/]+$}{}r );
                    File::Copy::copy( $File::Find::name, $dst );
                },
                no_chdir => 1,
            },
            $tpl_dir
        );
    }
}

# Enroll a server via Device Authorization Grant
# Returns the server access_token
#
# %opts:
#   scope         - scope to request (default 'pam:server')
#   client_id     - RP client id (default 'pam-access')
#   client_secret - RP client secret (default 'pamsecret')
# Enrolling another RP, or asking for another scope, yields a perfectly valid
# device-grant token that pam-access must nevertheless refuse.
sub enroll_server {
    my $json = _enroll(@_);
    return $json->{access_token};
}

# Same flow, returning ($access_token, $refresh_token). The caller must have
# asked for offline_access (and the RP must allow it), otherwise the refresh
# token is undef.
sub enroll_server_tokens {
    my $json = _enroll(@_);
    return ( $json->{access_token}, $json->{refresh_token} );
}

sub _enroll {
    my ( $op, $user_session_id, %opts ) = @_;

    my $scope     = defined $opts{scope} ? $opts{scope} : 'pam:server';
    my $client_id = $opts{client_id}     || 'pam-access';
    my $secret    = $opts{client_secret} || 'pamsecret';

    # Initiate device authorization
    my $query = main::buildForm( {
            client_id     => $client_id,
            client_secret => $secret,
            scope         => $scope,
        }
    );
    my $res = $op->_post(
        '/oauth2/device',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "Device auth failed: $res->[0]" unless $res->[0] == 200;

    my $json      = JSON::from_json( $res->[2]->[0] );
    my $device_code = $json->{device_code};
    my $user_code   = $json->{user_code};
    $user_code =~ s/-//g;

    # Get verification page for CSRF token
    $res = $op->_get(
        '/device',
        query  => "user_code=$user_code",
        cookie => "lemonldap=$user_session_id",
        accept => 'text/html',
    );
    my ($csrf_token) =
      $res->[2]->[0] =~ m/name="token"\s+value="([^"]+)"/;

    # Approve device
    $query = main::buildForm( {
            user_code => $user_code,
            action    => 'approve',
            token     => $csrf_token,
        }
    );
    $res = $op->_post(
        '/device',
        IO::String->new($query),
        cookie => "lemonldap=$user_session_id",
        accept => 'text/html',
        length => length($query),
    );

    # Exchange device code for token
    $query = main::buildForm( {
            grant_type    => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code   => $device_code,
            client_id     => $client_id,
            client_secret => $secret,
        }
    );
    $res = $op->_post(
        '/oauth2/token',
        IO::String->new($query),
        accept => 'application/json',
        length => length($query),
    );
    die "Token exchange failed: $res->[0]" unless $res->[0] == 200;

    return JSON::from_json( $res->[2]->[0] );
}

# Common OIDC+PamAccess config for tests
sub base_config {
    return (
        authentication                  => 'Demo',
        userDB                          => 'Same',
        issuerDBOpenIDConnectActivation => 1,
        customPlugins =>
          '::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization',
        oidcRPMetaDataExportedVars => {
            'pam-access' => {
                email  => 'mail',
                name   => 'cn',
                groups => 'groups',
            }
        },
        oidcServiceMetaDataAuthorizeURI       => 'authorize',
        oidcServiceMetaDataCheckSessionURI    => 'check_session',
        oidcServiceMetaDataJWKSURI            => 'jwks',
        oidcServiceMetaDataEndSessionURI      => 'logout',
        oidcServiceMetaDataRegistrationURI    => 'register',
        oidcServiceMetaDataTokenURI           => 'token',
        oidcServiceMetaDataUserInfoURI        => 'userinfo',
        oidcServiceMetaDataIntrospectionURI   => 'introspect',
        oidcServiceAllowAuthorizationCodeFlow => 1,
        oidcRPMetaDataOptions                 => {
            'pam-access' => {
                oidcRPMetaDataOptionsDisplayName          => 'PAM Access',
                oidcRPMetaDataOptionsClientID             => 'pam-access',
                oidcRPMetaDataOptionsClientSecret         => 'pamsecret',
                oidcRPMetaDataOptionsAccessTokenExpiration => 600,
                oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
            }
        },
        oidcRPMetaDataScopeRules => {
            'pam-access' => {
                pam          => '1',
                'pam:server' => '1',
            }
        },
        oidcOPMetaDataOptions    => {},
        oidcOPMetaDataJSON       => {},
        oidcOPMetaDataJWKS       => {},
        oidcServicePrivateKeySig => main::oidc_key_op_private_sig(),
        oidcServicePublicKeySig  => main::oidc_cert_op_public_sig(),
        pamAccessActivation      => 1,
        pamAccessRp              => 'pam-access',
    );
}

# The session record holding the (user, bastion_id) bastion voucher, addressed
# the way the plugin addresses it. Vouchers used to live under a key of the
# user's persistent session; they now have their own record, so a test that
# wants to age or corrupt one has to reach it here.
sub voucher_session {
    my ( $op, $user, $bastion_id ) = @_;

    my $plugin =
      $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::PamAccess'}
      or die 'pam-lib: PamAccess plugin not loaded';
    return Lemonldap::NG::Common::Session->new(
        { $plugin->_voucherStoreOpts( $user, $bastion_id ) } );
}

1;
