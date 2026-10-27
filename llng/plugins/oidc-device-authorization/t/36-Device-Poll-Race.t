use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# Regression: the polling path used to write `status => 'pending'` on every
# poll. The status it decided from was read at the start of the request, so an
# admin decision landing in between was reset — and because the session update
# merges rather than replaces, the approval fields (user_session_id, user,
# approved_at, scope) survived on a record that had gone back to `pending`.
#
#   * a clobbered approval left the device polling until expiry;
#   * a clobbered denial let a second approver grant what an admin refused.
#
# The poll now writes its bookkeeping only (poll_count, slow_down_count), so a
# decision stored meanwhile survives. The tests below reproduce the
# interleaving deterministically: they take the read the poll works from
# BEFORE the decision, let the decision land, then let that in-flight poll
# finish its write.

my $debug = 'error';

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
                    oidcRPMetaDataOptionsAllowDeviceAuthorization => 1,
                },
            },
            oidcServicePrivateKeySig => oidc_key_op_private_sig,
            oidcServicePublicKeySig  => oidc_cert_op_public_sig,
        }
    }
);

my $plugin =
  $op->p->loadedModules->{'Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization'};
ok( $plugin, 'Device authorization plugin loaded' );
count(1);

my $id = login( $op, 'french' );

# --- helpers ---------------------------------------------------------------

sub newDeviceAuth {
    my $query = buildForm( { client_id => 'rpid', scope => 'openid profile' } );
    my $res = $op->_post(
        "/oauth2/device", IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
    return expectJSON($res);
}

sub poll {
    my ($device_code) = @_;
    my $query = buildForm( {
            grant_type  => 'urn:ietf:params:oauth:grant-type:device_code',
            device_code => $device_code,
            client_id   => 'rpid',
        }
    );
    return $op->_post(
        "/oauth2/token", IO::String->new($query),
        accept => 'application/json',
        length => length($query)
    );
}

# Submit the verification form (approve or deny) with a fresh CSRF token
sub decide {
    my ( $user_code, $action ) = @_;
    my $res = $op->_get(
        "/device",
        query  => "user_code=$user_code",
        cookie => "lemonldap=$id",
        accept => 'text/html'
    );
    my ($csrf) =
      $res->[2]->[0] =~
      m%<input type="hidden" name="token" value="([\d_]+?)" />%;
    my $query =
      buildForm( { user_code => $user_code, action => $action, token => $csrf } );
    return $op->_post(
        "/device", IO::String->new($query),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($query)
    );
}

# What an in-flight poll writes once it is done: bookkeeping only. This is
# exactly the call deviceCodeGrantHook() makes on the pending branch.
sub finishInFlightPoll {
    my ($stale) = @_;
    return $plugin->_updateDeviceAuthFields( $stale,
        { poll_count => ( $stale->{poll_count} || 0 ) + 1 } );
}

# --- 1. an approval landing mid-poll must survive --------------------------

my $payload     = newDeviceAuth();
my $device_code = $payload->{device_code};
my $user_code   = $payload->{user_code} =~ s/-//gr;

expectReject( poll($device_code), 400, "authorization_pending" );

# The poll now reads the record...
my $stale = $plugin->_findByDeviceCode($device_code);
is( $stale->{status}, 'pending', "In-flight poll read a pending record" );
count(1);

# ...the admin approves while that poll is in flight...
expectOK( decide( $user_code, 'approve' ) );

# ...and the poll finally writes.
finishInFlightPoll($stale);

my $fresh = $plugin->_findByDeviceCode($device_code);
is( $fresh->{status}, 'approved',
    "Approval survives a poll that started before it" );
ok( $fresh->{user_session_id}, "Approval kept its user session id" );
is( $fresh->{poll_count}, 2, "Poll bookkeeping was still recorded" );
count(3);

# End to end: the device gets its tokens instead of polling until expiry
my $res = poll($device_code);
$payload = expectJSON($res);
is( $res->[0], 200, "Token exchange succeeds after the interleaved poll" );
ok( $payload->{access_token}, "Got access_token" );
count(2);

# --- 2. a denial landing mid-poll must survive -----------------------------

$payload     = newDeviceAuth();
$device_code = $payload->{device_code};
$user_code   = $payload->{user_code} =~ s/-//gr;

expectReject( poll($device_code), 400, "authorization_pending" );

$stale = $plugin->_findByDeviceCode($device_code);
is( $stale->{status}, 'pending', "In-flight poll read a pending record" );
count(1);

expectOK( decide( $user_code, 'deny' ) );

finishInFlightPoll($stale);

$fresh = $plugin->_findByDeviceCode($device_code);
is( $fresh->{status}, 'denied',
    "Denial survives a poll that started before it" );
count(1);

# End to end: a denied code stays denied, it does not go back to pending
# where a second approver could grant it
expectReject( poll($device_code), 400, "access_denied" );

# --- 3. a burst of late polls must not revert a decision either ------------

$payload     = newDeviceAuth();
$device_code = $payload->{device_code};
$user_code   = $payload->{user_code} =~ s/-//gr;

expectOK( decide( $user_code, 'approve' ) );

# Several devices (or retries) can have polls in flight at once; none of them
# may take the record back to pending.
$fresh = $plugin->_findByDeviceCode($device_code);
is( $fresh->{status}, 'approved', "Record approved before the burst" );
count(1);

# Simulate three in-flight polls (all read `pending`, all finish late)
my @inflight = map { { %$fresh, status => 'pending' } } ( 1 .. 3 );
finishInFlightPoll($_) for @inflight;

$fresh = $plugin->_findByDeviceCode($device_code);
is( $fresh->{status}, 'approved',
    "Approval survives a burst of late polls" );
count(1);

$res     = poll($device_code);
$payload = expectJSON($res);
ok( $payload->{access_token}, "Device still gets its tokens" );
count(1);

# --- 4. two token requests racing for the same approved device_code --------
#
# The device_code is single-use, but consumption used to be an unconditional
# delete: two requests reading `approved` before either deleted both minted a
# full token set, and the theft left the legitimate device's exchange
# succeeding, so nothing looked wrong (issue #68). The consumption is now
# conditional — whoever does not win the delete mints nothing.

{
    $payload     = newDeviceAuth();
    $device_code = $payload->{device_code};
    $user_code   = $payload->{user_code} =~ s/-//gr;
    expectOK( decide( $user_code, 'approve' ) );

    # Simulate losing the delete: the first removal of the deviceauth session
    # reports that it is already gone, exactly as it would for the request
    # that arrives second on the backend.
    my $orig = \&Lemonldap::NG::Common::Session::remove;
    my $lost = 0;
    no warnings 'redefine';
    local *Lemonldap::NG::Common::Session::remove = sub {
        my $self = shift;
        if ( ( $self->data->{_type} // '' ) eq 'deviceauth' and !$lost++ ) {
            $self->error('Object does not exist');
            return 0;
        }
        return $orig->( $self, @_ );
    };

    $res = poll($device_code);
    is( $res->[0], 400, 'The loser of the consumption race gets a 400' );
    my $err = from_json( $res->[2]->[0] );
    is( $err->{error}, 'invalid_grant', '  -> invalid_grant' );
    ok( !$err->{access_token}, '  -> and no token set is minted' );
    count(3);
}

# --- 5. consuming a device_code evicts it from every node's cache ----------
#
# Common::Apache::Session::Store->remove only drops the local cache of the
# node doing the write, so without an `unlog` event another node kept serving
# a deleted device_auth from cache for the whole code TTL (issue #68).

{
    my @unlogged;
    my $orig = \&Lemonldap::NG::Handler::Main::publishEvent;
    no warnings 'redefine';
    local *Lemonldap::NG::Handler::Main::publishEvent = sub {
        my ( $class, $req, $msg ) = @_;
        push @unlogged, $msg->{id}
          if ref $msg eq 'HASH' and ( $msg->{action} // '' ) eq 'unlog';
        return $orig->( $class, $req, $msg );
    };

    $payload     = newDeviceAuth();
    $device_code = $payload->{device_code};
    $user_code   = $payload->{user_code} =~ s/-//gr;
    expectOK( decide( $user_code, 'approve' ) );

    $res = poll($device_code);
    ok( expectJSON($res)->{access_token}, 'A normal exchange still succeeds' );
    is( scalar @unlogged, 2,
        '  -> both the device_code and user_code sessions are unlogged' );
    count(2);
}

clean_sessions();
done_testing();
