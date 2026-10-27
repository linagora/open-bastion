use warnings;
use Test::More;
use strict;
use IO::String;
use JSON;
use File::Find;
use Digest::SHA qw(sha256_hex hmac_sha256_hex);

BEGIN {
    require 't/test-lib.pm';
    require 't/oidc-lib.pm';
}

# The user_code is a live approval credential for as long as the enrollment is
# pending. It used to be stored in cleartext in BOTH device-authorization
# session records, and logged in cleartext at debug (creation) and info
# (invalid submission) level. Anyone able to read the session store or the
# production logs could approve — or deny — an enrollment in the device's
# place.
#
# It is now never persisted and never logged in cleartext. The lookup session
# is addressed by hmac_sha256_hex(user_code, key) rather than the bare digest:
# 20^8 is a few GPU-seconds, so an unkeyed digest let a reader of the session
# backend recover every pending code (issue #83). The audit trail gets the same
# index, not the code, wherever the code is still live (issue #84).
#
# This test pins all of it -- store, logs, audit records -- plus the
# per-session lockout that stops a logged-in user from brute-forcing the code
# space.

# Capturing logger, installed on the plugin instance ($self->logger is rw,
# inherited from Common::Module), and capturing audit sink, installed on the
# portal ($p->_auditLogger is rw, Common::PSGI). They are different sinks: the
# audit trail is usually shipped further than the debug log, so it needs its
# own assertions.
{

    package t::CaptureAudit;
    sub new { return bless { records => $_[1] }, $_[0] }

    sub log {
        my ( $self, $req, %info ) = @_;
        push @{ $self->{records} },
          join( ' ', map { "$_=" . ( $info{$_} // '' ) } sort keys %info );
        return 1;
    }
}

{

    package t::CaptureLogger;
    sub new { return bless { msgs => $_[1] }, $_[0] }

    foreach my $level (qw(error warn notice info debug)) {
        no strict 'refs';
        *{$level} = sub {
            push @{ $_[0]->{msgs} }, "$level|$_[1]";
            return 1;
        };
    }
}

my $debug = 'error';
my @logs;
my @audit;

# The secret the user_code index is keyed with
my $portalKey = 'a-portal-secret';

my $op = LLNG::Manager::Test->new( {
        ini => {
            logLevel                        => $debug,
            key                             => $portalKey,
            domain                          => 'op.com',
            portal                          => 'http://auth.op.com/',
            authentication                  => 'Demo',
            userDB                          => 'Same',
            issuerDBOpenIDConnectActivation => 1,
            customPlugins => '::Plugins::OIDCDeviceAuthorization',
            oidcServiceDeviceAuthorizationExpiration      => 600,
            oidcServiceDeviceAuthorizationPollingInterval => 5,
            oidcServiceDeviceAuthorizationUserCodeLength  => 8,

            # Lockout under test
            oidcServiceDeviceAuthorizationMaxFailures  => 3,
            oidcServiceDeviceAuthorizationLockoutDelay => 300,
            oidcRPMetaDataOptions                      => {
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

my $plugin = $op->p->loadedModules->{
    'Lemonldap::NG::Portal::Plugins::OIDCDeviceAuthorization'};
ok( $plugin, 'Device authorization plugin loaded' );
count(1);
$plugin->logger( t::CaptureLogger->new( \@logs ) );
$op->p->_auditLogger( t::CaptureAudit->new( \@audit ) );

# Every file of the session store that mentions $needle
sub storeHits {
    my ($needle) = @_;
    my @hits;
    find(
        {
            no_chdir => 1,
            wanted   => sub {
                return unless -f $_;
                open my $fh, '<', $_ or return;
                local $/;
                my $content = <$fh>;
                close $fh;
                push @hits, $_ if ( defined $content and $content =~ /\Q$needle\E/ );
            }
        },
        $main::tmpDir
    );
    return @hits;
}

sub logsMentioning {
    my ($needle) = @_;
    return grep { /\Q$needle\E/ } @logs;
}

sub auditMentioning {
    my ($needle) = @_;
    return grep { /\Q$needle\E/ } @audit;
}

# --- 1. creating a device authorization ------------------------------------

@logs  = ();
@audit = ();
my $query = buildForm( { client_id => 'rpid', scope => 'openid profile' } );
my $res   = $op->_post(
    "/oauth2/device", IO::String->new($query),
    accept => 'application/json',
    length => length($query)
);
my $payload = expectJSON($res);

my $device_code = $payload->{device_code};
my $user_code   = $payload->{user_code} =~ s/-//gr;
my $index       = hmac_sha256_hex( $user_code, $portalKey );
my $bareDigest  = sha256_hex($user_code);
ok( $user_code, "Got user_code" );
count(1);

is( $plugin->_userCodeIndex($user_code),
    $index, "The index is the code keyed with the portal secret" );
isnt( $index, $bareDigest, "... and not the bare digest" );
count(2);

is( scalar storeHits($user_code),
    0, "Plaintext user_code is nowhere in the session store" );
ok( scalar storeHits($index) >= 1,
    "The session store keys the lookup on the keyed index" );
is( scalar storeHits($bareDigest),
    0, "The bare digest -- which is invertible -- is nowhere in the store" );
count(3);

is( scalar logsMentioning($user_code),
    0, "Plaintext user_code was not logged at creation" );
ok( scalar logsMentioning($index) >= 1, "Its index was logged instead" );
count(2);

is( scalar auditMentioning($user_code),
    0, "Plaintext user_code did not reach the audit trail at creation" );
ok( scalar auditMentioning($index) >= 1,
    "The INITIATED record carries the index" );
count(2);

# The device_code is a secret too: only its digest may be stored
is( scalar storeHits($device_code),
    0, "Plaintext device_code is not in the session store" );
count(1);

# --- 2. submitting an invalid code -----------------------------------------

my $id = login( $op, 'french' );

sub submit {
    my ($code) = @_;
    my $r = $op->_get(
        "/device",
        query  => "user_code=$code",
        cookie => "lemonldap=$id",
        accept => 'text/html'
    );
    my ($csrf) =
      $r->[2]->[0] =~ m%<input type="hidden" name="token" value="([\d_]+?)" />%;
    my $q =
      buildForm( { user_code => $code, action => 'approve', token => $csrf } );
    @logs = ();
    return $op->_post(
        "/device", IO::String->new($q),
        cookie => "lemonldap=$id",
        accept => 'text/html',
        length => length($q)
    );
}

my $bogus = 'ZZZZZZZZ';
$res = submit($bogus);
expectOK($res);
like( $res->[2]->[0], qr/invalidUserCode/, "Invalid code rejected" );
is( scalar logsMentioning($bogus),
    0, "Submitted code was not logged in cleartext" );
ok(
    scalar logsMentioning( hmac_sha256_hex( $bogus, $portalKey ) ) >= 1,
    "Its index was logged instead"
);

# A submitted code may well be a valid one, probed or mistyped, so the
# INVALID_CODE record must not carry it either
is( scalar auditMentioning($bogus),
    0, "Submitted code did not reach the audit trail" );
ok(
    scalar auditMentioning( hmac_sha256_hex( $bogus, $portalKey ) ) >= 1,
    "The INVALID_CODE record carries the index"
);
count(5);

# --- 3. per-session lockout after too many invalid codes -------------------

# One failure already spent above; two more reach the configured maximum of 3
submit('ZZZZZZZY');
$res = submit('ZZZZZZZX');
like( $res->[2]->[0], qr/invalidUserCode/,
    "Third invalid code still answered with the plain error" );
count(1);

$res = submit('ZZZZZZZW');
like( $res->[2]->[0], qr/deviceTooManyAttempts/,
    "Fourth attempt is locked out" );
count(1);

# A valid code is refused too while the lockout holds: this is a session-wide
# brake, not a per-code one
$res = submit($user_code);
like( $res->[2]->[0], qr/deviceTooManyAttempts/,
    "The lockout also covers the valid code" );
count(1);

# ... until the lockout window elapses.
#
# +6m, not +10m. The lockout is oidcServiceDeviceAuthorizationLockoutDelay
# (300s) but the device code itself only lives
# oidcServiceDeviceAuthorizationExpiration (600s), counted from a request made
# in real time at the top of this file. Jumping +10m therefore landed exactly
# on the code's own expiry, with a margin equal to the real seconds this file
# had spent getting here: zero on a fast machine, negative on a loaded CI
# runner, where the "approval" below was in fact an expired-code refusal.
Time::Fake->offset("+6m");
$res = submit($user_code);
expectOK($res);
like( $res->[2]->[0], qr/deviceApproved/,
    "Approval works again once the lockout window elapsed" );
unlike( $res->[2]->[0], qr/invalidUserCode|deviceTooManyAttempts/,
    "  -> and it really is an approval, not a refusal" );
count(2);

# and a successful submission clears the budget
my $ssoSession = getSession($id)->data;
ok( !$ssoSession->{_deviceAuthFailures},
    "Failure counter reset by a valid submission" );
count(1);

Time::Fake->reset();

# --- 4. nothing leaks once the code has been exchanged ---------------------

$query = buildForm( {
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
$payload = expectJSON($res);
ok( $payload->{access_token}, "Device got its tokens" );
is( scalar storeHits($user_code),
    0, "Still no plaintext user_code in the store after the exchange" );
count(2);

# The lookup session is gone with the enrollment
is( scalar storeHits($index), 0, "Lookup session removed with the enrollment" );
count(1);

# --- 5. the index degrades safely, and finds pre-upgrade authorizations ----

# Without `key` there is nothing to key with. The plugin keeps working on the
# bare digest and says so once, rather than failing every lookup.
{
    @logs = ();
    local $plugin->conf->{key} = undef;
    is( $plugin->_userCodeIndex($user_code),
        $bareDigest, "No key configured: the index falls back to the digest" );
    ok( scalar( grep { /warn\|.*issue #83/ } @logs ),
        "... and warns about the exposure it falls back to" );

    # once per process, not once per code
    @logs = ();
    $plugin->_userCodeIndex($user_code);
    is( scalar( grep { /warn\|/ } @logs ), 0, "... exactly once" );
}
count(3);

# An authorization created by the previous version lives under the bare
# digest. It must still resolve during the upgrade window.
$query = buildForm( { client_id => 'rpid', scope => 'openid profile' } );
$res   = $op->_post(
    "/oauth2/device", IO::String->new($query),
    accept => 'application/json',
    length => length($query)
);
$payload = expectJSON($res);
my $old_code  = $payload->{user_code} =~ s/-//gr;
my $old_index = hmac_sha256_hex( $old_code, $portalKey );
my $old_id    = sha256_hex($old_code);

my $lookup =
  $op->p->getApacheSession( $old_index, kind => 'DEVA', hashStore => 0 );
ok( $lookup, "Lookup session created under the keyed index" );
my %copy = %{ $lookup->data };
$lookup->remove;
ok(
    $op->p->getApacheSession(
        $old_id,
        kind      => 'DEVA',
        info      => \%copy,
        force     => 1,
        hashStore => 0
    ),
    "Moved it to the pre-upgrade, unkeyed id"
);

ok( $plugin->_findByUserCode($old_code),
    "The code still resolves through the legacy fallback" );
count(3);

clean_sessions();
done_testing();
