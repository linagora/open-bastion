package Lemonldap::NG::Portal::Plugins::OIDCDeviceOrganization;

# Organizational Device Authorization - Extension to RFC 8628
#
# When a RP is configured with oidcRPMetaDataOptionsDeviceOwnership='organization',
# the tokens issued via Device Authorization Grant identify the *client application*
# (the enrolled device) rather than the *admin who approved* the enrollment.
#
# This is useful for enrolling servers, kiosks, smart TVs, etc. that belong to
# the organization. The admin approves the enrollment but the resulting token
# survives the admin leaving the organization.
#
# Implementation: hooks into oidcDeviceCodeGrant (provided by OIDCDeviceAuthorization
# plugin) and replaces the user session data with a synthetic session whose identity
# is the client_id.

use strict;
use Mouse;
use Digest::SHA qw(sha256_hex);
use Lemonldap::NG::Portal::Main::Constants qw(PE_OK PE_ERROR);

our $VERSION = '2.23.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

use constant hook => {
    oidcDeviceCodeGrant  => 'handleOrganizationDevice',
    oidcGenerateMetadata => 'addDeviceAuthMetadata',
};

sub init {
    my ($self) = @_;
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'OIDC issuer not enabled, OIDCDeviceOrganization disabled');
        return 0;
    }
    1;
}

# Hook: oidcDeviceCodeGrant
# Called by OIDCDeviceAuthorization._generateTokens() after PKCE validation
# and before token creation.
sub handleOrganizationDevice {
    my ( $self, $req, $device_auth, $rp, $session_data ) = @_;

    # Check if this RP uses organizational device ownership
    my $ownership =
      $self->oidc->rpOptions->{$rp}->{oidcRPMetaDataOptionsDeviceOwnership}
      // '';
    return PE_OK unless $ownership eq 'organization';

    my $client_id   = $device_auth->{client_id};
    my $approved_by = $device_auth->{user};

    # Lifetime of the synthetic session = lifetime of the offline refresh
    # token that will keep pointing at it (see _utime below).
    my $ttl =
         $self->oidc->rpOptions->{$rp}
      ->{oidcRPMetaDataOptionsOfflineSessionExpiration}
      || $self->conf->{oidcServiceOfflineSessionExpiration}
      || 365 * 86400;

    $self->logger->debug(
        "Organization device enrollment: client=$client_id approved_by=$approved_by"
    );

    # Build synthetic session data (same pattern as client_credentials grant)
    my $infos = {
        $self->conf->{whatToTrace} => $client_id,
        _clientId                  => $client_id,
        _clientConfKey             => $rp,
        _scope                     => $device_auth->{scope},
        _user                      => $client_id,
        _approved_by               => $approved_by,
        _approved_at => $device_auth->{approved_at} || time,
        _deviceOrg                 => 1,

        # Set _utime far enough in the future so this session outlives normal
        # SSO sessions. The device will use refresh tokens to get new access
        # tokens, and the refresh points back to this session, so the session
        # must live exactly as long as the offline refresh token: the per-RP
        # oidcRPMetaDataOptionsOfflineSessionExpiration when set, else the
        # global oidcServiceOfflineSessionExpiration — the same lookup
        # newRefreshToken() does (Lib/OpenIDConnect.pm).
        #
        # `time + ttl - timeout` is the core session pattern
        # (Lib/OpenIDConnect.pm), because expiry is tested as
        # `( now - _utime ) > timeout` (Portal/Main/Run.pm). Adding the plain
        # ttl, as this plugin used to, reaped the session `timeout` too late.
        _utime => time + $ttl - $self->conf->{timeout},
    };

    my $session =
      $self->p->getApacheSession( undef, info => $infos, kind => 'SSO' );
    unless ( $session and $session->id ) {

        # Fail CLOSED. Returning PE_OK here would let the enrolment complete
        # against the *approving admin's* session: the device would get a token
        # whose sub is the admin (dying with the admin's SSO session) and
        # carrying no _deviceId at all, silently breaking every downstream
        # consumer of the device identity. The caller turns PE_ERROR into a
        # token-endpoint error, so the enrolment fails where it fails.
        $self->logger->error(
            "Failed to create synthetic session for org device");
        return PE_ERROR;
    }

    # Point to the new synthetic session instead of the admin's (its real id is
    # used for session lookups). One synthetic session is created per enrolled
    # device, so it is also a stable, unique-per-device anchor — but we never
    # expose the raw session id: see _deviceId below.
    $device_auth->{user_session_id} = $session->id;

    # NOTE: we deliberately KEEP offline_access in the scope so the device
    # gets a long-lived *offline* refresh token (the durable machine identity,
    # decoupled from the admin's SSO session — RFC 8628 / OIDC offline_access).
    #
    # The classic objection — "offline refresh re-resolves the user in the
    # UserDB and fails for the synthetic client_id" — does not apply here:
    # Open Bastion never uses the core /oauth2/token refresh grant for these
    # tokens. The PamAccess /pam/heartbeat endpoint mints fresh access tokens
    # directly from the refresh token's stored (synthetic) session data, so
    # the UserDB is never queried at refresh time. The synthetic attributes
    # are copied into the refresh token via %$session_data below.

    # Replace session_data so tokens carry synthetic attributes
    %$session_data = %{ $session->data };

    # Stable, unique per-device identifier carried into every token derived from
    # this enrollment (access + refresh), so downstream consumers (PamAccess
    # bastion vouching) can identify the individual device — not just its shared,
    # project-wide client_id. We derive it as a SHA-256 digest of the synthetic
    # session id rather than exposing the id itself: the value is surfaced in
    # tokens and in the audit trail (pam-access logs it as `server_id`), and the
    # raw session id is a live credential — anyone who learned it could replay it as
    # a `lemonldap` cookie and impersonate the synthetic session. The digest is
    # deterministic (stable across refreshes), unique per device, and one-way.
    #
    # The fixed prefix is domain separation: with hashedSessionStore enabled the
    # backend storage key is itself sha256_hex(session id), so a bare
    # sha256_hex(session id) here would equal that internal key. Prefixing
    # guarantees the exposed device-id can never coincide with a LLNG storage
    # key, in either storage mode.
    $session_data->{_deviceId} = sha256_hex( 'pam-device-id:' . $session->id );

    $self->userLogger->notice(
"Organization device enrolled: client=$client_id for RP $rp (approved by $approved_by)"
    );

    $self->auditLog(
        $req,
        code        => "ISSUER_OIDC_DEVICE_ORG_ENROLLED",
        rp          => $rp,
        client_id   => $client_id,
        approved_by => $approved_by,
        message     =>
"Organization device $client_id enrolled for RP $rp by $approved_by",
    );

    return PE_OK;
}

# Hook: oidcGenerateMetadata
# Advertise device_authorization_endpoint in discovery if any RP allows it
sub addDeviceAuthMetadata {
    my ( $self, $req, $metadata ) = @_;
    my $issuer = $metadata->{issuer};
    my $path   = $self->oidc->path . '/';
    $path = '/' . $path unless $issuer =~ /\/$/;
    $metadata->{device_authorization_endpoint} =
      $issuer . $path . 'device';
    return PE_OK;
}

1;
