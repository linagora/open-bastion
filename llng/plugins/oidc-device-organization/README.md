# OIDC Device Organization - Organization Device Ownership

Extension to the [oidc-device-authorization](../oidc-device-authorization)
plugin that adds organization-level device ownership for RFC 8628 Device
Authorization Grant.

## Overview

By default, tokens issued via Device Authorization Grant are tied to the user
who approved the device enrollment. With organization ownership, the token
identifies the **client application** (the enrolled device) instead.

This is useful for:

- Server enrollment (bastions, CI/CD runners)
- Kiosks and shared devices
- IoT devices
- Any device that should remain authorized even if the approving admin leaves

## Requirements

- LemonLDAP::NG >= 2.23.2
- **oidc-device-authorization** plugin must be installed and active

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-device-organization
```

> **Important:** `::Plugins::OIDCDeviceAuthorization` must appear **before**
> `::Plugins::OIDCDeviceOrganization` in `customPlugins` so that the hooks
> it provides are registered first.

## Configuration

For each OIDC RP:

| Parameter                              | Default          | Description                                   |
| -------------------------------------- | ---------------- | --------------------------------------------- |
| `oidcRPMetaDataOptionsDeviceOwnership` | _(empty = user)_ | `organization` to enable org device ownership |

When set to `organization`:

- The admin approves the device enrollment
- The resulting token's subject (`sub`) is the `client_id` instead of the admin
- The token survives the admin leaving the organization
- Refresh tokens follow RP offline session expiration settings
  (`oidcRPMetaDataOptionsOfflineSessionExpiration`, else the global
  `oidcServiceOfflineSessionExpiration`), and the synthetic session behind them
  is given exactly that lifetime
- Every token derived from the enrollment carries a `_deviceId`: a stable,
  unique-per-device digest downstream consumers can pin on, rather than the
  `client_id` shared by every device of the project

## Failure behaviour

If the synthetic session cannot be created, the enrollment **fails** with an
OAuth `server_error` on the token endpoint. It does not fall back to the
approving admin's identity: such a token would carry the admin as its `sub`,
die with the admin's SSO session and have no `_deviceId` at all — a failure
that surfaces only hours later. Retry the enrollment once the session backend
is healthy.

## Refreshing an organization device token

The core `/oauth2/token` `refresh_token` grant **does not serve these tokens**:
it re-resolves the subject in the UserDB, and the synthetic identity is a
`client_id`, not a user. Open Bastion refreshes through pam-access's
`/pam/heartbeat`, which mints a fresh access token directly from the refresh
token's stored (synthetic) session data, so the UserDB is never queried.

`_deviceId` is derived from the synthetic session id and is therefore stable
across every refresh — which matters, because `PamAccess::_callerId` uses it as
the bastion identity, and a device whose id changed at refresh would silently
lose its vouchers.

With `oidcRPMetaDataOptionsAllowOffline = 0` and no online refresh token, the
device gets an access token and nothing to renew it with; the identity swap
still happens and `_deviceId` is still stamped.

## Testing

```
node mcp/cli.js test oidc-device-organization
```

The suite pulls in pam-access as a test-only dependency (`test_depends` in
`plugin.json`) so the `/pam/heartbeat` refresh path can be exercised
end to end.

## See Also

- [oidc-device-authorization plugin](../oidc-device-authorization) (required)
- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
