# OIDC Device Authorization - RFC 8628

This plugin implements [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
for LemonLDAP::NG.

## Features

- **Device code endpoint** (`/oauth2/device`): issues device and user codes
- **User verification page** (`/device`): portal page for users to enter the
  device code and approve/deny
- **Device code grant type** on the token endpoint
  (`urn:ietf:params:oauth:grant-type:device_code`)
- **PKCE support** for additional security
- **Configurable** expiration, polling interval, user code length and
  invalid-code lockout

## Requirements

- LemonLDAP::NG >= 2.23.2
- OIDC issuer must be enabled

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install oidc-device-authorization
```

Manually: copy `lib/` and `portal-templates/` into the appropriate directories,
copy `manager-overrides/` into `/etc/lemonldap-ng/manager-overrides.d/`,
add `::Plugins::OIDCDeviceAuthorization` to `customPlugins`, and run
`llng-build-manager-files`.

## Configuration

### OIDC Service Settings

In the Manager under **OpenID Connect Service** > **Device Authorization**:

| Parameter                                       | Default | Range   | Description                                                      |
| ----------------------------------------------- | ------- | ------- | ---------------------------------------------------------------- |
| `oidcServiceDeviceAuthorizationExpiration`      | `600`   | 60-3600 | Device code TTL (seconds)                                        |
| `oidcServiceDeviceAuthorizationPollingInterval` | `5`     | 1-60    | Min polling interval (seconds)                                   |
| `oidcServiceDeviceAuthorizationUserCodeLength`  | `8`     | 8-20    | User code length                                                 |
| `oidcServiceDeviceAuthorizationMaxFailures`     | `5`     | 0-100   | Invalid codes a session may submit before lockout (0 = disabled) |
| `oidcServiceDeviceAuthorizationLockoutDelay`    | `300`   | 30-3600 | How long that lockout lasts (seconds)                            |

The user code length has a floor of 8 for a reason: over the 20-character
alphabet of RFC 8628 section 6.1 that is ~34 bits of entropy, above the 20 bits
the RFC asks for. A code of 5 characters would leave 3.2 M candidates,
brute-forceable inside the code TTL.

The lockout is per SSO session and independent of CrowdSec: after
`MaxFailures` invalid codes, that session cannot submit any code — valid ones
included — for `LockoutDelay` seconds. A valid submission clears the counter.
CrowdSec, when configured, still gets an alert per invalid code
(`llng/device-auth-bruteforce` scenario) and adds IP-level protection.

### Per-RP Settings

| Parameter                                       | Default | Description                                   |
| ----------------------------------------------- | ------- | --------------------------------------------- |
| `oidcRPMetaDataOptionsAllowDeviceAuthorization` | `0`     | Enable Device Authorization Grant for this RP |

## Who may approve an enrollment

`oidcRPMetaDataOptionsAllowDeviceAuthorization` is a **boolOrExpr**, not a
plain flag, and the difference matters:

- `0` — the RP cannot use the device grant at all.
- `1` — the grant is enabled **and any authenticated user may approve (or deny)
  an enrollment for this RP**. There is no further check: whoever holds an SSO
  session and a pending user code becomes the identity behind the enrolled
  device.
- _an expression_ — the grant is enabled and the expression is evaluated,
  against the approving user's session, on every approve and deny.

**Enrolling a device is granting it an identity, so the expression form is the
recommended configuration.** For example, restricting approval to a group:

```
oidcRPMetaDataOptionsAllowDeviceAuthorization = $groups =~ /\bdeviceadmins\b/
```

### Restricting the verification page itself

The expression above governs the decision. You can also keep unauthorized
users away from the `/device` page entirely, with a `locationRules` entry on
the **portal's own virtual host** — the portal runs itself through the handler,
so its vhost rules apply to portal paths:

```
Virtual Hosts > auth.example.com > Access rules
    ^/device   ->   $groups =~ /\bdeviceadmins\b/
    default    ->   accept
```

> **The rule must not be anchored at the end.** Access rules are matched
> against `REQUEST_URI`, **query string included**, so `^/device$` would not
> match `/device?user_code=ABCD-EFGH` — the very URL RFC 8628's
> `verification_uri_complete` sends users to. Write `^/device`.

A `locationRules` entry alone is a coarse gate (it hides the page); the
per-RP expression is the one evaluated at decision time, for every RP. Use
both.

## Logging and audit

The plugin never logs a user code in cleartext, and never stores one. The
lookup record is addressed by `hmac_sha256_hex(user_code, key)` — keyed with
the portal secret, because a bare digest of an 8-character code over a
20-character alphabet is invertible in seconds by anyone who can list session
ids. The same index is what the debug and info lines carry.

With no `key` configured the index degrades to the bare digest, and the plugin
warns once that it has.

The audit log (`ISSUER_OIDC_DEVICE_AUTH_*`) records the submitted code on
approve and deny, which is what ties an enrollment to the admin who authorized
it and where the code is already spent. The records emitted while a code is
still live — `INITIATED`, `INVALID_CODE`, and `TOKEN_GRANTED` where only the
device code is known — carry `user_code_hash`, the index, instead.

## See Also

- [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [oidc-device-organization plugin](../oidc-device-organization): tokens that
  identify the enrolled device rather than the approving admin
