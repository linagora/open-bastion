# LemonLDAP::NG Plugin Parameters

Optional parameters for the Open Bastion LLNG plugins, inserted into
`lemonldap-ng.ini`, section `[portal]` (or set via the Manager). This is a
reference companion to [LemonLDAP::NG Configuration](llng-configuration.md) —
none of these are required to get started.

> **Indicative only.** Names and defaults below are provided for convenience and
> may lag behind the plugins. The **authoritative** reference is each plugin's
> own documentation in the
> [lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins/tree/main/plugins)
> repository (see the per-plugin links at the bottom) — defer to it in case of
> any doubt or discrepancy.

## General Parameters

| Parameter                                       | Default      | Description                                                                                                             |
| ----------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `oidcServiceDeviceAuthorizationExpiration`      | `600` (10mn) | Device authorization expiration time                                                                                    |
| `oidcServiceDeviceAuthorizationPollingInterval` | `5`          | Polling interval in seconds (clients polling faster get `slow_down` errors)                                             |
| `oidcServiceDeviceAuthorizationUserCodeLength`  | `8`          | Length of user code (base-20 charset, collision-safe)                                                                   |
| `portalDisplayPamAccess`                        | `0`          | Set to 1 (or a rule) to display PAM tab                                                                                 |
| `pamAccessRp`                                   | `pam-access` | OIDC Relying Party name                                                                                                 |
| `pamAccessTokenDuration`                        | `600` (10mn) | Token duration                                                                                                          |
| `pamAccessMaxDuration`                          | `3600` (1h)  | Maximum token duration                                                                                                  |
| `pamAccessExportedVars`                         | `{}`         | Exported variables                                                                                                      |
| `pamAccessOfflineTtl`                           | `86400` (1d) | Offline cache TTL                                                                                                       |
| `pamAccessSshRules`                             | `{}`         | SSH access rules                                                                                                        |
| `pamAccessServerGroups`                         | `{}`         | Server groups configuration                                                                                             |
| `pamAccessSudoRules`                            | `{}`         | Sudo rules                                                                                                              |
| `pamAccessOfflineEnabled`                       | `0`          | Enable offline mode                                                                                                     |
| `pamAccessHeartbeatInterval`                    | `300` (5mn)  | Heartbeat interval                                                                                                      |
| `pamAccessManagedGroups`                        | `{}`         | Unix groups managed by LLNG per server group (see [Group Synchronization](llng-configuration.md#group-synchronization)) |

## Per-RP Device Authorization Parameters

These are set in the LLNG Manager on each OIDC Relying Party:

| Parameter                                       | Default | Description                                                                                                                                                                                                           |
| ----------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oidcRPMetaDataOptionsAllowDeviceAuthorization` | `0`     | Enable device grant. Can be a rule expression to restrict who can approve                                                                                                                                             |
| `oidcRPMetaDataOptionsDeviceOwnership`          | (empty) | Set to `organization` for organizational device mode (see below)                                                                                                                                                      |
| `oidcRPMetaDataOptionsAllowOffline`             | `0`     | Set to `1` to issue an **offline refresh token** so `ob-heartbeat` can renew the server's access token. **Required** for server enrollment (with the `offline_access` scope and `oidc-device-organization` >= 0.3.3). |

## Organizational Device Enrollment

When `oidcRPMetaDataOptionsDeviceOwnership` is set to `organization` on an RP, the **OIDCDeviceOrganization** plugin changes the device authorization behavior:

- An administrator approves the device normally through the `/device` page
- The resulting tokens identify the **client application** (client_id) instead of the approving admin
- The device token survives the admin's session expiration or account removal
- Refresh tokens remain valid independently of the admin's session

This is useful for enrolling servers, kiosks, or IoT devices that belong to the organization rather than a specific user.

For the device to get a **durable** (offline) refresh token, also set
`oidcRPMetaDataOptionsAllowOffline = 1` and deploy `oidc-device-organization`
**>= 0.3.3** (earlier versions stripped `offline_access`, leaving the server
with a non-renewable token). See the critical note under
[Step 2](llng-configuration.md#step-2-create-the-oidc-relying-party).

## Device Authorization Security Features

- **CSRF protection**: the `/device` verification form uses a one-time token
- **Rate limiting**: clients polling faster than the configured interval receive `slow_down` errors with incremental backoff
- **User code collision detection**: codes are regenerated on collision (up to 10 retries)
- **Per-RP access rules**: `AllowDeviceAuthorization` accepts boolean expressions to restrict which users can approve devices
- **CrowdSec integration**: invalid user_code attempts are reported to CrowdSec (scenario `llng/device-auth-bruteforce`)

When offline mode is enabled, the server-side cache is protected by
[Cache Brute-Force Protection](security.md#cache-brute-force-protection).

## SSH CA Parameters (optional)

| Parameter               | Default    | Description                               |
| ----------------------- | ---------- | ----------------------------------------- |
| `portalDisplaySshCa`    | `0`        | Set to 1 (or a rule) to display SSHCA tab |
| `sshCaCertMaxValidity`  | `365` (1y) | Maximum certificate validity              |
| `sshCaSerialPath`       | `""`       | Path for certificate serial storage       |
| `sshCaPrincipalSources` | `$uid`     | Principal sources                         |
| `sshCaKrlPath`          | `""`       | Path for Key Revocation List              |

## See Also

- [LemonLDAP::NG Configuration](llng-configuration.md) — the setup walkthrough
- Per-plugin READMEs: [pam-access](https://github.com/linagora/lemonldap-ng-plugins/tree/main/plugins/pam-access#readme),
  [ssh-ca](https://github.com/linagora/lemonldap-ng-plugins/tree/main/plugins/ssh-ca#readme),
  [oidc-device-authorization](https://github.com/linagora/lemonldap-ng-plugins/tree/main/plugins/oidc-device-authorization#readme),
  [oidc-device-organization](https://github.com/linagora/lemonldap-ng-plugins/tree/main/plugins/oidc-device-organization#readme)
