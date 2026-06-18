# Access & Permissions: what you can control, and where

Open Bastion enforces access on **two layers**. Knowing which layer owns a given
decision is the key to operating it well:

- **SSO side (LemonLDAP::NG)** — _who_ may connect to which servers and _who_ may
  `sudo`, driven by **groups**. Centralized, applies fleet-wide, changes take
  effect in minutes.
- **Open Bastion side (per server)** — _how_ authentication and authorization are
  enforced locally: the PAM mode, the sudo policy, key-only service accounts,
  user provisioning, containment hardening, and any `sshd`/PAM tweaks.

The recommended posture is **"the SSO decides"**: keep per-server files minimal
and drive everything from LLNG groups. But every local knob below remains
available for defense-in-depth or for hosts that need a local exception
(see [Dual management](#dual-management)).

## Quick map — "I want to control X. Where?"

| Goal                                            | Layer            | How                                                                                           |
| ----------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------- |
| Who can SSH into which servers                  | **SSO**          | [Server groups](llng-configuration.md#server-groups) + `pam-access` rules                     |
| Who can `sudo`                                  | **SSO** (+local) | LLNG group → sudo authorization; optionally local `sudoers`                                   |
| Make `sudo` require a fresh SSO token           | **OB**           | [PAM Mode E](pam-modes.md) (max-security)                                                     |
| Which SSH **key types/sizes** are allowed       | **OB**           | `ssh_key_policy_enabled`, `ssh_key_allowed_types` ([security](security.md#ssh-key-policy))    |
| Auth method (token / SSH key / password)        | **OB**           | [PAM mode A–E](pam-modes.md)                                                                  |
| Non-SSO automation logins (ansible, backup, CI) | **OB**           | [`service-accounts.conf`](service-accounts.md)                                                |
| Auto-created home / shell / UID-GID range       | **OB**           | provisioning keys in [`openbastion.conf`](configuration.md)                                   |
| Which Unix groups are synced from LLNG          | **both**         | LLNG `managed_groups` + local `allowed_managed_groups` whitelist                              |
| Process containment (kill on logout, at/cron)   | **OB**           | [`--enable-hardening`](hardening.md)                                                          |
| Bastion → backend connection trust              | **both**         | LLNG signs the hop cert; backend `allowed_bastions` ([architecture](bastion-architecture.md)) |
| Revoke an admin everywhere                      | **SSO**          | remove from the group / close the account (see below)                                         |
| Onboard an admin                                | **SSO**          | add to the right group; they self-serve their SSH cert                                        |

## SSO side (LemonLDAP::NG)

Configured once in the portal, applied to the whole fleet. See
[LemonLDAP::NG Configuration](llng-configuration.md) for the setup.

- **Server groups** — tag each enrolled server with a group; access rules are
  written per group, not per host. See
  [Server groups](llng-configuration.md#server-groups).
- **Access rules (`pam-access`)** — for a given server group, decide which LLNG
  user groups may open an SSH session and which may `sudo`. This is the primary
  "who can do what, where" control.
- **SSH CA (`ssh-ca`)** — LLNG signs users' SSH certificates (validity window,
  principals). Users self-serve a cert with `ob-ssh-cert`; closing their account
  or letting the cert expire removes access. See the SSH CA section of
  [llng-configuration](llng-configuration.md).
- **Group synchronization** — LLNG advertises a user's `managed_groups`; the PAM
  module maps them to Unix supplementary groups on login (creating groups when
  needed). Pair with the local whitelist below.
- **Lifecycle**
  - _Onboarding_: add the user to a group → rights apply on next login.
  - _Role change_: change their groups → old rights drop and new ones apply
    within minutes (bounded by the [offline cache](offline-mode.md) TTL).
  - _Offboarding_: remove from the group or close the SSO account. See the
    detailed [offboarding procedure](security/03-offboarding.md).

## Open Bastion side (per server)

Written into `/etc/open-bastion/` by `ob-bastion-setup` / `ob-backend-setup` /
`ob-standalone-setup` (or the [ob-builder](../admin-builder/README.md) artefacts).

- **PAM mode (A–E)** — the strictness of authentication and whether `sudo` is
  token-gated. Mode E (max-security) accepts only SSO-signed certs, requires a
  fresh LLNG token for `sudo`, and enforces a KRL. See
  [PAM Authentication Modes](pam-modes.md).
- **sudo policy** — token-gated via `pam_openbastion` (Mode E), and/or a local
  rule: the setups create the `open-bastion-sudo` group and
  `/etc/sudoers.d/open-bastion`. A host can also keep its own classic `sudoers`
  in parallel.
- **Service accounts** — key-only local accounts that bypass OIDC, with a local
  sudo grant. Powerful and local: see the trade-offs (sudo without token,
  reachability requirements) in [Service Accounts](service-accounts.md).
- **User provisioning** — shell, home, UID/GID ranges, skeleton dir, plus the
  `approved_shells` / `approved_home_prefixes` allow-lists that bound what a
  provisioned (or service) account may use. See [Configuration](configuration.md).
- **Group-sync whitelist** — `allowed_managed_groups` limits which LLNG-managed
  groups may be created/modified locally (defense-in-depth); groups outside the
  pool are never touched. See [Configuration](configuration.md).
- **Offline resilience** — `cache_enabled`, `cache_ttl`, and a shorter high-risk
  TTL bound how long cached authorizations survive an SSO outage. See
  [Offline mode](offline-mode.md) and [cache administration](offline-cache-admin.md).
- **Containment hardening** — opt-in `--enable-hardening` adds logind
  `KillUserProcesses`, an `nproc` cap and `at`/`cron` allow-lists. See
  [Hardening](hardening.md).

### Tuning the generated `sshd` / PAM configuration

The setups own two things you may want to extend:

- **`sshd` drop-ins** under `/etc/ssh/sshd_config.d/` (e.g.
  `00-open-bastion-*.conf`, and `60-max-security.conf` in Mode E). You can layer
  **additional** drop-ins for site policy — for example an
  `AuthorizedKeysCommand` to serve [service-account keys](service-accounts.md) in
  Mode E, or `AllowTcpForwarding no` to close the port-forward channel. Mind
  `sshd`'s "first value wins" rule for single-valued keywords (the `00-` prefix
  makes the Open Bastion settings win over distro drop-ins).
- **`/etc/pam.d/sshd`** (and `/etc/pam.d/sudo`, `sudo-i`) — the PAM stacks that
  invoke `pam_openbastion`. You can add stock PAM modules (e.g. `pam_systemd`,
  `pam_mkhomedir` options) around them.

> **Re-running a setup regenerates these files.** Keep site additions in
> separate, higher-numbered `sshd_config.d` drop-ins where possible, and re-apply
> PAM changes after an upgrade (re-running `ob-*-setup` is the supported path —
> see the upgrade notes in the [CHANGELOG](../CHANGELOG.md)).

## Dual management

The two layers are complementary, not exclusive:

- **SSO-only (recommended)** — no local sudoers, no service accounts; every
  decision comes from LLNG groups. Simplest to reason about and audit.
- **SSO + local** — keep specific local exceptions alongside the SSO: a
  break-glass [service account](service-accounts.md), a host-local `sudoers`
  rule, or a stricter PAM mode on a sensitive host. Local grants are **not**
  visible to the SSO, so inventory and review them deliberately (see the EBIOS
  risks for service accounts in [risk reduction](security/99-risk-reduce.md)).

## See also

- [PAM Authentication Modes](pam-modes.md) — the A–E matrix
- [LemonLDAP::NG Configuration](llng-configuration.md) — server-side setup
- [Configuration Reference](configuration.md) — every `openbastion.conf` key
- [Service Accounts](service-accounts.md) — key-only local accounts
- [Bastion Architecture](bastion-architecture.md) — bastion→backend trust
