# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A rejected `/pam/verify` token now fails cleanly instead of looking like a
  server outage.** On any negative verdict — expired or invalid one-time token,
  wrong token type, or an SSH fingerprint the portal refuses — the pam-access
  plugin answers `{"valid":false,"error":"<reason>"}` with no `user` field
  (`user` is only present on a positive verdict). The client required `user`
  unconditionally and bailed out with `Missing required 'user' field in
  response`, returning `PAM_AUTHINFO_UNAVAIL` — which reads as a server problem
  and, with `auth sufficient`, fell through to `pam_unix` then `pam_deny`. It
  now treats a `valid:false` verdict as a normal negative result: the reason is
  surfaced, authentication fails with `PAM_AUTH_ERR`, and rate-limiting/CrowdSec
  reporting run as intended. The verify-response parser was extracted
  (`ob_parse_verify_response`) and is now covered by unit tests.

## [0.6.2] - 2026-06-25

Hotfix for 0.6.1: the Debian package failed to install/upgrade.

### Fixed

- **0.6.1 package configuration no longer aborts in `postinst`.** A comment in
  the `open-bastion` postinst contained the literal debhelper substitution
  token. debhelper substitutes that token wherever it appears — including inside
  the comment — so the trailing words of the comment ended up on their own line
  and were executed as a command (`so: not found`, exit 127). Every 0.6.1
  install/upgrade therefore failed at `configure`, leaving the package
  half-configured. The comment no longer contains the token; the assembled
  postinst is syntax-checked. Upgrading to 0.6.2 completes configuration and
  repairs a host left half-configured by 0.6.1 (`apt -f install` /
  `dpkg --configure -a` also recover once 0.6.2 is available).

## [0.6.1] - 2026-06-25

Maintenance release: fixes a long-running-process crash in the NSS module and
keeps already-configured bastions working across plain package upgrades.

### Fixed

- **The NSS module no longer crashes a long-lived caching consumer (e.g.
  `nscd`).** `cache_find()` / `cache_find_by_uid()` freed an expired in-memory
  cache entry's password buffer but left the pointer dangling; once the cache
  reached capacity, the LRU eviction in `cache_add()` freed it a second time,
  aborting the host process with a glibc `double free or corruption` (SIGABRT).

- **`apt upgrade` no longer breaks an already-configured bastion.** The
  socket-activated bastion helpers — `ob-cert.socket` (hop-certificate minting
  for `ob-ssh`/`ob-scp`) and `ob-record.socket` (the session-recording sink) —
  ship `--no-enable`/`--no-start`, since the package can't know a host's role;
  `ob-bastion-setup` is what enables them. A plain package upgrade therefore left
  them inactive, and because recording is fail-closed every login was then
  refused (`recording sink unreachable; access refused`). The `postinst` now
  re-asserts both sockets on `configure`, idempotently, **only** when the host is
  already a bastion (the `ob-bastion-setup` sshd drop-in is present) and only
  enables `ob-record.socket` when session recording is on. Backends and
  unconfigured hosts are untouched. Re-running `ob-bastion-setup` remains the
  documented recovery and is no longer required merely to survive an upgrade.

## [0.6.0] - 2026-06-22

New bastion file-transfer and remote-command paths, declarative service accounts,
and automatic session-recording retention. `ob-ssh` gains one-shot backend
commands, `ob-sftp` joins `ob-ssh`/`ob-scp`, `ob-builder` can bake in
SSH-key-only service accounts, and `ob-session-prune` bounds the recordings
store. Includes a `-c CIPHER` passthrough fix for `ob-scp`/`ob-sftp` and a
progressive-discovery documentation reorganization.

### Added

- **`ob-ssh` can run a one-shot command on the backend.** A trailing command is
  now forwarded to the backend (`ob-ssh backend uptime`) and run
  non-interactively — no pty, output captured verbatim, like `ssh host cmd` —
  instead of being mis-read as a port (`Bad port '...'`). New `-p`/`--port`,
  `-l`/`--login` and `-o` (ssh option passthrough) flags, plus `--` to end
  option parsing; the legacy positional `[port]` still works. Works in both
  direct and `ForceCommand` modes. From a workstation whose `ssh_config` sets
  `RemoteCommand ob-ssh ...`, override it to append the command:
  `ssh -o RemoteCommand="ob-ssh 10.0.0.5 ls -la" backend1` (ssh forbids
  combining a command-line command with a configured `RemoteCommand`).
- **`ob-sftp` bastion file-transfer connector.** The `sftp` counterpart of
  `ob-ssh` / `ob-scp`: run on a bastion, it mints a short-lived,
  LLNG-signed certificate (via the shared `ob-cert-lib.sh`) and opens an
  interactive or batch SFTP session to a backend — no user SSH key on the
  bastion and no agent forwarding. Connects to a single endpoint
  (`[user@]backend[:path]`); options after the connector's own flags pass
  straight through to `sftp(1)`. See `ob-sftp(1)`.
- **`ob-builder` can declare service accounts.** The builder now collects
  SSH-key-only local accounts (ansible, backup, CI/CD, …) — interactively or via
  a `service_accounts:` list in the `--config` YAML — validates each entry
  (name, `SHA256:`/`MD5:` fingerprint, absolute shell/home) at build time, and
  bakes them into both outputs: the shell installer writes
  `/etc/open-bastion/service-accounts.conf` (`0600 root:root`) and the Ansible
  role carries them as `ob_service_accounts_content` (overridable per
  host/group). `service_accounts_file` is set in the generated
  `openbastion.conf`. No PAM-module change — `src/service_account.c` already
  parses that file. See `doc/service-accounts.md` and `ob-builder(1)`.
  Validated end-to-end on a Mode E VM (`local-test/deploy-shell.sh`). ob-builder
  warns when an account would be unusable on the target: a `home`/`shell` outside
  the approved lists (silently dropped by the PAM module) or a missing fixed
  `uid`/`gid` (NSS cannot resolve it for sshd's pre-auth lookup, so it is
  unreachable over SSH unless it already exists locally). `doc/service-accounts.md`
  documents these requirements (including not reusing a system username).
- **Session-recording retention (`ob-session-prune`).** A new daily timer
  (`ob-session-prune.timer`, enabled at install) bounds the recordings store,
  which matters because recording is fail-closed — a full disk refuses new
  logins. It compresses closed recording payloads older than
  `recording_compress_after_days` (default 1; typescripts compress ~10–20×,
  the `.json` index is left readable) and deletes recordings older than
  `recording_retention_days` (default 365; `0` keeps them forever). Expiry is
  logged at `notice` level since it drops audit evidence. Runs as root from a
  sandboxed oneshot service and only writes under
  `/var/lib/open-bastion/sessions`, preserving the tamper-evident layout. See
  `doc/session-recording.md` and `ob-session-prune(8)`.

### Fixed

- **`ob-scp` / `ob-sftp` no longer shadow `scp`/`sftp`'s own `-c CIPHER`.** Their
  config option is now long-only (`--config`); a short `-c` used to be consumed
  as the config path, so `ob-scp -c aes256-gcm@openssh.com …` never reached
  `scp`. Other options (`-p`, `-P PORT`, `-r`, `-b FILE`, `-l`, …) already passed
  through and still do; use `--` to end ob-\* option parsing explicitly.

### Documentation

- Docs reorganized for progressive discovery.
- Service-account security model documented.
- Backend access guidance corrected.
- Retention guidance.

## [0.5.1] - 2026-06-17

Server-token resilience and session-visibility fixes: bastions no longer silently
lose their bastion voucher (and sudo) overnight, and SSH sessions are visible to
`who`/`w`/`loginctl` again.

> **Upgrade note.** After upgrading, **re-run `ob-bastion-setup` /
> `ob-backend-setup`** (or `ob-standalone-setup`) so the regenerated
> `/etc/pam.d/sshd` registers sessions with `systemd-logind` and the heartbeat
> timer is armed. On an already-enrolled host you are not re-running, just arm
> the timer once: `systemctl enable --now ob-heartbeat.timer`.

### Fixed

- **`ob-heartbeat.timer` is now armed at enrollment.** The timer ships with
  `ConditionPathExists=/var/lib/open-bastion/token`, but the package's
  install-time `systemctl start` runs _before_ enrollment writes that token, so
  the condition was false and the timer was silently skipped — it only armed on
  the next reboot (an ordering race: hosts enrolled before the package was
  (re)configured were fine, the usual "install then enroll" order was not).
  Until then the short-lived server token expired with nothing to refresh it,
  and `pam_openbastion` fell back to its offline cache: a bastion login still
  succeeded but minted **no bastion voucher** (`ob-ssh` failed with
  `LLNG_BASTION_VOUCHER is unset`) and `sudo` locked out (`server token invalid
or expired`). `ob-enroll`, `ob-bastion-setup` and `ob-backend-setup` now
  `systemctl enable --now ob-heartbeat.timer` once the token is in place.
- **Cert-hop SSH sessions are visible to `who` / `w` / `loginctl` again (#150).**
  The generated `/etc/pam.d/sshd` omitted `pam_systemd`, so sessions were never
  registered with `systemd-logind` and were invisible to session tooling — and
  to `ob-heartbeat`'s connected-users report, which reads `loginctl`/`who`.
  `who am i` was empty and `sudo su` surfaced only `root`. Both setups now add
  `session optional pam_systemd.so` to the sshd session stack, emitted only when
  the module is installed (mirroring how distros tie the line to
  `libpam-systemd`).

### Changed

- **The server access token is now refreshed on demand.** On a `401` from
  `/pam/verify` or `/pam/authorize` (expired server token), `pam_openbastion`
  refreshes the token via `/pam/heartbeat` — which preserves the per-device
  `bastion_id`, unlike the OIDC `/oauth2/token` grant — persists it, and retries
  once **before** any offline fallback. A fresh login is therefore self-healing
  even if the heartbeat timer lapsed, instead of silently degrading to an
  unvouched offline session.

## [0.5.0] - 2026-06-16

Tamper-evident session recording — a non-root user can no longer delete or alter
its own session recordings — plus `sudo -i` and backend `sudo` fixes.

> **Upgrade note (session recording).** Recording now streams to a root,
> socket-activated sink (`ob-record-sink`) instead of being written by the user.
> After upgrade, **re-run `ob-bastion-setup`** (or `ob-standalone-setup`) so it
> enables `ob-record.socket`, sets `/var/lib/open-bastion/sessions` to
> `root:ob-sessions 0750`, and migrates any legacy per-user dirs to root
> ownership. Recording is **fail-closed** when enabled: if `ob-record.socket` is
> not active, recorded logins are refused. `ForceCommand` now points directly at
> `ob-session-recorder` (the setgid `ob-session-recorder-wrapper` is removed).

### Added

- **Tamper-evident session recording (#151).** Sessions are now streamed to a
  root, systemd socket-activated sink (`ob-record-sink`) instead of being written
  by the user-side recorder. The sink derives the recorded user from the
  connection's `SO_PEERCRED` (kernel-verified) and writes the recording +
  metadata **root-owned** under `/var/lib/open-bastion/sessions/<user>/`
  (`root:ob-sessions 0750`, files `0640`). The recorded user is not in
  `ob-sessions`, so it can no longer list, read, delete or truncate any
  recording — including its own. The recorder reaches the sink through the new
  unprivileged `ob-record-connect` connector (a POSIX shell cannot open an
  `AF_UNIX` socket). Recording is **fail-closed**: if the sink is unreachable the
  session is refused rather than falling back to a user-deletable file.
  Because the recorder runs on the bastion, a user who is root on a backend does
  not escape recording. New units `ob-record.socket` / `ob-record@.service`.
  Drops R-S18 to P=1 (see `doc/security/99-risk-reduce.md`).

### Changed

- **The setgid `ob-session-recorder-wrapper` is removed.** It created the
  user-owned per-user recording directory that made recordings deletable; with
  the root sink it is obsolete. `ForceCommand` now points directly at
  `ob-session-recorder`, and `/var/lib/open-bastion/sessions` is
  `root:ob-sessions 0750` (was `3771` setgid+sticky). `ob-bastion-setup` enables
  `ob-record.socket` and migrates any legacy user-owned per-user dirs to root
  ownership.

### Fixed

- **`sudo -i` is authorized again on bastions (#152).** `sudo -i` runs under the
  PAM service name `sudo-i`; `pam_openbastion` forwarded it verbatim to LLNG,
  whose pam-access plugin only knows `ssh`/`sshd`/`sudo` and default-denied the
  rest — so `sudo -i` failed at PAM account management while `sudo`/`sudo su`
  worked. The module now canonicalizes `sudo-i` to `sudo` (self-contained in the
  bastion; no plugin change required).
- **Backend `sudo` works for SSO users (#154).** `ob-backend-setup` configured
  the PAM side of sudo but never created the `open-bastion-sudo` group nor the
  `/etc/sudoers.d/open-bastion` rule, so an LLNG-authorized user still got "not
  in the sudoers file". It now provisions both (mirroring `ob-bastion-setup`,
  `visudo`-validated).
- **Debian package ships the socket-activation template units.** `dh_installsystemd`
  does not auto-install named `@.service` templates, so `ob-cert@.service` and
  `ob-record@.service` were missing from the `.deb` — the sockets could not spawn
  an instance ("Connection refused"). Both templates are now installed. (This was
  a latent gap for `ob-cert@.service` too.)
- **RPM GPG signature check (#99).** Release RPMs are signed with the native EL
  `rpm` so the signature verifies.

## [0.4.1] - 2026-06-16

Decouples bastion hop-certificate minting from the interactive `sudo` policy,
which was breaking `ob-ssh`/`ob-scp` in max-security (Mode E).

> Requires the matching `pam-access` LemonLDAP::NG plugin update: `/pam/bastion-cert`
> and `/pam/bastion-token` no longer require the caller's server group to be a
> configured bastion group. The `(bastion_id, user)` voucher is the sole control
> (it is minted by `/pam/authorize` only for a host in `pamAccessBastionGroups`),
> so a single project-wide OIDC `client_id` works with finer-grained PAM groups
> inside the project.

### Changed

- **Bastion cert minting no longer goes through `sudo`.** The old
  `ob-bastion-cert-helper` + NOPASSWD sudoers bridge is replaced by
  `ob-cert-daemon`, a socket-activated service (runs as root) reached through the
  new unprivileged `ob-cert-request` client. The daemon derives the
  certificate's user from the connection's `SO_PEERCRED` (kernel-verified, never
  from the request), so a caller can still only mint a certificate for itself,
  and the root-only server token never leaves the daemon. This decouples machine
  certificate minting from the interactive sudo policy — in Mode E the sudo PAM
  stack required an LLNG token, which broke `ob-ssh`/`ob-scp` hops. No sudo, no
  setuid. `ob-bastion-setup` now enables `ob-cert.socket` instead of installing a
  sudoers drop-in (and removes the obsolete one on upgrade). Request inputs are
  bounded and a connection timeout prevents a stalled peer from pinning a
  per-connection process.

## [0.4.0] - 2026-06-16

Completes the certificate-based bastion→backend hop: `ob-ssh` and `ob-scp` now
work end to end on OpenSSH 9.8+ (Debian 13, etc.), and the session recorder no
longer hides command exit codes.

> Requires the matching `pam-access` LemonLDAP::NG plugin: the cert
> `source-address` pin is now opt-in (`pamAccessBastionCertPinSourceAddress`,
> off by default), and each ephemeral hop certificate's fingerprint is
> registered so the backend's `/pam/authorize` fingerprint binding accepts it.

### Fixed

- **`ob-ssh` / `ob-scp` bastion→backend hop works end to end.** The per-session
  `LLNG_BASTION_VOUCHER` and the onward ephemeral certificate never reached the
  backend on OpenSSH >= 9.8: each connection runs as **two** processes named
  `sshd-session` (the privileged monitor and an unprivileged child), and the
  SSH-fingerprint spool writer (`ob-ssh-principals`) and the `pam_openbastion`
  reader keyed the spool on different PIDs, so the fingerprint was never
  recovered and the hop fell back to a no-cert authorize. The bastion helper,
  the backend helper and `pam_openbastion` now all converge on the **outermost
  contiguous `sshd-session`** (the monitor), with an `sshd` fallback for pre-9.8
  OpenSSH (RHEL/Rocky 9). `/run/open-bastion` is created `0711` (traversable by
  the `nobody` principals helper, not listable) so the spool can actually be
  written.
- **`ob-session-recorder` no longer hides command failures.** As the bastion
  `ForceCommand` it wrapped commands in `script(1)` without `-e`, so any
  non-interactive command through a bastion (`ob-ssh` / `ob-scp` hops, scripted
  `ssh`, CI jobs) reported success even when it failed, and the recorded session
  status was always `completed`. It now uses `script -e` (util-linux >= 2.31:
  Debian 11+, RHEL/Rocky 8+) so the child's exit status propagates; older
  `script` falls back to the previous behaviour.

### Security

- The SSH-fingerprint spool parent `/run/open-bastion` is `0711` (traverse-only,
  not world-listable) on both bastion and backend, and the `ob-enroll`
  device-state file is `0600` (it now lives in the traversable
  `/run/open-bastion`, so it is locked down by its own mode).

## [0.3.2] - 2026-06-16

Bug-fix release: Mode E privilege escalation now behaves as documented —
`sudo` and `sudo -i` require a fresh LLNG token — plus an `ob-builder` Mode E
deploy fix surfaced while validating the above on a full VM lab.

### Fixed

- **Mode E `sudo` requires the LLNG token again (no longer passwordless).** On a
  bastion the PAM module runs in `authorize_only` mode (the SSH certificate has
  already authenticated the user for sshd), but that setting also applied to the
  `sudo` PAM stack, where there is no prior certificate auth — so `sudo`
  silently succeeded without ever asking for a token, defeating the Mode E
  guarantee. `pam_openbastion` now always enforces the token for the `sudo` /
  `sudo-i` PAM services regardless of `authorize_only`. Fixed in the module, so
  it covers bastion, backend and standalone in every mode.
- **`sudo -i` works for SSO users.** `sudo` 1.9 uses a separate `sudo-i` PAM
  service that `ob-bastion-setup` / `ob-backend-setup` never configured, so
  `sudo -i` fell back to the distro default (`pam_unix`) and failed for NSS-only
  SSO users with _"account validation failure, is your account locked?"_. Every
  function that writes `/etc/pam.d/sudo` now also writes `/etc/pam.d/sudo-i`
  with the same stack.
- **`ob-builder` Mode E roles always ship the KRL file.** A Mode E Ansible role
  failed to deploy with _"Could not find open-bastion-krl"_ whenever the
  portal's KRL was still empty (a fresh portal with no revocations): the role's
  mandatory _Deploy KRL_ task referenced `files/open-bastion-krl`, but the
  emitter only wrote it when the fetched KRL was non-empty. It now always ships
  the file (an empty KRL is valid; the refresh cron fills it later).

### Added

- **`ob-standalone-setup`** — a symlink to `ob-bastion-setup` installed for
  clarity. Invoked under that name it defaults `--node-role` to `standalone`; an
  explicit `--node-role` still overrides it.

### Documentation

- Documented the full **`pam-access` OIDC Relying Party** setup in
  `doc/llng-configuration.md`: the required options
  (`AllowDeviceAuthorization`, `DeviceOwnership = organization`,
  **`AllowOffline = 1`**), the `offline_access` scope, and the
  offline-refresh-token gotcha (needs `oidc-device-organization` >= 0.3.3, or
  the device flow returns a non-renewable token and enrollment fails in
  Mode E). Referenced as a prerequisite from all three quick-starts (Docker,
  Ansible, shell).

## [0.3.1] - 2026-06-15

Maintenance release: `ob-heartbeat` now reports fleet visibility data
("who is connected", client version, node role) to the SSO, plus
robustness fixes for enrollment and the `ob-builder` Ansible artefacts
surfaced while deploying a Mode E bastion.

### Added

- **`ob-heartbeat` reports the connected users** ("who is connected on this
  machine") to the SSO in each beat: a `sessions` array of
  `{user, from, tty, since}`, collected via `loginctl` (with a `who(1)`/utmp
  fallback when systemd-logind is unavailable). Two new config keys:
  `report_sessions` (default `true`; the list is privacy-sensitive and can be
  disabled) and `max_reported_sessions` (default 200, caps the payload). The
  pam-access plugin stores it per machine as `_pamSessions` / `_pamSessionCount`
  (requires the matching LLNG plugin).
- **`ob-heartbeat` reports the open-bastion client version and the node role**
  (`node_role`: `bastion` | `standalone` | `backend`). `ob-bastion-setup` /
  `ob-backend-setup` gained `--node-role` (validated, written to
  `openbastion.conf`), and the shell installer forwards the builder's target
  role so standalone hosts are recorded correctly. Stored server-side as
  `_pamVersion` / `_pamNodeRole`.
- **Ansible quick-start for the shell installer** and documentation of the SSH
  connection variables (`ansible_host` / `ansible_user` /
  `ansible_ssh_private_key_file` / `ansible_become`, plus the
  `IdentitiesOnly=yes` tip) in the example inventory.

### Fixed

- **`ob-enroll` now fails when `offline_access` was requested but no
  `refresh_token` is issued.** It removes the unrenewable token and exits
  non-zero with actionable guidance, instead of saving a token that would let
  NSS/SSO work for ~1 h and then break (`ob-*-setup` only choked later, and the
  dead token was reused on the next run). A refresh-less token is still accepted
  when `offline_access` was not requested.
- **`ob-builder`: dropped a duplicate `ob_verify_ssl` key** in the generated
  Ansible defaults, which triggered Ansible's "duplicate mapping key" warning on
  every run.
- **Ansible role: the `Restart sshd` handler runs only when `ob_auto_setup` is
  false** (`| bool`-cast so `--extra-vars` string overrides behave). With
  `ob_auto_setup: true`, `ob-*-setup` already restarts sshd, and Mode E locks
  `sudo` behind an LLNG token — so a `become` handler flushed afterwards failed
  with "Missing sudo password" on an otherwise-successful deploy.
- **`ob-heartbeat`: hardened session collection** — validate
  `max_reported_sessions` (fall back to 200 on a non-integer), fall back to
  `who(1)` when `loginctl` exists but `list-sessions` fails (containers/chroots
  without logind), and fix the man page OPTIONS to match the script.

## [0.3.0] - 2026-06-13

Headline: **certificate-based bastion→backend vouching** replaces the
previous `LLNG_BASTION_JWT` / `SendEnv` mechanism, which was structurally
broken (a `SendEnv`/`AcceptEnv` variable only ever reaches the eventual child
process environment, never the PAM environment `pam_getenv` reads, so a backend
with `bastion_jwt_required=true` rejected every session). The bastion now
vouches for each hop by obtaining a short-lived, LLNG-signed SSH user
certificate; backends validate it natively. Also bundles the token-lifecycle,
NSS, sshd-lockdown and session-recorder fixes, and makes the `ob-builder`
artefacts (Ansible role and shell installer) deploy fully unattended.

### Added

- **Certificate-based bastion→backend vouching.** `ob-ssh` (on the bastion)
  generates an ephemeral keypair in tmpfs and asks LLNG to sign it
  (`POST /pam/bastion-cert`, authorised by the bastion's device-grant server
  token plus a per-`(bastion_id, user)` voucher proving the user actually
  connected to _this_ bastion). The resulting ~120 s user certificate carries
  `principal = user`, a `bastion=<id>;user=<u>;target=<host>` key-id and a
  `source-address` critical option. The backend's sshd validates it against the
  LLNG CA (`TrustedUserCAKeys`) and refuses it off-bastion (source-address),
  while an `AuthorizedPrincipalsCommand` enforces the `allowed_bastions`
  allowlist from the cert key-id. No agent forwarding and no user key on the
  bastion are required. See `doc/bastion-architecture.md` and
  `doc/design/bastion-cert-vouching.md`.
- **`ob-scp`**: bastion file-copy counterpart of `ob-ssh`. Copies files
  bastion→backend, backend→bastion, or backend↔backend using a short-lived
  vouched certificate. All transfers are forced through the bastion (`scp -3`)
  so the connection's source address matches the certificate's pinned address
  (a direct backend-to-backend transfer would be rejected). All remote
  endpoints must share the same remote user (one vouched certificate = one
  principal).
- **Ansible quick-start guide** (`doc/ansible-quickstart.md`): generate the
  bastion + backend roles with `ob-builder`, declare hosts and their IPs in an
  inventory, and apply with `ansible-playbook` (including unattended
  device-code auto-approval via an LLNG cookie). Linked from the main README,
  which now points at the two quick-starts (Docker try-it and Ansible fleet)
  instead of inlining a third.

### Changed

- **`ob-ssh-proxy` renamed to `ob-ssh`.** The bastion-to-backend connector is
  now `ob-ssh`; the certificate-minting logic it shares with the new `ob-scp`
  was factored into a sourced library, `ob-cert-lib.sh` (installed under
  `/usr/lib/open-bastion/`).
- **Server token relocated from `/etc/open-bastion/token` to
  `/var/lib/open-bastion/token`.** The token is runtime state (refreshed every
  few minutes by `ob-heartbeat`), not configuration, so per the FHS it belongs
  under `/var/lib`. This also lets the `ob-heartbeat.service` sandbox keep
  `/etc` fully read-only (`ProtectSystem=strict`) instead of having to leave
  `/etc/open-bastion` writable. Upgrades migrate automatically: the Debian
  `postinst` / RPM `%post` move an existing token and repoint
  `server_token_file` / `SERVER_TOKEN_FILE` in the deployed config files. The
  path remains configurable via `server_token_file`.
- **`ob-heartbeat` renews the access token from the offline refresh token.**
  The server is enrolled with an `offline_access` grant; the timer (every
  5 min, below the access-token lifetime) refreshes the short-lived access
  token so NSS resolution and authorization keep working — previously the
  access token could lapse (e.g. overnight) and `getent passwd` went empty.
- **`ob-builder` artefacts deploy fully unattended.** The generated Ansible role
  and self-extracting shell installer now run `ob-{bastion,backend}-setup`
  non-interactively end to end: they pass `--client-id` and `--yes` (setup
  otherwise aborted on a "Missing --client-id" / a `[y/N]` prompt), pass
  `--insecure` when `verify_ssl` is false (an http test portal was otherwise
  rejected), the shell installer forwards `--allowed-bastions`, and the Ansible
  role gained `ob_approve_base_url` / `ob_approve_host` overrides for
  controller-side device-code approval in split-horizon / NAT topologies.
  `ob-builder` also fails fast when neither `--output-shell` nor
  `--output-ansible` is given, and validates `allowed_bastions` against a safe
  character set before embedding it.

### Removed

- **The bastion-JWT transport and its verification subsystem.** The
  `bastion_jwt_*` configuration keys and the `AcceptEnv LLNG_BASTION_JWT` sshd
  directive are gone, along with the in-module JWT verifier (and its JWKS / JTI
  caches). They are replaced by the certificate vouching above; the
  "accept only this bastion" policy is now `ob-backend-setup --allowed-bastions`
  writing `/etc/open-bastion/allowed_bastions`. Existing configs still load
  (the removed keys are silently ignored). The unrelated `client_secret_jwt`
  OIDC client-assertion authentication is unaffected.

### Fixed

- **`ob-ssh` interactive sessions: double echo, and Ctrl-C / a failing command
  tearing down the connection.** The connector relied on ssh's TTY
  auto-detection when re-originating to the backend, which is fragile across a
  bastion-pty → backend-pty hop and could leave the bastion-side terminal in
  cooked mode (input echoed twice) and deliver signals to the connector instead
  of the remote shell. `ob-ssh` now controls TTY allocation explicitly: `-tt`
  when stdin is a terminal (so the bastion-side tty goes raw — single echo, and
  Ctrl-C / failures act on the remote shell), `-T` otherwise.
- **NSS module kept serving a stale access token after rotation.**
  `libnss_openbastion` loaded the server token once per process and never
  re-read it, so once `ob-heartbeat` rotated the token the cached value
  expired and the portal answered `401`. That was treated as
  "user not found", poisoning the (nscd) negative cache and breaking
  `getent passwd` / SSH logins roughly once per access-token lifetime until
  the resolver was restarted. The module now reloads the token when its mtime
  changes and distinguishes an authoritative "not found" from a transient
  error (HTTP ≠ 200 / curl failure): transient errors trigger a reload+retry
  and return `EAGAIN` / `NSS_STATUS_UNAVAIL` instead of being cached as a miss.
- **sshd hardening drop-in could be silently overridden by cloud-init.** Cloud
  images ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` with
  `PasswordAuthentication yes`, and sshd keeps the _first_ value seen while
  `Include` expands the drop-in directory alphabetically. The open-bastion
  drop-in was written as `50-open-bastion-{bastion,backend}.conf`, which sorts
  _after_ `50-cloud-init.conf`, so password authentication stayed enabled on
  freshly provisioned bastions and backends. `ob-bastion-setup` /
  `ob-backend-setup` now write `00-open-bastion-{bastion,backend}.conf` (and
  remove the legacy `50-` file on rerun) so the cert-only lockdown wins.
- **Session recording aborted the session on a fresh install.** The per-user
  recording lives under `/var/lib/open-bastion/sessions/`, but the recorder runs
  as the connecting user (its `ob-sessions` gid is dropped before exec) and
  could not traverse into its own subdir. The Debian `postinst` / RPM `%post`
  now create `/var/lib/open-bastion` as `711` and `sessions/` as `3771`
  (setgid + sticky + o+x, no o+r) so the de-privileged recorder can traverse
  without being able to list other users' sessions.
- **`ob-heartbeat` could not rewrite the access token** under its own sandbox
  (the path was effectively read-only), so token renewal silently failed.
- **`ob-bastion-id` hit a 403** fetching the bastion identity; it now uses the
  probe mode of `/pam/bastion-token`.

### Security

- Refreshed threat model for the cert-vouching + heartbeat model
  (`doc/security/`). "Only this bastion" is enforced defence-in-depth, both by
  the certificate `source-address` critical option (sshd-native) and the
  `bastion_id` allowlist parsed from the cert key-id by `pam_openbastion`.

## [0.2.3] - 2026-05-23

Tooling release: ships a new admin builder for fleet deployments
(`open-bastion-builder`), a small helper to discover bastion identities
(`ob-bastion-id`), and an Ansible role with opt-in device-code
auto-approval. The PAM/NSS modules themselves are unchanged on the
wire — only operator-side ergonomics and packaging.

### Added

- **`open-bastion-builder`** (new admin-side package): interactive Bash
  CLI `ob-builder` that asks a short questionnaire (security scenario,
  SSO URL, OIDC client_id / client_secret policy, server group, target
  role, optional bastion whitelist, optional Ansible auto-approve) and
  emits either a self-extracting shell installer or an Ansible role
  (or both). The generated artefact configures the open-bastion package
  on target servers against an LLNG SSO without ad-hoc per-host
  scripts. Ships its own `.deb` / `.rpm`, distributed separately from
  the runtime package so the builder is only installed on admin
  workstations. See `admin-builder/README.md`.

- **`ob-bastion-id`**: small utility that runs on an enrolled bastion,
  requests a JWT from LLNG's `/pam/bastion-token`, decodes it and
  prints the `bastion_id` claim.

- **Ansible auto-approval of the OIDC Device Authorization Grant**:
  the generated Ansible role can drive LLNG's `/device` endpoint with
  a session cookie obtained ahead of time via the `llng` CLI from
  `simple-oidc-client`, automating the per-host browser approval that
  required by RFC 8628. Opt-in at build time; the cookie is asked for via
  `vars_prompt` at every play run and is never persisted.

- **`ob-enroll`**: new `OB_ENROLL_STATE_FILE` env var. When set,
  `ob-enroll` writes `{user_code, verification_uri, portal_url,
interval}` to that file as soon as LLNG returns the device-grant
  initiation, then continues polling. External orchestrators
  (notably the new Ansible auto-approve flow) can read this file
  to drive the approval while `ob-enroll` is still polling. The
  file is removed on successful enrolment.

### Changed

- **Docker demo images** (`docker-demo-{cert,token,maxsec,token-svc}/`):
  all 10 build Dockerfiles now use `cmake -DCMAKE_INSTALL_PREFIX=/usr
... && make install` instead of per-Dockerfile allowlists of
  `cp ../scripts/ob-X` lines. New ob-\* scripts added to `CMakeLists.txt`
  automatically land in the demo containers; no per-Dockerfile
  maintenance needed.

- **Debian packaging**: `debian/{config,templates,postinst,postrm}`
  renamed to `debian/open-bastion.{config,templates,postinst,postrm}`
  to disambiguate now that three binary packages are produced
  (`open-bastion`, `open-bastion-desktop`, `open-bastion-builder`).
  `debian/*.install` files dropped the redundant `debian/tmp/` prefix.

### Fixed

- **`ob-enroll`** no longer overrides the bash positional `set -e` due
  to `[ ... ] && X` chains at the end of `_load_config_yq`,
  `_load_config_awk`, `run_outputs_for_role` and `main` — these
  silently exited the process when their trailing test was false.
  All four functions now end with an explicit `return 0`.

- **`open-bastion-builder` (security)**: embedded client_secret is now
  stored base64-encoded in the generated shell installer so that a
  secret containing shell meta-characters (`$`, `` ` ``, `"`, `\`) can
  no longer break out of the bash literal and achieve command
  execution as root at install time. Tightened `is_valid_url` for the
  same reason. Conf-file substitution at install time switched from
  `sed` (which used `|` as a delimiter without escaping) to bash
  native `${var//pattern/repl}`.

- **`make install`** ships `config/openbastion.conf.example`,
  `config/service-accounts.conf.example`, the hardening / audit
  templates under `/usr/share/open-bastion/`, `README.md`, and the
  man pages, instead of leaving them out of the install set.

## [0.2.2] - 2026-05-21

Robustness release for the setup scripts and the session recorder. The
previous setup could brick a fresh bastion in several non-obvious ways
(failed enrollment + applied SSH/PAM lockdown, silently broken NSS,
PAM module rejecting its own generated config) and the ForceCommand
recorder broke scp / sftp / rsync. None of this changes the on-wire
protocol with LemonLDAP::NG — only the install path and the recorder
behaviour are affected.

### Fixed

- **`ob-bastion-setup`**: no longer locks down SSH/PAM before server
  enrollment has succeeded. Added a pre-flight check on
  `POST /oauth2/device` and reorganised `main()` into three phases:
  inert preparation → portal pre-flight + enrollment → SSH/PAM
  lockdown. In `--max-security`, enrollment failure is now FATAL and
  the script aborts before touching `/etc/ssh/sshd_config*`,
  `/etc/pam.d/sshd`, `/etc/pam.d/sudo`, etc. Inert files written
  during phase 1 are rolled back from `BACKUP_DIR` (or removed if
  no backup existed), so a failed run leaves the system unchanged.

- **`ob-bastion-setup`** (NSS): `configure_nss` no longer silently
  no-ops when `/etc/nsswitch.conf` ships with `passwd:` / `group:`
  commented out or missing. The new `nss_configure_db` helper handles
  three cases (already configured, active line present, missing/
  commented) and refuses to proceed if the resulting line still
  doesn't include `openbastion`. Without this fix, `getent passwd`
  returned nothing for LLNG-managed users and SSH cert auth failed
  with `Invalid user xxx` even though the certificate was valid.

- **`ob-bastion-setup`** (PAM config): `/etc/open-bastion/openbastion.conf`
  is now generated with `authorize_only = true` by default. Without
  this flag, `pam_openbastion`'s `config_validate()` requires both
  `client_id` and `client_secret` for OIDC token introspection —
  which the bastion never receives, since the user authenticates
  with an SSH certificate. Symptom of the old behaviour: PAM
  account step failed with `pam_openbastion: Invalid configuration`
  immediately after a successful certificate authentication.

- **`ob-enroll`**: dropped `curl -f` from `build_curl_opts()` so that
  HTTP 4xx responses surface the portal's actual error body. The
  script already checks `http_code != 200` manually; with `-f` curl
  exited non-zero before the body was read and the user was told
  `Failed to contact portal` regardless of whether the portal was
  unreachable or simply rejecting the request (unknown `client_id`,
  missing scope, Device Authorization Grant disabled, etc.). The
  error messages now include the JSON response and a list of common
  causes.

- **`ob-session-recorder`** (scp / sftp / rsync): the `ForceCommand`
  recorder used to wrap every command in `script` / `asciinema` /
  `ttyrec`, which spawns a PTY. File-transfer protocols exchange a
  binary stream over raw stdio and the PTY's `NL` → `CR+NL`
  translation corrupted it (clients hung or aborted with
  `Connection closed`). The new `is_file_transfer()` detects
  `scp -t/-f`, `sftp-server`, `internal-sftp` and `rsync --server`
  and `exec`s those commands directly via the user's shell. Metadata
  is still written (`format = "transfer"`); only the PTY recording
  is skipped.

- **`ob-session-recorder`** (channel hang): the background session
  timeout (`(sleep N; kill -ALRM $$) &`) inherited stdin/stdout/stderr
  from sshd. sshd waits for every process holding the channel FDs to
  release them before closing the channel, so even after a clean
  `scp` finished the client appeared to hang for up to
  `MAX_SESSION_DURATION` (8 h by default). The subshell now redirects
  its FDs to `/dev/null`, and a `TERM`/`HUP` trap kills the `sleep`
  grandchild on cleanup so we no longer leak an 8-hour sleep per
  session.

### Added

- **`ob-bastion-setup`**: `-c` / `--client-id`, `-S` /
  `--client-secret-file FILE` (use `-` for stdin) and support for the
  `OB_CLIENT_SECRET` environment variable. Secrets passed via file
  or env stay out of `/proc/<pid>/cmdline`. The credentials are
  forwarded to `ob-enroll` via env so they never appear on its
  command line either.

- **`ob-bastion-setup`**: interactive retry on enrollment failure.
  On `invalid_client` or similar, the script asks the user whether
  to provide / update credentials and tries again (up to 3 attempts)
  without restarting the whole setup. Credentials that succeed are
  persisted in `/etc/open-bastion/openbastion.conf` so future
  re-enrollments via `ob-enroll` alone keep working.

- **`ob-bastion-setup`**: interactive prompts for `--server-group`
  and `--client-id` when they are omitted on the CLI. The silent
  `SERVER_GROUP="bastion"` default has been removed. In `--yes`
  (non-interactive) mode both options must now be passed
  explicitly — the script errors out otherwise instead of using
  a default that probably does not match the LLNG configuration.

- **`ob-bastion-setup`** (summary): the post-run banner now reports
  enrollment outcome (`✓ Server enrolled`, `✓ Token installed`,
  `✗ Server enrollment FAILED`) and switches to
  `Bastion Configuration INCOMPLETE` with an `ACTION REQUIRED` block
  when enrollment did not succeed and the user chose to proceed
  anyway.

## [0.2.1] - 2026-05-20

Maintenance release that completes the `llng-pam-module` →
`open-bastion` rebranding in the setup scripts, docs and Docker
demos, and patches a regression in the upstream LemonLDAP::NG
portal image used by the demos. No behavioural change in the PAM
or NSS modules.

### Fixed

- **`ob-bastion-setup` / `ob-backend-setup`**: stop looking for the
  defunct `/usr/sbin/llng-pam-enroll` (renamed to `ob-enroll`); a
  fresh setup no longer prints `[WARN] Server not enrolled. Run
llng-pam-enroll manually after installation.` after a successful
  enrollment.

- **`ob-bastion-setup`**: give /var/lib/open-bastion/sessions mode 3771
  ob-bastion-setup posed mode 1770 (drwxrwx--T) on the sessions
  parent. The ob-session-recorder-wrapper setgid binary creates the
  per-user subdir while it holds effective gid ob-sessions, then
  drops back to the user's gid and execs the recorder script. With
  the parent at 1770 the connecting user (not a member of ob-sessions)
  has no traverse right on the parent, so the script cannot stat
  its own subdir and logs "User sessions directory ... does not
  exist and could not be created", leaving sessions unrecorded.

- Sweep the remaining `llng-*` leftovers across scripts, docs,
  configs and Docker demos so paths, modules, units, packages and
  internal identifiers match the names actually installed by the
  Debian / RPM packages:
  - binaries: `llng-pam-{enroll,heartbeat}`,
    `llng-{ssh-cert,session-recorder,principals}` → `ob-*`
  - modules: `pam_llng.so` → `pam_openbastion.so`,
    `libnss_llng.so` → `libnss_openbastion.so`
  - paths: `/etc/security/pam_llng.*` → `/etc/open-bastion/*`,
    `/var/{cache,log,lib}/pam_llng` → `.../open-bastion`
  - sshd: `/etc/ssh/llng_ca.pub` → `/etc/ssh/open-bastion_ca.pub`,
    dropins → `50-open-bastion-{bastion,backend}.conf`
  - systemd: `pam-llng-heartbeat.timer` → `ob-heartbeat.timer`
  - apt package: `libpam-llng` → `open-bastion`
  - bash/env vars: `PAM_LLNG_*`, `LLNG_RECORDER_*` renamed
    consistently
  - Tests updated to match (`test_ob_session_recorder.sh`,
    `test_integration_maxsec.sh`).
  - Legitimate references to the LemonLDAP::NG SSO portal and to
    the external `llng` CLI client are preserved.

- **CI**: bump GitHub Actions to versions running on Node.js 24
  (#115).

### Upgrade notes

- If you were driving `ob-session-recorder` via the `LLNG_*`
  environment variables (`LLNG_RECORDER_CONFIG`,
  `LLNG_SESSIONS_DIR`, `LLNG_RECORDER_FORMAT`, `LLNG_MAX_SESSION`),
  rename them to their `OB_*` counterparts.

## [0.2.0] - 2026-04-30

This release groups three independent opt-in features (service
accounts, session-containment hardening, syscall-level audit trace)
and a security-analysis update. None of them changes existing
behaviour: a v0.1.5 deployment upgrades to v0.2.0 with no flag set
and runs identically. (Note: v0.1.6 was prepared internally but
never published; its contents are folded into v0.2.0.)

### Added

- **Service accounts (machine accounts)** — local Unix accounts
  declared in `/etc/open-bastion/service-accounts.conf`
  (`0600 root:root`) that LemonLDAP::NG never sees, for CI agents
  and headless tooling.
  - `pam_openbastion` materialises the Unix user on first login
    (`create_user = true`), with forced uid/gid and auto-created
    primary group.
  - `libnss_openbastion` resolves service accounts so `sshd`'s
    pre-auth `getpwnam()` succeeds; path configurable via
    `service_accounts_file =` in `nss_openbastion.conf`.
  - Mode E support via `scripts/ob-service-account-keys`
    (`AuthorizedKeysCommand` helper) so plain (non-SSO-signed) keys
    can authenticate registered service accounts without breaking
    the `AuthorizedKeysFile none` guarantee.
  - New `docker-demo-token-svc/` variant (coexists with
    `docker-demo-token`) and integration tests
    (`tests/test_integration_token_svc.sh` + Phase 7 in
    `tests/test_integration_maxsec.sh`).

- **Session-containment hardening** (`ob-bastion-setup
--enable-hardening`, opt-in, off by default) — closes the known
  SSH evasion channels (`setsid`+`nohup` orphans, deferred
  `at`/`cron` jobs, `systemd-run --user` timers) without any new
  setuid binary.
  - `KillUserProcesses=yes` deployed via
    `/etc/systemd/logind.conf.d/open-bastion.conf` (SIGHUP-applied,
    non-disruptive — does not kill the admin's own session).
  - `/etc/at.allow` empty + `systemctl mask atd` disable `at(1)` for
    non-root users; `/etc/cron.allow` root-only disables `crontab(1)`
    for non-root users (cron itself stays up because Mode E uses
    `/etc/cron.d/open-bastion-krl`).
  - Pre-flight refusal if any non-root user has `Linger=yes`, which
    would let them schedule jobs via `systemd-run --user
--on-active=…` (operator must `loginctl disable-linger <user>`
    before re-running).
  - `nproc` cap (256, `@ob-service` group exempt) as defense in depth
    against fork-bomb-style runaway processes.
  - Templates ship under `/usr/share/open-bastion/hardening/` (read
    only; deployment artefacts in `/etc/` are written by
    `ob-bastion-setup`, not by dpkg/rpm).
  - New `doc/hardening.md` and `tests/test_ob_bastion_setup_hardening.sh`
    (20 tests).

- **Primary audit trace via auditd** (`ob-bastion-setup
--enable-audit-trace`, opt-in, off by default) — syscall-level,
  tamper-evident audit independent of the pty session recording.
  - `/etc/audit/rules.d/open-bastion.rules`: `-S execve -S execveat`
    (both — `execveat` alone bypasses an `execve`-only rule),
    `-S connect`, watches on `/etc/passwd`, `/etc/shadow`,
    `/etc/group`, `/etc/sudoers` (and `.d`), `/etc/ssh/sshd_config`
    (and `.d`), `/var/lib/open-bastion/sessions/`, `/etc/open-bastion/`.
  - `/etc/cron.daily/open-bastion-audit-rotate` — daily SIGUSR1 to
    auditd; combined with `num_logs=7` gives ~1 week local
    retention.
  - `/etc/audit/auditd.conf` is **intentionally not modified** (it
    is a single admin-tunable file owned by the `audit` package; we
    use the drop-in mechanism `rules.d/` and document the
    recommended retention values for the admin to apply manually).
  - Warns and skips (does not refuse) if `auditd` is not installed
    so the rest of `ob-bastion-setup` continues normally.
  - `auditd` is declared as `Recommends:` (Debian) /
    `Recommends:` (RPM) — never installed silently.
  - New `doc/audit.md` and `tests/test_ob_bastion_setup_audit.sh`
    (11 tests).

### Changed

- **Security analysis updated** (`doc/security/02-ssh-connection.md`,
  `doc/security/99-risk-reduce.md`):
  - **R-S18 corrected** — the previous claim that the setgid wrapper
    - sticky bit prevented users from deleting their own recordings
      was inaccurate: the per-user subdirectory is
      `2770 user:ob-sessions`, so the user is owner and can `rm` their
      own files. Score revised from `(P=1, I=1)` to `(P=2, I=1)` —
      syslog `auth.info` (start/end) and the new auditd watch on
      `/var/lib/open-bastion/sessions/` preserve the timeline and
      record any unlink even if the file is deleted. The wrapper still
      provides cross-user isolation (which is what it was always
      really doing).
  - **R-S19 (new)** — session-containment evasion via `setsid`/`nohup`.
    Initial `(P=3, I=3)`; residual `(P=1, I=1)` with hardening +
    audit trace activated.
  - **R-S20 (new)** — deferred action via `at`/`cron`/`systemd-run
--user --on-active=…`. Initial `(P=2, I=3)`; residual `(P=1, I=2)`
    with hardening (limit: pre-existing crontabs in
    `/var/spool/cron/crontabs/` are not purged on activation).
  - **R-S21 (new)** — action not captured by the pty (`execveat`,
    UDP `sendto`, `io_uring`, TIOCSTI, ptrace, intra-session
    `LD_PRELOAD`). Initial `(P=2, I=3)`; residual `(P=1, I=2)` with
    audit trace (limit: UDP `sendto`/`sendmsg` not traced by
    default — opt-in extension documented).
  - New section "Pistes d'amélioration — Containment et Traçabilité"
    in `99-risk-reduce.md` with concrete next-steps (privileged
    session collector, `audisp-syslog` forwarding, MAC profiles,
    cryptographic recording signatures, etc.).

### Security

- `libnss_openbastion`: enforce strict `0600 root:root` on
  `service-accounts.conf` (mirrors `pam_openbastion`).
- Service-account entries are not persisted to the on-disk NSS cache
  to avoid exposing local-only metadata.
- Hardening pre-flight is a **security gate**: the linger check
  fails the step (`return 1`, no `/etc/` writes) even under `--yes`,
  so an operator cannot accidentally bypass it in batch mode.

### Upgrade notes

- All three new features are **opt-in**:
  - Service accounts: leave `service_accounts_file` unset in
    `openbastion.conf` / `nss_openbastion.conf`.
  - Hardening: do not pass `--enable-hardening` to `ob-bastion-setup`.
  - Audit trace: do not pass `--enable-audit-trace`.

  A v0.1.5 deployment upgraded to v0.2.0 with no flag set behaves
  exactly like v0.1.5.

- On a dedicated bastion host, the recommended invocation is now
  `ob-bastion-setup --portal … --enable-hardening --enable-audit-trace`.
  Both flags can be combined with `--max-security` (Mode E).

- The hardening step refuses to run if any non-root user has
  `Linger=yes`. If you have legitimate lingering services, disable
  linger (`loginctl disable-linger <user>`) before re-running, or
  leave `--enable-hardening` off.

- `auditd` is a `Recommends:` not `Depends:` — it is **not**
  pulled in automatically by `apt install --no-install-recommends`.
  Operators who want the audit trace must `apt install auditd`
  explicitly.

- `v0.1.6` was prepared internally (CHANGELOG entry + commit
  `c591109`) but **never tagged or published**. Its contents are
  folded into v0.2.0; no v0.1.6 → v0.2.0 upgrade path exists.

## [0.1.5] - 2026-04-20

### Security

- **SSH key fingerprint binding on `/pam/authorize` and `/pam/verify`**
  (requires LemonLDAP::NG **PamAccess ≥ 0.1.16** and **SSHCA ≥ 0.1.16**).
  `pam_openbastion` now forwards the SHA256 fingerprint of the SSH key
  used to open the session in the JSON body of both endpoints. LLNG
  cross-checks it against the user's persistent session (`_sshCerts`)
  and rejects the call if the certificate is unknown, revoked, or
  expired — independently of the local `sshd` KRL. This closes a gap
  where a certificate revoked on the portal could still open a session
  (or escalate via sudo) until the KRL propagated, or at all if
  `RevokedKeys` was missing from `sshd_config`.
- **Out-of-band fingerprint channel** for modern OpenSSH (≥ 9.x), which
  does not propagate `SSH_USER_AUTH` to the PAM environment during
  `pam_acct_mgmt`:
  - New helper `/usr/local/sbin/ob-ssh-principals`, wired as
    `AuthorizedPrincipalsCommand %u %f` by `ob-bastion-setup` and
    `ob-backend-setup`. It drops the fingerprint to
    `/run/open-bastion/ssh-fp/<sshd-session-pid>.fp` atomically
    (`mktemp` + `mv`).
  - `pam_openbastion` walks `/proc` up to the `sshd-session` ancestor
    and reads the matching file, with strict validation: directory not
    group/world-writable, file regular, owner == spool directory owner,
    mode `0600`, `nlink == 1`, content matches `SHA256:<base64>`, size
    ≤ 512 B. Fall back to parsing `SSH_USER_AUTH` if a custom-patched
    sshd does expose it.
  - Spool directory deployed as `0700 nobody:nogroup` (the
    `AuthorizedPrincipalsCommandUser`); hardened `systemd-tmpfiles`
    drop-in (`/etc/tmpfiles.d/open-bastion-ssh-fp.conf`) recreates it
    at boot so `/run` wipes do not silently disable the binding.
- **Strict SHA256 filter.** `pam_openbastion` refuses to forward a
  fingerprint that is not in the `SHA256:<base64>` form expected by
  LLNG (so an `sshd` configured with `FingerprintHash md5` cannot
  trigger systematic HTTP 400 from the portal). Non-SHA256 values are
  discarded and the call falls back to the pre-binding behaviour.

### Added

- `ob_client`: new top-level `fingerprint` field in `/pam/authorize`
  and `/pam/verify` request bodies when available. `ob_verify_token()`
  grows an optional `fingerprint` parameter.
- `ob_ssh_cert_info_t`: new `key_fingerprint` field populated from the
  spool or, as a fallback, from `SSH_USER_AUTH`.
- Integration tests (`tests/test_integration_{docker,maxsec}.sh`):
  three new cases — fingerprint accepted/unknown/malformed on
  `/pam/authorize`, rejection of a certificate revoked via
  `/ssh/myrevoke` without KRL refresh, and an end-to-end SSH attempt
  with that revoked certificate that must be refused at the PAM
  `account` phase.

### Upgrade notes

- Re-run `ob-bastion-setup` or `ob-backend-setup` on every bastion /
  backend: they now install `/usr/local/sbin/ob-ssh-principals`, the
  `/run/open-bastion/ssh-fp` spool, and the `systemd-tmpfiles`
  drop-in. The `AuthorizedPrincipalsCommand` line in
  `sshd_config.d/50-llng-bastion.conf` is updated to pass `%u %f`.
- Bastions running against a LemonLDAP::NG portal without PamAccess
  0.1.16 remain fully functional: the portal ignores the `fingerprint`
  field (backward-compatible). The extra security layer activates as
  soon as the portal is upgraded.
- `ExposeAuthInfo yes` is **no longer required** for the fingerprint
  binding (the helper + spool are self-sufficient); it remains useful
  for session auditing.

## [0.1.4] - 2026-04-18

### Security

- **Session recorder wrapper** (`ob-session-recorder-wrapper`): full rewrite
  with defense-in-depth against privilege escalation
  - Explicitly drop elevated gid via `setregid()` before `exec` (fixes a
    vector where the `ob-sessions` gid would leak into the recorder
    script's saved gid and child processes)
  - Switch to directory-based privilege separation: the wrapper creates
    `$SESSIONS_DIR/$USER` with mode `2770` (setgid) so files inside
    inherit the `ob-sessions` group without the script needing elevated
    gid
  - Sanitize environment before `exec`: strip `LD_PRELOAD`,
    `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `SHELLOPTS`,
    `BASHOPTS`, `CDPATH`, `GCONV_PATH`, `HOSTALIASES`, `LOCALDOMAIN`,
    `LOCPATH`, `MALLOC_TRACE`, `NIS_PATH`, `NLSPATH`, `RESOLV_HOST_CONF`,
    `RES_OPTIONS`, `TMPDIR`; force `PATH=/usr/sbin:/usr/bin:/sbin:/bin`
  - Validate username against `^[a-z_][a-z0-9_.-]*$` before use in
    path construction (prevents path traversal)
  - Resolve username from the real uid via `getpwuid()` instead of a
    user-controllable env variable
  - Fix TOCTOU races in session directory creation by using
    `fstat`/`fchown`/`fchmod` on an opened fd (CodeQL)
- **`scripts/ob-session-recorder`**: derive `SESSION_USER` from `id -un`
  instead of `$USER`; validate with the same regex
- **NSS module** (`libnss_openbastion`):
  - Config file and token file now opened with `O_NOFOLLOW` and verified
    via `fstat`: must be owned by root, must be a regular file, must
    not be group/world-writable; token file must not be
    group/world-readable
  - Add integer overflow check and 256 KB response cap in
    `write_callback`
  - Emit syslog diagnostics for every previously-silent rejection path
- **Defense-in-depth sudo**:
  - New system group `open-bastion-sudo` created automatically by
    `debian/postinst` and the RPM pre-install scriptlet
  - `pam_openbastion` session hook syncs membership on every login:
    `sudo_allowed=true` → add user to the group, `false` → remove
  - `nscd` group cache invalidated after a membership change so `sudo`
    sees the update immediately
  - `ob-bastion-setup` writes `/etc/sudoers.d/open-bastion` as
    `%open-bastion-sudo ALL=(ALL) ALL` for new installs (does not
    overwrite an existing file)

### Fixed

- **NSS configuration path**: `libnss_openbastion` now reads its config
  from `/etc/open-bastion/nss_openbastion.conf` — where CMake installs
  it and where `ob-bastion-setup`/`ob-backend-setup` have always
  written. The module was hard-coded to `/etc/nss_llng.conf` (leftover
  from the `llng-pam-module` → `open-bastion` rename), so NSS never
  found its config and silently refused to resolve users. Docker demos
  masked this with a `useradd -m` fallback that created local accounts
  whenever NSS failed; the fallback is removed and demos now fail fast
  on real NSS breakage
- `ob-bastion-setup` / `ob-backend-setup`: update internal variable and
  write config to the new NSS path

### Added

- **`quick-start/`** directory: minimal 2-container demo (LLNG portal +
  single SSH server) using `yadd/lemonldap-ng-portal` directly,
  relying on the plugin autoloader (no `customPlugins` edit needed).
  README documents installing the four Open-Bastion plugins
  (`pam-access`, `ssh-ca`, `oidc-device-authorization`,
  `oidc-device-organization`) on an existing LemonLDAP::NG via
  `lemonldap-ng-store` or Debian packages
- `docker-demo-cert/README.md`: hands-on enrollment walkthrough fully
  refreshed (container names, config paths, script names) after the
  `llng-*` → `open-bastion`/`ob-*` rename

### Upgrade notes

- **NSS config path**: if you deployed v0.1.3 and ran
  `ob-bastion-setup` or `ob-backend-setup`, you have an orphaned
  `/etc/nss_llng.conf`. Re-running the setup script after upgrade
  writes the config to the new path and fixes user resolution. You can
  then `rm /etc/nss_llng.conf` to clean up. The Debian/RPM postinst
  does not migrate it automatically.
- **Session recorder usernames**: usernames with characters outside
  `[a-z_][a-z0-9_.-]*` (e.g. AD-style `DOMAIN\user` or `user@realm`)
  are now rejected by the wrapper. Open-Bastion's NSS module generates
  POSIX-safe usernames, so this only affects custom integrations.
- **NSS token file permissions**: the module now requires
  `/etc/open-bastion/token` to be mode `0600 root:root`. `ob-enroll`
  writes it with these permissions by default; custom deployments using
  `0640` with a group read will need to tighten.

## [0.1.3] - 2026-04-16

### Security

- **Session recording privilege separation** via setgid wrapper
  (`ob-session-recorder-wrapper`, group `ob-sessions`, directory mode
  `1770`)
- New risk R-S18: session recording tampering (mitigated P=1/I=1)

### Fixed

- PAM module name: `pam_llng.so` → `pam_openbastion.so` across scripts
  and setup tooling
- NSS module symbols: `_nss_llng_*` → `_nss_openbastion_*`
- NSS `nsswitch.conf` source name uses `openbastion`; `server_token_file`
  config key aligned
- `ob-enroll`: send `client_secret` to the device endpoint (optional but
  accepted by RFC 8628)
- `ob-bastion-setup`: add `Include` directive, `AuthorizedPrincipalsCommand`,
  `PermitRootLogin no`, NSS configuration, `pam_mkhomedir.so`
- Session recorder paths: `ob-session-recorder`, `/etc/open-bastion/`
- Sudo Mode E: remove `pam_unix.so` from `account` stack (NSS-only
  users), create `/etc/sudoers.d/open-bastion`

### Added

- Pre-hardening bootstrap: `securetty ttyS0`, `PermitRootLogin no`,
  emergency-access service account

## [0.1.2] - 2026-04-13

### Added

- **Mode E: Maximum Security** (#100): New security configuration enforcing the
  strictest SSH posture
  - SSH authentication via SSO-signed certificates only (`AuthorizedKeysFile none`)
  - sudo only via fresh LLNG temporary token (PAM-access re-authentication)
  - Mandatory KRL (Key Revocation List) with automatic refresh via `/ssh/revoked`
  - `--max-security` option in `ob-backend-setup` and `ob-bastion-setup` scripts
  - KRL refresh script with proper SSL/timeout option inheritance
- **docker-demo-maxsec**: Full Docker Compose demo for Mode E architecture
- **CI integration tests for Mode E** (`test_integration_maxsec.sh`): Validates
  certificate-only auth, unsigned key rejection, KRL configuration, sudo PAM
  hardening, and password authentication is disabled
- **EBIOS security study refactored** for maximum security target:
  - `doc/security/00-architecture.md` translated to French with Mode E introduction
  - `doc/security/02-ssh-connection.md` simplified to single architecture (Mode E)
  - `doc/security/03-offboarding.md` simplified to Mode E offboarding procedure
  - New risks R-S15 (stale KRL) and R-S16 (sudo escalation) documented

### Fixed

- **`OB_BASTION_JWT` → `LLNG_BASTION_JWT`**: Aligned environment variable name
  across all files to match the actual PAM module code and `ob-ssh-proxy`
- **`AllowAgentForwarding no`** on bastion: Agent forwarding is not needed
  (ob-ssh-proxy handles JWT injection, not ProxyJump)
- **ProxyJump references replaced with `ob-ssh-proxy`** in security documentation:
  native ProxyJump is incompatible with bastion JWT injection
- **KRL format validation**: Verify SSH KRL magic bytes (`SSHKRL`) before replacing
  the revocation file, preventing HTML error pages from breaking sshd

## [0.1.1] - 2026-02-07

### Added

- **Supplementary groups synchronization** (#95): LLNG can now manage Unix supplementary
  groups on target servers via the `managed_groups` configuration
  - **Local whitelist for managed groups** (`allowed_managed_groups`): Defense-in-depth
    option to restrict which groups LLNG can modify on each server
- **CrowdSec IP/CIDR whitelist** (#96): New `crowdsec_whitelist` option to bypass
  CrowdSec checks for trusted IPs/networks (VPN exit nodes, corporate NAT)
  - Supports IPv4, IPv6, and CIDR notation
  - Prevents self-inflicted DoS on shared IPs

### Fixed

- **TOCTOU race condition in cache_key.c** (#97): Use `open()` with
  `O_CREAT|O_EXCL|O_NOFOLLOW` instead of `fopen()` to prevent symlink attacks
- Check `fclose()` return value to detect flush errors before rename

## [0.1.0] - 2025-02-07

Initial release.
