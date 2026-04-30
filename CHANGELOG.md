# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
    + sticky bit prevented users from deleting their own recordings
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
