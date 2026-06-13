# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`ob-scp`**: bastion file-copy counterpart of `ob-ssh`. Copies files
  bastion→backend, backend→bastion, or backend↔backend using a short-lived
  vouched certificate. All transfers are forced through the bastion (`scp -3`)
  so the connection's source address matches the certificate's pinned address
  (a direct backend-to-backend transfer would be rejected). All remote
  endpoints must share the same remote user (one vouched certificate = one
  principal).

### Changed

- **`ob-ssh-proxy` renamed to `ob-ssh`.** The bastion-to-backend connector is
  now `ob-ssh`; the certificate-minting logic it shares with the new `ob-scp`
  was factored into a sourced library, `ob-cert-lib.sh` (installed under
  `/usr/lib/open-bastion/`).

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

### Changed

- **Server token relocated from `/etc/open-bastion/token` to
  `/var/lib/open-bastion/token`.** The token is runtime state (refreshed every
  few minutes by `ob-heartbeat`), not configuration, so per the FHS it belongs
  under `/var/lib`. This also lets the `ob-heartbeat.service` sandbox keep
  `/etc` fully read-only (`ProtectSystem=strict`) instead of having to leave
  `/etc/open-bastion` writable. Upgrades migrate automatically: the Debian
  `postinst` / RPM `%post` move an existing token and repoint
  `server_token_file` / `SERVER_TOKEN_FILE` in the deployed config files. The
  path remains configurable via `server_token_file`.

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
