# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Will ship as 0.7.0. Before deploying, read
[UPGRADE-NOTES.md](UPGRADE-NOTES.md): it changes the fingerprint spool's owner,
the `auth` line of certificate-mode PAM stacks, and the accepted permissions of
`cache.key`.

> **Known issue.** SELinux `enforcing` (Rocky/RHEL/AlmaLinux) is untested with
> the on-disk NSS cache. An NSS module writes from `sshd_t`, `sudo_t` and
> friends rather than from a daemon of its own, and a denied write is silent by
> design, so the cross-process cache may never populate there. No policy module
> ships with the RPM; `doc/admin-guide.md` gives the `ausearch`/`audit2allow`
> check to run first.

### Added

- **`ob-post-upgrade`(8)** finishes a package upgrade on a host without asking
  for anything. The sshd principals helper is generated on the host, not
  shipped, so an upgrade replaces the daemon it talks to and leaves the helper
  as it was — and the only cure was "re-run the setup script with the arguments
  you used before", which an operator who deployed through `ob-builder` months
  ago does not have. This command needs none of them: the helper text, the
  tmpfiles rule, the socket and the spool ownership are all derivable from the
  host. It reads `openbastion.conf` for `node_role` alone, to pick the bastion
  or backend helper, and writes nothing back. It deliberately does **not**
  enrol — re-enrolling mints a new device id that no backend allowlist
  contains, so it is the one repair that breaks more than it fixes — and does
  not touch the server token, `sshd_config` or any PAM stack, which carry
  decisions it cannot know. The helper text moved to `share/`, installed as
  data, because a third inline copy alongside the two setup scripts is how the
  systemd units of #254 drifted apart.
- **`ob-client-jwt`(8)** builds `ob-enroll`'s `client_secret_jwt` assertion with
  the secret on stdin (#256). See Security below.
- **`ob-builder` deploys the service-account key** (#263). A `service_accounts:`
  entry takes `public_key` or `public_key_file`, and the generated bundle —
  shell installer and Ansible role alike — writes
  `/etc/open-bastion/service-accounts.d/<name>.pub`. `service-accounts.conf`
  told `pam_openbastion` what fingerprint to expect and gave sshd nothing to
  accept, so the deployment looked complete while the account could not log in.

  When any account carries a key the bundle passes `--enable-service-keys` to
  the setup it runs (`service_keys:` overrides), and `/etc/open-bastion` is left
  traversable. Without either, the feature could not work: the setup run removed
  the drop-in the bundle had just deployed, and at `0700` the
  `AuthorizedKeysCommandUser` could not reach the keys — both silently, with
  everything looking deployed.

  Keys are also removed when an account is dropped from the configuration.
  `ob-service-account-keys` serves any `.pub` present without consulting
  `service-accounts.conf`, so a write-only deployment meant revocation did not
  revoke.

  `key_fingerprint` is now **derived** from the key. Supplying both cross-checks
  them, and a mismatch stops the build: two values maintained apart is how a
  login gets refused with a key that looks correct in every listing. Neither
  artefact can turn on the `AuthorizedKeysCommand` itself — that is host-wide,
  and stays with `--enable-service-keys` — so both report when they find none.

- **`--enable-service-keys`** on `ob-bastion-setup` and `ob-backend-setup`
  (#263). Writes the sshd drop-in that makes a service account able to log in —
  `AuthorizedKeysCommand` pointing at `ob-service-account-keys`,
  `AuthorizedKeysCommandUser nobody`, and `ExposeAuthInfo yes` — and creates
  `service-accounts.d`. `service-accounts.conf` alone never sufficed: without
  an authorized key sshd refuses at the protocol layer and PAM never runs, and
  the manual assembly is what a field report got half-right.

  `ExposeAuthInfo` is written by the flag rather than left to Mode E on
  purpose. It is what puts `SSH_USER_AUTH` in the PAM environment, and without
  it the fingerprint check has nothing to read for a plain public key — the
  drop-in would let sshd accept the key while `key_fingerprint` was never
  verified. Mode E writes `ExposeAuthInfo` but _not_ the
  `AuthorizedKeysCommand`, so it alone still leaves a service account unable to
  log in.

  Opt-in, per this project's rule for changes to system-wide behaviour: it
  alters sshd for every session on the host. It **refuses** rather than
  overriding an `AuthorizedKeysCommand` that is already configured — sshd keeps
  the first value it sees and the drop-in is read before `sshd_config`, so
  enabling it on a host running its own key server would have made that command
  dead and taken every user who authenticates through it with it. Running
  without the flag removes the drop-in again, but only one carrying our own
  header; a hand-written file is left alone and reported. The generated
  configuration is validated with `sshd -t` and rolled back if sshd rejects it,
  because `configure_sshd`'s own check runs before this step.

  `fingerprint_required` is a separate decision — it applies to every SSH login,
  not only service accounts — so the flag reports whether it is set, in its
  output and in the end-of-run summary, rather than setting it. **And it is now
  preserved across setup runs**: `render_openbastion_conf` rewrites
  `openbastion.conf` wholesale and never emitted this key, so an operator's
  deliberate setting was dropped by the next run — by the very run that then
  warned it was missing.

- **`--enable-sudo-fresh-otp`** on `ob-bastion-setup` and `ob-backend-setup`
  (#178). `sudo`'s own credential cache (`timestamp_timeout`, 15 min, idle) makes
  it skip the PAM `auth` phase, so "a fresh SSO re-authentication for each
  `sudo`" was not what a user experienced. The flag writes
  `timestamp_timeout=0` scoped to the SSO group. Opt-in: enabling it by default
  would start prompting inside scripts and long maintenance sessions. What it
  does **not** change — tokens stay single-use and authorization is re-checked
  live on every `sudo` — is in `doc/pam-modes.md` and EBIOS risk R-S16.
- **The postinst reports a mode-c install on an sshd that still accepts
  passwords** (#180), and escalates the warning under `UsePAM no`, where sshd
  reads `/etc/shadow` itself and the PAM denial is bypassed rather than
  redundant. Reported only, never fixed: turning passwords off from a package
  script can lock out an administrator on a password session.
- **The PAM module invalidates the NSS module's file cache directly**, by name
  and by uid, so user and group-membership changes are visible at once. Entries
  are removed with `unlinkat()` on `O_NOFOLLOW` directory descriptors verified
  root-owned. The `nscd --invalidate` fork is kept where `nscd` still exists,
  because glibc routes `group` through it and this module implements `passwd`
  only — without it a sudo revocation could stay cached for an hour.
- **[UPGRADE-NOTES.md](UPGRADE-NOTES.md)** — what to do or check before
  deploying, starting with the `lemonldap-ng-plugins` 0.6.0 upgrade.
- **The EBIOS RM study is now complete** (#212, #216, #217, #218).
  `doc/security/` was presented as an EBIOS RM study while containing only
  workshop 4 — no essential assets, no risk sources, no strategic scenarios, and
  no written likelihood or severity scales, though the matrices assumed them.
  Workshops 1–3, the treatment plan (29 measures with owner, priority and state)
  and the homologation dossier (perimeter, four trust assumptions, fifteen
  conditions of use, residual-risk acceptance) are added, plus eight workshop-4
  sheets for the LLNG portal and its four plugins, which were a trusted boundary
  with no sheets at all. Owner names, dates and acceptance decisions are left as
  `À COMPLÉTER`: they belong to the homologation authority. Start at
  [doc/security/README.md](doc/security/README.md).
- **Mutation testing runs in CI** (`tests/test_ob_mutation.sh`, catalogue in
  `tests/mutation/`). Each entry removes one security control and requires the
  suite that guards it to fail; a surviving mutant means a green suite that
  checks nothing.

  It exists because that is what the 0.7.0 reviews kept finding, one PR at a
  time: a `grep` matching the comment above a rule instead of the rule, an
  assertion that passed because the probed file was absent rather than because
  the check refused it, a `grep -q` whose SIGPIPE under `pipefail` turned a
  match into a miss. None were coverage gaps — the tests existed, ran, and were
  green.

  Writing the catalogue immediately found four more: three of its own entries
  proved nothing (a mutation that added an unreachable branch instead of
  removing one, two whose search text matched twice, one that mutated the test
  rather than its subject), and one real gap — the rendered installer was
  checked for the presence of the key-deployment text, which survives disabling
  the block that runs it.

  A mutation that does not apply is a hard error, never a pass; C mutants are
  rebuilt before the suite runs, since an uncompiled mutant would pass for the
  wrong reason; a suite that **skips** is refused rather than read as a
  surviving mutant, because it exits 0 both before and after and can neither
  confirm nor refute; an entry declares whether it needs `root` or `nonroot` and
  the runner switches privilege for it, since a control whose expected owner is
  root is vacuously satisfied in a root run and one that guards a path only
  bites in a privileged one — running everything at one level reports the other
  half as surviving; and the runner verifies the tree is unchanged afterwards,
  distinguishing "the tree differs" from "git could not tell us".

- **`tests/test_ob_ci_coverage.sh`** fails when a test file exists that no CI
  job runs. `tests/test_backend_cert_acceptance.sh` — the e2e guard for "a
  backend accepts a hop only from its allowlisted bastion" — sat outside the
  `tests/test_ob_*.sh` loop and was named by no job, so it had been exiting 1
  in silence. `tests/test_integration_token_svc.sh` was in the same position.
  Both are now wired into the Docker job. A test nobody runs is worse than a
  missing one: it looks like coverage in review and in an audit.
- **`tests/test_ob_upgrade.sh`** upgrades a host staged from the `v0.6.2` tag
  and checks it converges. Every other suite tests the new code against a clean
  host, and nobody upgrades a clean host: the real one has a `0700 nobody`
  spool and a helper that writes it, generated months ago. Both halves are
  pinned — that installing the package **does not** migrate it (the claim
  `UPGRADE-NOTES.md` rests on, and the reason `ob-post-upgrade` exists at all),
  and that `ob-post-upgrade` then does. The old artefacts are extracted from
  the tag rather than imitated.
- **The legacy portal image is pinned** (`docker-demo-cert`). `ob-bastion-id`'s
  fallback to the removed `/pam/bastion-token` probe is exercised by exactly
  one thing in the tree, and only because the portal that demo runs happens to
  be old. On `:latest` that coverage would vanish the day an image ships the
  0.6.0 plugins — silently, with the suite still green.
- **`tests/test_ob_bastion_id.sh`** replays `ob-bastion-id` against a mock portal
  in every shape it must survive, including LemonLDAP::NG's catch-all HTML. The
  migration below had no coverage: the docker test only exercises whichever path
  the published demo image happens to take.

### Changed

- **The sshd anchor walk lives in one place** (#268). `ob-fp-daemon` and
  `pam_openbastion` each carried their own copy of the walk that derives the
  per-connection sshd pid the fingerprint spool is keyed on, kept in step by a
  comment saying they must agree exactly. Nothing checked that they did, and a
  divergence would break the SSH fingerprint binding *silently*: no error at
  login, the module simply finds no drop, and the reduction
  `doc/security/99-risk-reduce.md` credits to R-S3 and R-S15 is gone. Both now
  call `ob_find_sshd_anchor()` (`src/sshd_anchor.c`), and
  `tests/test_sshd_anchor.c` drives it from the writer's and the reader's
  depths over the same synthetic `/proc` ancestry, plus the depth limit, a
  non-contiguous `sshd-session` chain, pid 1, a vanished parent and a
  self-parenting one. Two entries in `tests/mutation/catalogue` fail if the
  outermost-ancestor rule or the contiguity break is removed. No behaviour
  change: the shared walk is what both copies already did.
- **systemd units live in one place** (#254). The Debian packaging kept a second
  copy of the socket units for `dh_installsystemd`'s `package.NAME.socket` form,
  and the copies drifted — `a9a28d8` added `UMask=0077` and the syscall filter to
  `systemd/`, the `debian/` copies never got them. No shipped unit was missing
  the hardening (the templates always came from `systemd/`); the damage was two
  files looking authoritative while one was silently wrong. All six now install
  from `systemd/`, and `tests/test_ob_systemd_units.sh` fails if unit content
  reappears under `debian/`.
- **`ob-bastion-id` asks `POST /pam/whoami`** instead of the removed
  `/pam/bastion-token` (#246), falling back to the legacy probe so it works
  against 0.5.x and 0.6.0 alike. The device id is unchanged across the upgrade:
  no `allowed_bastions` rewriting, no re-enrolment. The absence of the endpoint
  does not look like a 404 — LemonLDAP::NG serves its own login page with a 200
  for any unregistered `/pam/*` path — so the fallback triggers on that too. The
  request also lost `curl -f`, which discarded the body and collapsed every
  refusal into "Request failed". Exit 2 is now "the request failed or was
  refused", 3 "the portal answered with no identity in it".
- **The lab deployment scripts no longer invent a `bastion_id`** when
  `ob-bastion-id` fails (#246). They wrote the literal `ob-bastion` into
  `allowed_bastions`, which matches no hop certificate, so every hop was refused
  several phases later with errors pointing at certificates. They now leave the
  list empty and say so: weaker, but honest and diagnosable.
- **Request signing has one implementation, pinned to the portal's** (#247). The
  generators move into `src/ob_sign.c`, shared by the PAM module,
  `ob-cert-daemon` and `ob-sign-request`. `tests/test_ob_sign.c` checks the wire
  format against `Digest::SHA`'s `hmac_sha256_hex` — the function `PamAccess.pm`
  itself calls — rather than recomputing with OpenSSL, which would only prove the
  file agrees with itself. Signing had no coverage before. A signing failure now
  fails the request rather than falling back to an unsigned one; the exception is
  `ob-session-monitor`, where "we could not ask" must not become "the user is
  gone".
- **`ob-builder` artefacts carrying the client secret are no longer
  world-readable** (#203), and an embedded bundle gets a `.gitignore` so a
  `git add -A` in a surrounding tree cannot publish it. Bundles built with the
  default `client_secret_mode: prompt` are unchanged — nothing secret reaches
  disk.
- **`ob-ssh` / `ob-scp` / `ob-sftp` lost their privileged shortcut around
  `ob-cert-daemon`** (#202). A `[ -r "$SERVER_TOKEN_FILE" ]` branch called
  `/pam/bastion-cert` directly with the bastion's bearer token whenever the
  caller could read the token file — an escape hatch around the `SO_PEERCRED`
  design with none of the daemon's checks. Root and unprivileged callers now take
  the same audited path.
- **The bastion→backend host-key policy can be tightened** (#202). The
  connectors passed `StrictHostKeyChecking=accept-new` _before_ the operator's
  `SSH_OPTIONS`, and `ssh` keeps the first value it is given, so the TOFU default
  could not be overridden at all. It is now emitted only when `SSH_OPTIONS` does
  not set it. The trade-off is documented in `doc/admin-guide.md`, `man ob-ssh`
  and risk R-S9, where it had never been stated.
- **An unrecognised key in `openbastion.conf` is logged instead of silently
  ignored** (#229) — which is how `auth_cache_offline_ttl`, a key the module has
  never parsed, stayed in the documentation. Unknown keys are still ignored, so
  no host can be locked out; the key alone is logged, never the value. Every key
  the project itself writes is recognised and stays silent, or `config_load()`
  would put warnings in syslog on every login. `tests/test_ob_config_keys.sh`
  reads the generators and fails if one emits a key the parser does not know. The
  PAM authorization cache has **no** local TTL setting; see
  [doc/configuration.md](doc/configuration.md).
- **`SECURITY.md` documents the cache that actually exists** — the
  `LLNGCACHE04` authorization cache, with its real layout — instead of the
  deleted token cache, whose documented layout did not match its code either.
  `doc/security/00-architecture.md` corrected the same way.
- **Every EBIOS matrix now agrees with the sheets it summarises** (#213, #214,
  #215). The five matrices were maintained by hand and had drifted: risks a
  column off, residual scores no sheet states, 11 analysed risks missing, two
  identifiers with no sheet, and three different values for `R-S18` on three
  lines. An evaluator reads the matrix, not the sheets. All five are now derived
  from the 39 sheets, and `tests/ebios_matrix_check.py` fails in CI on any
  divergence.
- **A failing `ctest` keeps its log, and the concurrency test says why it
  failed** (#244). A flake in the Rocky 9 job passed on re-run, and the re-run
  replaced the only record of it. The three `ctest` jobs now upload
  `Testing/Temporary/` on failure — two of them could not have held that evidence
  at all, since `test_offline_cache` is only compiled with `INSTALL_DESKTOP=ON`,
  which neither passed. `test_concurrent_failed_attempts` (the #186 lockout regression) had four failure paths
  that printed nothing, one of which made the test **pass silently** on a barrier
  that had not worked; that one is now a verdict change, not just added output.
- **The `test_offline_cache` flake was a one-second TTL boundary in the test**
  (#244), not a concurrency bug: `store()` and `verify()` both take `time()` at
  one-second granularity with an `fsync()` between them. Measured by interposing
  `time()`: 0.01% per run on tmpfs, 0.2% on ext4. #244 had recorded this
  candidate as ruled out on 60 local runs with no failure — a test with no power,
  since 60 runs were expected to produce 0.005 failures. The margin is widened;
  no production code changed.
- **`doc/offline-mode.md` states what actually works during a portal outage**
  (#165) — an eleven-row matrix, including why `sudo` for an SSO user is not a
  simple ❌, and whether a personal SSH key on the bastion is a usable fallback
  (Mode E: no; key modes: yes, at a stated cost). The key-mode path is labelled
  as analysis: the lab validation the issue asks for has not been done.
- **Resilience to an LLNG outage no longer depends on `nscd`, and the buffer is
  shorter.** The NSS module's own cache expires at `cache_ttl` (default 300 s)
  and never serves stale data, so `getent` stops resolving roughly that long
  after the last successful lookup. Raise `cache_ttl` for a longer buffer; the
  trade-off against how quickly a deprovisioned user disappears is in
  `doc/admin-guide.md`.
- **Only root can refill the NSS cache**, which is now visible in normal
  operation: past `cache_ttl` in a long idle session, `id` fails and outgoing
  `ssh` says `You don't exist, go away!`. Any root-side lookup repairs it at
  once — a nuisance, not a lockout. A socket-activated refresher is not
  implemented yet.
- **A lookup for a user that does not exist reaches LLNG on every attempt.**
  Negative results are cached in memory only, per process, deliberately: the
  on-disk cache is populated from an unauthenticated path, and letting `sshd`
  create files there would let a remote client fill it with inodes. Bound it
  where connection floods are already bounded (`MaxStartups`, CrowdSec).

### Removed

- **`secret_store`, the last dead cryptographic module** (#225). Every entry
  point was reachable only from its own unit test; nothing in the authentication
  path ever stored a secret through it. This removes AES-GCM code and writes
  under `/etc/open-bastion` from a root PAM module that had no use for them, and
  settles two findings that had landed inside dead code (#187, #184). `SECURITY.md`
  and `doc/security/00-architecture.md` advertised `secrets_encrypted = true`;
  they now state the truth — secrets in `openbastion.conf` are protected by file
  permissions only, and the way to avoid a secret on disk is not to write one.
  **Not** removed: `src/cache_key.c` and `src/offline_cache.c`, which are used.
- **The dead token cache, `client_context`, and the kernel-keyring settings.**
  All three were documented in `SECURITY.md` as active features and never wired
  into the PAM chain: `cache_lookup()`/`cache_store()` had no caller outside
  their unit test, `client_context.c` had zero callers, and no `add_key` or
  `keyctl` call existed anywhere behind `secrets_use_keyring`. Rewiring the cache
  would have reopened an offline authentication path nothing needs, so it was
  deleted. Their settings still parse as unknown keys, so existing files load.
  **Not** removed: `src/auth_cache.c` and the `cache_rate_limit_*` settings,
  which protect the authorization cache.
- **`nscd` is no longer a dependency.** The NSS module keeps its own in-memory
  and on-disk cache, so a second cache in front of it adds nothing; `nscd` is
  also deprecated upstream and absent from modern distributions. Existing hosts
  are left alone. (It also used to crash with `SIGABRT` in this module's NSS
  path — that was a double-free fixed in 0.6.1, and is no longer a reason to
  avoid it, only the reason the redundancy was noticed.)

### Fixed

- **Three records that contradicted the tree** (#268). `SECURITY.md` still
  listed "encrypted secrets in the secret store become permanently
  unrecoverable" among the consequences of a machine-id change, although the
  `secret_store` module and the `secrets_encrypted` setting were both removed —
  the main passage was corrected then, this bullet was not. In
  `doc/security/07-plan-de-traitement.md`, MT51 and MT52 were still "en revue"
  and "ouvert" with #248 and #252 merged; both now read as delivered and
  unpublished, and `doc/security/08-dossier-homologation.md` no longer counts
  MT52 among what keeps R-P7 orange — only the upstream session-store work does.
- **`ob-service-account-keys` is now shipped** (#263). The
  `AuthorizedKeysCommand` helper that makes a service account usable existed in
  the tree and was installed by **none** of the three packaging paths — not
  CMake, not the `.deb`, not the RPM. So there was no copy on a host to point
  `AuthorizedKeysCommand` at, and everyone who needed one installed their own at
  a path of their choosing: `/usr/local/bin/` in two demos, `/usr/local/sbin/`
  in the lab and in the documentation. It now installs to
  `/usr/sbin/ob-service-account-keys` (a package must not write under
  `/usr/local`), and every shipped reference uses that path.

  Two passages of `doc/service-accounts.md` were actively misleading, and they
  are the ones an operator reads before deploying. Of Mode E it said _"No
  `authorized_keys` file is required"_ — literally true and read as "nothing
  else is needed", when in fact sshd rejects at the protocol layer and
  `pam_openbastion` never runs; the fingerprint check it describes is a
  re-validation, not an authorisation. And it said `ExposeAuthInfo yes` is
  written by "the setups", which happens only inside
  `configure_max_security_sshd()` — never on a host that is not in Mode E. Both
  corrected, and `tests/test_ob_service_account_keys.sh` fails if either claim
  comes back or if the helper leaves the packaging again.

  The directory the helper reads, `/etc/open-bastion/service-accounts.d`, is
  shipped with it — nothing created it before, and a helper without its
  directory is inert.

  What `key_fingerprint` is actually worth is now written down instead of
  assumed. For a **plain public key** on a current OpenSSH the PAM
  re-validation usually does not run at all: `sshd` does not call
  `pam_authenticate()` on that path, `SSH_USER_AUTH` is absent without
  `ExposeAuthInfo yes`, and the principals spool is empty because `sshd` runs
  `AuthorizedPrincipalsCommand` only for certificate sessions — so the check is
  skipped rather than failed. On such a host an orphan `.pub` is accepted by
  `sshd` and **not** rejected by PAM. `ExposeAuthInfo yes` plus
  `fingerprint_required = true` turn it back into a control, and
  `doc/service-accounts.md` now says so in a table rather than implying the
  check always happens.

  Reported from the field with a complete reproduction; the deployment still
  requires the sshd drop-in to be written by hand, which is tracked separately.

- **The SSH key policy is now actually enforced, fail-closed** (#181).
  `ssh_key_policy_enabled` was documented as implemented and enforced nothing:
  the check read `SSH_USER_AUTH`, which sshd does not export during
  `pam_acct_mgmt` on OpenSSH >= 9.8, and silently skipped the whole block when it
  came back `NULL`; `ssh_key_policy_check_rsa_size()` had no production caller at
  all. `ob-ssh-principals` now writes a second spool drop carrying the key blob,
  `pam_openbastion` decodes it and cross-checks it against the fingerprint, and an
  unidentifiable key **denies** rather than skipping. Still defaults to `false`.
  A package upgrade replaces the module but not the generated helper, so the
  postinst warns when it finds the policy enabled next to a pre-v1 helper.
- **Service-account `sudo` with `sudo_nopasswd = false` works at all** (#194).
  The fingerprint check read `SSH_USER_AUTH`, which does not exist in a `sudo`
  PAM handle, so the branch always returned `PAM_AUTH_ERR` — leaving
  `sudo_nopasswd = true`, which grants sudo with no proof of identity, as the
  only workable setting. The fingerprint is now also recovered from the spool.
- **`fingerprint_required` covers service accounts, and their SSH check runs.**
  The service-account branch returned `PAM_SUCCESS` before the enforcement block,
  so the setting documented as covering "every SSH login" skipped them; their
  check also read `SSH_USER_AUTH` alone, which is the only check that runs on a
  public-key login. It is also now documented in `doc/admin-guide.md`, where an
  operator looks for it — it is condition of use CE09 and the assumption behind
  the R-S3 / R-S15 residual scores.
- **A missing `.key` drop is no longer reported as a missing key binding.** It
  only exists when `sshd` passes `%t`; its absence is a missing capability the
  caller handles by falling back, not a missing security binding. WARN for `.fp`,
  DEBUG for the rest.
- **A server-supplied `gid` is no longer validated against the synthetic UID
  range.** The portal's `gid` — an LDAP `gidNumber` exported through
  `pamAccessExportedVars` — was checked against `[min_uid, max_uid]`, so an
  ordinary group such as `1000` fell outside it and was silently replaced by
  `default_gid`. GIDs have their own `min_gid`/`max_gid`, defaulting to the
  Debian/RHEL system-group boundary. `gid 0` and `nogroup` are refused whatever
  the configuration says, and an out-of-policy gid is logged with its value.
- **A rejected `/pam/verify` token fails cleanly** instead of looking like a
  server outage. The plugin answers `valid:false` with no `user` field, the
  client required `user` unconditionally, and the resulting
  `PAM_AUTHINFO_UNAVAIL` fell through to `pam_unix` under `auth sufficient`. The
  reason is now surfaced and authentication fails with `PAM_AUTH_ERR`.
- **Three defects in `ob-bastion-id`'s own error paths.** `die()` logged `$*`,
  appending the exit code to every message as a stray digit; a portal answering
  200 with no identity exited 2 where the contract says 3; and a JWT whose
  payload is not base64url killed the script under `set -e` before its own `die`
  could run, so the caller got rc=1 and no message.

### Security

- **R-P1 is now a release prerequisite, not an assumption** (#268). With
  `pamAccessServerGroups` empty — the shipped default, and the multi-group model
  `doc/bastion-architecture.md` used to recommend — `server_group` is read from
  the request body, so any enrolled host of the project that is compromised can
  declare itself a bastion on `/pam/authorize` and obtain a hop voucher for a
  user. Two positions were tenable: make the configuration a prerequisite, or
  accept it as a signed residual risk. The first was taken. `pamAccessServerGroups`,
  `pamAccessAllowedRps`, published plugins and a non-empty `allowed_bastions`
  are **blocking** conditions (CE03, CE21, CE16, CE06), and the docs that told
  operators to leave the first one empty now say the opposite, including what it
  costs: one `client_id` per server group, because an unmapped one is refused.

  The product can neither set nor verify the portal-side half — those are LLNG
  Manager settings, and reading them back would need an API that publishes the
  project's bastions, server groups and RPs. So the enforcement is declarative
  and it is everywhere an operator passes: `ob-bastion-setup`,
  `ob-backend-setup`, `ob-desktop-setup` and `ob-post-upgrade` print the
  requirement on every run, and `ob-builder` writes a `PORTAL-CHECKLIST.md` next
  to each artefact, pre-filled with that deployment's `client_id` and
  `server_group` — which matters most for the Ansible role, whose setup task
  nobody reads the output of. One shared text
  (`/usr/lib/open-bastion/ob-portal-prerequisites.txt`), because four heredocs
  is how the units of #254 drifted apart.
- **`ob-enroll` no longer puts the OIDC client secret on a command line**
  (#256). It signed its `client_secret_jwt` assertion with
  `openssl dgst -sha256 -hmac "$client_secret"`, and OpenSSL has no form that
  reads the key from anywhere but `argv`, which `/proc/<pid>/cmdline` publishes
  to every local user. Not a one-shot exposure: the call sits in the device-grant
  polling loop, so the secret landed in `argv` of the order of sixty times over
  five minutes, during exactly the interval when an operator is away in a browser
  approving the grant. `ob-client-jwt`(8) reads the secret on stdin instead. It
  does not read it from `openbastion.conf` the way `ob-sign-request`(8) does,
  because `ob-enroll` may hold it from the environment, from `--client-secret`,
  or from a file that does not exist yet on a first enrolment — so `ob-enroll`
  decides and hands it over. No fallback to the `openssl` path. Rationale in
  `doc/security/01-enrollment.md`, which listed `ps aux` as a threat while its
  own remediation reintroduced it.
- **`ob-session-monitor` no longer terminates sessions because it failed to
  reach the portal** (#257). `check_user_valid()` ended with
  `curl -sf ... || return 1`, and the caller reads non-zero as "this user was
  revoked" — it runs `loginctl terminate-session`. But `curl -sf` fails on a
  connection error, a timeout **and any HTTP status >= 400**, so a 500, a rate
  limit, or a `SERVER_TOKEN` that expired overnight terminated every offline
  session while logging "no longer valid on LLNG", which was untrue. The
  reachability probe did not cover it: `check_portal()` fetches a different
  endpoint. There are now three outcomes — valid, revoked, unknown — and only a
  portal that answered `found: false` can terminate anything. An unusable
  endpoint still converges on the same one-hour bound, through its own counter.
- **The SSH fingerprint spool no longer trusts `nobody`** (#249). `sshd` requires
  an unprivileged `AuthorizedPrincipalsCommandUser`, so the helper wrote the
  drops itself and the spool had to be `0700 nobody` — putting the integrity of
  the whole binding on a shared, low-trust account, which matters most on the
  service-account path where a fingerprint match grants `sudo_allowed`. Deposits
  now go through `ob-fp-submit` to a socket-activated root daemon (the
  `ob-cert-daemon` pattern, no new setuid binary). Reading is closed outright.
  For writing, the load is carried by **deriving the sshd anchor from the
  depositing process's own `/proc` ancestry** rather than reading it from the
  request: a client cannot name the session it deposits for, so forging a binding
  needs code execution as the helper user _inside the target connection's own
  process tree_. There is deliberately no configuration key for the depositing
  user — it is the owner of the listening socket. A host that upgrades without
  re-running setup keeps the old trust root, and the module now logs that state;
  see [UPGRADE-NOTES.md](UPGRADE-NOTES.md).
- **The fingerprint spool was already made harder to forge** (#235 review),
  before #249 replaced its trust root. The anchor must be a live **root**
  process, because the anchor is chosen by process _name_ and
  `prctl(PR_SET_NAME)` accepts fifteen characters while `sshd-session` is
  twelve — half the forge needed no privilege at all. A drop older than its
  anchor is refused, because nothing removes a drop when a session ends and a
  recycled PID inherited the previous occupant's binding with every check
  passing. And a service-account grant resting on a spool-derived fingerprint is
  logged at WARN and carried in the audit reason.
- **A missing SSH fingerprint drop is visible, and can be made fatal** (#192).
  The module dropped the binding with a DEBUG line and authorized anyway, so a
  provisioning failure silently removed a control `doc/security/99-risk-reduce.md`
  credits with reducing R-S3 and R-S15. It is now WARN, and opt-in
  `fingerprint_required = true` refuses such a login. Enable it on
  certificate-mode hosts **before** upgrading the portal: from
  `lemonldap-ng-plugins` 0.6.0 an unbound voucher expires in 15 min, so a missing
  drop stops degrading silently and starts breaking a hop a quarter of an hour
  into the session instead of at login. Do **not** enable it in the token-only
  modes, where no fingerprint ever exists.
- **Every caller of a `/pam/` endpoint signs its request, so
  `pamAccessRequestSigningMode = required` is deployable** (#247). The portal
  verifies `X-Signature-256` in `_checkCaller`, ahead of any caller identity, for
  all six endpoints; two were signed. `/pam/heartbeat` was the dangerous one — it
  is how every enrolled host renews its access token, so turning `required` on
  broke nothing at the moment of the change and took the whole fleet down hours
  later, together. Three call sites were missing from the issue's own inventory
  and are signed here too, including `/pam/userinfo`, recorded as having no
  caller, which `ob-session-monitor` uses to terminate sessions.
  `tests/test_ob_request_signing.sh` now walks the tree for anything building a
  `/pam/` URL and fails if it is not in the signed inventory.
- **The shell callers sign through `ob-sign-request`(8), not
  `openssl dgst -hmac`** (#247) — same `argv` exposure as #256, and here it would
  have been the fleet-wide signing secret, published by a timer that runs every
  few minutes forever. The helper reads the secret from the root-only config file
  and takes the body on stdin, since `ob-heartbeat`'s body carries the host's
  `refresh_token`.
- **`request_signing_secret` is no longer truncated at a `#`** (#247).
  `config.c` exempts opaque secrets from inline-comment stripping; the three
  other readers did not. A secret containing `#` produced a valid-looking
  signature over the wrong key, reported by the portal as `bad_signature` —
  which looks like a portal problem and is not.
- **Certificate-mode sshd PAM stacks refuse password authentication** (#180).
  The `auth` path was a single `auth required pam_permit.so`, so
  `pam_authenticate()` succeeded unconditionally. The certificate path never
  calls it, but sshd does for password and keyboard-interactive logins — and
  `apt install open-bastion` writes the stack without touching `sshd_config`, so
  any password authenticated any account the `account` phase approved. Every
  generated stack now uses `auth required pam_deny.so`; the mode-c `sudo` stack
  keeps permitting, through a fail-closed permit whose trailing `pam_permit` is
  required or PAM returns `PAM_PERM_DENIED`. `tests/test_ob_pam_runtime.sh` calls
  `pam_authenticate()` on each generated stack instead of checking the text.
  Upgrading an existing host is manual: see [UPGRADE-NOTES.md](UPGRADE-NOTES.md).
- **The portal `locationRules` guarding `/device` and the SSH CA admin routes
  are shipped and documented** (#195). The two plugin regimes fail in opposite
  directions: at `v0.5.2` and earlier the vhost rule is the _only_ control, and
  without it any SSO account can revoke anyone's certificate; from `0.6.0`
  `sshCaAdminRule` is fail-closed, so a portal configured with the vhost rule
  alone loses its admin UI on upgrade. Both are in
  [doc/llng-configuration.md](doc/llng-configuration.md), with two traps whose
  previously documented mechanism was wrong and is corrected there.
  `tests/test_ob_llng_location_rules.sh` compiles the rules and runs URIs through
  them rather than matching text.
- **An empty `allowed_bastions` no longer passes unnoticed** (#182). An empty
  allowlist means "accept a hop from any vouched bastion", and it is the residual
  defence behind a real gap on the SSO side. `ob-backend-setup` now asks for the
  list interactively — pressing Enter is not an answer — warns loudly when it is
  left empty, and `ob-ssh-principals` logs on **every** unchecked hop, so a
  running fleet shows the condition in its logs. The empty-means-any semantic is
  deliberately unchanged and a non-interactive run still defaults to it:
  inverting it would deny every hop the moment a backend upgrades. The list is
  validated and split with globbing off — word-splitting it also ran pathname
  expansion, so `b[1]` matching a local file was rewritten to that file and the
  typo accepted as a different valid-looking id.
- **A mistyped boolean no longer silently means `false`** (#183). Every
  unrecognised value mapped to `false`, so `verify_ssl = TRUE` turned TLS
  verification **off** without a word — fail-open on the setting protecting every
  call to the portal, and the same for ~25 other booleans. Booleans now accept
  only the documented spellings; anything else keeps the safe default, logs, and
  makes `config_validate()` refuse the configuration.
- **The NSS module no longer disables TLS verification on a typo** (#183). It had
  its own parser with the same fail-open expression. It cannot refuse to start —
  it is loaded into every process that resolves a name, and failing there would
  lock the host out — so it reports and uses the safe value instead.
- **The request-signing nonce is covered by the HMAC** (#188). The client sent
  `X-Nonce` but signed `timestamp.method.path.body`, despite a comment claiming
  otherwise, so a captured request could be replayed with a fresh nonce and still
  verify. The message is now `timestamp.nonce.method.path.body`; the format is in
  `SECURITY.md`.
- **`ob-builder` validates `apt_url`, `apt_suite` and `apt_component`** (#190).
  They are interpolated verbatim into an installer that runs as root, and were
  the only build inputs with no validation: `apt_url: "https://x/$(…)"` executed
  at install time.
- **A world- or group-readable `/etc/open-bastion/cache.key` is rejected**
  rather than used with a warning. `SECURITY.md` used to suggest creating it with
  `dd`, which under root's umask 022 produces `0644`. Upgrade impact and the
  one-line remedy are in [UPGRADE-NOTES.md](UPGRADE-NOTES.md).

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
