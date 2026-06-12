# Design: certificate-based bastion→backend vouching

Status: **proposed** (replaces the broken `LLNG_BASTION_JWT` / `SendEnv` transport).
Branch: `various-setup-fixes`. Spans two repos: `open-bastion` and `lemonldap-ng-plugins` (`pam-access`, reusing `ssh-ca`).

## Why the current mechanism is dead

`ob-ssh-proxy` requested a JWT from `POST /pam/bastion-token` and passed it to the
backend via `ssh -o SendEnv=LLNG_BASTION_JWT`; `pam_openbastion` read it with
`pam_getenv("LLNG_BASTION_JWT")` (`pam_sm_acct_mgmt`) and rejected the session when
`bastion_jwt_required=true` and it was empty.

**Proven broken (docker-demo-cert, 12/06/2026):** `SendEnv`/`AcceptEnv` populate only
the eventual *child process* environment (a login shell's `echo $VAR` sees it), never
the **PAM** environment that `pam_getenv` reads — at *any* stage (account or session,
pty or not). A `pam_exec.so session` probe shows `LLNG_BASTION_JWT=[<unset>]` while the
child shell shows `SESSION_SEES=[MARKER]`. So `pam_getenv` can never see it, and moving
the check to `pam_sm_open_session` does not help. The only client data sshd exposes to
PAM is `SSH_USER_AUTH` (key/cert, via `ExposeAuthInfo`), `PAM_RHOST`, and the username.
The hop was never covered by `tests/test_integration_docker.sh`, so it shipped rejecting
every session.

## Chosen design: the bastion mints a short-lived, LLNG-signed user certificate

Key property (Xavier): **the user needs no key on the bastion and no agent forwarding.**
The user only authenticates to the bastion with their normal SSO cert; the bastion
vouches by obtaining a per-hop certificate.

### Flow
1. User SSHes to the bastion with their SSO-issued cert (`ssh-ca` / `ob-ssh-cert`).
   `pam_openbastion` on the bastion authorizes them and stamps `_pamSeen` (already done).
2. `ob-ssh-proxy <backend>` on the bastion:
   a. generates an **ephemeral** keypair in tmpfs (private key never leaves the bastion);
   b. `POST /pam/bastion-cert` to LLNG, **Bearer = the bastion's device-grant server
      token**, body `{ user, target_host, target_group, public_key, voucher }`
      (the `voucher` proves this user really connected to this bastion — see below);
   c. receives a signed certificate; writes ephemeral key + cert to tmpfs;
   d. `ssh -i <ephkey> -o CertificateFile=<cert> -o IdentitiesOnly=yes <user>@<backend>`
      (or `-W` in ProxyCommand mode); wipes the temp files afterwards.
3. Backend sshd (`TrustedUserCAKeys` = LLNG CA, already configured) validates the cert
   natively: CA signature, validity window, `principal == login user`, and the
   `source-address` critical option (if set, sshd itself refuses the cert unless the
   connection comes from the vouching bastion). `pam_openbastion` (`acct_mgmt`) reads the
   cert from `SSH_USER_AUTH` — it **already parses SSH certs** — extracts `bastion_id`
   from the cert key-id/extension and enforces `allowed_bastions`. The existing
   `/pam/authorize` user-authorization call is unchanged.

### Vouching binding & voucher lifecycle (the core security property)

**Problem the voucher solves.** Today's `bastionToken` only gates on the *portal-global*
`_pamSeen` marker — "did this user use pam-access anywhere on this portal in the last 7
days". It does **not** prove "*this* user is connected to *this* bastion". A bastion
holding a valid bastion-group device token could therefore mint a cert for **any** user
who touched the portal recently, even one who never connected to it. We close this with a
per-`(bastion_id, user)` voucher.

**Voucher = a reusable, session-scoped capability** (NOT a one-time nonce — a strict
one-time nonce would break `scp backend1:/f backend2:/g` run *from the bastion*, which
opens two outbound SSH connections → two `/pam/bastion-cert` calls):
- Minted in `/pam/authorize` when the user actually connects to the bastion: that handler
  already knows `server_id = client_id` (= `bastion_id`) **and** `user`, and has just
  re-validated the user's SSH cert fingerprint. When the caller's `server_group` is a
  bastion group and the user is authorized, store a random nonce in the user's persistent
  session under `_pamBastionVouchers->{ $bastion_id } = { nonce, exp }` and return it in
  the authorize response (`bastion_voucher`, `bastion_voucher_expires_in`).
- **Validity = the user's SSO cert lifetime.** `exp = min(now +
  pamAccessBastionVoucherTtl, userCert.expires_at)`, where `userCert.expires_at` comes from
  the cert record `_checkSshFingerprint` already returns at authorize time. The user's SSO
  cert lasts hours (ssh-ca config), so a multi-hour admin session is covered as long as the
  cert is valid — there is no separate "idle timeout" to trip over. `pamAccessBastionVoucherTtl`
  is just an **optional upper cap** for sites that want a tighter bound; default **43200 s
  (12 h)**, effectively deferring to the cert lifetime. (If the caller gave no fingerprint,
  fall back to `now + pamAccessBastionVoucherTtl`.)
- **Reusable** for any number of onward hops while valid → multiplexed / chained hops and
  bastion-launched `scp host1: host2:` all work with the same voucher.
- When the SSO cert expires or is revoked, the voucher is gone → the user reconnects to the
  bastion (which they must do anyway, their cert being dead). No sliding window needed.

**Renewal = fail-closed + reconnect (no hidden re-vouching).** If a hop arrives after the
window, `/pam/bastion-cert` returns `voucher_expired`; `ob-ssh-proxy` prints a clear,
actionable error on stderr ("Your bastion authorization has expired. Reconnect to the
bastion: ssh <bastion>") and exits non-zero. The user reconnects to the bastion (cheap,
normal), pam re-runs `/pam/authorize`, a fresh voucher is minted. We deliberately do NOT
have `ob-ssh-proxy` silently re-authorize: reconnecting is the explicit, auditable proof
of presence, and it removes the threat-model ambiguity of on-demand re-vouching.

**Transport (bastion-local, so the `SendEnv`/`pam_getenv` trap does not apply):** the
voucher reaches `ob-ssh-proxy` on the *same host* — `pam_putenv` at login seeds it into the
session, and/or it is cached in a per-session tmpfs file (`$XDG_RUNTIME_DIR`, mode 600)
so renewals/refreshes persist across hops. The voucher is useless without the bastion's
root-only server token (required as Bearer on `/pam/bastion-cert`), so a user reading their
own voucher gains nothing, and it is bound to `(bastion_id, user)` anyway.

### LLNG `pam-access`: new `POST /pam/bastion-cert`
Same vouching gates as today's `bastionToken` (grant_type=device_code, server_group ∈
`pamAccessBastionGroups`, probe mode for `ob-bastion-id`) **plus** the per-`(bastion_id,
user)` voucher check above (replacing the coarse global `_pamSeen` gate). Instead of
signing a JWT, sign the supplied `public_key` with the **`ssh-ca` CA key** (reuse SSHCA
signing internals via `$self->p->loadedModules->{'...::SSHCA'}->_signSshKey`), producing a
user cert with:
- `principal = user`;
- short validity (config `pamAccessBastionCertTtl`, default ~120 s);
- `key-id` carrying `bastion=<bastion_id>;user=<user>;target=<target_host>` (audit + allowlist);
- custom extension `bastion-id@open-bastion = <bastion_id>` (+ optional `user-groups`);
- optional `source-address` critical option = the bastion's IP (`$req->address`).
Keep `/pam/bastion-token` temporarily for backward-compat, or remove with a CHANGELOG note.

### open-bastion changes
- `scripts/ob-ssh-proxy`: ephemeral keypair → `/pam/bastion-cert` → `CertificateFile`
  connect; drop `SendEnv=LLNG_BASTION_JWT`.
- `src/pam_openbastion.c`: read `bastion_id` from the presented cert (extend existing
  `ob_ssh_cert_info` parsing) and enforce `allowed_bastions`; remove the
  `bastion_jwt` env path. `src/bastion_jwt.c` becomes cert-extension reading (or is
  retired).
- `scripts/ob-backend-setup`: keep `TrustedUserCAKeys`; remove `bastion_jwt_required` /
  `AcceptEnv LLNG_BASTION_JWT`; document the cert-source-address + `allowed_bastions`
  enforcement. (`bastion_id` is the enrolling `client_id`; for per-bastion identity give
  each bastion its own OIDC client.)
- `ob-builder` template `openbastion.conf.j2`: replace the `bastion_jwt_*` block with the
  cert-vouching settings; `allowed_bastions` still threads through.
- Add a real e2e assertion to `tests/test_integration_docker.sh` for the backend hop
  (the gap that hid this bug).

### New config parameters (`pam-access`)
- `pamAccessBastionCertTtl` — ephemeral user-cert validity, default **120 s**.
- `pamAccessBastionVoucherTtl` — optional upper cap on `(bastion_id, user)` voucher
  validity, default **43200 s (12 h)**. Effective voucher exp = `min(now + this,
  userCert.expires_at)`, so the user's SSO cert lifetime is the real bound.

### Resolved decisions
- "Only this bastion" enforced **both** ways: cert `source-address` critical option
  (sshd-native, refuses the cert off-bastion) **and** the `bastion_id` allowlist parsed by
  `pam_openbastion`. Defense in depth.
- `bastion_id` is carried in the cert **key-id** (`-I`), encoded as
  `bastion=<id>;user=<user>;target=<host>` — `pam_openbastion` reads the key-id from
  `SSH_USER_AUTH` (simple string, no custom-extension parsing needed). A custom extension
  `bastion-id@open-bastion` may be added later as nice-to-have, but key-id is sufficient.
- Voucher is **reusable + sliding TTL**, renewal is **fail-closed + reconnect** (above).

### Open questions
- Backward-compat / deprecation of `/pam/bastion-token` and the `bastion_jwt_*` config
  (keep one release with a CHANGELOG deprecation note, then remove).
- `scp host1:/f host2:/g` *initiated on a backend* (not on the bastion) — re-vouching
  backend→backend without a user key on the backend — is a separate, harder topic; out of
  scope here, noted as future work.
