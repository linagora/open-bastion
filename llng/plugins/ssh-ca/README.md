# SSH CA - SSH Certificate Authority

This plugin provides SSH certificate signing functionality for LemonLDAP::NG.
Users can sign their SSH public keys to obtain short-lived certificates for
passwordless authentication on servers that trust the CA.

## Features

- **Certificate signing** with configurable validity and principals.
- **Mandatory key labels** for human-friendly identification (e.g.
  `laptop-pro`), enforced unique per user among active certificates.
- **Automatic dedup on re-signature**: signing the same SSH public key
  twice replaces the previous record in the user's session and publishes
  the superseded serial in the KRL — a user has a single active record
  per fingerprint at all times.
- **User self-revocation** via `POST /ssh/myrevoke` and a per-row
  "Revoke" button in the "My Certificates" table.
- **Certificate listing** for users (their own) and admins (all users).
- **Certificate revocation** with KRL (Key Revocation List) management.
- **SSH SHA256 fingerprint** computed and stored with each cert, surfaced
  in the responses — the `pam-access` plugin uses it to bind PAM tokens
  to a specific SSH key.
- **Admin interface** for searching and revoking certificates, guarded by
  the `sshCaAdminRule` rule — **default deny**, no admin until you say who.
- **Audit logging** of all signing and revocation operations.

## Requirements

- LemonLDAP::NG >= 2.23.2
- `ssh-keygen` available on the system
- `Crypt::PK::Ed25519` (for Ed25519 CA keys) or `Crypt::PK::RSA` (for RSA CA keys)

## Installation

With `lemonldap-ng-store` _(LLNG >= 2.24.0)_ or [linagora-lemonldap-ng-store](../../README.md#installation-with-debian-packages):

```bash
sudo lemonldap-ng-store install ssh-ca
```

Manually: copy `lib/` into your Perl `@INC` path, copy `portal-templates/`
and `portal-static/` into the portal directories, copy `manager-overrides/`
into `/etc/lemonldap-ng/manager-overrides.d/`, add `::Plugins::SSHCA` to
`customPlugins`, and run `llng-build-manager-files`.

## Configuration

In the Manager under **General Parameters** > **Plugins** > **SSH CA**:

| Parameter               | Description                                                               | Default                                  |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| `sshCaKeyRef`           | Reference to the SSH CA key in LLNG keys store                            | _(required)_                             |
| `sshCaAdminRule`        | Rule granting access to the admin endpoints (boolOrExpr)                  | _(empty — denies everyone)_              |
| `sshCaKrlPath`          | Path to the KRL file on disk                                              | `/var/lib/lemonldap-ng/ssh/revoked_keys` |
| `sshCaCertMaxValidity`  | Maximum certificate validity in days                                      | `365`                                    |
| `sshCaAllowedKeyTypes`  | Key families accepted for signing (comma/space separated)                 | `ed25519,ecdsa,sk-ed25519,sk-ecdsa,rsa`  |
| `sshCaMinKeyBits`       | Minimum key size in bits, RSA/DSA only                                    | `2048`                                   |
| `sshCaPrincipalSources` | Session attributes to use as principals (space-separated `$var` template) | `$uid`                                   |

### Administration rule (`sshCaAdminRule`)

`/ssh/admin`, `/ssh/certs` and `/ssh/revoke` list **every** user's
certificates and can revoke any of them. They are guarded by
`sshCaAdminRule`, a standard LLNG rule (boolOrExpr) evaluated against the
caller's session:

```perl
$uid eq 'admin'
inGroup('ssh-admins')
1                       # any authenticated user — NOT recommended
```

**The rule has no permissive default: while it is empty (or `0`), the three
admin endpoints answer HTTP 403 for everyone**, including users the portal
vhost `locationRules` would let through. This is deliberate — a portal that
has not been told who its SSH CA admins are must not expose the whole
certificate estate. The per-user endpoints (`/ssh/sign`, `/ssh/mycerts`,
`/ssh/myrevoke`) are unaffected.

Denials are logged (`userLogger->warn`) and audited under the
`SSH_CA_ADMIN_DENIED` code.
### Key policy

Before anything is signed, the submitted public key is checked against
`sshCaAllowedKeyTypes` and `sshCaMinKeyBits`. The key type and size are read
from the **decoded key blob** (the SSH wire format), not from the textual
prefix of the pubkey line, so a key cannot get through by mislabelling
itself.

| Token        | Key types                                              |
| ------------ | ------------------------------------------------------ |
| `ed25519`    | `ssh-ed25519`                                          |
| `sk-ed25519` | `sk-ssh-ed25519@openssh.com` (FIDO2 / hardware-backed) |
| `ecdsa`      | `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521`        |
| `sk-ecdsa`   | `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO2)           |
| `rsa`        | `ssh-rsa`                                              |
| `dss`        | `ssh-dss` — **not allowed by default**                 |

`ssh-dss` is excluded by default: DSA is capped at 1024-bit keys with SHA-1
signatures, was disabled at compile time in OpenSSH 9.8 and removed in
OpenSSH 10. Operators who still need it can add `dss` to the list.

`sshCaMinKeyBits` only applies to families whose size varies — RSA and DSA.
An Ed25519 key is always 256 bits and is stronger than RSA-3072, so
comparing the two numbers would reject the best keys available; fixed-size
families are governed by the allowlist alone.

Rejected keys get HTTP 400 with the reason (`SSH key type '<type>' is not
allowed`, `SSH key is too small (<n> bits, minimum <m>)`).


### Limits (`sshCaSignMaxPerHour`, `sshCaMaxCertsPerUser`)

Every `/ssh/sign` forks `ssh-keygen` twice and rewrites the **whole** KRL, and
re-signing a key you already hold appends the superseded serial — which is
allowed on purpose, so nothing stopped a shell loop from growing the KRL
without bound. The cost per call grows with the KRL, and every appended serial
is then loaded by every `sshd` on every backend (issue #63).

| Setting                | Default | Effect                                                            |
| ---------------------- | ------- | ----------------------------------------------------------------- |
| `sshCaSignMaxPerHour`  | `20`    | `/ssh/sign` calls per user per hour. `0` disables the limit.       |
| `sshCaMaxCertsPerUser` | `20`    | Active (non-revoked, non-expired) certificates. `0` disables it.   |

Over the rate limit, `/ssh/sign` answers **429** with a `Retry-After` header
and `retry_after` in the body, audited as `SSH_CA_SIGN_RATE_LIMITED`. The
counter is a fixed hourly window kept in the user's own session, so it is
shared across portal nodes with no extra storage; two racing signatures can
under-count by one, which does not matter for bounding a loop.

Over the certificate quota, `/ssh/sign` answers **409**, audited as
`SSH_CA_CERT_QUOTA_EXCEEDED`. A **re-signature of a key you already hold
replaces its record and is never counted**, so a user sitting at the quota can
still rotate; a new key needs a `/ssh/myrevoke` first. Only *active* records
grant that exemption: at the quota, re-signing a key whose certificate has
already expired is refused like a new one, even though it would replace the
expired record rather than grow the set. Revoke or wait for the counter to
reflect reality — the conservative direction.

Together these bound KRL growth. The KRL itself is never capped: refusing to
record a revocation would be a silent fail-open.

> **`disablePersistentStorage`.** Both limits live in the user's session, so
> with persistent storage disabled the counter is never written and *neither
> limit applies*. This matches the rest of the plugin — certificates are not
> persisted either, so `/ssh/mycerts` is empty and the quota has nothing to
> count — but it means a deployment relying on the rate limit must keep
> persistent sessions enabled.

### CA key setup

The CA key must be configured in the LLNG keys store (Manager > Keys). Both
Ed25519 and RSA keys are supported. The plugin converts PEM keys to OpenSSH
format internally.

### Principal sources

Principals are always derived from the authenticated user's session, never
from the request. The `sshCaPrincipalSources` parameter is a template string
where `$varname` references are replaced with session attribute values.

Examples:

- `$uid` → principal is the user's uid (e.g. `john`)
- `$uid $mail` → two principals: uid and email (e.g. `john`, `john@example.com`)

## Endpoints

### Public endpoints (no authentication)

| Method | Path           | Description                                                                                                        |
| ------ | -------------- | ------------------------------------------------------------------------------------------------------------------ |
| GET    | `/ssh/ca`      | Returns the CA public key in SSH format. Servers use this to configure `TrustedUserCAKeys`.                        |
| GET    | `/ssh/revoked` | Returns the binary KRL file. Servers use this to configure `RevokedKeys`. Always a valid KRL — an empty one when nothing is revoked yet; HTTP 500 rather than a KRL the portal cannot parse. |

### User endpoints (authentication required)

| Method | Path            | Description                                                                    |
| ------ | --------------- | ------------------------------------------------------------------------------ |
| GET    | `/ssh`          | User interface for signing SSH keys                                            |
| POST   | `/ssh/sign`     | Sign a user's SSH public key (requires a unique `label` among active certs)    |
| GET    | `/ssh/mycerts`  | List the current user's certificates (JSON)                                    |
| POST   | `/ssh/myrevoke` | Self-revoke one of the caller's own certificates; immediately added to the KRL |

### Admin endpoints (authentication + `sshCaAdminRule`)

| Method | Path          | Description                                             |
| ------ | ------------- | ------------------------------------------------------- |
| GET    | `/ssh/admin`  | Admin interface for searching and revoking certificates |
| GET    | `/ssh/certs`  | Search all certificates across all users (JSON)         |
| POST   | `/ssh/revoke` | Revoke a certificate by session ID and serial           |

These three endpoints enforce `sshCaAdminRule` themselves and **deny by
default** (HTTP 403) until you set it — see
[Administration rule](#administration-rule-sshcaadminrule).

Configuring `locationRules` on the portal vhost on top of the rule is still
supported and recommended as defence in depth — but it is no longer the only
thing standing between an ordinary user and everyone's certificates:

```perl
# In LLNG Manager > Virtual Hosts > portal vhost > Rules
^/ssh/admin    => $uid eq 'admin' or inGroup('ssh-admins')
^/ssh/certs    => $uid eq 'admin' or inGroup('ssh-admins')
^/ssh/revoke   => $uid eq 'admin' or inGroup('ssh-admins')
```

## API details

All three POST routes (`/ssh/sign`, `/ssh/myrevoke`, `/ssh/revoke`) require
`Content-Type: application/json` and answer **400** otherwise. If the request
carries an `Origin` header it must be the portal's own, else **403**. Together
these refuse the cross-site form POST that could otherwise re-sign a victim's
key and revoke their live certificate (issue #62). Non-browser callers send no
`Origin` and are unaffected.

### POST /ssh/sign

Request (JSON):

```json
{
  "public_key": "ssh-ed25519 AAAA... user@host",
  "validity_days": 30,
  "label": "laptop-pro"
}
```

Response (JSON):

```json
{
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "serial": 3,
  "key_id": "john@llng-1713300000-000003",
  "principals": ["john"],
  "valid_until": "2026-05-16T12:00:00Z",
  "label": "laptop-pro",
  "fingerprint": "SHA256:CfGkzWrzpeKEsYPdBMDjEjoN1n/o4YzuM8StGuMQMcs"
}
```

- `label` is **mandatory**. It must be unique across the user's active
  (non-revoked, non-expired) certificates. Re-using a label on a different
  key yields HTTP 409. If omitted, the plugin falls back to the SSH public
  key's comment (third token) for back-compat; if that is also empty the
  request is rejected with 400.
- `validity_days` must be a positive integer (anything else is rejected
  with 400) and is clamped to `sshCaCertMaxValidity`. Omitted means 30 days.
- The key must pass the [key policy](#key-policy).
- Principals are derived from the session; any `principals` field in the
  request is ignored (and logged as a warning).
- `fingerprint` is the SHA256 of the signed key, stored with the cert and
  used by the `pam-access` plugin to bind PAM tokens to a specific key.

**Re-signing the same SSH public key** (same fingerprint) replaces the
previous record in the user's persistent session and revokes the
superseded serial in the KRL. The `label` may change on re-signature. The
KRL retains all revoked serials regardless.

### POST /ssh/myrevoke

Request (JSON):

```json
{ "serial": "3" }
```

Marks the cert as `revoked` in the caller's persistent session (keeping
it visible in `/ssh/mycerts`) and publishes the serial in the KRL.

Returns HTTP 400 if already revoked, HTTP 404 if the serial is not in the
caller's own certs.

### GET /ssh/mycerts

Response (JSON):

```json
{
  "certificates": [
    {
      "serial": 3,
      "key_id": "john@llng-1713300000-000003",
      "label": "laptop-pro",
      "fingerprint": "SHA256:CfGkzWrzpeKEsYPdBMDjEjoN1n/o4YzuM8StGuMQMcs",
      "principals": "john",
      "issued_at": 1713300000,
      "expires_at": 1715892000,
      "status": "active"
    }
  ]
}
```

Status is computed dynamically: `active`, `expired` (past `expires_at`), or
`revoked` (has `revoked_at`). Entries are sorted newest-first.

### GET /ssh/certs

Query parameters: `user`, `serial`, `key_id`, `status`, `limit` (max 1000),
`offset`. `limit` and `offset` must be non-negative integers; anything else
falls back to the defaults (100 and 0).

Response includes all fields from `/ssh/mycerts` (including `label` and
`fingerprint`) plus: `session_id`, `user`, `revoked_at`, `revoked_by`,
`revoke_reason`.

### POST /ssh/revoke

Request (JSON):

```json
{
  "session_id": "persistent-session-id",
  "serial": "1",
  "reason": "Key compromised"
}
```

This does two things:

1. Marks the certificate as revoked in the user's persistent session
2. Updates the KRL file on disk via `ssh-keygen -k [-u] -s ca.pub -f <krlPath>`

`reason` is optional, trimmed, limited to 256 characters and must not
contain control characters — it ends up in the portal log and in the audit
log, where a newline or an ANSI escape would let a caller forge log lines.

## KRL (Key Revocation List)

The KRL is a binary file managed by `ssh-keygen`. An empty (header-only) KRL
is generated at plugin init, and it is updated each time a certificate is
revoked via `/ssh/revoke` (`-u` flag). Every write goes to a temporary file in
the same directory and is `rename()`d over the live KRL, under an exclusive
`flock` on `<sshCaKrlPath>.lock` shared by the portal workers and the
`sshca-rebuild-krl` cron job — so a reader never sees a half-written KRL, and
concurrent revocations do not overwrite each other.

This matters because sshd fails **closed** on a KRL it cannot parse: a KRL
truncated mid-write makes `RevokedKeys` unusable and every single key is
rejected with `incomplete message`, locking the host out entirely.

Servers should periodically fetch the KRL from `/ssh/revoked` and configure:

```
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/revoked_keys
```

A cron job or systemd timer can keep the KRL up to date. Download to a
temporary file and only install it once `ssh-keygen` confirms it parses —
checking the `SSHKRL` magic is **not** enough, a truncated KRL still has it:

```bash
tmp=$(mktemp /etc/ssh/.revoked_keys.XXXXXX)
if curl -sf https://auth.example.com/ssh/revoked -o "$tmp" &&
   ssh-keygen -Q -l -f "$tmp" >/dev/null 2>&1; then
    chmod 644 "$tmp" && mv "$tmp" /etc/ssh/revoked_keys
else
    rm -f "$tmp"    # keep the previous KRL
fi
```

## Storage

Certificates are stored in each user's **persistent session**, one key per
certificate: `_sshCert::<fingerprint>`, holding a JSON record. This means
certificates survive across SSO sessions. The admin search endpoint
(`/ssh/certs`) scans all persistent sessions to find certificates.

One key per certificate rather than one shared array, because LLNG sessions
have no locking (`Apache::Session::Lock::Null`) and every save rewrites the
whole session blob: a shared array made two concurrent `/ssh/sign` calls — or
a revocation racing a signature — lose one of the two records (issue #66).
Writing only the affected key narrows the collision window to a single store
round-trip.

Sessions written before this layout keep their `_sshCerts` JSON array. It is
still read, and the next signature or revocation on that session republishes
every record under its own key and removes the array. Nothing needs to be
migrated by hand.

Serial numbers are stateless: they are derived from the current
microsecond-precision wall clock plus a small random tail, so two portals
can issue in parallel without coordination and without collisions.

## Multi-portal deployments (issue #9)

If you run more than one portal node behind a load balancer, each node
keeps its own local KRL file. The plugin keeps those KRLs in sync via
LLNG's message broker (available since LLNG 2.20.0): every revocation
is both written to the local KRL and published as a `sshCaRevoke` event
on the `eventQueueName` channel. Sibling nodes subscribe to that event
at plugin init and apply the same revocation to their local KRL,
typically within 5 seconds (the handler's event poll interval).

**Requirement**: configure a real message broker. The default
`::NoBroker` only dispatches in-process, so revocations would not
propagate between portals. Supported backends:

```perl
# /etc/lemonldap-ng/lemonldap-ng.ini (each portal node)
messageBroker        = ::Redis
messageBrokerOptions = { "server": "redis.example.com:6379" }
# or ::MQTT, ::Pg (PostgreSQL LISTEN/NOTIFY)
```

### Drift recovery: `sshca-rebuild-krl` cron

The broker is the fast path, not the source of truth: it is a
non-durable pub/sub, so a node that is down during a revocation misses
the event. Schedule the `sshca-rebuild-krl` script (shipped in
`scripts/`) from cron on every portal node to reconcile:

```
# /etc/cron.d/lemonldap-ng-sshca
*/5 * * * * www-data [ -x /usr/share/lemonldap-ng/bin/sshca-rebuild-krl ] && /usr/share/lemonldap-ng/bin/sshca-rebuild-krl
```

The script scans the persistent sessions (which are shared across
portals via the session backend), collects every certificate with a
`revoked_at` timestamp, and rewrites the local KRL with
`ssh-keygen -k`. Safe to run on a single-node setup too — it just
becomes a no-op when nothing is out of sync.

## Server-side configuration

To configure an SSH server to trust certificates signed by this CA:

```bash
# Fetch the CA public key
curl -sf https://auth.example.com/ssh/ca -o /etc/ssh/ca.pub

# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/revoked_keys

# Optionally restrict principals
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

## See Also

- [SSH CA documentation](https://lemonldap-ng.org/documentation/latest/sshca)
- [OpenSSH certificates](https://man.openbsd.org/ssh-keygen#CERTIFICATES)
- [PAM Access plugin](../pam-access/README.md) — consumes the SHA256
  fingerprint exposed here to bind PAM tokens to a specific SSH key.
