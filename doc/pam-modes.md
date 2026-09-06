# PAM Authentication Modes

Open Bastion supports several PAM configurations depending on your security requirements.

> **Important**: The configurations below have different security implications regarding
> which authentication methods are accepted. Read the descriptions carefully.

## Mode A: LLNG Token Only (Strictest)

**Only LLNG tokens are accepted as passwords. Unix passwords are rejected.**

This is the most secure mode: users must authenticate via LemonLDAP::NG.

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Only LLNG tokens accepted
# - Unix passwords: REJECTED
# - LLNG tokens: ACCEPTED
# - SSH keys: depends on sshd_config (PubkeyAuthentication)

auth       sufficient   pam_openbastion.so
auth       required     pam_deny.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

## Mode B: LLNG Token or Unix Password (Fallback)

**Both LLNG tokens AND traditional Unix passwords are accepted.**

Useful for transition periods or when some users don't have LLNG accounts.

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: LLNG token OR unix password
# - Unix passwords: ACCEPTED (fallback)
# - LLNG tokens: ACCEPTED (tried first)
# - SSH keys: depends on sshd_config

auth       sufficient   pam_openbastion.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

## Mode C: SSH Key with LLNG Authorization

> **Offline behaviour differs from the certificate modes.** Because Mode C does
> not set `AuthorizedKeysFile none`, `sshd` still honours `~/.ssh/authorized_keys`
> — which makes a personal key an _opt-in_ fallback during a portal outage, with
> trade-offs worth knowing before relying on it. See
> [what works offline](offline-mode.md#what-works-offline-and-what-needs-the-portal).

**SSH key authentication only, but LLNG checks if user is authorized.**

Users authenticate with SSH keys. PAM doesn't handle password authentication,
but LLNG verifies the user has permission to access this server.
You can restrict allowed key types with [SSH Key Policy](security.md#ssh-key-policy).

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Handled by SSH keys (not PAM); the PAM auth stack denies
# - Unix passwords: NOT USED (disable PasswordAuthentication in sshd_config)
# - LLNG tokens: NOT USED
# - SSH keys: REQUIRED
#
# AUTHORIZATION: LLNG checks if user can access this server

auth       required     pam_deny.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

For this mode, configure `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
PubkeyAuthentication yes
```

> **Why `auth required pam_deny.so`?** A certificate/pubkey login never calls
> `pam_authenticate()` — sshd only runs `pam_acct_mgmt()` for it — so this
> `auth` stack is reached only by password and keyboard-interactive
> authentication, which is exactly what this mode refuses. The single
> `pam_deny.so` line returns `PAM_AUTH_ERR` for those: a deliberate,
> unconditional refusal. Earlier versions used `auth required pam_permit.so`
> here, which made `pam_authenticate()` succeed for any password on a host
> where password authentication was still enabled.
>
> Set `PasswordAuthentication no` and `KbdInteractiveAuthentication no` anyway,
> so sshd never prompts in the first place. `ob-bastion-setup` /
> `ob-backend-setup` write both; the Debian package's `pam-mode` debconf prompt
> writes the PAM stack but does **not** touch `sshd_config`, so set the sshd
> options yourself if you install that way.

## Mode D: All Methods with LLNG Authorization (Most Flexible)

**SSH keys, LLNG tokens, AND Unix passwords all accepted. LLNG authorization required.**

Maximum flexibility: any authentication method works, but users must be authorized
in LLNG to access this server.

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Any method accepted
# - Unix passwords: ACCEPTED
# - LLNG tokens: ACCEPTED
# - SSH keys: ACCEPTED (if enabled in sshd_config)
#
# AUTHORIZATION: LLNG checks if user can access this server

auth       sufficient   pam_openbastion.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

## Mode E: SSO Certificates + sudo PAM-access (Maximum Security)

**SSH: only via certificates signed by the LLNG CA. sudo: only via LLNG temporary token.**

This mode provides the strictest separation between access (long-lived SSH certificate)
and privilege escalation (SSO re-authentication with a single-use token, and a live
authorization check, on every sudo — see
[sudo's timestamp cache](#how-often-you-are-actually-prompted-sudos-timestamp-cache)
for how often an operator is actually prompted).

### Prerequisites

- SSHCA plugin enabled in LemonLDAP::NG
- PamAccess plugin enabled in LemonLDAP::NG
- KRL (Key Revocation List) configured in LLNG (`/ssh/admin`)
- `ob-ssh-cert` deployed on client workstations
- Signed certificates for all users (recommended validity: 1 year)

### Configuration sshd

```
# /etc/ssh/sshd_config
PasswordAuthentication no                         # No SSH passwords
KbdInteractiveAuthentication no
PubkeyAuthentication yes                          # SSH certificates only
TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub
AuthorizedKeysFile none                           # No unsigned keys
RevokedKeys /etc/ssh/revoked_keys                 # KRL mandatory
ExposeAuthInfo yes                                # For certificate audit
AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f
AuthorizedPrincipalsCommandUser nobody
PermitRootLogin no
```

`ob-bastion-setup --max-security` writes these settings automatically via an
`Include` directive in `sshd_config`.

> **Do not replace `ob-ssh-principals` with `/bin/echo %u`.** Earlier revisions
> of this document showed that shortcut; it silently disables two controls:
>
> - `%f` is what feeds the [SSH fingerprint binding](#ssh-fingerprint-binding-on-pamauthorize-and-pamverify)
>   (the helper drops it in `/run/open-bastion/ssh-fp/<pid>.fp` for
>   `pam_openbastion` to read). With `/bin/echo` no fingerprint is ever
>   captured, so the binding degrades to "not sent".
> - On **backends** the helper is invoked with a third token,
>   `AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %i`,
>   and `%i` (the certificate key-id) is what carries `bastion=<id>`, checked
>   against `/etc/open-bastion/allowed_bastions` **before PAM runs**. With
>   `/bin/echo` any CA-signed certificate whose principal matches the login
>   name is accepted, including a direct user SSO certificate that never went
>   through a bastion.
>
> The helper is written to `/usr/local/sbin/ob-ssh-principals` at setup time by
> `ob-bastion-setup` / `ob-backend-setup`; it is not shipped as a packaged file.

### PAM Configuration for sshd

This is what `ob-bastion-setup` writes (from v0.6.3 — see #220). Reproduce it
exactly if you configure PAM by hand: every line below is load-bearing.

> **Two independent controls keep passwords out.** First,
> **`PasswordAuthentication no`** in the sshd drop-in, which the setup scripts
> also write: sshd then never runs this stack for a password at all. Second,
> the `auth` phase itself now refuses — `pam_deny` returns `PAM_AUTH_ERR`, so
> even if password or keyboard-interactive authentication were re-enabled, no
> password is accepted here.
>
> The certificate path is unaffected: sshd validates keys and certificates
> itself and never calls `pam_authenticate()` on that path, so this stack is
> only ever reached by password or keyboard-interactive authentication — which
> this mode does not allow. See #180.

```
# /etc/pam.d/sshd   (bastion / standalone — written by ob-bastion-setup)
#
# AUTHENTICATION: Handled by SSH certificates (not PAM); the PAM auth stack denies
# - Unix passwords: DISABLED
# - LLNG tokens: NOT USED for SSH
# - SSH certificates: REQUIRED (signed by LLNG CA)
#
# AUTHORIZATION: LLNG checks if user can access this server

auth       required     pam_deny.so

account    required     pam_openbastion.so ssh_cert_aware=true

session    optional     pam_mkhomedir.so skel=/etc/skel umask=0077
session    required     pam_unix.so
session    optional     pam_openbastion.so
session    optional     pam_systemd.so
```

On a **backend**, `ob-backend-setup` writes the same `auth` and `account` lines
but a different `session` block, because there the module creates the account
rather than only managing groups:

```
# /etc/pam.d/sshd   (backend — written by ob-backend-setup)
session    required     pam_openbastion.so create_user=true
session    required     pam_unix.so
session    optional     pam_systemd.so
```

Line by line, and why each matters:

| Line                            | Why it is there                                                                                                                                                                                                                                                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `auth required pam_deny.so`     | The certificate path never calls `pam_authenticate()`, so this stack is only reached by password or keyboard-interactive authentication, which certificate modes do not allow. `pam_deny` refuses it outright (`PAM_AUTH_ERR`). `PasswordAuthentication no` in `sshd_config` remains the first line of defence — this is the second. |
| `account … ssh_cert_aware=true` | See the note below — the module currently ignores this argument.                                                                                                                                                                                                                                                                     |
| **no** `account … pam_unix.so`  | In Mode E users exist only in NSS, not in `/etc/passwd`. `pam_unix`'s account check has no shadow entry to look at and can refuse the login. The same reasoning is already spelled out for `/etc/pam.d/sudo` below.                                                                                                                  |
| `session … pam_mkhomedir.so`    | Without it an SSO user lands in a non-existent home directory on a bastion. (On a backend, `pam_openbastion create_user=true` provisions the home instead.)                                                                                                                                                                          |
| `session … pam_openbastion.so`  | This is where the module manages `open-bastion-sudo` group membership from the SSO's `sudo_allowed` flag. **Omit it and Mode E sudo breaks**: sudoers grants only `%open-bastion-sudo`, and nothing ever adds the user to it.                                                                                                        |
| `session … pam_systemd.so`      | Registers the session with `systemd-logind`. Without it, cert-hop sessions are invisible to `who`, `w`, `loginctl` and to the heartbeat's connected-users report (fixed in 0.5.1). Both setups append this line only when `pam_systemd.so` is actually installed, so a non-systemd host does not get a per-login `dlopen` error.     |

> **`ssh_cert_aware=true` is currently a no-op.** Both setup scripts pass it as
> a module argument, but no code reads it: PAM module arguments of the form
> `key=value` are handed to `config_parse_args()` → `parse_line()`, whose final
> branch silently ignores unknown keys (`src/config.c`). Nothing in `src/`
> mentions `ssh_cert_aware`. Keep it or drop it as you like — it changes no
> behaviour today. This is tracked as a code cleanup, not a configuration knob;
> do not document it as one.

### PAM Configuration for sudo

```
# /etc/pam.d/sudo
#
# AUTHENTICATION: LLNG temporary token ONLY
# - Unix passwords: REJECTED
# - LLNG tokens: REQUIRED (fresh re-authentication via SSO)
#
# AUTHORIZATION: LLNG checks sudo_allowed flag
#
# NOTE: pam_unix.so is intentionally absent from the account section.
# In Mode E, users exist only in NSS (not /etc/passwd), so pam_unix.so
# account check would fail for them.

auth       sufficient   pam_openbastion.so
auth       required     pam_deny.so

account    required     pam_openbastion.so

session    required     pam_unix.so
```

`ob-bastion-setup --max-security` creates `/etc/sudoers.d/open-bastion` with
`%open-bastion-sudo ALL=(ALL) ALL` and a system group `open-bastion-sudo`.
The PAM module dynamically manages group membership during SSH session setup
based on the `sudo_allowed` flag from the SSO portal. This provides
**defense in depth**: even if the PAM module fails during sudo authentication,
users without group membership are blocked by sudoers before PAM is invoked.

### Security Model

```
┌──────────────────────────┐       ┌──────────────────────────┐
│       SSH Access         │       │    sudo Escalation       │
│                          │       │                          │
│  SSO Certificate (1 yr)  │       │  LLNG Token (5-60 min)  │
│  + /pam/authorize        │       │  + /pam/authorize        │
│                          │       │  (sudo_allowed=true)     │
│  "I have the right       │       │  "I want to perform a    │
│   to be here"            │       │   privileged action      │
│                          │       │   now"                   │
└──────────────────────────┘       └──────────────────────────┘
         │                                    │
         ▼                                    ▼
   Revocation:                         Revocation:
   - KRL (immediate)                   - Disable LLNG account
   - Disable LLNG account              - Remove sudo_allowed
   - Remove from groups                  (immediate effect)
```

### How often you are actually prompted: sudo's timestamp cache

Mode E is described above as "fresh SSO re-authentication for each `sudo`".
That claim holds **at the SSO layer**, and it is worth being precise about what
an operator sees, because the two are not the same thing.

What the SSO guarantees:

- The LLNG temporary token is **one-time**. `/pam/verify` consumes it
  server-side on first use, so a token that has been used cannot be replayed —
  not by the user, not by anyone who captured it.
- Its lifetime is short (`llng pam_token` mints a token with a TTL measured in
  minutes).
- Authorization is re-evaluated **live at every escalation**: `pam_openbastion`
  calls the portal each time, so revoking `sudo_allowed` or disabling the
  account takes effect on the next `sudo`, with no cached verdict.

What an operator observes:

- `sudo` keeps its own **timestamp cache**, independent of PAM. While that
  timestamp is valid, `sudo` skips the PAM `auth` phase entirely and never
  prompts. On Debian the default is `timestamp_timeout=15` (minutes), and it is
  **re-armed on each use**, so a continuously working admin can go a long time
  between token prompts. The `account` phase — and therefore the live
  authorization check — still runs on every `sudo`.

So the residual gap is one of prompt frequency, not of authorization: a stolen
_token_ is useless (single use, short TTL), and a revoked _right_ is enforced
immediately. What survives inside the window is the operator's own already
authenticated terminal.

If your policy requires a token prompt for **every** `sudo`, set
`timestamp_timeout=0`. Put it in its own sudoers drop-in — `ob-bastion-setup`
and `ob-backend-setup` regenerate `/etc/sudoers.d/open-bastion`, so anything
written there is lost on the next run:

```bash
cat > /etc/sudoers.d/open-bastion-local << 'EOF'
# Require a fresh LLNG token for every sudo (no timestamp reuse).
Defaults:%open-bastion-sudo timestamp_timeout=0
EOF
chmod 0440 /etc/sudoers.d/open-bastion-local
visudo -c
```

This is deliberately **not** the default: with `timestamp_timeout=0` every
`sudo` in a shell loop or a long maintenance session needs a new token, which
in practice pushes operators towards `sudo -i`. Choose per site.

### Mandatory KRL

With long-lived certificates (1 year), the KRL is **mandatory**:

```bash
# Initial KRL download
curl -o /etc/ssh/revoked_keys https://auth.example.com/ssh/revoked

# Automatic refresh (cron)
# /etc/cron.d/open-bastion-krl
*/30 * * * * root curl -sf -o /etc/ssh/revoked_keys.tmp https://auth.example.com/ssh/revoked && mv /etc/ssh/revoked_keys.tmp /etc/ssh/revoked_keys
```

### SSH fingerprint binding on `/pam/authorize` and `/pam/verify`

From plugin PamAccess 0.1.16 onwards, `pam_openbastion` forwards the
SHA256 fingerprint of the SSH key used to open the session in **both**
the `/pam/authorize` request issued at every SSH connection (PAM
`account` phase) and the `/pam/verify` request issued on every
LLNG-token operation (sudo, re-authentication).

#### How the fingerprint is captured

Modern OpenSSH (≥ 9.x) does **not** propagate the authentication info
to the PAM environment during `pam_acct_mgmt` — `ExposeAuthInfo yes`
is not sufficient on its own. The bastion therefore uses an explicit
out-of-band channel:

1. sshd invokes
   `AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %t %k`
   (deployed by `ob-bastion-setup` / `ob-backend-setup`; the backend
   variant also gets `%i`, the certificate key-id). The `%f` token is
   the SHA256 fingerprint of the client key or certificate (not `%F`,
   which is the CA key's fingerprint), `%t` is the key or certificate
   type and `%k` its base64 blob. All of these have been supported on
   `AuthorizedPrincipalsCommand` since OpenSSH 7.4.
2. The helper writes two drop files (atomic `mktemp` + `mv`), keyed on
   the per-connection sshd anchor PID:
   - `/run/open-bastion/ssh-fp/<sshd-session-pid>.fp` — the fingerprint,
     exactly as before (a bare `SHA256:<base64>` line);
   - `/run/open-bastion/ssh-fp/<sshd-session-pid>.key` — v1 key metadata,
     `v=1` / `fp=` / `alg=` / `key=` lines, used by the SSH key policy.

   They are separate files on purpose: an older `pam_openbastion` that
   only knows `.fp` keeps working byte-for-byte against a newer helper.
   The spool directory is owned by the `AuthorizedPrincipalsCommandUser`
   (typically `nobody`) with mode `0700`, so no other unprivileged user
   can pre-create or substitute a drop file.

3. `pam_openbastion` walks `/proc/<pid>/status` from its own PID up to
   the `sshd-session` ancestor, reads the corresponding spool files and
   validates each one (regular file owned by the spool-dir owner, mode
   `0600`, `nlink == 1`, size-capped; `.fp` must additionally match the
   strict `SHA256:<base64>` format). The fingerprint is forwarded to
   LLNG; the key metadata feeds the key policy below. If the two drops
   disagree on the fingerprint, the metadata is discarded as stale.

As a fallback, if a custom sshd variant does populate
`SSH_USER_AUTH` with the content (`publickey <algo> SHA256:<fp>`), the
module will parse it from there instead.

#### SSH key policy enforcement (`ssh_key_policy_enabled`)

The same channel is what makes `ssh_key_policy_*` enforceable. When
`ssh_key_policy_enabled = true`, `pam_openbastion` determines the key
type and size for the `sshd` PAM service and denies the account phase
when they violate the policy.

- The **key blob** (`%k`) is decoded by the module itself. That is the
  only source for an RSA modulus size, so `ssh_key_min_rsa_bits` is
  really applied; it also means the key type cannot be misreported.
- If no blob is available, the sshd-reported type (`%t`) is used. An
  RSA key is then rejected, because its size cannot be verified.
- If neither is available, the login is **denied** (fail-closed) with an
  explicit log line. Before this was fixed (issue #181), the whole check
  was silently skipped in that case, which made the policy a no-op on
  every OpenSSH that does not export `SSH_USER_AUTH` to PAM — i.e. all
  current ones.

`ssh_key_policy_enabled` is `false` by default, and nothing in this path
runs while it is off. **Enable it only on a host whose setup script has
been re-run with the version that installs the v1 helper**, otherwise no
`.key` drop is written and every SSH login is denied. Check with:

```bash
grep -q 'spool-format: v1' /usr/local/sbin/ob-ssh-principals && echo OK
```

On a package upgrade the PAM module is replaced but the helper is not —
it lives in `/usr/local/sbin` and is written by the setup script — so
re-run `ob-bastion-setup` / `ob-backend-setup` for the host's role. The
postinst warns when it sees the policy enabled next to a pre-v1 helper.

#### Security properties

LLNG rejects the call unless it finds a matching, non-revoked and
non-expired SSH CA record in the user's persistent session
(`_sshCerts`). This provides a second line of defense on top of the
local `sshd` KRL check:

- **Session opening**: even if the bastion's `/etc/ssh/revoked_keys`
  is stale or `RevokedKeys` is missing from `sshd_config`, a newly
  revoked certificate is rejected at `/pam/authorize` (`account`
  phase), and the SSH session is refused before the shell is spawned.
- **Privilege escalation**: the same check runs on `/pam/verify`, so
  a compromised or revoked certificate cannot be used to obtain
  privileges via sudo from an already-established session either.
- **Token binding**: a stolen LLNG token cannot be replayed from a
  machine holding a different SSH key — the fingerprint presented in
  the request would not match any `_sshCerts` entry of the token's
  `sub` user.

#### Operational requirements

- `ob-bastion-setup` / `ob-backend-setup` install
  `/usr/local/sbin/ob-ssh-principals`, wire it as
  `AuthorizedPrincipalsCommand`, and prepare the spool directory +
  `/etc/tmpfiles.d/open-bastion-ssh-fp.conf` drop-in so that `/run`
  gets the directory recreated at boot.
- `ExposeAuthInfo yes` is **not** required for the fingerprint
  binding itself (the helper + spool are self-sufficient); it remains
  useful for session auditing.
- The `fingerprint` field is optional on the LLNG side, so bastions
  running on older portals that lack PamAccess 0.1.16 remain fully
  compatible — the portal simply ignores it.

## Summary Table

| Mode             | Unix Password | LLNG Token | SSH Key    | LLNG Authorization |
| ---------------- | ------------- | ---------- | ---------- | ------------------ |
| A - LLNG Only    | Rejected      | Required   | Optional\* | Required           |
| B - LLNG + Unix  | Fallback      | Preferred  | Optional\* | Required           |
| C - SSH Key Only | Disabled      | Not used   | Required   | Required           |
| D - All Methods  | Accepted      | Accepted   | Optional\* | Required           |
| E - Max Security | Disabled      | sudo only  | Cert only  | Required           |

\* SSH key authentication depends on `PubkeyAuthentication` in sshd_config

## SSH Server Configuration

Edit `/etc/ssh/sshd_config` according to your chosen mode:

### For Mode A or B (Password/Token authentication)

```
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes          # Optional: also allow SSH keys
PermitEmptyPasswords no
```

### For Mode C (SSH Key only)

```
UsePAM yes
PasswordAuthentication no         # Disable password authentication
KbdInteractiveAuthentication no
PubkeyAuthentication yes          # SSH keys required
PermitEmptyPasswords no
```

### For Mode D (All methods)

```
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
```

### For Mode E (Certificate + sudo token)

```
UsePAM yes
PasswordAuthentication no                         # No passwords for SSH
KbdInteractiveAuthentication no
PubkeyAuthentication yes                          # SSH certificates required
TrustedUserCAKeys /etc/ssh/open-bastion_ca.pub
AuthorizedKeysFile none                           # No unsigned keys
RevokedKeys /etc/ssh/revoked_keys                 # KRL mandatory
ExposeAuthInfo yes
# Bastion: two tokens (%u %f). Backend: three (%u %f %i) — %i carries the
# bastion= key-id checked against /etc/open-bastion/allowed_bastions.
AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f
AuthorizedPrincipalsCommandUser nobody
PermitRootLogin no
PermitEmptyPasswords no
```

Restart SSH after changes:

```bash
sudo systemctl restart sshd
```

## See Also

- [Access & Permissions](permissions.md) - Which controls live SSO-side vs server-side
- [LemonLDAP::NG Configuration](llng-configuration.md) - Server-side setup
- [Configuration Reference](configuration.md) - All configuration options
- [Service Accounts](service-accounts.md) - SSH key authentication for automation
- [Security Features](security.md) - Key policies and rate limiting
- [Security Analysis - SSH Connection](security/02-ssh-connection.md) - Risk analysis including Mode E
