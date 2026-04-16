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

**SSH key authentication only, but LLNG checks if user is authorized.**

Users authenticate with SSH keys. PAM doesn't handle password authentication,
but LLNG verifies the user has permission to access this server.
You can restrict allowed key types with [SSH Key Policy](security.md#ssh-key-policy).

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Handled by SSH keys (not PAM)
# - Unix passwords: NOT USED (disable PasswordAuthentication in sshd_config)
# - LLNG tokens: NOT USED
# - SSH keys: REQUIRED
#
# AUTHORIZATION: LLNG checks if user can access this server

auth       required     pam_permit.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

For this mode, configure `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
PubkeyAuthentication yes
```

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
and privilege escalation (fresh SSO re-authentication for each sudo).

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
TrustedUserCAKeys /etc/ssh/llng_ca.pub
AuthorizedKeysFile none                           # No unsigned keys
RevokedKeys /etc/ssh/revoked_keys                 # KRL mandatory
ExposeAuthInfo yes                                # For certificate audit
AuthorizedPrincipalsCommand /bin/echo %u          # Accept cert whose principal matches the Unix username
AuthorizedPrincipalsCommandUser nobody
PermitRootLogin no
```

`ob-bastion-setup --max-security` writes these settings automatically via an
`Include` directive in `sshd_config`.

### PAM Configuration for sshd

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Handled by SSH certificates (not PAM)
# - Unix passwords: DISABLED
# - LLNG tokens: NOT USED for SSH
# - SSH certificates: REQUIRED (signed by LLNG CA)
#
# AUTHORIZATION: LLNG checks if user can access this server

auth       required     pam_permit.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

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

`ob-bastion-setup --max-security` creates `/etc/sudoers.d/open-bastion` to grant
sudo rights to authorized users without relying on local Unix group membership.

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

### Mandatory KRL

With long-lived certificates (1 year), the KRL is **mandatory**:

```bash
# Initial KRL download
curl -o /etc/ssh/revoked_keys https://auth.example.com/ssh/revoked

# Automatic refresh (cron)
# /etc/cron.d/llng-krl-refresh
*/30 * * * * root curl -sf -o /etc/ssh/revoked_keys.tmp https://auth.example.com/ssh/revoked && mv /etc/ssh/revoked_keys.tmp /etc/ssh/revoked_keys
```

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
TrustedUserCAKeys /etc/ssh/llng_ca.pub
AuthorizedKeysFile none                           # No unsigned keys
RevokedKeys /etc/ssh/revoked_keys                 # KRL mandatory
ExposeAuthInfo yes
AuthorizedPrincipalsCommand /bin/echo %u
AuthorizedPrincipalsCommandUser nobody
PermitRootLogin no
PermitEmptyPasswords no
```

Restart SSH after changes:

```bash
sudo systemctl restart sshd
```

## See Also

- [LemonLDAP::NG Configuration](llng-configuration.md) - Server-side setup
- [Configuration Reference](configuration.md) - All configuration options
- [Service Accounts](service-accounts.md) - SSH key authentication for automation
- [Security Features](security.md) - Key policies and rate limiting
- [Security Analysis - SSH Connection](security/02-ssh-connection.md) - Risk analysis including Mode E
