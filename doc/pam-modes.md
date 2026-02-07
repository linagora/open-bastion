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

## Summary Table

| Mode             | Unix Password | LLNG Token | SSH Key    | LLNG Authorization |
| ---------------- | ------------- | ---------- | ---------- | ------------------ |
| A - LLNG Only    | Rejected      | Required   | Optional\* | Required           |
| B - LLNG + Unix  | Fallback      | Preferred  | Optional\* | Required           |
| C - SSH Key Only | Disabled      | Not used   | Required   | Required           |
| D - All Methods  | Accepted      | Accepted   | Optional\* | Required           |

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

Restart SSH after changes:

```bash
sudo systemctl restart sshd
```
