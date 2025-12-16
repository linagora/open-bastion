# PAM Module for LemonLDAP::NG

This PAM module enables Linux servers to authenticate users via LemonLDAP::NG (LLNG), supporting both:

- **Token-based authentication**: Users generate temporary access tokens from the LLNG portal to use as SSH passwords
- **Key-based authorization**: When users connect via SSH keys, the module checks if they're authorized to access this server

## Features

- Token introspection via OIDC introspection endpoint
- Server authorization via `/pam/authorize` endpoint
- Server groups support for granular access control
- Token caching to reduce server load
- Secure communication with SSL/TLS support
- Easy server enrollment with `llng-pam-enroll` script
- **Security hardening**:
  - Structured JSON audit logging with correlation IDs
  - Rate limiting with exponential backoff
  - AES-256-GCM encrypted secret storage
  - Webhook notifications for security events
  - Token binding (IP, fingerprint)

## Requirements

- LemonLDAP::NG >= 2.22.0 with PAM Access plugin enabled
- libcurl
- json-c
- OpenSSL
- libkeyutils
- PAM development headers
- curl and jq (for enrollment script)

### Debian/Ubuntu

```bash
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libpam0g-dev libssl-dev libkeyutils-dev cmake curl jq
```

### RHEL/CentOS/Fedora

```bash
sudo dnf install libcurl-devel json-c-devel pam-devel openssl-devel keyutils-libs-devel cmake curl jq
```

## Building and Installation

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

This installs:
- `/usr/lib/security/pam_llng.so` - The PAM module
- `/usr/sbin/llng-pam-enroll` - Server enrollment script
- `/etc/security/pam_llng.conf.example` - Example configuration

## Quick Start

### Step 1: Create the Configuration File

```bash
sudo cp /etc/security/pam_llng.conf.example /etc/security/pam_llng.conf
sudo chmod 600 /etc/security/pam_llng.conf
sudo nano /etc/security/pam_llng.conf
```

Configure at minimum:
```ini
portal_url = https://auth.example.com
client_id = pam-access
client_secret = your-secret-here
server_group = default
```

### Step 2: Enroll the Server

Run the enrollment script as root:

```bash
sudo llng-pam-enroll
```

The script will:
1. Initiate a Device Authorization request
2. Display a user code for administrator approval
3. Wait for the administrator to approve the server
4. Save the server token to `/etc/security/pam_llng.token`

**Administrator approval**: An administrator must visit the LLNG portal, go to the device verification page, and enter the displayed code to approve this server.

### Step 3: Configure PAM for SSH

Edit `/etc/pam.d/sshd`. The configuration depends on your authentication mode.

> **Important**: The configurations below have different security implications regarding
> which authentication methods are accepted. Read the descriptions carefully.

#### Mode A: LLNG Token Only (Strictest)

**Only LLNG tokens are accepted as passwords. Unix passwords are rejected.**

This is the most secure mode: users must authenticate via LemonLDAP::NG.

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: Only LLNG tokens accepted
# - Unix passwords: REJECTED
# - LLNG tokens: ACCEPTED
# - SSH keys: depends on sshd_config (PubkeyAuthentication)

auth       sufficient   pam_llng.so
auth       required     pam_deny.so

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

#### Mode B: LLNG Token or Unix Password (Fallback)

**Both LLNG tokens AND traditional Unix passwords are accepted.**

Useful for transition periods or when some users don't have LLNG accounts.

```
# /etc/pam.d/sshd
#
# AUTHENTICATION: LLNG token OR unix password
# - Unix passwords: ACCEPTED (fallback)
# - LLNG tokens: ACCEPTED (tried first)
# - SSH keys: depends on sshd_config

auth       sufficient   pam_llng.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

#### Mode C: SSH Key with LLNG Authorization

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

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

For this mode, configure `/etc/ssh/sshd_config`:
```
PasswordAuthentication no
PubkeyAuthentication yes
```

#### Mode D: All Methods with LLNG Authorization (Most Flexible)

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

auth       sufficient   pam_llng.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

#### Summary Table

| Mode | Unix Password | LLNG Token | SSH Key | LLNG Authorization |
|------|---------------|------------|---------|-------------------|
| A - LLNG Only | ❌ Rejected | ✅ Required | Optional* | ✅ Required |
| B - LLNG + Unix | ✅ Fallback | ✅ Preferred | Optional* | ✅ Required |
| C - SSH Key Only | ❌ Disabled | ❌ Not used | ✅ Required | ✅ Required |
| D - All Methods | ✅ Accepted | ✅ Accepted | Optional* | ✅ Required |

\* SSH key authentication depends on `PubkeyAuthentication` in sshd_config

### Step 4: Configure SSH Server

Edit `/etc/ssh/sshd_config` according to your chosen mode:

#### For Mode A or B (Password/Token authentication)

```
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes          # Optional: also allow SSH keys
PermitEmptyPasswords no
```

#### For Mode C (SSH Key only)

```
UsePAM yes
PasswordAuthentication no         # Disable password authentication
KbdInteractiveAuthentication no
PubkeyAuthentication yes          # SSH keys required
PermitEmptyPasswords no
```

#### For Mode D (All methods)

```
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

### Step 5: Test

**Important**: Open a **new terminal** and keep your current session open as backup!

```bash
# Test with LLNG token (Modes A, B, D)
ssh user@server
Password: <paste LLNG token from portal>

# Test with Unix password (Modes B, D only)
ssh user@server
Password: <unix password>

# Test with SSH key (Modes C, D, or any mode with PubkeyAuthentication yes)
ssh -i ~/.ssh/id_rsa user@server
```

## Server Enrollment Script

The `llng-pam-enroll` script automates the Device Authorization Grant flow.

### Usage

```bash
sudo llng-pam-enroll [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-p, --portal URL` | LemonLDAP::NG portal URL |
| `-c, --client-id ID` | OIDC client ID (default: pam-access) |
| `-s, --client-secret SECRET` | OIDC client secret |
| `-g, --server-group GROUP` | Server group name (default: default) |
| `-t, --token-file FILE` | Where to save the token (default: /etc/security/pam_llng.token) |
| `-C, --config FILE` | Configuration file (default: /etc/security/pam_llng.conf) |
| `-k, --insecure` | Skip SSL certificate verification |
| `-q, --quiet` | Quiet mode |
| `-h, --help` | Show help |

### Examples

```bash
# Enroll using settings from config file
sudo llng-pam-enroll

# Enroll with explicit parameters
sudo llng-pam-enroll -p https://auth.example.com -s mysecret

# Enroll for a specific server group
sudo llng-pam-enroll -g production

# Enroll with custom token file location
sudo llng-pam-enroll -t /etc/pam_llng/server.token
```

### Manual Enrollment (Without Script)

If you prefer manual enrollment:

#### 1. Initiate enrollment

```bash
curl -X POST https://auth.example.com/oauth2/device \
  -d "client_id=pam-access" \
  -d "scope=pam:server"
```

Response:
```json
{
  "device_code": "...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://auth.example.com/device",
  "expires_in": 1800
}
```

#### 2. Admin approval

An administrator visits `https://auth.example.com/device`, logs in, and enters the user code.

#### 3. Get access token

```bash
curl -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<device_code_from_step_1>" \
  -d "client_id=pam-access" \
  -d "client_secret=your-secret"
```

#### 4. Save the token

```bash
echo "<access_token>" | sudo tee /etc/security/pam_llng.token
sudo chmod 600 /etc/security/pam_llng.token
```

## Configuration Reference

### /etc/security/pam_llng.conf

```ini
# Required: LemonLDAP::NG portal URL
portal_url = https://auth.example.com

# Required: OIDC client credentials
client_id = pam-access
client_secret = your-secret

# Server token file (created by enrollment)
server_token_file = /etc/security/pam_llng.token

# Server group for authorization rules
server_group = default

# HTTP settings
timeout = 10
verify_ssl = true
# ca_cert = /etc/ssl/certs/custom-ca.pem

# Cache settings
cache_enabled = true
cache_dir = /var/cache/pam_llng
cache_ttl = 300
cache_ttl_high_risk = 60
high_risk_services = sudo,su

# Logging: error, warn, info, debug
log_level = warn

# Audit logging
audit_enabled = true
audit_log_file = /var/log/pam_llng/audit.json
audit_to_syslog = true
audit_level = 1  # 0=critical, 1=auth events, 2=all

# Rate limiting
rate_limit_enabled = true
rate_limit_max_attempts = 5
rate_limit_initial_lockout = 30
rate_limit_max_lockout = 3600

# Webhook notifications (optional)
# notify_enabled = true
# notify_url = https://alerts.example.com/webhook
# notify_secret = your-hmac-secret
```

### PAM Module Arguments

Arguments can be passed directly in PAM configuration:

```
auth required pam_llng.so portal_url=https://auth.example.com debug
```

| Argument | Description |
|----------|-------------|
| `conf=/path/to/file` | Use alternate config file |
| `portal_url=URL` | Override portal URL |
| `server_group=GROUP` | Override server group |
| `debug` | Enable debug logging |
| `authorize_only` | Skip password check (for SSH key mode) |
| `no_cache` | Disable token caching |
| `insecure` | Skip SSL verification |
| `no_audit` | Disable audit logging |
| `no_rate_limit` | Disable rate limiting |
| `no_bind_ip` | Disable IP binding for tokens |

## Server Groups

Server groups allow different authorization rules for different server categories.

### Configure in LLNG Manager

```
General Parameters > Plugins > PAM Access > Server Groups

production => $hGroup->{ops}
staging    => $hGroup->{ops} or $hGroup->{dev}
dev        => $hGroup->{dev}
default    => 1
```

### Configure on Each Server

In `/etc/security/pam_llng.conf`:

```ini
server_group = production
```

Or during enrollment:

```bash
sudo llng-pam-enroll -g production
```

## User Experience

### Token Authentication

1. User visits the LLNG portal
2. Navigates to "PAM Access" tab
3. Generates a temporary token (valid 5-60 minutes)
4. SSH to server, paste token as password:

```bash
ssh user@server.example.com
Password: <paste token>
```

### SSH Key Authentication

1. User has SSH key configured normally
2. SSH to server:

```bash
ssh user@server.example.com
```

3. PAM module checks authorization via LLNG
4. Access granted or denied based on rules

## Troubleshooting

### Check Logs

```bash
# System auth log
sudo tail -f /var/log/auth.log

# Or journald
sudo journalctl -u sshd -f
```

### Enable Debug Mode

In `/etc/security/pam_llng.conf`:
```ini
log_level = debug
```

### Test Token Introspection

```bash
curl -X POST https://auth.example.com/oauth2/introspect \
  -u "pam-access:secret" \
  -d "token=<user_token>"
```

### Test Authorization Endpoint

```bash
curl -X POST https://auth.example.com/pam/authorize \
  -H "Authorization: Bearer $(sudo cat /etc/security/pam_llng.token)" \
  -H "Content-Type: application/json" \
  -d '{"user": "testuser", "host": "'$(hostname)'", "server_group": "default"}'
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `PAM unable to load module` | Module not in path | Check `/lib/security/` or `/lib64/security/` |
| `Token introspection failed` | Wrong credentials | Verify client_id and client_secret |
| `Server not enrolled` | Missing/invalid token | Run `llng-pam-enroll` |
| `User not authorized` | Server group rules | Check LLNG Manager configuration |
| `Connection refused` | Portal unreachable | Check network and portal_url |

### Re-enrollment

If the server token expires or is compromised:

```bash
sudo rm /etc/security/pam_llng.token
sudo llng-pam-enroll
```

## Security Considerations

1. **Protect configuration files**: `/etc/security/pam_llng.conf` and `.token` should be readable only by root
2. **Use TLS**: Always use HTTPS for portal_url
3. **Server tokens**: Server tokens are automatically rotated via refresh token mechanism (`token_rotate_refresh = true` by default). If you suspect compromise, re-enroll the server with `llng-pam-enroll`
4. **Backup access**: Keep a root password or console access as fallback

## License

AGPL-3.0

## Author

Xavier Guimard <xguimard@linagora.com>

Copyright (C) 2025 [Linagora](https://linagora.com)
