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

## Requirements

- LemonLDAP::NG >= 2.22.0 with PAM Access plugin enabled
- libcurl
- json-c
- PAM development headers
- curl and jq (for enrollment script)

### Debian/Ubuntu

```bash
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libpam0g-dev cmake curl jq
```

### RHEL/CentOS/Fedora

```bash
sudo dnf install libcurl-devel json-c-devel pam-devel cmake curl jq
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

Edit `/etc/pam.d/sshd`. The configuration depends on your authentication mode:

#### Mode A: Token Authentication Only (Password)

Users authenticate with LLNG tokens as passwords:

```
# /etc/pam.d/sshd
auth       sufficient   pam_llng.so
auth       required     pam_deny.so

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

#### Mode B: SSH Key with LLNG Authorization

Users authenticate with SSH keys, LLNG checks authorization:

```
# /etc/pam.d/sshd
auth       required     pam_unix.so

account    required     pam_llng.so
account    required     pam_unix.so

session    required     pam_unix.so
```

#### Mode C: Both Token and SSH Key (Recommended)

Support both authentication methods:

```
# /etc/pam.d/sshd

# Authentication: try LLNG token first, fallback to unix password
auth       sufficient   pam_llng.so
auth       sufficient   pam_unix.so nullok
auth       required     pam_deny.so

# Account: check LLNG authorization for all users
account    required     pam_llng.so
account    required     pam_unix.so

# Session
session    required     pam_unix.so
```

### Step 4: Configure SSH Server

Edit `/etc/ssh/sshd_config`:

```
# Enable PAM
UsePAM yes

# For token authentication (Mode A or C)
PasswordAuthentication yes
KbdInteractiveAuthentication yes

# For SSH key authentication (Mode B or C)
PubkeyAuthentication yes

# Recommended: disable empty passwords
PermitEmptyPasswords no
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

### Step 5: Test

Open a **new terminal** (keep current session open as backup) and test:

```bash
# Test with token
ssh user@server
Password: <paste LLNG token from portal>

# Test with SSH key
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

# Logging: error, warn, info, debug
log_level = warn
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
3. **Server tokens**: Treat like SSH private keys; rotate if compromised
4. **Backup access**: Keep a root password or console access as fallback

## License

GPL-2.0

## Authors

- LemonLDAP::NG team <https://lemonldap-ng.org/team>
- Linagora <https://linagora.com>
