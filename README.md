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

## Requirements

- LemonLDAP::NG >= 2.22.0 with PAM Access plugin enabled
- libcurl
- json-c
- PAM development headers

### Debian/Ubuntu

```bash
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libpam0g-dev cmake
```

### RHEL/CentOS/Fedora

```bash
sudo dnf install libcurl-devel json-c-devel pam-devel cmake
```

## Building

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## Server Enrollment

Before the PAM module can check authorizations, the server must be enrolled with the LLNG portal using the Device Authorization Grant flow.

### 1. Initiate enrollment

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

### 2. Admin approval

An administrator must visit `https://auth.example.com/device`, log in, and enter the user code to approve the server.

### 3. Get access token

```bash
curl -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=..." \
  -d "client_id=pam-access" \
  -d "client_secret=pamsecret"
```

### 4. Save the token

```bash
echo "access_token_from_response" | sudo tee /etc/security/pam_llng.token
sudo chmod 600 /etc/security/pam_llng.token
```

## Configuration

### PAM module configuration

Create `/etc/security/pam_llng.conf`:

```ini
portal_url = https://auth.example.com
client_id = pam-access
client_secret = your-secret
server_token_file = /etc/security/pam_llng.token
server_group = production
```

See `pam_llng.conf.example` for all options.

### PAM service configuration

#### For token-based authentication (password)

Add to `/etc/pam.d/sshd`:

```
auth    sufficient    pam_llng.so
auth    required      pam_unix.so
```

#### For key-based authorization only

```
account required pam_llng.so authorize_only
```

#### Full example for SSH with both modes

```
# /etc/pam.d/sshd

# Authentication: try LLNG token first, fallback to unix
auth    sufficient    pam_llng.so
auth    required      pam_unix.so

# Account: check authorization via LLNG
account required      pam_llng.so
account required      pam_unix.so

# Session and password unchanged
session required      pam_unix.so
password required     pam_unix.so
```

### SSH server configuration

In `/etc/ssh/sshd_config`:

```
# Allow both password and key authentication
PasswordAuthentication yes
PubkeyAuthentication yes

# Use PAM
UsePAM yes

# Allow keyboard-interactive for token input
ChallengeResponseAuthentication yes
```

## Server Groups

Server groups allow different authorization rules for different server categories. Configure groups in the LLNG Manager:

```
General Parameters > Plugins > PAM Access > Server Groups

production => $hGroup->{ops}
staging    => $hGroup->{ops} or $hGroup->{dev}
dev        => $hGroup->{dev}
default    => 1
```

Then configure each server's group in `/etc/security/pam_llng.conf`:

```ini
server_group = production
```

## User Experience

### With token authentication

1. User visits the LLNG portal and navigates to "PAM Access"
2. User generates a temporary token (valid for 5-60 minutes)
3. User SSHs to the server and uses the token as password:

```bash
ssh user@server.example.com
Password: <paste token>
```

### With SSH key authentication

1. User has their SSH key configured normally
2. User SSHs to server with their key
3. PAM module checks authorization in the background
4. Access is granted or denied based on LLNG rules

## Troubleshooting

### Check logs

```bash
# System logs
journalctl -u sshd

# Or
tail -f /var/log/auth.log
```

### Enable debug mode

In `/etc/security/pam_llng.conf`:
```ini
log_level = debug
```

Or in PAM config:
```
auth required pam_llng.so debug
```

### Test token introspection

```bash
curl -X POST https://auth.example.com/oauth2/introspect \
  -u "pam-access:secret" \
  -d "token=user_token_here"
```

### Test authorization

```bash
curl -X POST https://auth.example.com/pam/authorize \
  -H "Authorization: Bearer $(cat /etc/security/pam_llng.token)" \
  -H "Content-Type: application/json" \
  -d '{"user": "testuser", "host": "server.example.com"}'
```

## License

GPL-2.0

## Authors

- LemonLDAP::NG team <https://lemonldap-ng.org/team>
- Linagora <https://linagora.com>
