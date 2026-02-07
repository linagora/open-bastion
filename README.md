# Open Bastion

**Control SSH access and sudo privileges on your Linux servers through a centralized bastion server.**

Open Bastion integrates your servers with [LemonLDAP::NG](https://lemonldap-ng.org) (LLNG)
to centrally manage who can SSH into which servers and who can use [sudo](https://en.wikipedia.org/wiki/Sudo).
Administrators define access rules in the portal, and the PAM/NSS modules enforce them on each server.

The module supports two authentication methods:

- **Token-based authentication**: Users generate temporary access tokens from the portal to use as SSH passwords
- **Key-based authorization**: When users connect via SSH keys, the module checks if they're authorized to access this server

## Features

- Token introspection via OIDC introspection endpoint
- Server authorization via `/pam/authorize` endpoint
- [Server groups](doc/llng-configuration.md#server-groups) support for granular access control
- Token caching to reduce server load
- Secure communication with SSL/TLS support
- Easy server enrollment with `ob-enroll` script
- **[Offline mode](doc/security.md#cache-brute-force-protection)**:
  - Encrypted authorization cache (AES-256-GCM)
  - Continue SSH key authentication when LLNG server is unavailable
  - Configurable cache TTL with shorter TTL for high-risk services (sudo, su)
  - Cache brute-force protection with rate limiting
- **NSS module**:
  - Resolve users from LLNG via `/pam/userinfo` endpoint
  - Automatic UID generation from username hash
  - Cross-process file cache for performance
- **Automatic user provisioning**:
  - Auto-create Unix accounts on first login
  - Configurable shell, home directory, UID/GID ranges
  - Skeleton directory support
- **[Group synchronization](doc/llng-configuration.md#group-synchronization)**:
  - Sync Unix supplementary groups from LLNG on each login
  - Automatic group creation if needed
  - Local whitelist for defense-in-depth (`allowed_managed_groups`)
  - Groups outside managed pool are never modified
- **[Service accounts](doc/service-accounts.md)** (ansible, backup, etc.):
  - SSH key authentication without OIDC
  - Per-server configuration file
  - Fine-grained sudo permissions
  - Automatic account creation
- **[Bastion-to-backend authentication](doc/bastion-architecture.md)**:
  - JWT-based proof of connection origin
  - Backends only accept SSH from authorized bastions
  - Offline verification via cached JWKS public keys
  - `ob-ssh-proxy` script for seamless bastion connections
- **[Session recording](doc/session-recording.md)** (optional):
  - Record all terminal I/O for audit compliance
  - Multiple formats: script, asciinema, ttyrec
  - Session metadata with unique IDs
- **[Security hardening](doc/security.md)**:
  - Structured JSON audit logging with correlation IDs
  - Rate limiting with exponential backoff
  - AES-256-GCM encrypted secret storage
  - Webhook notifications for security events
  - Token binding (IP, fingerprint)
  - [SSH key policy](doc/security.md#ssh-key-policy) enforcement (allowed types, minimum sizes)
- **[CrowdSec integration](doc/crowdsec.md)** (optional):
  - Pre-authentication IP blocking via CrowdSec bouncer
  - Post-authentication failure reporting via CrowdSec watcher
  - Auto-ban after configurable failure threshold
  - Compatible with [Crowdsieve](https://github.com/linagora/crowdsieve) for centralized alert management
- **Monitoring**:
  - Server heartbeat via `ob-heartbeat`
  - Statistics reporting to portal

## Installation

### From Package Repository

Pre-built packages are available for:

- **Debian/Ubuntu**: Debian 12, Debian 13, Ubuntu 24.04
- **RHEL/Rocky Linux**: Rocky Linux 9, Rocky Linux 10

See installation instructions at: **https://linagora.github.io/open-bastion/**

### From Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libpam0g-dev libssl-dev libkeyutils-dev cmake curl jq

# Build
mkdir build && cd build
cmake ..
make
sudo make install
```

## Quick Start

### 1. Configure LemonLDAP::NG

See [LemonLDAP::NG Configuration](doc/llng-configuration.md) for detailed setup.

### 2. Create Configuration

```bash
sudo cp /etc/open-bastion/openbastion.conf.example /etc/open-bastion/openbastion.conf
sudo chmod 600 /etc/open-bastion/openbastion.conf
```

Edit with your settings:

```ini
portal_url = https://auth.example.com
client_id = pam-access
client_secret = your-secret
server_group = default
```

### 3. Enroll the Server

```bash
sudo ob-enroll
```

The script will display a user code. An administrator must visit the LLNG portal and enter this code to approve the server.

### 4. Configure PAM

Edit `/etc/pam.d/sshd` (recommended mode - LLNG tokens only):

```
auth       sufficient   pam_openbastion.so
auth       required     pam_deny.so

account    required     pam_openbastion.so
account    required     pam_unix.so

session    required     pam_unix.so
```

See [PAM Authentication Modes](doc/pam-modes.md) for other configurations.

### 5. Test

**Important**: Open a **new terminal** and keep your current session open as backup!

```bash
ssh user@server
Password: <paste LLNG token from portal>
```

## Documentation

See the full [documentation index](doc/README.md) or jump directly to:

| Document                                                 | Description                            |
| -------------------------------------------------------- | -------------------------------------- |
| [LemonLDAP::NG Configuration](doc/llng-configuration.md) | Server-side LLNG setup and plugins     |
| [PAM Authentication Modes](doc/pam-modes.md)             | All 4 PAM configurations with examples |
| [Configuration Reference](doc/configuration.md)          | All configuration options              |
| [Service Accounts](doc/service-accounts.md)              | Ansible, backup, CI/CD accounts        |
| [Bastion Architecture](doc/bastion-architecture.md)      | Bastion-to-backend JWT authentication  |
| [Session Recording](doc/session-recording.md)            | SSH session recording for audit        |
| [CrowdSec Integration](doc/crowdsec.md)                  | IP blocking and alert reporting        |
| [Security Features](doc/security.md)                     | Key policies, rate limiting, audit     |
| [Admin Guide](doc/admin-guide.md)                        | Complete administration guide          |

## Troubleshooting

### Check Logs

```bash
# System auth log
sudo tail -f /var/log/auth.log

# Or journald
sudo journalctl -u sshd -f
```

### Enable Debug Mode

In `/etc/open-bastion/openbastion.conf`:

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
  -H "Authorization: Bearer $(sudo cat /etc/open-bastion/token)" \
  -H "Content-Type: application/json" \
  -d '{"user": "testuser", "host": "'$(hostname)'", "server_group": "default"}'
```

### Common Issues

| Issue                        | Cause                 | Solution                                     |
| ---------------------------- | --------------------- | -------------------------------------------- |
| `PAM unable to load module`  | Module not in path    | Check `/lib/security/` or `/lib64/security/` |
| `Token introspection failed` | Wrong credentials     | Verify client_id and client_secret           |
| `Server not enrolled`        | Missing/invalid token | Run `ob-enroll`                              |
| `User not authorized`        | Server group rules    | Check LLNG Manager configuration             |
| `Connection refused`         | Portal unreachable    | Check network and portal_url                 |

### Re-enrollment

If the server token expires or is compromised:

```bash
sudo rm /etc/open-bastion/token
sudo ob-enroll
```

## Requirements

- A LemonLDAP::NG system >= 2.21.0 _(LTS)_ with [additional plugins](./llng-plugin) installed and enabled
- libcurl, json-c, OpenSSL, libkeyutils, PAM development headers
- curl and jq (for enrollment script)

## License

AGPL-3.0

## Author

Xavier Guimard <xguimard@linagora.com>

Copyright (C) 2025 [Linagora](https://linagora.com)
