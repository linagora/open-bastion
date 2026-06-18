# Open Bastion

**Control SSH access and sudo privileges on your Linux servers from your SSO —
no more per-server keys or sudoers.**

Open Bastion integrates your servers with [LemonLDAP::NG](https://lemonldap-ng.org) (LLNG)
so you manage your Linux administrators as easily as you already manage your SSO
users. Administrators define access rules once in the portal; the PAM/NSS modules
enforce them on every server.

## What Open Bastion gives you

- **The SSO decides SSH access** — no SSH keys to install or rotate on each
  server; group membership grants or revokes access fleet-wide.
- **The SSO decides `sudo` too** — no `sudoers` to maintain per host (local/dual
  management stays possible when you want it).
- **The recorder can't be bypassed** — no escaping the session recorder via
  port-forwarding, while `~/.ssh/config` keeps access _visually_ direct.
- **Fleet deployment in one command** — `ob-builder --output-ansible <role>` (or
  a self-extracting shell installer), then roll it out to every host.
- **A "backup" account with access everywhere** — with or without `sudo` — via
  [service accounts](doc/service-accounts.md).
- **Self-service onboarding** — a new admin signs their SSH key at the portal and
  instantly has every right their groups grant.
- **One-click offboarding** — close the SSO account and access is gone.
- **Instant role changes** — change someone's groups and, within minutes, old
  rights drop and new ones apply.

Two layers do this: the **SSO (LLNG) decides** policy centrally, the **PAM/NSS
modules enforce** it on each server. See [Access & Permissions](doc/permissions.md)
for exactly which control lives where.

## Quick start

Three quick-starts cover the ways to get going:

| Quick-start                                                  | Use it to…                                                                                                                                           |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **[Try it in Docker](quick-start/README.md)**                | Spin up a LemonLDAP::NG portal + a self-enrolling SSH server in ~2 minutes and log in with an LLNG token — the fastest way to see Open Bastion work. |
| **[Deploy a fleet with Ansible](doc/ansible-quickstart.md)** | Generate bastion + backend roles with `ob-builder`, declare your hosts and IPs, and apply with `ansible-playbook` — the path to a real deployment.   |
| **[Deploy with a shell installer](doc/shell-quickstart.md)** | Generate a self-extracting installer per role with `ob-builder --output-shell`, then `scp` + `sudo`-run it on each host — no Ansible control node.   |

For the underlying concepts and per-step manual configuration, see
[PAM Authentication Modes](doc/pam-modes.md), the
[Configuration Reference](doc/configuration.md), and the
[Admin Guide](doc/admin-guide.md).

## How it works

1. A user authenticates to a server — with an LLNG **token** (used as the SSH
   password) or an **SSO-signed SSH certificate** (self-served via `ob-ssh-cert`).
2. `pam_openbastion` asks LLNG `/pam/authorize` whether this user may access this
   server group, and `sudo` is gated the same way; an encrypted local cache keeps
   this working during an SSO outage.
3. The **NSS** module resolves SSO users (and key-only service accounts) so the
   system sees them as real Unix accounts; provisioning creates the home on first
   login.
4. To reach a **backend behind a bastion**, the bastion mints a short-lived,
   LLNG-signed certificate and re-originates the connection with `ob-ssh` /
   `ob-scp` / `ob-sftp` — no user key or agent on the bastion. Backends accept
   only vouched bastions.
5. Sessions are **recorded** to a tamper-evident, root-owned store for audit.

See [Bastion Architecture](doc/bastion-architecture.md) and the
[documentation index](doc/README.md) for the details.

## Features

- Token introspection via OIDC introspection endpoint
- Server authorization via `/pam/authorize` endpoint
- [Server groups](doc/llng-configuration.md#server-groups) support for granular access control
- Token caching to reduce server load
- Secure communication with SSL/TLS support
- Easy server enrollment with `ob-enroll` script
- **[Offline mode](doc/offline-mode.md)**:
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
  - Certificate-based proof of connection origin (LLNG-signed ephemeral SSH cert, ~120 s)
  - Backends only accept SSH from authorized bastions (`allowed_bastions` + `source-address` critical option)
  - No agent forwarding or user key on the bastion required
  - `ob-ssh` / `ob-scp` / `ob-sftp` scripts for seamless bastion connections and file transfers
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
- **Desktop SSO** (LightDM integration):
  - Authenticate workstations via LLNG Single Sign-On
  - LightDM webkit2-greeter theme with embedded LLNG portal
  - Offline mode with cached credentials (Argon2id + AES-256-GCM)
  - Multi-factor authentication support (TOTP, WebAuthn, etc.)
  - Automatic session and desktop environment selection

## Installation

### From Package Repository

Pre-built packages are available for:

- **Debian/Ubuntu**: Debian 12, Debian 13, Ubuntu 24.04
- **RHEL/Rocky Linux**: Rocky Linux 9, Rocky Linux 10

See installation instructions at: **https://linagora.github.io/open-bastion/**

### Deploying to a fleet — `open-bastion-builder`

For administrators rolling Open Bastion out to several servers, a separate
`open-bastion-builder` package provides an interactive CLI (`ob-builder`)
that generates a self-extracting shell installer and/or an Ansible role
tailored to your SSO, scenario, and target role (bastion / standalone /
backend). Install it once on an admin workstation, run the questionnaire,
then push the resulting artefact to every target machine.

See [admin-builder/README.md](admin-builder/README.md) for the questionnaire,
configuration keys, and usage examples.

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

## Documentation

The full, theme-organized index is in **[doc/README.md](doc/README.md)**. Highlights:

- **Get started** — [Docker demo](quick-start/README.md) · [Shell](doc/shell-quickstart.md) / [Ansible](doc/ansible-quickstart.md) quick-starts · [Admin guide](doc/admin-guide.md)
- **Connections & architecture** — [Bastion architecture](doc/bastion-architecture.md) · [PAM modes](doc/pam-modes.md) · [LLNG configuration](doc/llng-configuration.md)
- **Access & permissions** — [Access & Permissions](doc/permissions.md) (SSO-side vs server-side) · [Service accounts](doc/service-accounts.md)
- **Recording & audit** — [Session recording](doc/session-recording.md) · [Audit trace](doc/audit.md)
- **Offline & resilience** — [Offline mode](doc/offline-mode.md) · [Cache administration](doc/offline-cache-admin.md)
- **Security & hardening** — [Security features](doc/security.md) · [Hardening](doc/hardening.md) · [CrowdSec](doc/crowdsec.md)
- **Reference** — [Configuration](doc/configuration.md) · [Desktop SSO](doc/desktop-sso.md) · [Competitors](doc/competitors.md)
- **Security analysis (EBIOS)** — [threat model & risk study](doc/security/00-architecture.md)

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
  -H "Authorization: Bearer $(sudo cat /var/lib/open-bastion/token)" \
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
sudo rm /var/lib/open-bastion/token
sudo ob-enroll
```

## Requirements

- A LemonLDAP::NG system >= 2.21.0 _(LTS)_ with [additional plugins](https://linagora.github.io/lemonldap-ng-plugins/) installed and enabled
- libcurl, json-c, OpenSSL, libkeyutils, PAM development headers
- curl and jq (for enrollment script)

## Desktop SSO (LightDM Integration)

Open Bastion can authenticate desktop workstations via LemonLDAP::NG Single Sign-On
using LightDM.

### Quick Setup

```bash
# Install the greeter package
sudo apt install lightdm-openbastion-greeter

# Run the setup script
sudo ob-desktop-setup -p https://auth.example.com

# For offline mode support
sudo ob-desktop-setup -p https://auth.example.com --offline
```

### Features

- **SSO Authentication**: Users login with their LLNG credentials via embedded portal
- **Multi-Factor Authentication**: Supports TOTP, WebAuthn/FIDO2, SMS, and more
- **Offline Mode**: Cached credentials allow login when LLNG is unreachable
- **Session Selection**: Choose between multiple desktop environments

### Documentation

- [Desktop SSO Guide](doc/desktop-sso.md) - Complete setup and configuration
- [Offline Mode](doc/offline-mode.md) - Cached credential authentication
- [Security Architecture](SECURITY.md#offline-credential-cache-security) - Security details

### Cache Management

```bash
# Show cache statistics
sudo ob-cache-admin stats

# List cached users
sudo ob-cache-admin list

# Invalidate a user's cache (after termination)
sudo ob-cache-admin invalidate username
```

## License

AGPL-3.0

## Author

Xavier Guimard <xguimard@linagora.com>

Copyright (C) 2025 [Linagora](https://linagora.com)
