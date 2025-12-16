# Bastion Architecture with LemonLDAP::NG

This document describes the overall architecture for SSH access control
using LemonLDAP::NG as the central identity provider.

## Overview

```
                                    ┌─────────────────────┐
                                    │   LemonLDAP::NG     │
                                    │      Portal         │
                                    │                     │
                                    │  - User auth        │
                                    │  - PAM tokens       │
                                    │  - Authorization    │
                                    │  - Session mgmt     │
                                    └──────────┬──────────┘
                                               │
                           ┌───────────────────┼───────────────────┐
                           │                   │                   │
                           ▼                   ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
                    │   Bastion   │     │   Bastion   │     │   Bastion   │
                    │   (Zone A)  │     │   (Zone B)  │     │   (Zone C)  │
                    │             │     │             │     │             │
                    │ pam_llng.so │     │ pam_llng.so │     │ pam_llng.so │
                    │ nss_llng.so │     │ nss_llng.so │     │ nss_llng.so │
                    │ recorder    │     │ recorder    │     │ recorder    │
                    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │                   │
              ┌────────────┼────────────┐      │      ┌────────────┼────────────┐
              ▼            ▼            ▼      │      ▼            ▼            ▼
         ┌────────┐   ┌────────┐   ┌────────┐  │ ┌────────┐   ┌────────┐   ┌────────┐
         │Backend │   │Backend │   │Backend │  │ │Backend │   │Backend │   │Backend │
         │Server 1│   │Server 2│   │Server 3│  │ │Server 4│   │Server 5│   │Server 6│
         └────────┘   └────────┘   └────────┘  │ └────────┘   └────────┘   └────────┘
                                               │
                                    (similar for Zone B)
```

## Components

### LemonLDAP::NG Portal

Central identity and access management:

- **User authentication**: OIDC, SAML, LDAP, etc.
- **PAM token generation**: Temporary tokens for SSH access
- **Authorization rules**: Per-user, per-group, per-server-group
- **Server enrollment**: Device Authorization Grant (RFC 8628)
- **Audit logging**: Centralized access logs

### Bastion Hosts

Jump servers that users connect to first:

| Component | Purpose |
|-----------|---------|
| `pam_llng.so` | Authenticate users via LLNG tokens or authorize SSH key users |
| `libnss_llng.so` | Resolve LLNG users before local account exists |
| `llng-session-recorder` | Record all SSH sessions for audit |
| SSH CA | Optional: sign user certificates |

### Backend Servers

Internal servers accessed through bastions:

| Component | Purpose |
|-----------|---------|
| `pam_llng.so` | Authorize access based on server_group |
| `libnss_llng.so` | Resolve users, auto-create accounts |
| Standard SSH | ProxyJump through bastion |

## Authentication Flow

### 1. User Obtains PAM Token

```
User Browser                    LLNG Portal
     │                               │
     │──── Login (OIDC/SAML) ───────▶│
     │◀─── Session cookie ───────────│
     │                               │
     │──── Request PAM token ───────▶│
     │◀─── Temporary token ──────────│
           (valid 5-60 min)
```

### 2. User Connects to Bastion

```
User                    Bastion                    LLNG Portal
  │                        │                            │
  │─── SSH + token ───────▶│                            │
  │                        │─── POST /oauth2/introspect ▶│
  │                        │◀── {active: true, user} ───│
  │                        │                            │
  │                        │─── POST /pam/authorize ────▶│
  │                        │◀── {authorized: true} ─────│
  │                        │                            │
  │◀── Session started ────│                            │
  │    (recording active)  │                            │
```

### 3. User Jumps to Backend

```
User                    Bastion                 Backend              LLNG
  │                        │                       │                   │
  │─── SSH to backend ────▶│                       │                   │
  │    (ProxyJump)         │─── SSH ──────────────▶│                   │
  │                        │                       │─ POST /pam/auth ─▶│
  │                        │                       │◀─ {authorized} ───│
  │                        │                       │                   │
  │                        │                       │─ getpwnam() ─────▶│
  │                        │                       │◀─ user info ──────│
  │                        │                       │                   │
  │                        │                       │ (create account)  │
  │                        │◀─ Session ────────────│                   │
  │◀─────────────────────────────────────────────────────────────────────
```

## Server Groups

Server groups allow different authorization rules for different environments:

```
LLNG Manager Configuration:

Server Groups:
┌────────────────┬─────────────────────────────────────┐
│ Group Name     │ Authorization Rule                  │
├────────────────┼─────────────────────────────────────┤
│ production     │ $hGroup->{sre} or $hGroup->{oncall} │
│ staging        │ $hGroup->{sre} or $hGroup->{dev}    │
│ development    │ $hGroup->{dev}                      │
│ bastion        │ $hGroup->{employees}                │
│ default        │ 0  (deny all)                       │
└────────────────┴─────────────────────────────────────┘
```

Each server enrolls with its server_group:

```bash
# On production servers
llng-pam-enroll -g production

# On staging servers
llng-pam-enroll -g staging

# On bastions
llng-pam-enroll -g bastion
```

## NSS Integration

The NSS module (`libnss_llng`) enables user resolution before account creation:

```
SSH Connection                   NSS                      LLNG
      │                           │                         │
      │── getpwnam("dwho") ──────▶│                         │
      │                           │── POST /pam/userinfo ──▶│
      │                           │◀── {found: true, ...} ──│
      │◀── passwd entry ──────────│                         │
      │                                                     │
      │   (SSH accepts connection because user "exists")    │
      │                                                     │
      │── PAM open_session ──────────────────────────────────
      │   (creates real /etc/passwd entry)
```

### nsswitch.conf

```
passwd: files llng
group:  files
shadow: files
```

### NSS Configuration

`/etc/nss_llng.conf`:
```ini
portal_url = https://auth.example.com
server_token_file = /etc/llng/server_token
timeout = 5
cache_ttl = 300
min_uid = 10000
max_uid = 60000
default_gid = 100
```

## Automatic Account Creation

When a user connects for the first time:

1. **NSS resolution**: `libnss_llng` queries LLNG for user info
2. **SSH accepts**: User appears to exist (virtual passwd entry)
3. **PAM session**: `pam_sm_open_session` creates real account
4. **Home directory**: Created with skel files
5. **Permissions**: Set to user's UID/GID from LLNG

### Configuration

In `/etc/security/pam_llng.conf`:
```ini
create_user = true
create_user_home_base = /home
create_user_shell = /bin/bash
create_user_skel = /etc/skel
```

In `/etc/pam.d/sshd`:
```
session required pam_llng.so
session required pam_unix.so
```

## Session Recording

All sessions through bastions are recorded:

```
/var/lib/llng-sessions/
├── dwho/
│   ├── 20251216-103000_<uuid>.cast      # Recording
│   └── 20251216-103000_<uuid>.json      # Metadata
└── rtyler/
    └── ...
```

### sshd_config

```sshd_config
Match Group *,!admin
    ForceCommand /usr/sbin/llng-session-recorder
```

See [session-recording.md](session-recording.md) for details.

## Security Model

### Defense in Depth

```
Layer 1: Network
  └── Firewall rules, VPN, network segmentation

Layer 2: Bastion
  └── LLNG authentication, session recording, audit logs

Layer 3: Authorization
  └── Server groups, per-user rules, time-based access

Layer 4: Backend
  └── LLNG authorization, minimal privileges, auto-provisioning

Layer 5: Audit
  └── Centralized logging, session replay, compliance reports
```

### Token Security

- **Short-lived**: PAM tokens expire in 5-60 minutes
- **Single-use**: Tokens invalidated after successful use
- **IP binding**: Optional token-to-IP binding
- **Rate limiting**: Exponential backoff on failures

### Server Token Security

- **Automatic rotation**: Refresh tokens rotate server credentials
- **Secure storage**: Tokens stored with 0600 permissions
- **Per-server**: Each server has unique credentials
- **Revocable**: Admin can revoke server access in LLNG

## Setup Scripts

### Bastion Setup

Use `llng-bastion-setup` to automate bastion configuration:

```bash
sudo llng-bastion-setup --portal https://auth.example.com --server-group bastion
```

This script:
- Downloads SSH CA public key from LLNG
- Configures sshd with `TrustedUserCAKeys`
- Enables session recording via `ForceCommand`
- Configures PAM for LLNG authorization
- Enrolls the server with LLNG

Options:
| Option | Description |
|--------|-------------|
| `-p, --portal URL` | LLNG portal URL (required) |
| `-g, --server-group NAME` | Server group (default: bastion) |
| `-t, --token-file FILE` | Read server token from file |
| `-k, --insecure` | Skip SSL verification |
| `-n, --dry-run` | Show what would be done |

### Backend Setup

Use `llng-backend-setup` to automate backend server configuration:

```bash
sudo llng-backend-setup --portal https://auth.example.com --server-group production
```

This script:
- Downloads SSH CA public key from LLNG
- Configures sshd for certificate authentication
- Configures PAM with automatic user creation
- Configures sudo to use LLNG authorization
- Configures NSS for user/group resolution
- Enrolls the server with LLNG

Options:
| Option | Description |
|--------|-------------|
| `-p, --portal URL` | LLNG portal URL (required) |
| `-g, --server-group NAME` | Server group (default: default) |
| `-t, --token-file FILE` | Read server token from file |
| `--no-sudo` | Don't configure sudo |
| `--no-create-user` | Disable auto user creation |
| `-k, --insecure` | Skip SSL verification |
| `-n, --dry-run` | Show what would be done |

## SSH Certificates

Users can obtain SSH certificates from LLNG using `llng-ssh-cert`:

```bash
llng-ssh-cert --portal https://auth.example.com --validity 60
```

This uses the Device Authorization Grant to authenticate and sign the user's public key.

## Deployment Checklist

### LLNG Portal

- [ ] PAM Access plugin enabled
- [ ] SSH CA enabled (`sshCaActivation`)
- [ ] Server groups configured
- [ ] Authorization rules defined
- [ ] Device authorization enabled

### Bastion Hosts

```bash
sudo llng-bastion-setup --portal https://auth.example.com
```

Or manually:
- [ ] `pam_llng.so` installed
- [ ] Server enrolled (`llng-pam-enroll`)
- [ ] PAM configured in `/etc/pam.d/sshd`
- [ ] SSH CA key configured (`TrustedUserCAKeys`)
- [ ] Session recorder configured (`ForceCommand`)
- [ ] sshd_config updated

### Backend Servers

```bash
sudo llng-backend-setup --portal https://auth.example.com -g production
```

Or manually:
- [ ] `pam_llng.so` installed
- [ ] `libnss_llng.so` installed
- [ ] Server enrolled with correct server_group
- [ ] `create_user = true` if auto-provisioning needed
- [ ] PAM, NSS, and sudo configured

## See Also

- [README.md](../README.md) - Installation and configuration
- [SECURITY.md](../SECURITY.md) - Security considerations
- [session-recording.md](session-recording.md) - Session recording details
