---
title: PAM Module for LemonLDAP::NG
author: Linagora
---

# PAM Module for LemonLDAP::NG

## Secure Linux Authentication with SSO

![](linagora.png)

Authenticate and authorize Linux users via **LemonLDAP::NG** for:

- SSH connections
- Other PAM services

<!-- end_slide -->

# Two Components

## 1. Server-side (LLNG)

Portal plugins and endpoints

## 2. Client-side (Linux)

C PAM module (`pam_llng.so`)

<!-- end_slide -->

# Key Security Feature

## One-Time Tokens (PAMTOKEN)

<!-- pause -->

- User tokens are **single-use**

<!-- pause -->

- Destroyed after first use

<!-- pause -->

- **Prevents replay attacks**

<!-- pause -->

- Even if intercepted, tokens cannot be reused

```
Token generated → Used once → Destroyed
                              ↓
                    Replay attempt → DENIED
```

<!-- end_slide -->

# Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                        User                             │
│  1. Login to LLNG portal                                │
│  2. Generate temporary token ("PAM Access" tab)         │
│  3. Use token as SSH password                           │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│               LemonLDAP::NG Portal                      │
│  Endpoints: /pam/verify, /pam/authorize, /pam/userinfo  │
│  Plugins: PamAccess.pm, OIDCDeviceFlow.pm               │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│               Linux Server (PAM Client)                 │
│  /lib/security/pam_llng.so  - PAM module                │
│  /lib/*/libnss_llng.so.2    - NSS module                │
│  /etc/security/pam_llng.*   - Configuration             │
└─────────────────────────────────────────────────────────┘
```

<!-- end_slide -->

# LLNG Portal Endpoints

| Endpoint              | Purpose                           |
| --------------------- | --------------------------------- |
| `GET/POST /pam`       | User interface (token generation) |
| `POST /pam/verify`    | One-time token validation         |
| `POST /pam/authorize` | Authorization check               |
| `POST /pam/userinfo`  | User info for NSS                 |
| `POST /pam/heartbeat` | Server heartbeat                  |
| `POST /oauth2/device` | Device Authorization Grant        |
| `POST /oauth2/token`  | Token exchange                    |

<!-- end_slide -->

# Server Enrollment (RFC 8628)

## Device Authorization Grant

One-time setup per Linux server:

```bash
sudo llng-pam-enroll
```

<!-- pause -->

## Enrollment Flow

1. Script contacts `/oauth2/device`
2. Displays user code (e.g., `ABCD-EFGH`)
3. Admin approves on LLNG portal
4. Script receives `access_token` + `refresh_token`
5. Tokens saved to `/etc/security/pam_llng.token`

<!-- end_slide -->

# Authentication Flow

## Token-Based SSH Login

```
User                    Linux Server                LLNG
 │                           │                        │
 │  1. ssh user@server       │                        │
 │──────────────────────────>│                        │
 │                           │                        │
 │  2. Password: <token>     │                        │
 │──────────────────────────>│                        │
 │                           │  3. POST /pam/verify   │
 │                           │──────────────────────> │
 │                           │                        │
 │                           │  4. {valid, user, grp} │
 │                           │     TOKEN DESTROYED    │
 │                           │<───────────────────────│
 │                           │                        │
 │  5. Connection OK         │                        │
 │<──────────────────────────│                        │
```

<!-- end_slide -->

# SSH Key Authentication

## Authorization-Only Mode

When using SSH keys, PAM only checks authorization:

```
User                    Linux Server                LLNG
 │                           │                        │
 │  1. ssh -i key user@srv   │                        │
 │──────────────────────────>│                        │
 │                           │                        │
 │  2. SSH key validated     │                        │
 │                           │                        │
 │                           │ 3. POST /pam/authorize │
 │                           │──────────────────────> │
 │                           │                        │
 │                           │ 4. {authorized: bool}  │
 │                           │<───────────────────────│
 │                           │                        │
 │  5. Access granted/denied │                        │
 │<──────────────────────────│                        │
```

<!-- end_slide -->

# NSS Module: libnss_llng

## The Problem

SSH checks if user exists in `/etc/passwd` **BEFORE** calling PAM

<!-- pause -->

## The Solution

`libnss_llng` queries LLNG for unknown users

```bash
# /etc/nsswitch.conf
passwd:         files llng
```

<!-- pause -->

## Flow

1. SSH calls `getpwnam("dwho")`
2. NSS checks `/etc/passwd` → not found
3. NSS calls `libnss_llng` → queries `/pam/userinfo`
4. LLNG returns user attributes
5. SSH continues with PAM authentication

<!-- end_slide -->

# Automatic User Creation

## First Login Provisioning

PAM can automatically create Unix accounts on first connection

<!-- pause -->

## Configuration

```ini
# /etc/security/pam_llng.conf
create_user = true
create_user_shell = /bin/bash
create_user_groups = users,docker
create_user_home_base = /home
create_user_skel = /etc/skel
```

<!-- pause -->

## LLNG Exported Attributes

```
pamAccessExportedVars:
  gecos => cn
  shell => loginShell
  home  => homeDirectory
```

<!-- end_slide -->

# Heartbeat Monitoring

## Server Registration & Health Checks

```bash
sudo systemctl enable --now pam-llng-heartbeat.timer
```

<!-- pause -->

## Benefits

- Detect "ghost" servers (uninstalled PAM modules)
- Maintain active server registry
- Collect usage statistics
- Detect stolen tokens (rotation)

<!-- pause -->

## Heartbeat Payload

```json
{
  "hostname": "server.example.com",
  "server_group": "production",
  "version": "0.1.0",
  "stats": { "auth_success": 42 }
}
```

<!-- end_slide -->

# Server Groups & Authorization

## LLNG Manager Configuration

```perl
# Server Groups → Access Rules
production => $hGroup->{ops}
staging    => $hGroup->{ops} or $hGroup->{dev}
dev        => $hGroup->{dev}
default    => 1
```

<!-- pause -->

## Per-Server Configuration

```ini
# /etc/security/pam_llng.conf
server_group = production
```

<!-- pause -->

Only members of `ops` group can access production servers!

<!-- end_slide -->

# Security Features

## PAM Module Security

- **AES-256-GCM** encryption for secrets
- **Rate limiting** with exponential backoff
- **JSON audit logging**
- **Token binding** (IP, fingerprint)
- **Webhook notifications** for security events

<!-- pause -->

## Communications

- HTTPS mandatory
- SSL verification enabled by default
- Short-lived access tokens (1h)
- Long-lived refresh tokens with rotation

<!-- end_slide -->

# Token Rotation

## Detecting Token Theft

Refresh token rotation is enabled via:

```
oidcRPMetaDataOptionsRefreshTokenRotation = 1
```

<!-- pause -->

## How It Works

1. New refresh token generated on each renewal
2. Old refresh token invalidated
3. All `_pam*` metadata automatically copied

<!-- pause -->

## Theft Detection

If attacker uses stolen token:

→ Legitimate server's token becomes invalid

→ Attack detected!

<!-- end_slide -->

# PAM Configuration Modes

## Mode A: LLNG Token Only

```
auth       sufficient   pam_llng.so
auth       required     pam_deny.so
account    required     pam_llng.so
```

<!-- pause -->

## Mode B: LLNG Token OR Unix Password

```
auth       sufficient   pam_llng.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so
```

<!-- pause -->

## Mode C: SSH Key + LLNG Authorization

```
auth       required     pam_permit.so
account    required     pam_llng.so
```

<!-- end_slide -->

# Installation

## Debian/Ubuntu

```bash
sudo apt install libpam-llng
```

## From Source

```bash
cd llng-pam-module
mkdir build && cd build
cmake ..
make
sudo make install
```

<!-- end_slide -->

# Quick Setup

## 1. Configure

```bash
vim /etc/security/pam_llng.conf
```

<!-- pause -->

## 2. Enroll

```bash
sudo llng-pam-enroll
```

<!-- pause -->

## 3. Configure PAM

```bash
vim /etc/pam.d/sshd
```

<!-- pause -->

## 4. Enable heartbeat

```bash
sudo systemctl enable --now pam-llng-heartbeat.timer
```

<!-- end_slide -->

# Troubleshooting

## Logs

```bash
# System logs
sudo tail -f /var/log/auth.log

# PAM audit logs
sudo tail -f /var/log/pam_llng/audit.json

# Journalctl
sudo journalctl -u sshd -f
```

<!-- pause -->

## Debug Mode

```ini
# /etc/security/pam_llng.conf
log_level = debug
```

<!-- pause -->

## Re-enrollment

```bash
sudo rm /etc/security/pam_llng.token
sudo llng-pam-enroll
```

<!-- end_slide -->

# Summary

## Key Benefits

- **Single Sign-On** for Linux servers
- **One-time tokens** prevent replay attacks
- **Centralized authorization** via LLNG
- **Automatic provisioning** of Unix accounts
- **Token rotation** detects theft
- **Heartbeat monitoring** tracks server fleet

<!-- pause -->

## Components

| Component            | Function                           |
| -------------------- | ---------------------------------- |
| `pam_llng.so`        | PAM authentication & authorization |
| `libnss_llng.so`     | User resolution before PAM         |
| `llng-pam-enroll`    | Server enrollment                  |
| `llng-pam-heartbeat` | Server monitoring                  |

<!-- end_slide -->

<!-- jump_to_middle -->

# Thank You!

![](linagora.png)

## References

- RFC 8628 - Device Authorization Grant
- https://lemonldap-ng.org
- https://github.com/linagora
