# Desktop SSO with Open Bastion

This document describes how to configure desktop workstations to use Open Bastion
for Single Sign-On (SSO) via LightDM.

## Overview

Desktop SSO allows users to login to their Linux workstations using their
LemonLDAP::NG credentials. The authentication flow is:

1. LightDM displays the Open Bastion greeter with an embedded LLNG iframe
2. User enters their credentials in the LLNG login form
3. LLNG authenticates the user and returns an OAuth2 access token
4. The greeter passes the token to the PAM module
5. PAM validates the token via introspection and grants access

```
┌─────────────────────────────────────────────────────────────────┐
│                    LightDM Greeter                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              LLNG Portal (iframe)                         │  │
│  │                                                           │  │
│  │    ┌──────────────────────────────────┐                   │  │
│  │    │  Username: [_______________]     │                   │  │
│  │    │  Password: [_______________]     │                   │  │
│  │    │         [  Sign In  ]            │                   │  │
│  │    └──────────────────────────────────┘                   │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    OAuth2 Access Token
                              │
                              ▼
                 ┌────────────────────────┐
                 │   PAM Module           │
                 │   (oauth2_token_auth)  │
                 └────────────────────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │   LLNG /oauth2/        │
                 │   introspect           │
                 └────────────────────────┘
```

## Requirements

### Server-side (LemonLDAP::NG)

- LemonLDAP::NG 2.x with OIDC issuer enabled
- DesktopLogin plugin installed and configured
- OIDC Relying Party for desktop SSO

### Client-side (Workstation)

- Linux with LightDM display manager
- lightdm-webkit2-greeter
- Open Bastion PAM module (pam_openbastion.so)

## Installation

### Quick Setup

The `ob-desktop-setup` script automates the installation process:

```bash
sudo ob-desktop-setup -p https://auth.example.com
```

For offline mode support:

```bash
sudo ob-desktop-setup -p https://auth.example.com --offline
```

### Manual Installation

#### 1. Install LightDM and webkit2-greeter

**Debian/Ubuntu:**
```bash
apt install lightdm lightdm-webkit2-greeter
```

**Fedora:**
```bash
dnf install lightdm lightdm-webkit2-greeter
```

**Arch Linux:**
```bash
pacman -S lightdm lightdm-webkit2-greeter
```

#### 2. Install Open Bastion greeter theme

Copy the greeter files to the LightDM themes directory:

```bash
mkdir -p /usr/share/lightdm-webkit/themes/open-bastion
cp -r /usr/share/open-bastion/lightdm/greeter/* /usr/share/lightdm-webkit/themes/open-bastion/
```

Create the theme metadata file:

```bash
cat > /usr/share/lightdm-webkit/themes/open-bastion/index.theme << EOF
[theme]
name=Open Bastion
author=Linagora
version=1.0
description=Open Bastion SSO greeter for LightDM
EOF
```

#### 3. Configure LightDM

Edit `/etc/lightdm/lightdm.conf`:

```ini
[Seat:*]
greeter-session=lightdm-webkit2-greeter
```

Create or edit `/etc/lightdm/lightdm-webkit2-greeter.conf`:

```ini
[greeter]
webkit_theme = open-bastion
debug_mode = false
secure_context_localhost = true

[open-bastion]
portal_url = https://auth.example.com
desktop_login_path = /desktop/login
check_online_interval = 30000
offline_mode_enabled = false
```

#### 4. Configure PAM

Create `/etc/pam.d/lightdm`:

```
# Open Bastion OAuth2 token authentication
auth    sufficient    pam_openbastion.so oauth2_token_auth

# Fallback to standard authentication
auth    include       system-auth

# Account management
account sufficient    pam_openbastion.so
account include       system-auth

# Session management
session optional      pam_openbastion.so
session include       system-auth
```

#### 5. Configure Open Bastion

Create `/etc/open-bastion/openbastion.conf`:

```ini
portal_url = https://auth.example.com

# Enable OAuth2 token authentication
oauth2_token_auth = true
oauth2_token_min_ttl = 60

# Cache settings
cache_enabled = true
cache_ttl = 300

# Logging
log_level = warn
audit_enabled = true
```

#### 6. Enable LightDM

```bash
systemctl enable lightdm
systemctl disable gdm  # or sddm, etc.
```

## LemonLDAP::NG Configuration

### Enable DesktopLogin Plugin

Add the plugin to your LLNG configuration:

```perl
# In lemonldap-ng.ini
[portal]
plugins = DesktopLogin
```

### Configure the Desktop SSO Relying Party

In the LLNG Manager, create a new OIDC Relying Party:

1. **Client ID:** `desktop-sso`
2. **Client Type:** Public (no secret required for greeter)
3. **Redirect URIs:** `http://localhost/*`
4. **Allowed Scopes:** `openid desktop pam`

### Plugin Configuration

Set these parameters in the Manager:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `desktopLoginRp` | RP name for desktop tokens | `desktop-sso` |
| `desktopLoginTokenDuration` | Token TTL in seconds | `28800` (8 hours) |
| `desktopLoginAllowedCallbacks` | Allowed callback URLs | `["http://localhost/*"]` |

## How It Works

### Authentication Flow

1. **User Initiates Login**
   - User powers on workstation
   - LightDM starts and loads the webkit2-greeter
   - Greeter loads the Open Bastion theme

2. **Greeter Checks Connectivity**
   - Greeter attempts to reach the LLNG portal
   - If online, displays SSO mode with iframe
   - If offline, switches to offline mode (if enabled)

3. **SSO Authentication**
   - LLNG login form is displayed in iframe
   - User enters credentials
   - LLNG validates credentials and creates session
   - LLNG generates OAuth2 access token
   - Token is sent to greeter via postMessage

4. **PAM Authentication**
   - Greeter calls `lightdm.authenticate(username)`
   - LightDM prompts for password
   - Greeter responds with the OAuth2 token
   - PAM module (`pam_openbastion.so`) receives the token

5. **Token Validation**
   - PAM module introspects token via `/oauth2/introspect`
   - Validates token is active and not expired
   - Verifies `sub` claim matches username
   - Checks minimum TTL requirement

6. **Session Start**
   - PAM returns success
   - LightDM starts the user's desktop session

### Security Considerations

- **Token Minimum TTL:** Tokens expiring within `oauth2_token_min_ttl` seconds
  are rejected to prevent login with nearly-expired credentials
- **HTTPS Required:** Portal URL should use HTTPS for production
- **Iframe Security:** Only localhost callbacks are allowed by default
- **Token Scope:** Desktop tokens have limited `desktop pam` scope

## Offline Mode

When the LLNG server is unreachable, the greeter can fall back to offline
authentication using cached credentials. See [offline-mode.md](offline-mode.md)
for details.

## Troubleshooting

### Greeter Doesn't Load

1. Check LightDM configuration:
   ```bash
   lightdm --test-mode --debug
   ```

2. Verify webkit2-greeter is installed:
   ```bash
   dpkg -l | grep webkit2-greeter
   ```

3. Check theme installation:
   ```bash
   ls /usr/share/lightdm-webkit/themes/open-bastion/
   ```

### SSO Iframe Doesn't Load

1. Verify network connectivity:
   ```bash
   curl -v https://auth.example.com/desktop/login
   ```

2. Check browser console in greeter (enable debug_mode)

3. Verify CORS settings on LLNG server

### Authentication Fails

1. Check PAM configuration:
   ```bash
   cat /etc/pam.d/lightdm
   ```

2. Review PAM logs:
   ```bash
   journalctl | grep pam_openbastion
   ```

3. Verify Open Bastion configuration:
   ```bash
   cat /etc/open-bastion/openbastion.conf
   ```

4. Test token introspection manually:
   ```bash
   curl -X POST https://auth.example.com/oauth2/introspect \
     -d "token=YOUR_TOKEN" \
     -d "client_id=desktop-sso"
   ```

### Log Files

- LightDM: `/var/log/lightdm/lightdm.log`
- Greeter: `/var/log/lightdm/x-0-greeter.log`
- PAM/Open Bastion: `journalctl | grep pam_openbastion`
- Audit log: `/var/log/open-bastion/audit.json`

## See Also

- [Open Bastion Admin Guide](admin-guide.md)
- [PAM Module Configuration](../README.md#configuration)
- [Offline Mode](offline-mode.md)
- [LemonLDAP::NG Documentation](https://lemonldap-ng.org/documentation)
