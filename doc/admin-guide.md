# Administrator Guide

This guide explains how to configure Linux servers to authenticate
and authorize users via LemonLDAP::NG.

## Server Types

There are three typical deployment scenarios:

| Type | Description | Use Case |
|------|-------------|----------|
| **Standalone** | Single server with direct LLNG auth | Web servers, databases, isolated systems |
| **Bastion** | Jump host with session recording | Entry point for all SSH access |
| **Backend** | Internal server behind bastion | Production servers, accessed via ProxyJump |

## Prerequisites

### On All Servers

1. Install the PAM module package
2. Network access to LLNG portal (HTTPS)
3. Root access for configuration

### On LLNG Portal

1. PAM Access plugin enabled
2. Server groups configured (if using)
3. OIDC client for PAM (`pam-access`)

---

## Standalone Server Configuration

A standalone server authenticates users directly with LLNG, without
going through a bastion.

```
User ──── SSH ────▶ Standalone Server ────▶ LLNG Portal
```

### Step 1: Install Packages

```bash
# Debian/Ubuntu
apt-get install pam-llng libnss-llng

# RHEL/Rocky
dnf install pam-llng nss-llng
```

### Step 2: Create Configuration

```bash
cat > /etc/security/pam_llng.conf << 'EOF'
# LLNG Portal URL
portal_url = https://auth.example.com

# OIDC client credentials
client_id = pam-access
client_secret = your-client-secret

# Server group (must match LLNG configuration)
server_group = standalone

# Token file (created by enrollment)
server_token_file = /etc/security/pam_llng.token

# Security settings
verify_ssl = true
timeout = 10

# Logging
log_level = warn
audit_enabled = true
audit_to_syslog = true

# Rate limiting
rate_limit_enabled = true
rate_limit_max_attempts = 5
EOF

chmod 600 /etc/security/pam_llng.conf
```

### Step 3: Enroll Server

```bash
llng-pam-enroll -g standalone
```

Follow the instructions to approve the server in LLNG.

### Step 4: Configure PAM

```bash
cat > /etc/pam.d/sshd << 'EOF'
# Authentication: LLNG token or Unix password
auth       sufficient   pam_llng.so
auth       sufficient   pam_unix.so nullok try_first_pass
auth       required     pam_deny.so

# Authorization: LLNG checks access
account    required     pam_llng.so
account    required     pam_unix.so

# Session
session    required     pam_unix.so
EOF
```

### Step 5: Configure SSH

```bash
cat >> /etc/ssh/sshd_config << 'EOF'

# LLNG PAM Authentication
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
EOF

systemctl restart sshd
```

### Step 6: Test

```bash
# From another terminal (keep current session open!)
ssh user@server
# Enter LLNG token as password
```

---

## Bastion Configuration

A bastion is a hardened jump host that:
- Authenticates all users via LLNG
- Records all SSH sessions
- Proxies connections to backend servers

```
User ──── SSH ────▶ Bastion ──── SSH ────▶ Backend Servers
                       │
                       ▼
              Session Recording
```

### Step 1: Install Packages

```bash
# Debian/Ubuntu
apt-get install pam-llng libnss-llng uuid-runtime jq

# RHEL/Rocky
dnf install pam-llng nss-llng util-linux jq
```

### Step 2: Create Configuration

```bash
cat > /etc/security/pam_llng.conf << 'EOF'
# LLNG Portal URL
portal_url = https://auth.example.com

# OIDC client credentials
client_id = pam-access
client_secret = your-client-secret

# Server group for bastions
server_group = bastion

# Token file
server_token_file = /etc/security/pam_llng.token

# Security settings (stricter for bastion)
verify_ssl = true
timeout = 10

# Logging (verbose for audit)
log_level = info
audit_enabled = true
audit_log_file = /var/log/pam_llng/audit.json
audit_to_syslog = true
audit_level = 2

# Rate limiting (stricter for bastion)
rate_limit_enabled = true
rate_limit_max_attempts = 3
rate_limit_initial_lockout = 60
EOF

chmod 600 /etc/security/pam_llng.conf
```

### Step 3: Configure Session Recording

```bash
mkdir -p /etc/llng
cat > /etc/llng/session-recorder.conf << 'EOF'
# Session recordings directory
sessions_dir = /var/lib/llng-sessions

# Recording format (script is default, always available)
# Use asciinema for web replay if installed
format = script

# Max session duration (8 hours)
max_duration = 28800
EOF

# Create sessions directory
mkdir -p /var/lib/llng-sessions
chmod 700 /var/lib/llng-sessions
```

### Step 4: Enroll Server

```bash
llng-pam-enroll -g bastion
```

### Step 5: Configure PAM

```bash
cat > /etc/pam.d/sshd << 'EOF'
# Authentication: LLNG only (no Unix passwords on bastion)
auth       sufficient   pam_llng.so
auth       required     pam_deny.so

# Authorization: LLNG required
account    required     pam_llng.so
account    required     pam_unix.so

# Session
session    required     pam_unix.so
EOF
```

### Step 6: Configure SSH with Recording

```bash
cat > /etc/ssh/sshd_config.d/llng-bastion.conf << 'EOF'
# LLNG PAM Authentication
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes

# Session recording for all users except emergency admin
Match User *,!root,!admin
    ForceCommand /usr/sbin/llng-session-recorder

# Emergency admin access (no recording, direct shell)
Match User admin
    ForceCommand none
EOF

systemctl restart sshd
```

### Step 7: Configure Log Rotation

```bash
cat > /etc/logrotate.d/llng-sessions << 'EOF'
/var/lib/llng-sessions/*/*.cast
/var/lib/llng-sessions/*/*.json {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF
```

### Step 8: Test

```bash
# Connect to bastion
ssh user@bastion

# Verify recording was created
ls -la /var/lib/llng-sessions/$USER/

# Jump to backend
ssh backend-server
```

---

## Backend Server Configuration

Backend servers are internal servers accessed through the bastion.
They auto-create Unix accounts for LLNG users.

```
Bastion ──── SSH ────▶ Backend Server
                            │
                            ▼
                    Auto-create account
```

### Step 1: Install Packages

```bash
# Debian/Ubuntu
apt-get install pam-llng libnss-llng

# RHEL/Rocky
dnf install pam-llng nss-llng
```

### Step 2: Create PAM Configuration

```bash
cat > /etc/security/pam_llng.conf << 'EOF'
# LLNG Portal URL
portal_url = https://auth.example.com

# OIDC client credentials
client_id = pam-access
client_secret = your-client-secret

# Server group (production, staging, dev, etc.)
server_group = production

# Token file
server_token_file = /etc/security/pam_llng.token

# Security settings
verify_ssl = true
timeout = 10

# User creation settings
create_user = true
create_user_home_base = /home
create_user_shell = /bin/bash
create_user_skel = /etc/skel

# Logging
log_level = warn
audit_enabled = true
audit_to_syslog = true
EOF

chmod 600 /etc/security/pam_llng.conf
```

### Step 3: Create NSS Configuration

```bash
cat > /etc/nss_llng.conf << 'EOF'
# LLNG Portal URL
portal_url = https://auth.example.com

# Server token (same as PAM)
server_token_file = /etc/security/pam_llng.token

# Timeouts
timeout = 5

# Cache settings (reduce LLNG queries)
cache_ttl = 300

# UID/GID allocation range
min_uid = 10000
max_uid = 60000
default_gid = 100
EOF

chmod 644 /etc/nss_llng.conf
```

### Step 4: Configure NSS

```bash
# Edit /etc/nsswitch.conf
# Change:
#   passwd: files
# To:
#   passwd: files llng

sed -i 's/^passwd:.*/passwd: files llng/' /etc/nsswitch.conf
```

### Step 5: Enroll Server

```bash
llng-pam-enroll -g production
```

### Step 6: Configure PAM

```bash
cat > /etc/pam.d/sshd << 'EOF'
# Authentication: Accept from bastion (SSH keys)
auth       required     pam_permit.so

# Authorization: LLNG required
account    required     pam_llng.so
account    required     pam_unix.so

# Session: Create user if needed
session    required     pam_llng.so
session    required     pam_unix.so
EOF
```

### Step 7: Configure SSH

```bash
cat > /etc/ssh/sshd_config.d/llng-backend.conf << 'EOF'
# PAM required for authorization and user creation
UsePAM yes

# SSH key authentication only (via bastion)
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes

# Accept connections from bastion only
# (combine with firewall rules)
EOF

systemctl restart sshd
```

### Step 8: Firewall (Optional but Recommended)

```bash
# Allow SSH only from bastion
ufw allow from bastion-ip to any port 22
ufw deny 22
ufw enable
```

### Step 9: Test

```bash
# From bastion, connect to backend
ssh backend-server

# Verify user was created
grep $USER /etc/passwd

# Verify home directory
ls -la /home/$USER
```

---

## Server Groups Reference

Configure server groups in LLNG Manager:

```
General Parameters > Plugins > PAM Access > Server Groups
```

Example configuration:

| Server Group | Rule | Description |
|--------------|------|-------------|
| `bastion` | `$hGroup->{employees}` | All employees can access bastions |
| `production` | `$hGroup->{sre} or $hGroup->{oncall}` | Only SRE and on-call can access prod |
| `staging` | `$hGroup->{sre} or $hGroup->{dev}` | SRE and developers |
| `development` | `$hGroup->{dev}` | Only developers |
| `database` | `$hGroup->{dba}` | Only DBAs |
| `default` | `0` | Deny by default |

## Troubleshooting

### Server Enrollment Issues

```bash
# Check token file exists
ls -la /etc/security/pam_llng.token

# Re-enroll if needed
rm /etc/security/pam_llng.token
llng-pam-enroll -g <server_group>
```

### Authentication Failures

```bash
# Check PAM logs
journalctl -u sshd | grep pam_llng

# Enable debug mode
# In /etc/security/pam_llng.conf:
log_level = debug

# Test token introspection
curl -X POST https://auth.example.com/oauth2/introspect \
  -u "pam-access:secret" \
  -d "token=<user_token>"
```

### NSS Issues

```bash
# Test NSS resolution
getent passwd username

# Check NSS configuration
grep passwd /etc/nsswitch.conf

# Check NSS logs
journalctl | grep nss_llng
```

### User Creation Issues

```bash
# Check if create_user is enabled
grep create_user /etc/security/pam_llng.conf

# Check PAM session configuration
grep session /etc/pam.d/sshd

# Manually check user creation
grep username /etc/passwd
ls -la /home/username
```

## Quick Reference

### File Locations

| File | Purpose |
|------|---------|
| `/etc/security/pam_llng.conf` | PAM module configuration |
| `/etc/security/pam_llng.token` | Server enrollment token |
| `/etc/nss_llng.conf` | NSS module configuration |
| `/etc/llng/session-recorder.conf` | Session recorder configuration |
| `/var/lib/llng-sessions/` | Session recordings |
| `/var/log/pam_llng/audit.json` | Audit log |

### Commands

| Command | Purpose |
|---------|---------|
| `llng-pam-enroll` | Enroll server with LLNG |
| `llng-pam-enroll -g GROUP` | Enroll with specific server group |
| `llng-session-recorder` | Record SSH session (ForceCommand) |

## See Also

- [bastion-architecture.md](bastion-architecture.md) - Architecture overview
- [session-recording.md](session-recording.md) - Session recording details
- [../README.md](../README.md) - Installation and quick start
- [../SECURITY.md](../SECURITY.md) - Security considerations
