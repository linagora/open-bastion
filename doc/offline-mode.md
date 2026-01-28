# Offline Mode for Desktop SSO

This document describes the offline authentication feature for Desktop SSO,
which allows users to login when the LemonLDAP::NG server is unreachable.

## Overview

When the LLNG portal is unavailable (network outage, server maintenance, etc.),
users can still authenticate using cached credentials from their last successful
online authentication.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Normal Operation (Online)                     │
│                                                                  │
│   User ──► Greeter ──► LLNG Portal ──► OAuth2 Token ──► PAM    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Offline Operation                             │
│                                                                  │
│   User ──► Greeter ──► [LLNG unreachable] ──► Cached Creds     │
│               │                                      │           │
│               └──► Offline Form ──► PAM ──► Argon2id Verify    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## How It Works

### Credential Caching

After each successful online authentication, the PAM module caches the user's
credentials securely:

1. **Password hashing**: The password is hashed using Argon2id with strong parameters
2. **Encryption**: The cached data is encrypted with AES-256-GCM
3. **Machine binding**: The encryption key is derived from `/etc/machine-id`
4. **User attributes**: GECOS, shell, and home directory are also cached

### Offline Authentication Flow

1. User attempts to login via LightDM greeter
2. Greeter detects that LLNG portal is unreachable
3. Greeter automatically switches to offline mode (or user manually switches)
4. User enters username and password in the offline form
5. PAM module receives the password and checks the offline cache
6. If credentials match, user is authenticated with cached attributes

## Configuration

### Enable Offline Mode

In `/etc/open-bastion/openbastion.conf`:

```ini
# Enable offline credential caching
offline_cache_enabled = true

# Cache directory (must be secure, root-owned)
offline_cache_dir = /var/cache/open-bastion/credentials

# How long cached credentials remain valid (default: 7 days)
offline_cache_ttl = 604800

# Maximum failed attempts before lockout (default: 5)
offline_cache_max_failures = 5

# Lockout duration in seconds (default: 300 = 5 minutes)
offline_cache_lockout = 300
```

### Enable OAuth2 Token Mode (Required for Desktop SSO)

```ini
# Accept OAuth2 tokens as passwords (required for greeter)
oauth2_token_auth = true

# Cache successful OAuth2 auth for offline mode
oauth2_token_cache = true

# Minimum token TTL for acceptance (prevents near-expiry tokens)
oauth2_token_min_ttl = 60
```

### Greeter Configuration

In `/etc/lightdm/lightdm-webkit2-greeter.conf`:

```ini
[open-bastion]
portal_url = https://auth.example.com
offline_mode_enabled = true
offline_cache_ttl = 604800
```

## Security Architecture

### Argon2id Parameters

The offline cache uses OWASP-recommended Argon2id parameters:

| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 64 MiB | Memory cost (prevents GPU attacks) |
| Iterations | 3 | Time cost |
| Parallelism | 4 | Degree of parallelism |
| Hash length | 32 bytes | Output hash size |
| Salt length | 16 bytes | Random per-user salt |

### AES-256-GCM Encryption

All cached data is encrypted:

| Component | Description |
|-----------|-------------|
| Algorithm | AES-256-GCM (authenticated encryption) |
| Key derivation | PBKDF2-SHA256 from machine-id |
| IV | 12 bytes, random per write |
| Authentication tag | 16 bytes (prevents tampering) |

### Machine Binding

The encryption key is derived from:

1. `/etc/machine-id` (unique per system)
2. A random salt stored in the cache directory
3. PBKDF2 with 100,000 iterations

This means:
- Cached credentials only work on the same machine
- Copying cache files to another machine is useless
- If machine-id changes, all cached credentials become invalid

### Brute Force Protection

| Feature | Description |
|---------|-------------|
| Per-user lockout | After 5 failed attempts, entry is locked |
| Lockout duration | 5 minutes by default |
| Failure tracking | Stored encrypted in cache file |
| Reset on success | Failures reset after successful online auth |

## Cache File Format

Cache files are stored in `$offline_cache_dir/<username_hash>.cred`:

```
[Magic: OBCRED01][Encrypted JSON]
```

The encrypted JSON contains:

```json
{
  "v": 1,
  "user": "username",
  "password_hash": "<base64 argon2id hash>",
  "salt": "<base64 salt>",
  "created_at": 1234567890,
  "expires_at": 1235172690,
  "last_success": 1234567890,
  "failed_attempts": 0,
  "locked_until": 0,
  "gecos": "User Name",
  "shell": "/bin/bash",
  "home": "/home/username"
}
```

## Administration

### Cache Management Script

Use `ob-cache-admin` to manage the offline credential cache:

```bash
# Show cache statistics
sudo ob-cache-admin stats

# List all cached users
sudo ob-cache-admin list

# Show details for a specific user
sudo ob-cache-admin show username

# Invalidate a user's cached credentials
sudo ob-cache-admin invalidate username

# Invalidate all cached credentials (emergency flush)
sudo ob-cache-admin invalidate-all

# Reset failed attempts for a locked user
sudo ob-cache-admin unlock username

# Clean up expired entries
sudo ob-cache-admin cleanup
```

### Manual Cache Inspection

```bash
# Cache directory
ls -la /var/cache/open-bastion/credentials/

# Cache files are encrypted, but you can see metadata
stat /var/cache/open-bastion/credentials/*.cred
```

### Forcing Online Authentication

Create a trigger file to force online authentication even when cached
credentials exist:

```bash
# Create force-online trigger
sudo touch /etc/open-bastion/force_online

# Remove to allow offline auth again
sudo rm /etc/open-bastion/force_online
```

Configure in `openbastion.conf`:

```ini
auth_cache_force_online = /etc/open-bastion/force_online
```

## Troubleshooting

### User Cannot Login Offline

1. **Check if offline mode is enabled**:
   ```bash
   grep offline_cache_enabled /etc/open-bastion/openbastion.conf
   ```

2. **Verify cached credentials exist**:
   ```bash
   sudo ob-cache-admin show username
   ```

3. **Check if entry is expired or locked**:
   ```bash
   sudo ob-cache-admin show username | grep -E "expires_at|locked_until"
   ```

4. **Check PAM logs**:
   ```bash
   journalctl | grep pam_openbastion | grep offline
   ```

### Cache Not Being Created

1. **Verify OAuth2 token caching is enabled**:
   ```ini
   oauth2_token_auth = true
   oauth2_token_cache = true
   offline_cache_enabled = true
   ```

2. **Check cache directory permissions**:
   ```bash
   ls -la /var/cache/open-bastion/credentials/
   # Should be: drwx------ root root
   ```

3. **Verify machine-id exists**:
   ```bash
   cat /etc/machine-id
   ```

### Locked Out User

```bash
# Check lock status
sudo ob-cache-admin show username

# Unlock the user
sudo ob-cache-admin unlock username
```

### All Cached Credentials Invalid

This happens when `/etc/machine-id` changes (VM cloning, reinstall):

```bash
# Option 1: Clear all cache and let users re-authenticate online
sudo ob-cache-admin invalidate-all

# Option 2: Regenerate machine-id and clear cache
sudo rm /etc/machine-id
sudo systemd-machine-id-setup
sudo ob-cache-admin invalidate-all
```

## Security Considerations

### When to Use Offline Mode

**Recommended scenarios:**
- Corporate workstations with occasional network issues
- Laptops that may be used in areas with poor connectivity
- Business continuity during LLNG server maintenance

**Not recommended for:**
- High-security environments where real-time authorization is required
- Shared workstations in public areas
- Systems where immediate access revocation is critical

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Stale credentials | Configure short `offline_cache_ttl` |
| Unauthorized access after termination | Flush cache immediately via `ob-cache-admin invalidate username` |
| Cache file theft | Files are encrypted with machine-bound key |
| Brute force attacks | Per-user lockout after failed attempts |
| Password changes | New password cached after next online auth |

### Emergency Procedures

**Immediate access revocation:**

```bash
# On the workstation
sudo ob-cache-admin invalidate username

# Force online-only authentication
sudo touch /etc/open-bastion/force_online
```

**Complete cache flush:**

```bash
# Remove all cached credentials
sudo ob-cache-admin invalidate-all

# Or manually
sudo rm -rf /var/cache/open-bastion/credentials/*.cred
```

## See Also

- [Desktop SSO Guide](desktop-sso.md)
- [Security Architecture](../SECURITY.md)
- [PAM Module Configuration](../README.md#configuration)
