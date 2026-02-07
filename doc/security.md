# Security Features

## Security Considerations

1. **Protect configuration files**: `/etc/open-bastion/openbastion.conf` and `token` should be readable only by root
2. **Use TLS**: Always use HTTPS for portal_url
3. **Server tokens**: Server tokens are automatically rotated via refresh token mechanism (`token_rotate_refresh = true` by default). If you suspect compromise, re-enroll the server with `ob-enroll`
4. **Backup access**: Keep a root password or console access as fallback

## SSH Key Policy

Open Bastion can optionally restrict which SSH key types and sizes are allowed for authentication. This is useful for enforcing security policies that require modern key types or minimum key sizes.

### Configuration

```ini
# Enable SSH key policy enforcement
ssh_key_policy_enabled = true

# Only allow Ed25519 and ECDSA keys (no RSA)
ssh_key_allowed_types = ed25519,ecdsa

# Require at least 3072-bit RSA keys (if RSA is allowed)
ssh_key_min_rsa_bits = 3072

# Require at least P-384 for ECDSA (if ECDSA is allowed)
ssh_key_min_ecdsa_bits = 384
```

### Allowed Key Types

| Type      | Description                           |
| --------- | ------------------------------------- |
| `ed25519` | Ed25519 keys (recommended, 256-bit)   |
| `ecdsa`   | ECDSA keys (P-256, P-384, P-521)      |
| `rsa`     | RSA keys (variable size)              |
| `dsa`     | DSA keys (deprecated, 1024-bit)       |
| `sk`      | FIDO2/Security keys (hardware tokens) |
| `all`     | All types except DSA                  |

### Example Policies

**Strict Modern (Ed25519 only):**

```ini
ssh_key_policy_enabled = true
ssh_key_allowed_types = ed25519
```

**FIPS-like (ECDSA P-384+ or RSA 3072+):**

```ini
ssh_key_policy_enabled = true
ssh_key_allowed_types = ecdsa,rsa
ssh_key_min_ecdsa_bits = 384
ssh_key_min_rsa_bits = 3072
```

**No RSA (modern keys only):**

```ini
ssh_key_policy_enabled = true
ssh_key_allowed_types = ed25519,ecdsa,sk
```

### Configuration Options

| Option                   | Default | Description                       |
| ------------------------ | ------- | --------------------------------- |
| `ssh_key_policy_enabled` | `false` | Enable SSH key policy enforcement |
| `ssh_key_allowed_types`  | (all)   | Comma-separated allowed types     |
| `ssh_key_min_rsa_bits`   | `2048`  | Minimum RSA key size in bits      |
| `ssh_key_min_ecdsa_bits` | `256`   | Minimum ECDSA key size in bits    |

**Note:** This feature requires `ExposeAuthInfo yes` in `sshd_config` to function.

## Cache Brute-Force Protection

When the LLNG server is unavailable, Open Bastion uses cached authorization data (offline mode). This feature adds rate limiting to cache lookups to prevent brute-force attacks against the cache.

### Configuration

```ini
# Enable cache rate limiting
cache_rate_limit_enabled = true

# Lock out after 3 failed cache lookups (default)
cache_rate_limit_max_attempts = 3

# Initial lockout: 60 seconds (uses exponential backoff)
cache_rate_limit_lockout_sec = 60

# Maximum lockout: 1 hour
cache_rate_limit_max_lockout_sec = 3600
```

### How It Works

1. When the LLNG server is unreachable, cache lookups are attempted
2. Every cache lookup attempt is counted (hits and misses) to prevent enumeration
3. After `max_attempts` attempts, the user is locked out from cache lookups
4. Lockout duration doubles on each subsequent violation (exponential backoff)
5. Only authorized cache hits reset the failure counter (prevents attackers from resetting by finding cached users)

### Configuration Options

| Option                             | Default | Description                          |
| ---------------------------------- | ------- | ------------------------------------ |
| `cache_rate_limit_enabled`         | `false` | Enable cache lookup rate limiting    |
| `cache_rate_limit_max_attempts`    | `3`     | Cache lookup attempts before lockout |
| `cache_rate_limit_lockout_sec`     | `60`    | Initial lockout duration in seconds  |
| `cache_rate_limit_max_lockout_sec` | `3600`  | Maximum lockout duration in seconds  |

## Rate Limiting

Open Bastion includes rate limiting to protect against brute-force attacks:

```ini
# Rate limiting
rate_limit_enabled = true
rate_limit_max_attempts = 5
rate_limit_initial_lockout = 30
rate_limit_max_lockout = 3600
```

After `max_attempts` failed authentication attempts, the user is locked out. The lockout duration uses exponential backoff, starting at `initial_lockout` seconds and doubling up to `max_lockout` seconds.

## Audit Logging

Structured JSON audit logging with correlation IDs:

```ini
# Audit logging
audit_enabled = true
audit_log_file = /var/log/open-bastion/audit.json
audit_to_syslog = true
audit_level = 1  # 0=critical, 1=auth events, 2=all
```

## Webhook Notifications

Get notified of security events:

```ini
# Webhook notifications
notify_enabled = true
notify_url = https://alerts.example.com/webhook
notify_secret = your-hmac-secret
```
