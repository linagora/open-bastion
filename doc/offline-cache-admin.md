# Offline Credential Cache Administration

This document describes the configuration and administration of the Open Bastion offline credential cache, which enables authentication when the central LLNG server is unavailable.

## Overview

The offline credential cache stores encrypted user credentials locally, allowing users to authenticate even when network connectivity to the authentication server is lost. This is particularly useful for:

- Laptop users who need to login while traveling
- Desktop systems in locations with unreliable network connectivity
- Emergency access when the authentication server is down

## Security

The cache uses industry-standard cryptographic primitives:

- **Password Hashing**: Argon2id with OWASP-recommended parameters
  - Memory: 64 MB
  - Iterations: 3
  - Parallelism: 4 lanes

- **Data Encryption**: AES-256-GCM
  - Key derived from machine-id using PBKDF2
  - Unique IV per encryption

- **Lockout Protection**: Configurable failed attempt limit and lockout duration

## Configuration

### Configuration File

Add the following options to `/etc/open-bastion/openbastion.conf`:

```ini
# Enable offline credential caching
offline_cache_enabled = true

# Directory for credential cache files (default: /var/cache/open-bastion/credentials)
offline_cache_dir = /var/cache/open-bastion/credentials

# Credential TTL in seconds (default: 604800 = 7 days)
offline_cache_ttl = 604800

# Maximum failed attempts before lockout (default: 5)
offline_cache_max_failures = 5

# Lockout duration in seconds (default: 300 = 5 minutes)
offline_cache_lockout = 300
```

### PAM Configuration

The offline cache can be enabled/disabled per PAM configuration:

```
# Enable offline cache
auth required pam_openbastion.so offline_cache

# Disable offline cache (explicitly)
auth required pam_openbastion.so no_offline_cache
```

### Directory Permissions

The cache directory should have restricted permissions:

```bash
mkdir -p /var/cache/open-bastion/credentials
chmod 700 /var/cache/open-bastion/credentials
chown root:root /var/cache/open-bastion/credentials
```

## Administration Tool

The `ob-cache-admin` command-line tool provides administrative functions for managing the cache.

### Installation

The tool is installed to `/usr/sbin/ob-cache-admin` with the `pam-openbastion` package.

### Commands

#### List Cached Credentials

```bash
sudo ob-cache-admin list
```

Output:
```
USER                 STATUS       CREATED              EXPIRES              LOCKOUT
----                 ------       -------              -------              -------
john.doe             valid        2024-01-15 09:30     2024-01-22 09:30     none
jane.smith           valid        2024-01-14 14:00     2024-01-21 14:00     2x
bob.wilson           expired      2024-01-01 10:00     2024-01-08 10:00     none

Total: 3 cached credential(s)
```

#### Show Statistics

```bash
sudo ob-cache-admin stats
```

Output:
```
  Offline Credential Cache Statistics
  ====================================

  Cache directory:    /var/cache/open-bastion/credentials
  Total entries:      15
  Valid entries:      12
  Expired entries:    3
  Locked accounts:    1
  Total size:         45K

  Configuration:
  --------------
  TTL:                604800 seconds (7.0 days)
  Max failures:       5
  Lockout duration:   300 seconds
```

#### Clear User Cache

Remove cached credentials for a specific user:

```bash
sudo ob-cache-admin clear-user johndoe
```

#### Unlock User

Remove lockout for a user who has been locked out due to failed attempts:

```bash
sudo ob-cache-admin unlock johndoe
```

#### Remove Expired Entries

Clean up expired credential entries:

```bash
sudo ob-cache-admin expire
```

#### Clear All Cache

Remove all cached credentials (requires confirmation):

```bash
sudo ob-cache-admin clear

# Force without confirmation
sudo ob-cache-admin clear --force
```

#### Show Configuration

Display current cache configuration:

```bash
sudo ob-cache-admin config
```

### Options

| Option | Description |
|--------|-------------|
| `-d, --cache-dir <dir>` | Override cache directory |
| `-c, --config <file>` | Override configuration file |
| `-f, --force` | Force operation without confirmation |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress non-error output |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OB_CACHE_DIR` | Override default cache directory |
| `OB_CONFIG_FILE` | Override default configuration file |

## Cache File Format

Each user's credentials are stored in a separate file:

```
/var/cache/open-bastion/credentials/
├── username1.cache    # Encrypted credential data
├── username1.lock     # Lockout state (if locked)
├── username2.cache
└── ...
```

### Cache Entry Structure

The cache file contains JSON-encoded data (encrypted):

```json
{
  "user": "johndoe",
  "hash": "<argon2id hash>",
  "salt": "<random salt>",
  "expires": 1705916400,
  "created": 1705311600,
  "gecos": "John Doe",
  "shell": "/bin/bash",
  "home": "/home/johndoe"
}
```

### Lockout File Structure

```json
{
  "failures": 3,
  "locked_until": 1705312200,
  "last_attempt": 1705311900
}
```

## Monitoring

### Log Messages

Offline authentication events are logged to syslog with the `auth` facility:

```
Jan 15 09:30:00 hostname pam_openbastion[1234]: Offline authentication successful for user johndoe
Jan 15 09:31:00 hostname pam_openbastion[1235]: Offline authentication failed for user johndoe (wrong password)
Jan 15 09:32:00 hostname pam_openbastion[1236]: User johndoe locked out after 5 failed attempts
```

### Metrics

For monitoring systems, consider tracking:

- Number of offline authentications per day
- Number of lockout events
- Cache hit/miss ratio
- Cache size growth

## Troubleshooting

### User Cannot Login Offline

1. Check if offline cache is enabled:
   ```bash
   grep offline_cache /etc/open-bastion/openbastion.conf
   ```

2. Verify user has cached credentials:
   ```bash
   sudo ob-cache-admin list | grep username
   ```

3. Check if credentials are expired:
   ```bash
   sudo ob-cache-admin stats
   ```

4. Check if user is locked out:
   ```bash
   sudo ob-cache-admin list | grep username
   sudo ob-cache-admin unlock username
   ```

### Cache Not Working

1. Verify directory exists with correct permissions:
   ```bash
   ls -la /var/cache/open-bastion/
   ```

2. Check PAM configuration includes offline_cache:
   ```bash
   grep pam_openbastion /etc/pam.d/lightdm
   ```

3. Check syslog for errors:
   ```bash
   journalctl -u lightdm | grep pam_openbastion
   ```

### Credentials Not Caching

Credentials are only cached after a successful online authentication. Ensure:

1. User has logged in successfully while online
2. The `offline_cache_enabled` option is set to `true`
3. The cache directory is writable by root

## Security Considerations

### Risk Assessment

| Risk | Mitigation |
|------|------------|
| Stolen device | Short TTL, lockout protection, full disk encryption |
| Brute force | Argon2id slow hashing, lockout after failed attempts |
| Cache tampering | File permissions (0600), root ownership |
| Key extraction | Machine-id based key, requires root access |

### Recommendations

1. **Use short TTL**: Set `offline_cache_ttl` to the minimum acceptable value (e.g., 7 days)

2. **Enable disk encryption**: Use LUKS or similar for the system drive

3. **Monitor lockouts**: Alert on repeated lockout events

4. **Regular cleanup**: Run `ob-cache-admin expire` periodically via cron

5. **Audit trail**: Review auth logs for offline authentication patterns

### Compliance Notes

- Cached credentials are hashed, not stored in plaintext
- Encryption key is derived from machine-specific data
- No credentials are transmitted or stored externally
- Cache can be cleared instantly if device is compromised
