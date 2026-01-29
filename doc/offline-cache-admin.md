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
  - Key read from a root-only key file (`/etc/open-bastion/cache.key`)
  - Falls back to machine-id derivation if no key file is present (less secure)
  - Unique IV per encryption

- **Lockout Protection**: 5 failed attempts triggers a 5-minute lockout

## Configuration

### Configuration File

Add the following options to `/etc/open-bastion/openbastion.conf`:

```ini
# Enable offline credential caching
auth_cache_enabled = true

# Directory for credential cache files (default: /var/cache/open-bastion/credentials)
offline_cache_dir = /var/cache/open-bastion/credentials

# Credential TTL in seconds (default: 604800 = 7 days, range: 3600–2592000)
offline_cache_ttl = 604800
```

### PAM Configuration

The offline cache can be enabled/disabled per PAM service via module arguments:

```
# Enable offline cache for this PAM service
auth sufficient pam_openbastion.so oauth2_token_auth offline_cache

# Disable offline cache (explicitly)
auth sufficient pam_openbastion.so oauth2_token_auth no_offline_cache
```

Or via the configuration file with `auth_cache_enabled = true`.

### Directory Permissions

The cache directory should have restricted permissions:

```bash
mkdir -p /var/cache/open-bastion/credentials
chmod 700 /var/cache/open-bastion/credentials
chown root:root /var/cache/open-bastion/credentials
```

### Encryption Key

For maximum security, generate a dedicated key file:

```bash
dd if=/dev/urandom of=/etc/open-bastion/cache.key bs=32 count=1 status=none
chmod 600 /etc/open-bastion/cache.key
```

The `ob-desktop-setup --offline` script generates this automatically.

## Administration Tool

The `ob-cache-admin` command-line tool provides administrative functions for managing the cache. All commands require root.

### Installation

The tool is installed to `/usr/sbin/ob-cache-admin` with the `open-bastion` package.

### Commands

#### List Cached Entries

```bash
sudo ob-cache-admin list
```

Output:
```
Cached credential entries:
--------------------------
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6  2025-06-15 09:30:12  (512 bytes)
  d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1  2025-06-14 14:00:45  (498 bytes)

Total: 2 entries

Note: Filenames are SHA256 hashes of usernames.
Use 'ob-cache-admin show <username>' to check a specific user.
```

#### Show Statistics

```bash
sudo ob-cache-admin stats
```

Output:
```
Open Bastion Offline Cache Statistics
======================================

Cache directory: /var/cache/open-bastion/credentials

Total entries:   2
Valid format:    2

Disk usage:      12K

Oldest entry:    2025-06-14 14:00:45
Newest entry:    2025-06-15 09:30:12
```

#### Show User Details

Check if a specific user has cached credentials:

```bash
sudo ob-cache-admin show johndoe
```

#### Invalidate User Cache

Remove cached credentials for a specific user (uses `shred` for secure deletion):

```bash
sudo ob-cache-admin invalidate johndoe
```

#### Invalidate All

Remove all cached credentials (requires typing "yes" to confirm):

```bash
sudo ob-cache-admin invalidate-all
```

This also removes the salt file, forcing new key derivation.

#### Unlock User

Reset failed attempts for a locked user. Since cache files are encrypted, the tool cannot modify them directly and offers alternatives:

```bash
sudo ob-cache-admin unlock johndoe
```

Options presented:
1. Wait for lockout to expire (default: 5 minutes)
2. Invalidate and re-cache (user must authenticate online next time)
3. Force online auth

#### Cleanup

Remove invalid and orphaned cache files:

```bash
sudo ob-cache-admin cleanup
```

This removes files with invalid magic headers, empty files, and orphaned `.tmp` files. Expired entries are checked at runtime by the PAM module.

### Options

| Option | Description |
|--------|-------------|
| `-c, --config <file>` | Override configuration file |
| `-d, --cache-dir <dir>` | Override cache directory |
| `-q, --quiet` | Quiet mode (less output) |
| `-h, --help` | Show help message |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OB_CACHE_DIR` | Override default cache directory |
| `OB_CONFIG_FILE` | Override default configuration file |

## Cache File Format

Cache files are named by a SHA256 hash of the username and stored with a `.cred` extension:

```
/var/cache/open-bastion/credentials/
├── a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.cred
├── d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1.cred
└── .cred_salt
```

The filename hash is computed as: `SHA256("cred:<username>")` truncated to 32 hex characters.

### File Structure

Each `.cred` file has the format:

```
OBCRED01 (8-byte magic header) + AES-256-GCM encrypted JSON
```

The encrypted JSON payload contains:

```json
{
  "v": 1,
  "user": "johndoe",
  "created_at": 1750000000,
  "expires_at": 1750604800,
  "last_success": 1750000000,
  "failed_attempts": 0,
  "locked_until": 0,
  "password_hash": "<base64-encoded Argon2id hash>",
  "salt": "<base64-encoded salt>",
  "gecos": "John Doe",
  "shell": "/bin/bash",
  "home": "/home/johndoe"
}
```

Lockout state (`failed_attempts`, `locked_until`) is stored inside the encrypted entry — there are no separate lockout files.

## Monitoring

### Log Messages

Offline authentication events are logged to syslog with the `auth` facility:

```
Jun 15 09:30:00 hostname pam_openbastion[1234]: Offline authentication successful for user johndoe
Jun 15 09:31:00 hostname pam_openbastion[1235]: Offline authentication failed for johndoe: Password does not match
Jun 15 09:32:00 hostname pam_openbastion[1236]: Offline authentication failed for johndoe: Entry locked
```

### Metrics

For monitoring systems, consider tracking:

- Number of offline authentications per day
- Number of lockout events
- Cache size growth
- Expired entry cleanup frequency

## Troubleshooting

### User Cannot Login Offline

1. Check if offline cache is enabled:
   ```bash
   grep auth_cache_enabled /etc/open-bastion/openbastion.conf
   ```

2. Verify user has cached credentials:
   ```bash
   sudo ob-cache-admin show username
   ```

3. Check cache statistics:
   ```bash
   sudo ob-cache-admin stats
   ```

4. If user is locked out, wait 5 minutes or invalidate:
   ```bash
   sudo ob-cache-admin unlock username
   ```

### Cache Not Working

1. Verify directory exists with correct permissions:
   ```bash
   ls -la /var/cache/open-bastion/credentials/
   ```

2. Check PAM configuration:
   ```bash
   grep pam_openbastion /etc/pam.d/lightdm
   ```

3. Check syslog for errors:
   ```bash
   journalctl | grep pam_openbastion
   ```

### Credentials Not Caching

Credentials are only cached after a successful online authentication. Ensure:

1. User has logged in successfully while online
2. The `auth_cache_enabled` option is set to `true` in the config
3. The cache directory is writable by root
4. The key file exists (`/etc/open-bastion/cache.key`)

## Security Considerations

### Risk Assessment

| Risk | Mitigation |
|------|------------|
| Stolen device | Short TTL, lockout protection, full disk encryption |
| Brute force | Argon2id slow hashing (64 MB memory), lockout after 5 failed attempts |
| Cache tampering | File permissions (0600), root ownership, AES-256-GCM integrity |
| Key extraction | Dedicated key file (0600), requires root access |

### Recommendations

1. **Use short TTL**: Set `offline_cache_ttl` to the minimum acceptable value (default: 7 days)

2. **Enable disk encryption**: Use LUKS or similar for the system drive

3. **Generate a key file**: Use `ob-desktop-setup --offline` or create one manually (see above)

4. **Monitor lockouts**: Alert on repeated lockout events in syslog

5. **Regular cleanup**: Run `ob-cache-admin cleanup` periodically via cron

6. **Audit trail**: Review auth logs for offline authentication patterns

### Compliance Notes

- Cached credentials are hashed with Argon2id, not stored in plaintext
- Encryption key is stored in a root-only file (or derived from machine-specific data)
- No credentials are transmitted or stored externally
- Cache can be cleared instantly with `ob-cache-admin invalidate-all`
