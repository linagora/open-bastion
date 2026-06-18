# Service Accounts

Service accounts (ansible, backup, deploy, etc.) are local accounts that authenticate via SSH key
only, without OIDC authentication. They are defined in a local configuration file on each server.

## Why Service Accounts?

Some accounts don't correspond to real users and can't authenticate via OIDC:

- **Automation tools**: Ansible, Puppet, Chef
- **Backup systems**: rsync, borg, restic
- **CI/CD pipelines**: GitLab Runner, GitHub Actions
- **Monitoring agents**: Prometheus, Zabbix

These accounts need:

- SSH key authentication (no interactive login)
- Fine-grained sudo permissions
- Automatic account creation
- Full audit logging

## Configuration

Create `/etc/open-bastion/service-accounts.conf`:

```ini
# Ansible automation account
[ansible]
key_fingerprint = SHA256:abc123def456...
sudo_allowed = true
sudo_nopasswd = true
gecos = Ansible Automation
shell = /bin/bash
home = /var/lib/ansible

# Backup service account
[backup]
key_fingerprint = SHA256:xyz789...
sudo_allowed = false
gecos = Backup Service Account
shell = /bin/sh
home = /var/lib/backup
```

**Security requirements for this file:**

- Owned by root (uid 0)
- Permissions 0600
- Not a symlink

**SSH server requirement:**
The SSH server must have `ExposeAuthInfo yes` in `/etc/ssh/sshd_config` for fingerprint
validation to work. This allows the PAM module to verify that the SSH key used matches
the configured fingerprint. See also [SSH Key Policy](security.md#ssh-key-policy) for
restricting allowed key types.

```bash
# /etc/ssh/sshd_config
ExposeAuthInfo yes
```

**Mode E compatibility:**
In Mode E deployments (`AuthorizedKeysFile none`), service accounts still work correctly.
Although there is no `authorized_keys` file lookup, authentication succeeds via a different
path: the SSH client presents its key, sshd exposes the key fingerprint through
`SSH_USER_AUTH` (enabled by `ExposeAuthInfo yes`), and the PAM module validates that
fingerprint against `service-accounts.conf`. No `authorized_keys` file is required.

Get the SSH key fingerprint:

```bash
ssh-keygen -lf /path/to/key.pub
# Output: 256 SHA256:abc123def456 user@host (ED25519)
# Use the "SHA256:abc123def456" part
```

## Configuration Options

| Option            | Required | Description                                        |
| ----------------- | -------- | -------------------------------------------------- |
| `key_fingerprint` | Yes      | SSH key fingerprint (SHA256:... or MD5:...)        |
| `sudo_allowed`    | No       | Allow sudo access (default: false)                 |
| `sudo_nopasswd`   | No       | Sudo without password (default: false)             |
| `gecos`           | No       | User description                                   |
| `shell`           | No       | Login shell (must be in approved_shells)           |
| `home`            | No       | Home directory (must match approved_home_prefixes) |
| `uid`             | No       | Fixed UID (0 = auto-assign)                        |
| `gid`             | No       | Fixed GID (0 = auto-assign)                        |

## How It Works

1. Service account connects via SSH with its configured key
2. PAM module extracts the SSH key fingerprint from `SSH_USER_AUTH` environment
3. PAM module checks if user is in `service-accounts.conf`
4. If found, the SSH key fingerprint is validated against the configured value
5. If fingerprint matches, account is authorized locally (no LLNG call needed)
6. Account is created automatically if it doesn't exist
7. sudo permissions are enforced based on configuration

## Generating with ob-builder

Instead of hand-writing `service-accounts.conf` on each server, you can declare
service accounts once in [`ob-builder`](../admin-builder/README.md) and have them
baked into the generated shell installer and/or Ansible role.

**Interactive:** the questionnaire asks whether to define service accounts and
loops over name / fingerprint / sudo / shell / home for each.

**Non-interactive (`--config`):** add a `service_accounts:` list to the YAML:

```yaml
service_accounts:
  - name: ansible
    key_fingerprint: "SHA256:abc123def456..."
    sudo_allowed: true
    sudo_nopasswd: true
    shell: /bin/bash
    home: /var/lib/ansible
    gecos: Ansible Automation
  - name: backup
    key_fingerprint: "SHA256:xyz789..."
    sudo_allowed: false
    shell: /bin/sh
```

ob-builder validates each entry (name, fingerprint format, absolute shell/home
paths) at build time, then:

- the **shell installer** writes `/etc/open-bastion/service-accounts.conf`
  (`0600 root:root`) and sets `service_accounts_file` in `openbastion.conf`;
- the **Ansible role** carries the accounts as `ob_service_accounts_content`
  (overridable per host/group via `host_vars` / `group_vars` to vary which
  accounts reach which servers) and deploys the file when
  `ob_service_accounts_enabled` is true.

Service accounts apply to every role (bastion, backend, standalone).

## Per-Server Control

Since the configuration file is local to each server, you control which service accounts
can access which servers:

- Server `web01` has `[ansible]` and `[backup]` → both can connect
- Server `db01` has only `[backup]` → only backup can connect
- Server `dev01` has no service accounts → none can connect

Use configuration management (Ansible, Puppet) to deploy the appropriate configuration
to each server.

## Specifying the Configuration File

In `/etc/open-bastion/openbastion.conf`:

```ini
service_accounts_file = /etc/open-bastion/service-accounts.conf
```

## See Also

- [Configuration Reference](configuration.md) - All configuration options
- [PAM Authentication Modes](pam-modes.md) - PAM configurations
- [Security Features](security.md) - SSH key policies
