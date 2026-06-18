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

> **⚠️ `home` and `shell` must be within the approved lists, or the account is
> silently dropped.** `pam_openbastion` validates each account at load and
> **discards** any whose `home` is not under `approved_home_prefixes` (default
> `/home:/var/home`) or whose `shell` is not in `approved_shells` (default:
> `/bin/bash`, `/bin/sh`, `/bin/zsh`, `/bin/dash`, `/bin/fish` and their
> `/usr/bin` variants). A dropped account is not recognized as a service account,
> so its login falls through to LLNG and is refused with "user not found". The
> `/var/lib/...` homes above therefore require widening the prefix list:
>
> ```ini
> # /etc/open-bastion/openbastion.conf
> approved_home_prefixes = /home:/var/home:/var/lib
> ```
>
> Either keep service-account homes under `/home` (works out of the box) or set
> `approved_home_prefixes` accordingly.

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
| `shell`           | No       | Login shell — must be in `approved_shells` (default: common shells) or the account is dropped |
| `home`            | No       | Home directory — must be under `approved_home_prefixes` (default `/home:/var/home`) or the account is dropped |
| `uid`             | See note | Fixed UID. **Required (with `gid`) for SSH-reachable accounts** — NSS resolves them only when both are set; `0` = auto-assign (works only if the account already exists locally) |
| `gid`             | See note | Fixed GID. See `uid` |

## How It Works

1. Service account connects via SSH with its configured key
2. PAM module extracts the SSH key fingerprint from `SSH_USER_AUTH` environment
3. PAM module checks if user is in `service-accounts.conf`
4. If found, the SSH key fingerprint is validated against the configured value
5. If fingerprint matches, account is authorized locally (no LLNG call needed)
6. Account is created automatically if it doesn't exist
7. sudo permissions are enforced based on configuration

> **Do not reuse an existing system username.** `shell`, `home`, `uid` and `gid`
> are applied only when the account is **created**. If the name already exists
> (e.g. the Debian system users `backup`, `www-data`, `nobody`), the existing
> account is used as-is — typically with `/usr/sbin/nologin`, which breaks the
> login ("This account is currently not available."). Pick a dedicated name such
> as `obdeploy`, `obbackup` or `ci-runner`.

## Generating with ob-builder

Instead of hand-writing `service-accounts.conf` on each server, you can declare
service accounts once in [`ob-builder`](../admin-builder/README.md) and have them
baked into the generated shell installer and/or Ansible role.

**Interactive:** the questionnaire asks whether to define service accounts and
loops over name / fingerprint / sudo / shell / home for each.

**Non-interactive (`--config`):** add a `service_accounts:` list to the YAML:

```yaml
service_accounts:
  - name: ci-ansible          # avoid system names like 'ansible' only if they exist; use a dedicated name
    key_fingerprint: "SHA256:abc123def456..."
    sudo_allowed: true
    sudo_nopasswd: true
    shell: /bin/bash
    home: /home/ci-ansible    # under an approved prefix (/home, /var/home)
    gecos: Ansible Automation
    uid: 6001                 # fixed uid+gid → NSS-resolvable → reachable over SSH
    gid: 6001
  - name: obbackup
    key_fingerprint: "SHA256:xyz789..."
    sudo_allowed: false
    shell: /bin/sh
    home: /home/obbackup
    uid: 6002
    gid: 6002
```

ob-builder validates each entry (name, fingerprint format, absolute shell/home
paths) at build time — and **warns** when a `home`/`shell` falls outside the
module defaults (it would otherwise be silently dropped on the target; see the
warning above) — then:

- the **shell installer** writes `/etc/open-bastion/service-accounts.conf`
  (`0600 root:root`) and sets `service_accounts_file` in `openbastion.conf`;
- the **Ansible role** carries the accounts as `ob_service_accounts_content`
  (overridable per host/group via `host_vars` / `group_vars` to vary which
  accounts reach which servers) and deploys the file when
  `ob_service_accounts_enabled` is true.

Service accounts apply to every role (bastion, backend, standalone).

> **ob-builder deposits the fingerprint, not the public key.** The generated
> `service-accounts.conf` carries `key_fingerprint` only. That is what
> `pam_openbastion` checks, but it is **not** enough for `sshd` to accept the
> connection — you must also authorize the public key at the SSH layer (next
> section). This is an explicit, documented manual step.

## Authorizing the public key at the SSH layer

`pam_openbastion` validates the fingerprint **after** `sshd` has already accepted
the public key. So `sshd` must be told the key is acceptable, by one of:

- **`authorized_keys` (PAM modes A–D).** Put the public key in
  `~<name>/.ssh/authorized_keys` (mode `0600`, owned by the account). Because the
  service account is auto-created only on first login, you must **pre-create the
  account and its `~/.ssh/authorized_keys`** (e.g. `useradd -m`, then drop the
  key) — there is no home directory to read the file from otherwise.

- **`AuthorizedKeysCommand` (required for Mode E, works in all modes).** Mode E
  sets `AuthorizedKeysFile none`, so `authorized_keys` is ignored. Use the
  `ob-service-account-keys` helper, which serves a public key from
  `/etc/open-bastion/service-accounts.d/<name>.pub` (`root:root 0644`) and does
  **not** depend on the account already existing:

  ```
  # /etc/ssh/sshd_config.d/09-open-bastion-service-keys.conf
  AuthorizedKeysCommand /usr/local/sbin/ob-service-account-keys %u
  AuthorizedKeysCommandUser nobody
  ```

  Drop each account's public key at `/etc/open-bastion/service-accounts.d/<name>.pub`
  and reload `sshd`. The mere presence of the `.pub` lets `sshd` present the key;
  `pam_openbastion` still re-validates the SHA256 fingerprint against
  `service-accounts.conf` (which is `0600` and unreadable by the
  `AuthorizedKeysCommandUser`), so an orphan `.pub` is accepted by `sshd` but
  still rejected by PAM.

`ExposeAuthInfo yes` must be set (the setups do this) so the fingerprint reaches
the PAM module.

### The account must be resolvable (fixed `uid`/`gid`)

`sshd` runs `getpwnam(<user>)` **before** authentication and refuses unknown
users ("Invalid user"). A brand-new service account therefore has to be
resolvable up front, which `nss_openbastion` does — **but only when the account
has a fixed `uid` *and* `gid`** (`nss/libnss_openbastion.c`); otherwise NSS skips
it and the login is refused before PAM ever runs. So, for an SSH-reachable
service account that does not already exist as a local user:

- set both `uid` and `gid` (also gives stable, fleet-consistent ownership), **or**
- pre-create the account locally (`useradd`), in which case the `files` NSS
  source resolves it.

`ob-builder` warns at build time when a service account lacks `uid`/`gid`. The
auto-create-on-first-login behaviour fills in the home directory etc. during the
session phase, but it cannot help sshd's pre-auth lookup — hence this
requirement.

## Reaching servers through a bastion (no ProxyJump recording)

Service accounts authenticate by **direct SSH key**, independently of the bastion
certificate-vouching used by human users. Consequences:

- A service account does **not** use `ob-ssh`: that path needs an SSO-issued
  bastion voucher, which a key-only account never obtains. So the seamless,
  recorded bastion→backend hop is **not** available to service accounts.
- The intended pattern is therefore to point service accounts **directly at the
  servers they automate** (where their account is configured), not to relay
  through the bastion.
- A native `ssh -J bastion backup@backend` (ProxyJump) _can_ work if `backup` is
  a configured service account on **both** the bastion and the backend and the
  bastion permits TCP forwarding. **But the bastion's session recorder
  (`ForceCommand`) does not cover the forwarded `direct-tcpip` channel**, so such
  a hop is **not recorded**. Treat this as a deliberate audit bypass: if you need
  service-account activity audited, run it against the target directly (the
  target's own logs/auditd apply) rather than tunnelling through the bastion.

## Sudo bypasses the SSO token (including in Mode E)

A service account's sudo rights come **entirely** from `service-accounts.conf`
(`sudo_allowed` / `sudo_nopasswd`): `pam_openbastion` grants them locally and
returns success **without any LLNG call** — even in Mode E, where human users
must present a fresh LLNG token to use sudo. A service key with `sudo_allowed`
(especially `sudo_nopasswd`) is therefore a **standing local privilege that
escapes the SSO-gated sudo model**. Grant it sparingly, prefer no sudo or
tightly-scoped `sudoers` rules, and rotate/inventory these keys like any other
long-lived credential. (You still need a `sudoers` entry permitting the account;
PAM authorizes the _attempt_, `sudoers` authorizes _which commands_.)

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
