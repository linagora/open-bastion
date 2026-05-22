# ob-builder — Open Bastion Deployment Artifact Generator

`ob-builder` is an administrative tool that generates customized deployment artifacts for Open Bastion. It runs once on an administrator's workstation, produces reusable bootstrap scripts and Ansible playbooks pre-loaded with SSO configuration and keys, and those artifacts are then distributed to target servers without further administrator interaction.

## How it Fits in the Project

Administrators use `ob-builder` to answer a single questionnaire once, capturing deployment parameters (SSO URL, authentication scenario, target role, etc.). The builder fetches the SSH CA key and JWKS from the SSO server and generates two types of artifacts:

1. **Self-extracting shell installer** (`bootstrap-<slug>.sh`) — can be copied to target servers and executed; handles package installation, configuration, and enrollment
2. **Ansible role tree** — for playbook-based deployments across fleets

Each artifact is self-contained: it embeds the SSO CA key, includes pre-validated configuration, and can be distributed via any channel (scp, artifact repository, CI/CD). On the target server, the artifact installs the Open Bastion package via APT/YUM, writes configuration, optionally launches `ob-enroll` and `ob-bastion-setup` / `ob-backend-setup`, and cleans up automatically. The administrator never distributes secrets in the artifacts; instead, secrets are passed via CLI flags, environment variables, or secure files at deployment time.

## Quick Start (Interactive)

```bash
ob-builder --output-shell /tmp/bootstrap-mybastion.sh
```

By default the builder uses the Linagora APT repo keyring shipped with the
package. Override with `--repo-keyring /path/to/your.gpg` if you publish
Open Bastion packages from your own mirror.

This launches an interactive questionnaire:

1. Deployment slug (name used for the generated script)
2. Security scenario (`token-only`, `token+unix`, `keys+llng`, `mixed`, `max-security`)
3. SSO portal URL (validated via OIDC discovery)
4. OIDC client_id and policy (`fixed` or `modifiable`)
5. OIDC client_secret mode (`none` or `prompt`)
6. Server group and policy
7. Target role (`bastion`, `standalone`, or `backend`)
8. Auto-launch enrollment/setup on target (`yes`, `no`, or `prompt`)

## Quick Start (Non-Interactive with Config File)

For reproducible builds in CI or when deploying the same configuration to multiple targets, use a YAML config file. Here is a complete `build.yml` for the max-security backend scenario:

```yaml
# build.yml
deployment_slug: prod-backend-us-east
scenario: max-security
portal_url: https://sso.example.com
client_id: backend-prod
client_id_policy: fixed
client_secret_mode: prompt
server_group: backend-prod-us-east
server_group_policy: fixed
target_role: backend
auto_enroll_setup: prompt
# repo_keyring: /etc/apt/keyrings/your-own.gpg   # optional; defaults to the Linagora keyring
apt_url: https://linagora.github.io/open-bastion
apt_suite: trixie
apt_component: main
```

Generate the artifacts:

```bash
ob-builder \
  --config build.yml \
  --output-shell bootstrap-prod-backend.sh \
  --output-ansible /tmp/role-prod-backend/
```

The builder fetches the CA SSH key and JWKS from the SSO server, validates the configuration, and produces both a shell installer and Ansible role with all credentials pre-loaded (except the client secret, which is handled separately on the target).

## Outputs

### Self-Extracting Shell Installer

The shell installer is a single, portable bash script. Copy it to the target server and execute:

```bash
scp bootstrap-prod-backend.sh server.example.com:/tmp/
ssh server.example.com sudo /tmp/bootstrap-prod-backend.sh
```

The script performs:
- Repository configuration (APT sources + GPG key)
- Deployment of Open Bastion configuration to `/etc/open-bastion/openbastion.conf`
- Installation of the `open-bastion` package
- Optionally, automatic enrollment via `ob-enroll` and service setup via `ob-bastion-setup` or `ob-backend-setup`

Run with `./bootstrap-prod-backend.sh info` to inspect embedded metadata (scenario, SSO URL, CA fingerprint) without making changes.

### Ansible Role Tree

The generated Ansible role is ready for fleet deployments. It includes:
- Pre-populated defaults (configuration from the build)
- Tasks for repository setup, package installation, and enrollment
- SSH CA and signing keys embedded as files
- Support for per-host variable overrides via `host_vars/`, `group_vars/`, or extra-vars

Use the role in a playbook:

```bash
ansible-playbook -i inventory.yml playbook.yml \
  --vault-password-file ~/.vault_pass
```

For full details on role variables and usage, see [`templates/ansible/role/README.md`](templates/ansible/role/README.md).

## Shell Installer Options

The generated shell installer accepts CLI flags to override embedded defaults. Precedence: **CLI flag > environment variable > embedded default > interactive prompt**.

| Flag | Environment | Description |
|------|-------------|-------------|
| `--client-id ID` | `OB_CLIENT_ID` | Override OIDC client_id (if policy allows) |
| `--client-secret SECRET` | `OB_CLIENT_SECRET` | Provide secret directly (insecure; visible in `/proc`) |
| `--client-secret-file PATH` | `OB_CLIENT_SECRET_FILE` | Read secret from file (use `-` for stdin); recommended for fleet deployments |
| `--server-group GROUP` | `OB_SERVER_GROUP` | Override server group |
| `--portal-url URL` | `OB_PORTAL_URL` | Override SSO URL (rare; mainly for testing) |
| `-y, --yes` | - | Answer yes to all prompts (auto-enroll and auto-setup) |
| `--skip-enroll` | - | Install package and config, but skip `ob-enroll` |
| `--skip-setup` | - | Run `ob-enroll` but skip `ob-bastion-setup` / `ob-backend-setup` |
| `--dry-run` | - | Print actions without executing them |
| `--force` | - | Overwrite existing `/etc/open-bastion` (normally refused) |
| `--non-interactive` | - | Fail instead of prompting (for CI strict mode) |
| `-h, --help` | - | Show help and embedded scenario details |

Example: deploy with a secret from a file and auto-enroll:

```bash
./bootstrap-prod-backend.sh \
  --client-secret-file /secure/secret.txt \
  --yes
```

The `info` subcommand displays the scenario, SSO URL, role, and CA SSH fingerprint:

```bash
./bootstrap-prod-backend.sh info
```

## Bundle Mode

To generate a matched set of bastion and backend artifacts that share the same SSH CA and JWKS, use `--bundle`:

```bash
ob-builder \
  --config build.yml \
  --bundle \
  --output-shell /tmp/bastion-bundle.sh \
  --output-ansible /tmp/role-bundle/
```

This is useful when deploying an entire PAC at once: a single `build.yml` produces both bastion and backend configurations with synchronized keys.

## Security Notes

- **TLS 1.3 enforced**: The builder refuses `http://` SSO URLs by default (use `--allow-http` only for testing).
- **Client secrets never embedded**: The `client_secret` is not included in any artifact. It is either prompted for on the target (mode `prompt`) or passed via a secure file at deployment time (`--client-secret-file`).
- **GPG signatures**: Use `--sign-with KEYID` to GPG-sign the shell installer; targets can verify with `gpg --verify bootstrap-<slug>.sh.sig bootstrap-<slug>.sh` before execution.
- **Repository keyring**: Defaults to the Linagora keyring shipped with the builder package (`/usr/share/open-bastion-builder/keyrings/open-bastion-linagora.gpg`). Override via `--repo-keyring` or the `repo_keyring` config key when targeting a different APT mirror.
- **Existing config protection**: The shell installer refuses to overwrite `/etc/open-bastion` unless `--force` is passed, preventing accidental clobbering of production configurations.

## Limitations

- **APT-focused**: The shell installer uses APT (Debian/Ubuntu). On RPM-based systems (RHEL, Rocky), it prints a warning and skips repository setup; administrators must configure YUM/DNF separately.
- **Device Authorization Grant requires browser approval**: The `ob-enroll` command uses the OIDC Device Authorization Grant flow, which displays a URL and code. An administrator must open that URL in a browser and approve the request before the enrollment completes. This step cannot be automated.

## See Also

- [`doc/admin-guide.md`](../doc/admin-guide.md) — General administrative procedures for Open Bastion
- [`doc/pam-modes.md`](../doc/pam-modes.md) — Detailed explanation of security scenarios (modes A–E)
- [`templates/ansible/role/README.md`](templates/ansible/role/README.md) — Ansible role variables and usage
