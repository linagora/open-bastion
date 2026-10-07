# ob-builder — Open Bastion Deployment Artifact Generator

`ob-builder` is an administrative tool that generates customized deployment artifacts for Open Bastion. It runs once on an administrator's workstation, produces reusable bootstrap scripts and Ansible playbooks pre-loaded with SSO configuration and keys, and those artifacts are then distributed to target servers without further administrator interaction.

## How it Fits in the Project

Administrators use `ob-builder` to answer a single questionnaire once, capturing deployment parameters (SSO URL, authentication scenario, target role, etc.). The builder fetches the SSH CA key and JWKS from the SSO server and generates two types of artifacts:

1. **Self-extracting shell installer** (`bootstrap-<slug>-<role>.sh`) — can be copied to target servers and executed; handles package installation, configuration, and enrollment
2. **Ansible role tree** — for playbook-based deployments across fleets

Each artifact is self-contained: it embeds the SSO CA key, includes pre-validated configuration, and can be distributed via any channel (scp, artifact repository, CI/CD). On the target server, the artifact installs the Open Bastion package via APT/YUM, writes configuration, optionally launches `ob-enroll` and `ob-bastion-setup` / `ob-backend-setup`, and cleans up automatically. The administrator never distributes secrets in the artifacts; instead, secrets are passed via CLI flags, environment variables, or secure files at deployment time.

## Quick Start (Interactive)

```bash
ob-builder
```

By default the builder uses the Linagora APT repo keyring shipped with the
package. Override with `--repo-keyring /path/to/your.gpg` if you publish
Open Bastion packages from your own mirror.

This launches an interactive questionnaire covering every option (values
given on the command line, e.g. `--output-shell` or `--apt-url`, are not
asked again):

1. Deployment slug (name used for the generated script)
2. Artefacts to generate (`shell`, `ansible` or `both`) and their paths
   (default `.`, the directory receiving the shell installers, and
   `./ansible-<slug>`)
3. Security scenario (`token-only`, `token+unix`, `keys+llng`, `mixed`, `max-security`)
4. SSO portal URL (validated via OIDC discovery). An `http://` URL offers to
   switch to `--insecure` (test setups only)
5. OIDC client_id and policy (`fixed` or `modifiable`)
6. OIDC client_secret mode (`none`, `prompt`, or `embedded`; an embedded
   secret is typed twice)
7. Server group and policy
8. Target role(s): `bastion`, `standalone`, `backend` — one or more. With
   several roles, each Ansible role tree is suffixed with the role
   (`ansible-<slug>-backend`, …)
9. Allowed bastions (backend), hardening, audit trace, session recording
10. Service accounts — optional SSH-key-only local accounts (ansible, backup, …)
11. Auto-launch enrollment/setup on target (`yes`, `no`, or `prompt`), self-delete
12. APT repository (URL, suite, component, keyring) and optional GPG signing key
13. Save the answers as a YAML config for `--config` (default
    `./ob-builder-<slug>.yml`)

With `--config`, at least one of `--output-shell` / `--output-ansible` is required.

`--output-shell` takes a directory, created if missing. ob-builder names
what it writes there: `bootstrap-<slug>-<role>.sh` for each target role, its
`.sig` with `--sign-with`, and `PORTAL-CHECKLIST-<role>.md`. A path ending in
`.sh`, or naming an existing file, is refused.

## Quick Start (Non-Interactive with Config File)

For reproducible builds in CI or when deploying the same configuration to multiple targets, use a YAML config file.

The simplest way to get one is to let the questionnaire write it: answer yes to
its last question, or pass `--save-config build.yml`. Every key is written,
defaults included, with the accepted values as comments, and the header gives
the command that replays it. Two things are not carried over:

- an embedded `client_secret` stays out (as a commented
  `embedded_client_secret:` line to fill in) unless you agree to write it, in
  which case the file is created mode 0600;
- interactively entered service accounts have no public key: add one where the
  commented `public_key_file:` line says, or the account cannot log in.

`--config build.yml --save-config full.yml` also turns a hand-written config
into the complete form.

Because that file is meant to be completed by hand, a path typed at the
questionnaire that already exists is only reused after confirmation (the
default path is the same on every run for a given slug); a path that names a
directory is rejected rather than confirmed. After a refused path
the follow-up prompt has no default: pressing Enter there skips the save. A
path given as `--save-config FILE` on the command line is taken as consent and
is not re-checked; either way the file is replaced wholesale when it is
written, so keep hand-added keys elsewhere than in the file you overwrite.

Here is a complete `build.yml` for the max-security backend scenario:

```yaml
# build.yml
deployment_slug: prod-backend-us-east
scenario: max-security
portal_url: https://sso.example.com
client_id: backend-prod
client_id_policy: fixed
client_secret_mode: prompt # none | prompt | embedded
# embedded_client_secret: ...  # required when client_secret_mode=embedded
server_group: backend-prod-us-east
server_group_policy: fixed
target_role: backend # bastion | standalone | backend, or several: "bastion,backend"
auto_enroll_setup: prompt
ansible_auto_approve: no # yes = Ansible role can approve device codes via LLNG cookie
# repo_keyring: /etc/apt/keyrings/your-own.gpg   # optional; defaults to the Linagora keyring
# insecure: "yes"   # same as --insecure: http:// portal, no TLS verification (tests only)
# sign_with: "0xKEYID"  # same as --sign-with (the command line wins); keep the quotes
apt_url: https://linagora.github.io/open-bastion
apt_suite: trixie
apt_component: main

# Optional SSH-key-only local accounts (no OIDC), rendered into
# /etc/open-bastion/service-accounts.conf (0600) on every target.
# Use a dedicated name (not a system user), a home under /home or /var/home, and
# a fixed uid+gid (required so NSS can resolve the account for sshd pre-auth).
# service_accounts:
#   - name: ci-ansible
#     public_key_file: keys/ci-ansible.pub   # relative to this file; or public_key: "ssh-ed25519 …"
#     # key_fingerprint is derived from the key. Alone, it gives sshd no key to
#     # accept: the account cannot log in (never, under maximum security).
#     sudo_allowed: true
#     sudo_nopasswd: true
#     shell: /bin/bash
#     home: /home/ci-ansible
#     gecos: Ansible Automation
#     uid: 6001
#     gid: 6001
```

See [`doc/service-accounts.rst`](../doc/service-accounts.rst) for the full schema
and how service accounts are matched and created on the target.

Generate the artifacts:

```bash
ob-builder \
  --config build.yml \
  --output-shell . \
  --output-ansible /tmp/role-prod-backend/
```

With `deployment_slug: prod` and `target_role: backend`, the shell installer
is `./bootstrap-prod-backend.sh`. The builder fetches the CA SSH key and JWKS from the SSO server, validates the configuration, and produces both a shell installer and Ansible role with all credentials pre-loaded (except the client secret, which is handled separately on the target).

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
- On a bastion/standalone, a final summary with its bastion ID (`ob-bastion-id`), the value backends list in `allowed_bastions`

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

### Unattended fleet deployments — device-code auto-approval

For fleets where opening a browser to approve every host is impractical, the
Ansible role can be built with `ansible_auto_approve: yes`. At play time it
asks for an LLNG session cookie via `vars_prompt` (never stored on disk) and
uses it to POST to LLNG's `/device` endpoint, approving the device code
without human interaction.

```bash
# Build the role with auto-approve enabled
ob-builder --config build.yml --output-ansible /tmp/role/

# Run the playbook — paste the cookie when prompted
ansible-playbook -i inventory.yml /tmp/role/playbook.yml

# Or pass the cookie non-interactively (CI)
ansible-playbook -i inventory.yml /tmp/role/playbook.yml \
  --extra-vars "ob_llng_cookie=$(llng --llng-server https://sso.example.com llng_cookie)"
```

The cookie is short-lived (typically under 24 h, matching the LLNG session
lifetime), so it is not worth persisting. An empty cookie falls back to the
manual browser-approval flow.

## Shell Installer Options

The generated shell installer accepts CLI flags to override embedded defaults. Precedence: **CLI flag > environment variable > embedded default > interactive prompt**.

| Flag                        | Environment             | Description                                                                  |
| --------------------------- | ----------------------- | ---------------------------------------------------------------------------- |
| `--client-id ID`            | `OB_CLIENT_ID`          | Override OIDC client_id (if policy allows)                                   |
| `--client-secret SECRET`    | `OB_CLIENT_SECRET`      | Provide secret directly (insecure; visible in `/proc`)                       |
| `--client-secret-file PATH` | `OB_CLIENT_SECRET_FILE` | Read secret from file (use `-` for stdin); recommended for fleet deployments |
| `--server-group GROUP`      | `OB_SERVER_GROUP`       | Override server group                                                        |
| `--portal-url URL`          | `OB_PORTAL_URL`         | Override SSO URL (rare; mainly for testing)                                  |
| `-y, --yes`                 | -                       | Answer yes to all prompts (auto-enroll and auto-setup)                       |
| `--skip-enroll`             | -                       | Install package and config, but skip `ob-enroll`                             |
| `--skip-setup`              | -                       | Run `ob-enroll` but skip `ob-bastion-setup` / `ob-backend-setup`             |
| `--dry-run`                 | -                       | Print actions without executing them                                         |
| `--force`                   | -                       | Overwrite existing `/etc/open-bastion` (normally refused)                    |
| `--non-interactive`         | -                       | Fail instead of prompting (for CI strict mode)                               |
| `--insecure`                | -                       | `verify_ssl = false`, `ob-enroll`/setup `-k` (default when built with `--insecure`) |
| `-h, --help`                | -                       | Show help and embedded scenario details                                      |

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
  --output-shell /tmp/bundle/ \
  --output-ansible /tmp/role-bundle/
```

This is useful when deploying an entire PAC at once: a single `build.yml` produces both bastion and backend configurations with synchronized keys.

## Security Notes

- **TLS enforced**: The builder refuses `http://` SSO URLs by default. `--insecure` (test setups only; `--allow-http` is a deprecated alias) allows them and disables TLS verification both in the builder and in the generated artefacts: `verify_ssl = false` in `openbastion.conf`, `ob-enroll`/`ob-*-setup` run with `-k`, `ob_verify_ssl: false` in the Ansible role. Without it, `pam_openbastion` refuses an `http://` portal and nobody can log in.
- **Client secret handling**: Three modes are supported. With `none` the relying party is public (no secret). With `prompt` the secret is asked for at install time on the target (recommended). With `embedded` the secret is baked into the artifact in clear text — convenient but the artifact must then be treated as confidential; the generated installer defaults to `--self-delete` so the script removes itself from disk after a successful run.
- **GPG signatures**: Use `--sign-with KEYID` to GPG-sign the shell installer; targets can verify with `gpg --verify bootstrap-<slug>-<role>.sh.sig bootstrap-<slug>-<role>.sh` before execution.
- **Repository keyring**: Defaults to the Linagora keyring shipped with the builder package (`/usr/share/open-bastion-builder/keyrings/open-bastion-linagora.gpg`). Override via `--repo-keyring` or the `repo_keyring` config key when targeting a different APT mirror.
- **Existing config protection**: The shell installer refuses to overwrite `/etc/open-bastion` unless `--force` is passed, preventing accidental clobbering of production configurations.

## Limitations

- **APT-focused**: The shell installer uses APT (Debian/Ubuntu). On RPM-based systems (RHEL, Rocky), it prints a warning and skips repository setup; administrators must configure YUM/DNF separately.
- **Device Authorization Grant approval**: The `ob-enroll` command uses the OIDC Device Authorization Grant flow, which displays a URL and code. By default an administrator must open that URL in a browser and approve the request before enrollment completes. For Ansible fleet deployments, an opt-in auto-approval path is available (`ansible_auto_approve: yes`) — see [Unattended fleet deployments](#unattended-fleet-deployments--device-code-auto-approval). The shell installer remains manual by design (it is meant to run on one machine at a time).

## See Also

- [`doc/deployment/index.rst`](../doc/deployment/index.rst) — Deploying and configuring Open Bastion
- [`doc/security-scenarios/index.rst`](../doc/security-scenarios/index.rst) — Detailed explanation of the security scenario and its alternatives
- [`templates/ansible/role/README.md`](templates/ansible/role/README.md) — Ansible role variables and usage
