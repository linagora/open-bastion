# Quick-start: deploy Open Bastion with Ansible

This guide takes you from nothing to a working bastion + backends fleet using
`ob-builder` to generate the Ansible artefacts and a single `ansible-playbook`
run to apply them.

The flow is always the same three steps:

1. **Generate** the role(s) with `ob-builder` (one questionnaire / config per role).
2. **Declare your hosts** (and their IPs) in an inventory.
3. **Apply** with `ansible-playbook`.

> `ob-builder` runs **once on your workstation**. It talks to the SSO portal to
> fetch the SSH CA public key and JWKS, then bakes them — plus your scenario,
> client_id and APT repo — into a self-contained Ansible role. The role is then
> pushed to the fleet; the targets never contact your workstation again.

## Prerequisites

- `ob-builder` on your workstation (ships in the `open-bastion-builder` package).
- `ansible` on your workstation.
- The Open Bastion `.deb`/`.rpm` reachable by the targets from an APT/YUM repo
  (the default is the Linagora repo; override with `--apt-url`).
- SSO reachable from your workstation (for the build-time OIDC discovery) **and**
  from the targets (at run time, for enrolment).
- SSH access from your workstation to each target as a user that can `sudo`.

## Step 1 — Generate the roles

A bastion and a backend differ only by `target_role` (and the backend's
"accept only this bastion" allowlist). You can generate them in **two runs**, or
in **one run** with `--bundle` so both share the exact same CA / JWKS.

### Option A — bundle (recommended: bastion + backend share one CA)

Write one `build.yml` describing the deployment, then let `--bundle` emit the
matched pair:

```yaml
# build.yml
deployment_slug: acme
scenario: token-only            # token-only | token+unix | keys+llng | mixed | max-security
portal_url: https://sso.example.com
client_id: ob-bastion           # the bastion's OIDC client (= its bastion_id)
client_id_policy: fixed
client_secret_mode: prompt      # none | prompt | embedded
server_group: bastion
server_group_policy: fixed
target_role: bastion            # bundle derives the matching backend automatically
auto_enroll_setup: yes
ansible_auto_approve: yes        # let the play approve device codes via an LLNG cookie
apt_url: https://linagora.github.io/open-bastion
apt_suite: trixie
apt_component: main
```

```bash
ob-builder --config build.yml --bundle --output-ansible ./roles-acme/
```

### Option B — two independent runs

Generate the bastion role:

```bash
ob-builder --config build-bastion.yml --output-ansible ./role-bastion/
```

…and the backend role (same file, `target_role: backend`, a backend
`server_group`, and optionally an `allowed_bastions` allowlist):

```bash
ob-builder --config build-backend.yml --output-ansible ./role-backend/
```

The generated tree contains `defaults/main.yml` (all the baked-in `ob_*`
values), `tasks/`, `templates/` and a `files/` directory holding the SSH CA
public key fetched from the portal. See
[`admin-builder/templates/ansible/role/README.md`](../admin-builder/templates/ansible/role/README.md)
for the full list of `ob_*` variables.

## Step 2 — Declare your hosts and their IPs

**This is where the IPs of the machines you are building go.** Create an
`inventory.yml` next to the role and list every target under the right group —
the bastion(s) under `bastions`, every backend under `backends`. The address of
each machine is the `ansible_host` line:

```yaml
# inventory.yml
all:
  vars:
    ansible_user: admin                 # a sudo-capable account on the targets
    ansible_ssh_private_key_file: ~/.ssh/id_fleet

  children:
    bastions:
      hosts:
        bastion-1:
          ansible_host: 10.0.0.10        # <-- IP (or DNS name) of the bastion
          ob_role: bastion
          ob_server_group: bastion
          ob_client_id: ob-bastion       # this bastion's id (== client_id)
          ob_client_secret: "{{ vault_bastion_secret }}"

    backends:
      hosts:
        web-1:
          ansible_host: 10.0.0.21        # <-- IP of the first backend
          ob_role: backend
          ob_server_group: backend
          # "Accept only this bastion": the backend refuses any cert whose
          # key-id does not carry bastion=<one of these ids>.
          ob_bastion_allowed_bastions: "ob-bastion"
        web-2:
          ansible_host: 10.0.0.22        # <-- IP of the second backend
          ob_role: backend
          ob_server_group: backend
          ob_bastion_allowed_bastions: "ob-bastion"
```

Notes:

- `ansible_host` accepts an IP **or** a resolvable hostname — use whichever your
  workstation can reach. Adding a machine to the fleet is just one more `hosts:`
  entry with its `ansible_host`.
- Per-host values (`ob_role`, `ob_server_group`, `ob_client_id`,
  `ob_bastion_allowed_bastions`) override the role's baked-in defaults, so a
  single role can drive both bastions and backends — dispatch is by `ob_role`.
- Keep the OIDC client secret in **ansible-vault**, not in clear text. The role
  also never persists the LLNG approval cookie (it is asked per run).

A matching `playbook.yml` is trivial — apply the one role to everyone and let
`ob_role` dispatch:

```yaml
# playbook.yml
- hosts: all
  become: true
  roles:
    - role: open-bastion
```

## Step 3 — Apply

If you enabled `ansible_auto_approve: yes`, fetch a short-lived LLNG session
cookie (it auto-approves the device-code enrolment for the whole fleet — no
browser needed) and pass it at run time:

```bash
COOKIE=$(llng --llng-url https://sso.example.com --login admin --password '***' llng_cookie)

ansible-playbook -i inventory.yml playbook.yml \
  --ask-vault-pass \
  --extra-vars "ob_llng_cookie='$COOKIE'"
```

Without auto-approve, omit `ob_llng_cookie`: the play prints a device URL + code
per host for manual browser approval.

Limit a run to one group or host while iterating:

```bash
ansible-playbook -i inventory.yml playbook.yml --limit bastions
ansible-playbook -i inventory.yml playbook.yml --limit web-1
```

## What the play does on each host

1. Configures the APT/YUM repo and installs the `open-bastion` package.
2. Writes `/etc/open-bastion/openbastion.conf` from the baked-in scenario.
3. Runs `ob-enroll` (Device Authorization Grant) to obtain the server's
   long-lived **offline** token; `ob-heartbeat.timer` then keeps the short-lived
   access token fresh.
4. Runs `ob-bastion-setup` / `ob-backend-setup`, which locks SSH down to
   SSO-issued certificates and — on backends — enforces the
   `allowed_bastions` policy (a backend accepts only certificates vouched by a
   listed bastion).

After the play, users connect with their SSO certificate to a bastion, then hop
to any backend with `ob-ssh <backend>` (or copy files with `ob-scp`); the
bastion mints a short-lived, CA-signed certificate for each hop. No user key
ever lands on the bastion or the backends.

## Updating the fleet

Re-running the playbook is idempotent: bump the package in your repo and run
again to upgrade, or change a host's `ob_*` vars and re-apply to reconfigure.
Adding a server is one new inventory entry plus a `--limit <newhost>` run.
