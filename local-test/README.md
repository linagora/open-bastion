# `local-test/` — end-to-end deploy harnesses on a throwaway VM lab

Two scripts deploy Open Bastion to a fresh **3-VM libvirt lab** (one bastion +
two backends) **exactly as the quick-starts document it**, then assert the whole
chain works (NSS, the `ob-ssh` bastion→backend hop, `ob-scp`). They exercise the
real two-phase admin workflow:

```
ob-builder → bastion → deploy → ob-bastion-id → ob-builder → backends → deploy → verify
```

| Script | Path it validates |
| ------ | ----------------- |
| [`deploy-ansible.sh`](deploy-ansible.sh) | `ob-builder --output-ansible` + `ansible-playbook` (the [Ansible quick-start](../doc/ansible-quickstart.md)) |
| [`deploy-shell.sh`](deploy-shell.sh)     | `ob-builder --output-shell` self-extracting installer |

Both use [`lib.sh`](lib.sh) for the shared steps (build the `.deb`, serve the
repo, bring up the SSO, recreate + bootstrap VMs, fetch the approval cookie,
verify e2e).

> ## ⚠️ Not part of CI — on purpose
> These need **libvirt VMs** (nested virtualisation) and a **Docker SSO**, which
> GitHub's hosted runners don't provide. Nothing here is referenced by a
> workflow, CMake or `ctest`; the shellcheck action only scans `./scripts`. Run
> them by hand on a workstation that has the prerequisites. They are
> maintainer/regression tools, not a gate.

The **ob-builder-generated artefacts are used UNCHANGED** — that is the point:
the harness validates the generator's output as a real admin would receive it.
All lab-only adaptations live *outside* the generated role/installer (inventory
overrides, a VM bootstrap step, a repacked `.deb`); see
[Lab-only quirks](#lab-only-quirks).

## Prerequisites

| Need | Why |
|------|-----|
| `libvirt` + `virt-install` + `qemu-img` + `cloud-localds`, user in `libvirt` group | create/boot the VMs on the `default` NAT network (`virbr0`, `192.168.122.0/24`) |
| A Debian **genericcloud** golden image (`debian-*-genericcloud-*.qcow2`) | base for the overlays — put it in `vm/` or set `OB_GOLDEN` |
| `docker` + `docker compose` | the `ob-sso` LemonLDAP::NG container |
| `ansible` (for `deploy-ansible.sh`) | deployment |
| `dpkg-buildpackage`, `dpkg-scanpackages`, `python3`, `curl`, `jq` | build/serve the `.deb`, probe the SSO, run assertions |
| The `llng` client ([simple-oidc-client](https://github.com/linagora/simple-oidc-client)) | fetch the device-code auto-approval cookie |
| A passphrase-less lab key at `~/.ssh/id_oblab` | the host ssh-agent hangs on signing; the VMs trust this key |
| A dwho SSO cert at `/tmp/ob-e2e/id_dwho` (+ `-cert.pub`) | the connection-phase assertions (absent ⇒ that phase is skipped) |

## Run

```bash
local-test/deploy-ansible.sh      # validate the Ansible path
local-test/deploy-shell.sh        # validate the shell-installer path
```

Each one runs the full cycle (build → SSO → recreate VMs → deploy both phases →
assert) and prints a PASS/FAIL scoreboard. Generated roles/installers, logs and
the cookie land in `local-test/.work/` (git-ignored).

### Knobs (environment variables)

| Variable | Default | Effect |
|----------|---------|--------|
| `SKIP_BUILD=1` | off | reuse the `.deb` already staged in `sso/aptrepo/` |
| `OB_GOLDEN` | search `vm/` | path to the genericcloud golden qcow2 |
| `GW_IP` | `192.168.122.1` | libvirt gateway serving the APT repo + SSO |
| `OB_SSH_KEY` | `~/.ssh/id_oblab` | lab management key |
| `OB_DWHO_KEY` / `OB_DWHO_CERT` | `/tmp/ob-e2e/id_dwho[-cert.pub]` | dwho SSO cert for phase-2 assertions |
| `OB_SSO_USER` / `OB_SSO_PASS` | `dwho` / `dwho` | login used to fetch the approval cookie |
| `LLNG` | `llng` on PATH, else `~/bin/llng` | the OIDC client |
| `OB_BASTION_VM` / `OB_BACKEND_VMS` | `lab-a` / `lab-b lab-c` | VM names |

## The two-phase workflow

1. **Bastion.** `ob-builder` generates the bastion artefact from
   [`config/build-bastion.yml`](config/build-bastion.yml) (it enrols as
   `client_id: ob-bastion`, which the lab LLNG maps to a *bastion* server group).
   Deploy it to `lab-a`.
2. **`ob-bastion-id`.** Read the bastion's id from the freshly-deployed bastion.
   It is `ob-bastion` (= its client_id). This is the value the backends must
   allow.
   - Ansible: captured by a `post_task` on the play's still-alive connection.
   - Shell: the bastion is enrolled first (`--skip-setup`), `ob-bastion-id` is
     read while port 22 still answers, then setup runs (`--skip-enroll`) — see
     the [lockdown note](#iterating).
3. **Backends.** `ob-builder` generates the backend artefact with
   `allowed_bastions=<bastion_id>`; deploy it to `lab-b`/`lab-c`. Their
   `AuthorizedPrincipalsCommand` then rejects any cert not vouched by `ob-bastion`.
4. **Verify.** With the dwho SSO cert: log into the bastion, `getent passwd dwho`
   (NSS), `ob-ssh` hop to a backend, `ob-scp` bastion→backend and
   backend→backend (`scp -3`).

## Lab-only quirks

These keep the **generated artefact pristine**; the workarounds live in the
harness, not in what `ob-builder` produced.

- **Unsigned APT repo** → the lab serves a flat repo with no signature, so the
  Ansible inventory overrides `ob_apt_sources_list_line` to `[trusted=yes]`.
- **`libsodium` ABI** → the `.deb` built on this host depends on `libsodium26`
  (so.26) but Debian 13 (trixie) ships `libsodium23` (so.18). `build_deb`
  repacks the dependency `26→23` and the VM bootstrap adds a
  `libsodium.so.26 → .so.23` symlink. **This is LAB-ONLY and never happens in
  production**: the public-repo `.deb` is built per-distro in CI and already
  depends on the matching libsodium.
- **Plain-http SSO** → `pam_openbastion` refuses an http portal unless
  `verify_ssl=false`. Ansible sets `ob_verify_ssl: false` (which makes the role
  pass `--insecure`); the shell installer is run with `--insecure`.
- **Split-horizon approval** → the control node can't resolve
  `auth.example.com`, so Ansible sets `ob_approve_base_url`/`ob_approve_host` to
  reach the SSO at the gateway; the shell path approves the device code from the
  host with a `Host:` header.
- **Bastion client_id** → must be `ob-bastion` (the lab LLNG
  `pamAccessServerGroups` maps `ob-bastion → bastion`, `pam-access → backend`).

## Iterating

`ob-bastion-setup` / `ob-backend-setup` lock **port 22** down to SSO certs
(`pam_openbastion` rejects the local `debian` user). So once a host is deployed
you **cannot redeploy over port 22** — a fresh connection is refused. To
re-run, **recreate the VMs** (both scripts do this every run). This is also why
the shell path reads `ob-bastion-id` *before* running setup.

## SSO

`sso/configure.sh` registers the OIDC clients (`ob-bastion`, `pam-access`) and
the `ssh-ca` plugin, with a short access-token TTL (exercises `ob-heartbeat`)
and a 30-day offline session (so the lab doesn't expire mid-run). The
`ob-builder-curl-shim.sh` (symlinked as `curl` on PATH during generation)
resolves `auth.example.com` to the gateway and returns a dummy CA for `/ssh/ca`;
`ob-*-setup` re-fetches the real CA from the portal at deploy time.

To test unreleased LLNG plugin code, drop a `sso/docker-compose.override.yml`
(git-ignored) bind-mounting your working copies over the baked-in versions.
