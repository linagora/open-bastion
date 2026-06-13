# `ansible-test/` — end-to-end VM integration test

This directory spins up a throwaway **3-VM lab** (one bastion + two backends),
deploys Open Bastion to it with **Ansible** against a local **LemonLDAP::NG**
SSO, and asserts the whole chain works:

- NSS user resolution (`getent passwd dwho`) on every host;
- the token lifecycle (`ob-heartbeat.timer` keeps the access token fresh);
- the runtime-dir permissions the session recorder needs (`711` / `3771`);
- the `ob-ssh` **bastion→backend** hop (the bastion mints a short-lived,
  CA-signed certificate — no user key ever lands on the bastion);
- `ob-scp` **bastion→backend** _and_ **backend→backend** (forced through the
  bastion with `scp -3`);
- session recording on the bastion.

It is the automated form of the manual pre-release validation. `run-test.sh`
does the full cycle end to end and prints a PASS/FAIL scoreboard.

> ## ⚠️ Not part of CI — on purpose
>
> This test needs **libvirt VMs** (nested virtualisation) and a **Docker SSO**.
> GitHub's hosted runners provide neither, so nothing here is wired into the CI
> workflows: no GitHub Action references `ansible-test/`, and CMake/`ctest`
> never picks it up. Run it **by hand on a workstation** that has the
> prerequisites below. It is a developer/maintainer tool, not a gate.

This is the committed, sanitised sibling of the throwaway `local/` lab tree
(which is git-ignored). The Ansible role here is the one `ob-builder` generates,
with the lab post-edits kept (see [Lab post-edits](#lab-post-edits)).

## Layout

```
ansible-test/
├── README.md              # this file
├── run-test.sh            # one-shot orchestrator + assertions (the test)
├── vm/
│   └── mkvm.sh            # create/destroy Debian VMs on libvirt (overlay + cloud-init)
├── sso/
│   ├── docker-compose.yml # LemonLDAP::NG all-in-one (ob-sso container)
│   ├── configure.sh       # installs the OIDC clients + ssh-ca into the SSO
│   ├── ob-builder-curl-shim.sh  # helper for regenerating the role with ob-builder
│   └── aptrepo/           # flat APT repo served to the VMs (the .deb is git-ignored)
└── ansible/
    ├── inventory.yml      # the 3 hosts (IPs filled in by run-test.sh)
    ├── playbook.yml       # applies the open-bastion role, dispatched by ob_role
    ├── build-bastion.yml  # ob-builder config (bastion) — for regenerating the role
    ├── build-backend.yml  # ob-builder config (backend)
    └── roles/open-bastion/  # the generated role (with lab post-edits)
```

## Prerequisites

On the workstation (host):

| Need                                                                                          | Why                                                                             |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `libvirt` + `virt-install` + `qemu-img` + `cloud-localds`, user in the `libvirt` group        | create/boot the VMs on the `default` NAT network (`virbr0`, `192.168.122.0/24`) |
| A Debian **genericcloud** golden image (`debian-*-genericcloud-*.qcow2`)                      | base image for the overlays — put it in `vm/` or point `OB_GOLDEN` at it        |
| `docker` + `docker compose`                                                                   | runs the `ob-sso` LemonLDAP::NG container                                       |
| `ansible` / `ansible-playbook`                                                                | deployment                                                                      |
| `dpkg-buildpackage`, `dpkg-scanpackages`                                                      | build + index the `.deb`                                                        |
| `python3`, `curl`, `jq`, `ssh-keygen`                                                         | repo server, SSO probe, assertions                                              |
| The `llng` OIDC client ([simple-oidc-client](https://github.com/linagora/simple-oidc-client)) | fetch the device-code auto-approval cookie                                      |
| A passphrase-less lab SSH key at `~/.ssh/id_oblab`                                            | the host ssh-agent hangs on signing; the VMs trust this key                     |

> **Why `id_oblab` + `IdentityAgent=none`?** A forwarded/foreign ssh-agent on
> the host hangs during signing, which makes every VM connection appear to
> "freeze" after the key exchange. The lab always uses a dedicated on-disk key
> with the agent disabled. `mkvm.sh` and `run-test.sh` already encode this.

## Run it

From the repo root (or anywhere):

```bash
ansible-test/run-test.sh
```

That single command will, in order: build the `.deb`, serve the flat APT repo,
bring up + configure the SSO, **destroy and recreate** the three VMs, write
their leased IPs into `inventory.yml`, plant the `:2222` escape-hatch sshd, run
the playbook, assert everything, and tear the VMs down again.

### Knobs (environment variables)

| Variable                       | Default                           | Effect                                             |
| ------------------------------ | --------------------------------- | -------------------------------------------------- |
| `KEEP_VMS=1`                   | off                               | leave the VMs running at the end (to poke at them) |
| `SKIP_RECREATE=1`              | off                               | reuse existing VMs (redeploy + re-assert only)     |
| `SKIP_BUILD=1`                 | off                               | reuse the `.deb` already staged in `sso/aptrepo/`  |
| `OB_GOLDEN`                    | search `vm/`                      | path to the genericcloud golden qcow2              |
| `GW_IP`                        | `192.168.122.1`                   | libvirt gateway that serves the APT repo + SSO     |
| `OB_SSH_KEY`                   | `~/.ssh/id_oblab`                 | the lab management key                             |
| `OB_DWHO_KEY` / `OB_DWHO_CERT` | `/tmp/ob-e2e/id_dwho[-cert.pub]`  | dwho SSO cert for the connection-phase assertions  |
| `LLNG`                         | `llng` on PATH, else `~/bin/llng` | the OIDC client binary                             |

### The dwho SSO certificate (connection-phase assertions)

Phase 8 (`ob-ssh` hop + `ob-scp`) needs a **user** SSO certificate for `dwho`,
signed by the lab's `ssh-ca`. The `llng` client mints tokens but not SSH certs,
so the harness does **not** create one for you:

- If a dwho key+cert exists (default `/tmp/ob-e2e/id_dwho` and
  `…-cert.pub`, or wherever `OB_DWHO_KEY`/`OB_DWHO_CERT` point), phase 8 runs.
- If not, phase 8 is **clearly reported as skipped** — phases 0–7 (build,
  SSO, VMs, deploy, NSS/token/perms assertions) still run and gate the result.

The cert just needs principal `dwho` and a validity window covering the run; the
backends fetch the matching CA from the portal during `ob-*-setup`.

## What each phase asserts

| Phase          | Checks                                                                                                                              |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 0 Preflight    | all required host tools are present                                                                                                 |
| 1 Build        | `.deb` builds, is staged + indexed, **contains `ob-scp`**, repo is reachable                                                        |
| 2 SSO          | the `ob-sso` device endpoint returns a `device_code`                                                                                |
| 3 VMs          | three VMs created and leased an IP                                                                                                  |
| 4 Escape hatch | `:2222` no-PAM sshd is active on each VM                                                                                            |
| 5 NAT          | source-address fidelity rule (best effort; needs host root)                                                                         |
| 6 Deploy       | `ansible-playbook` finishes with `failed=0`                                                                                         |
| 7 Infra        | per host: `getent passwd dwho`, `ob-heartbeat.timer` active, `/var/lib/open-bastion` = `711`, `sessions/` = `3771 root:ob-sessions` |
| 8 Connection   | dwho cert logs into the bastion; `ob-ssh` hop; `ob-scp` ×2; bastion recorded the session                                            |

Logs for the heavy steps land in `/tmp/ob-test-{build,sso,play,apt}.log`.

## The `:2222` escape-hatch (debug only)

The playbook runs `ob_auto_setup: true`, which locks **port 22** down to
SSO-issued certificates. A control connection on port 22 would be severed by
that lockdown mid-play, so the harness plants a second sshd on **`:2222`** with
`UsePAM no` and connects Ansible there. **This is a lab debugging aid only** —
it is not produced by `ob-builder` and has no place in a real deployment, where
hosts are administered _through_ the bastion. (It is intentionally absent from
[`doc/ansible-quickstart.md`](../doc/ansible-quickstart.md).)

## Lab post-edits

The role under `ansible/roles/open-bastion/` is `ob-builder` output with a few
edits needed for a self-contained local lab; each is commented `LAB POST-EDIT`
in the task files:

- **Unsigned APT source** — `deb [trusted=yes] http://192.168.122.1:8088/ ./`
  (the flat repo `run-test.sh` serves is unsigned).
- **libsodium ABI shim** — the `.deb` links `libsodium.so.26`; Debian 13 ships
  `libsodium.so.23`. The role installs `libsodium23` and symlinks `.so.26 →
.so.23` (the 1.x ABI is stable for the symbols used), then `dpkg -i
--force-depends` to bypass the unsatisfiable `libsodium26` package name.
- **Device-code approval reachability** — `ob_approve_base_url` +
  `ob_approve_host` so the controller-side approval reaches the SSO at the
  gateway with the right `Host:` header.
- **NSS shortcut** — disabled here (`ob_lab_configure_nss: false`) because
  `ob_auto_setup: true` makes `ob-*-setup` configure NSS itself.

### Regenerating the role

`ob-builder` shells out to `curl`, so the shim must be reachable **as `curl`**
on `PATH` (it resolves `auth.example.com` to the gateway and returns the lab CA
for `/ssh/ca`). Symlink it into a temp dir and prepend that dir:

```bash
shimdir="$(mktemp -d)"
ln -s "$PWD/sso/ob-builder-curl-shim.sh" "$shimdir/curl"
PATH="$shimdir:$PATH" \
  admin-builder/ob-builder --config ansible/build-bastion.yml \
  --output-ansible /tmp/role-bastion --allow-http
```

Then re-apply the post-edits above. See
[`doc/ansible-quickstart.md`](../doc/ansible-quickstart.md) for the general
(non-lab) `ob-builder` → Ansible workflow.

## SSO token TTLs

`sso/configure.sh` sets a deliberately **short access-token TTL (600 s)** so a
run exercises the `ob-heartbeat` refresh (the timer fires every 5 min, well
inside the window), while keeping a **30-day offline session** so the lab does
not expire mid-test. Adjust both in `configure.sh` if you want different bounds.
