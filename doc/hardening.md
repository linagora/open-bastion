# Session Containment Hardening

> **Status (v0.1.x):** PR1 of a two-part hardening series. PR2 (auditd as
> primary trace) will be tracked separately.

This document describes the host-level configuration deployed by
`ob-bastion-setup` to keep an authenticated user from escaping the
recorded SSH session. Everything here is **pure system configuration** —
no setuid binary is added.

## Threat model

`ob-session-recorder-wrapper` (setgid `root:ob-sessions`, mode `2755`)
captures the pty via `script(1)`. An authenticated user can still try to:

1. **Detach a process from the pty** with `setsid nohup … &`. The child
   re-parents to PID 1 and survives logout, running outside the
   recorded session.
2. **Schedule deferred work** with `at(1)` or `crontab(1)`. The
   commands run later, again outside the recorded session.
3. **Fork bomb** the host to deny service to other users.

PR1 closes channels (1)–(3) by configuration. PR2 will additionally
log every `execve()` system-wide via `auditd` so any attempt to bypass
the recorder leaves a primary trace independent of the wrapper.

## What `ob-bastion-setup` deploys

| Destination                                     | Source template                                          | Purpose                                                                                       |
| ----------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `/etc/systemd/logind.conf.d/open-bastion.conf`  | `share/open-bastion/hardening/logind.conf.d/…`           | `KillUserProcesses=yes` — logind reaps every process owned by a user when their last session ends. |
| `/etc/security/limits.d/open-bastion.conf`      | `share/open-bastion/hardening/security/limits.d/…`       | Caps `nproc` per user at 256, root unlimited. Fork-bomb guardrail.                            |
| `/etc/at.allow`                                 | `share/open-bastion/hardening/at.allow`                  | Whitelist: empty (root only by design). Non-root users cannot use `at(1)`.                    |
| `/etc/cron.allow`                               | `share/open-bastion/hardening/cron.allow`                | Whitelist: `root` only. Add admins as needed.                                                 |
| `systemctl mask atd`                            | —                                                        | Disables the at daemon entirely if it is installed.                                           |

`systemd-logind` is reloaded at the end of the step. **This kills any
active user session on the host** — run the setup outside business
hours or warn users first.

`cron.service` is **not** masked. `ob-bastion-setup --max-security`
writes `/etc/cron.d/open-bastion-krl` to refresh the SSH key
revocation list periodically; that job needs cron running. The
allowlist is sufficient: only root can submit jobs via `crontab(1)`,
and `/etc/cron.d/` already requires root to write.

## Why `KillUserProcesses=yes`

Without it, `setsid nohup <reverse-shell> &` survives `exit`: the
child detaches from the pty, re-parents to PID 1, and the wrapper
never sees its output again. The session recording stops at the
wrapper exit, but the process keeps running with the user's
credentials. With `KillUserProcesses=yes`, logind sends `SIGTERM`
followed by `SIGKILL` to the user's slice when the last session ends,
including children re-parented to init.

If a legitimate user really needs to keep a long-running job, that
should go through a service account (see `doc/service-accounts.md`)
and a systemd unit, not a backgrounded shell on the bastion.

`Linger=no` is the implicit default per user; you can confirm it
post-deploy with:

```bash
loginctl show-user <user> | grep -E 'Linger|State'
```

If `Linger=yes` for any user, that user has been allowed to keep
processes after logout (`loginctl enable-linger`). Disable it:

```bash
loginctl disable-linger <user>
```

## Why allow-listing `at` and `cron`

`at` and `cron` run a command **at a later time**, outside the
SSH session and outside the wrapper. Even with `KillUserProcesses=yes`
on the SSH session, `atd`/`crond` would still execute the queued
command from a fresh PID 1 child. The allow-lists prevent the user
from queueing in the first place.

We mask `atd` rather than only relying on `at.allow` because some
distros ship `atd` enabled by default, and a mis-edited `at.allow`
would silently re-open the channel.

## Why a `nproc` cap

Without it, a fork bomb (`:(){ :|:& };:`) inside the recorded session
can saturate the host's PID space and deny service to other admins
trying to clean it up. 256 is comfortable for interactive use and
common build/test workloads; raise it in `/etc/security/limits.d/`
with a more specific drop-in (e.g. `99-build-agents.conf`) if a
service account legitimately needs more.

## Verifying after deployment

```bash
# logind picked up KillUserProcesses
busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager KillUserProcesses
# Expected: b true

# limits drop-in is parsed
ulimit -u   # as a non-root user on the bastion → ≤ 256

# at and cron whitelists in place, no extra users
cat /etc/at.allow /etc/cron.allow

# atd is gone
systemctl is-enabled atd 2>&1   # masked / not-found

# No user has linger enabled
loginctl list-users
loginctl show-user <user> | grep Linger
```

End-to-end manual check (the canonical PR1 acceptance test):

```bash
# From a workstation
ssh user@bastion
setsid nohup sleep 3600 &
exit

# From root on the bastion
ps -u user | grep sleep        # → no output
```

If `sleep` is still running, either `KillUserProcesses=yes` was not
applied (logind not reloaded?) or the user has `Linger=yes`.

## Lifecycle of the deployed files

The four files written under `/etc/` (`at.allow`, `cron.allow`,
`systemd/logind.conf.d/open-bastion.conf`,
`security/limits.d/open-bastion.conf`) are **deployment artefacts of
`ob-bastion-setup`**, not package-managed conffiles. The hardening step
is opt-in (the operator runs `ob-bastion-setup` and confirms the
prompt), so the package itself does not place these files.

Practical consequences:

- `apt purge open-bastion` (or `rpm -e open-bastion`) **does not
  remove** `/etc/at.allow`, `/etc/cron.allow`,
  `/etc/systemd/logind.conf.d/open-bastion.conf`, or
  `/etc/security/limits.d/open-bastion.conf`. Remove them with `rm`
  if you no longer want the hardening.
- A package upgrade **does not overwrite** them either. Re-run
  `ob-bastion-setup` after an upgrade if a template changes and you
  want the new content; the script backs up the existing file before
  replacing it.
- The templates themselves live under `/usr/share/open-bastion/hardening/`
  and *are* reinstalled on upgrade. They are read-only references; do
  not edit them.

To reapply or update the deployed files, edit them under `/etc/` and
either re-run the relevant step (e.g. `systemctl reload systemd-logind`
after touching the logind drop-in) or re-run `ob-bastion-setup` (which
will back up and overwrite the logind/limits drop-ins, and warn if it
finds an admin-managed `at.allow` or `cron.allow`).

## Disabling parts of the hardening

If a deployment needs a specific subsystem back, edit the deployed
files in `/etc/` directly.

| Re-enable           | What to do                                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `at(1)` for a user  | Add the username to `/etc/at.allow`, then `systemctl unmask atd && systemctl enable --now atd`.                        |
| `crontab` for a user | Add the username to `/etc/cron.allow`. (`cron.service` is already running.)                                            |
| Background processes | Remove `/etc/systemd/logind.conf.d/open-bastion.conf`, then `systemctl restart systemd-logind`. Discouraged on a bastion. |
| Higher `nproc`       | Add a more specific drop-in **after** `open-bastion.conf` (alphabetical order, e.g. `99-build.conf`).                  |

To skip the entire step at install time:

```bash
ob-bastion-setup --portal https://auth.example.com --skip-hardening
```

## What PR1 does **not** cover

- **Primary trace.** If the wrapper crashes or is bypassed (e.g.
  through a PAM mis-config), nothing else logs `execve()`. PR2 will
  add an `auditd` ruleset that records every `execve()` system-wide,
  so even a process that escapes the recorder leaves a syscall trail.
- **Container escape / kernel exploits.** Out of scope; rely on
  upstream kernel hardening and timely patching.
- **`systemd-run --user` with a service template.** Covered by
  `KillUserProcesses=yes` *only* if the user does not have linger
  enabled. Confirm with `loginctl show-user`.

## See also

- [`session-recording.md`](session-recording.md) — wrapper and recorder details
- [`security.md`](security.md) — broader security policy
- [`SECURITY.md`](../SECURITY.md) — disclosure policy
