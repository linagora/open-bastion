# Primary Audit Trace (auditd)

This document describes Open Bastion's optional **primary audit trace**
based on the Linux kernel `auditd` subsystem. It is the second pillar of
session traceability, complementary to the session recording covered in
[Session Recording](session-recording.md).

## Rationale

Session recording (`ob-session-recorder`) gives you a faithful, replayable
view of what a user did inside their pty: keystrokes, screen output,
timing. This is invaluable for incident review — but it is **not** an
independent audit trail:

- Recordings live on disk; the user's session can sometimes reach them
  (e.g. in `/var/lib/open-bastion/sessions/<user>/`).
- A determined user can attempt to bypass the pty entirely: `setsid`,
  `at`, `cron`, jobs spawned through systemd `--user`, daemons launched
  with `nohup`. Containment ([Session Containment](session-recording.md#session-containment)
  in PR1) closes most of these paths, but not all.
- A coredump, a panic, or an out-of-disk event mid-session can leave a
  partial recording.

`auditd` solves a different problem: it records **every syscall** of
interest, at the kernel level, into an append-only log under
`/var/log/audit/`. Rules filter on `auid` (the audit user id, which is
set at login by PAM and **does not change** across `setuid`/`setgid`
transitions). This means:

- Even if a user spawns a child via `at` two hours later, the child's
  `auid` still points back to the original SSH login.
- `execve` is logged with full `argv`, working dir, and credentials,
  before the program even gets to run.
- The audit log is owned by `root:root` (mode 0600 by default); the
  unprivileged user cannot tamper with it from inside their session.

In short: recording answers _"what did the user see and type?"_, auditd
answers _"what syscalls did the kernel actually execute on behalf of
this auid?"_. You want both.

## Threat model

What this trace **covers**:

- Every `execve` performed by a logged-in non-system user (auid ≥ 1000),
  including programs launched via `at`, `cron`, `systemd --user`, or
  any process whose ancestry goes back to a PAM-authenticated login.
- Every outbound `connect` syscall by such users (useful to detect
  exfiltration, reverse shells, or unusual back-connect targets).
- Writes / attribute changes on sensitive files: `/etc/passwd`,
  `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`,
  `/etc/sudoers.d/`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`.
- Writes / attribute changes on the session recordings directory
  (`/var/lib/open-bastion/sessions/`) and on Open Bastion's own config
  directory (`/etc/open-bastion/`). This catches a user trying to
  delete or rewrite their own `.typescript`.

What this trace **does not** cover:

- Contents of files read or written (auditd records the syscall, not
  the data).
- Keystrokes inside an already-running program (use session recording
  for that).
- Anything before login (those processes are tagged
  `auid=4294967295` / "unset" and explicitly excluded by our rules).
- System processes (auid < 1000 — daemons, kernel threads). They are
  excluded on purpose, because they generate orders of magnitude more
  events and have no business showing up in a user audit trail.
- Outbound UDP exfiltration via `sendto`/`sendmsg` on an unconnected
  socket (the canonical DNS-tunnel pattern). We trace `connect` only,
  by design — adding `sendto`/`sendmsg` would be very chatty by default.
  Operators who need broader coverage can add `-S sendto -S sendmsg` to
  `/etc/audit/rules.d/open-bastion.rules` and accept the volume.
- Outbound traffic over `io_uring` (`io_uring_enter` with
  `IORING_OP_CONNECT` / `IORING_OP_SEND*`). Same trade-off as above.
- Programs that use `vfork`+exec patterns the kernel does not classify
  as `execve`/`execveat` (rare in practice). Both `execve` and
  `execveat` (syscall #322) are covered by our rules.

## Activation

The audit trace is **opt-in** and **off by default**, consistent with
Open Bastion's policy of not modifying global system state without an
explicit admin decision (see also `--enable-hardening` in PR1).

```bash
sudo ob-bastion-setup \
    --portal https://auth.example.com \
    --enable-audit-trace
```

What `--enable-audit-trace` does, in order:

1. Warns and skips the audit-trace step if the `auditd` package is
   not installed (Debian/Ubuntu: `apt install auditd`; RHEL/Rocky/Fedora:
   `dnf install audit`). The rest of `ob-bastion-setup` continues
   normally — the operator can install `auditd` later and re-run
   with `--enable-audit-trace`. We declare `auditd` as a `Recommends`
   soft dependency so installing the bastion package alone never
   silently flips a global system knob.
2. Asks the admin to confirm (skipped under `--yes`).
3. Installs `/etc/audit/rules.d/open-bastion.rules` (mode 0640
   `root:root`) from the template at
   `/usr/share/open-bastion/audit/rules.d/open-bastion.rules`.
4. Installs `/etc/cron.daily/open-bastion-audit-rotate` (mode 0755
   `root:root`) from the corresponding template — this triggers a daily
   rotation so that `num_logs=7` gives a ~1-week retention window.
5. Loads the new rules with `augenrules --load` and restarts the
   `auditd` service. **Note:** restarting auditd does _not_ terminate
   active SSH sessions (unlike `logind`), so this is safe to run on a
   live bastion.

**`/etc/audit/auditd.conf` is deliberately NOT modified.** See
[Tuning retention](#tuning-retention) below for the manual step.

## Verification

After `--enable-audit-trace` succeeds, verify on the bastion:

```bash
# 1. Rules loaded?
auditctl -l

# Expect lines like:
#   -a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -F key=ob-exec
#   -w /etc/passwd -p wa -k ob-passwd
#   ...

# 2. Recent execve events for any non-system user?
ausearch -k ob-exec -ts recent | head -40

# 3. Audit log present and being written?
ls -lh /var/log/audit/audit.log

# 4. auditd running and enabled at boot?
systemctl status auditd
```

For a more pointed test, log in as a non-system user and run any command:

```bash
# As root:
ausearch -k ob-exec -x /usr/bin/whoami -ts today
```

You should see at least one `type=EXECVE` record per `whoami` invocation
made by an interactively logged-in user.

## File lifecycle

Like the PR1 hardening drop-ins, the audit-trace files are **deployment
artefacts**, not dpkg conffiles or rpm `%config(noreplace)` files. The
distinction matters when you upgrade or remove the bastion package.

| Path                                                                 | Owner            | Purpose                                                                |
| -------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------- |
| `/usr/share/open-bastion/audit/rules.d/open-bastion.rules`           | open-bastion pkg | Read-only template (shipped by package).                               |
| `/usr/share/open-bastion/audit/cron.daily/open-bastion-audit-rotate` | open-bastion pkg | Read-only template.                                                    |
| `/etc/audit/rules.d/open-bastion.rules`                              | deployment       | Live copy deployed by `--enable-audit-trace`. Edit in place if needed. |
| `/etc/cron.daily/open-bastion-audit-rotate`                          | deployment       | Live copy deployed by `--enable-audit-trace`. Edit in place if needed. |
| `/etc/audit/auditd.conf`                                             | audit pkg        | Admin-tunable. **NOT modified by Open Bastion.**                       |

We deliberately do **not** modify `/etc/audit/auditd.conf` because it
is a single admin-tunable file owned by the `audit` distro package.
Drop-in mechanisms (`rules.d/`, `cron.daily/`) are used where they
exist; the single admin-tunable file `auditd.conf` is left untouched.
If we patched it in place, any `dpkg`/`rpm` conffile prompt on the next
`audit` package upgrade would confront the admin with unexpected diffs.

## Tuning retention (manual post-deployment step)

**This is a required manual step** after running `--enable-audit-trace`.
Open Bastion does not modify `/etc/audit/auditd.conf`. The distribution
defaults (often `num_logs=5`, `max_log_file=8`) give only a few days of
retention on a busy bastion.

**Recommended: ~1 week local retention**

```bash
sudo sed -i \
  -e 's/^max_log_file = .*/max_log_file = 50/' \
  -e 's/^num_logs = .*/num_logs = 7/' \
  -e 's/^max_log_file_action = .*/max_log_file_action = ROTATE/' \
  /etc/audit/auditd.conf
sudo systemctl restart auditd
```

Or edit the file directly:

```bash
sudo vim /etc/audit/auditd.conf
```

To further tune:

| Want              | Edit `/etc/audit/auditd.conf`                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| Longer history    | Raise `num_logs` (e.g. `num_logs = 30`).                                                                      |
| Bigger files      | Raise `max_log_file` (in MB).                                                                                 |
| Disk-full safety  | Set `space_left = 500` and `space_left_action = SYSLOG` (warns to syslog when free space drops below 500 MB). |
| Stop on disk full | `disk_full_action = HALT` (paranoid; default is `SUSPEND`).                                                   |

After editing, run:

```bash
sudo systemctl restart auditd
```

You may also want to adjust the cron frequency. By default we rotate
daily; if your event volume is low you can move
`/etc/cron.daily/open-bastion-audit-rotate` to `/etc/cron.weekly/`, in
which case `num_logs = 7` gives a ~7-week window instead.

## Forwarding to a remote collector

A bastion that can be compromised should not store its only audit trail
locally. The recommended next step (out of scope for this release) is to
forward audit events to an external SIEM:

- The `audispd` plugin framework is shipped by the `audit` package
  itself.
- The `audisp-syslog` plugin (in the `audisp-plugins` package on Debian)
  forwards every audit record to syslog, from where rsyslog or
  systemd-journal-upload can ship them off-host over TLS.
- For Splunk / Elastic / Wazuh, vendor-specific collectors hook into
  the same audispd socket.

Open Bastion does **not** install or configure any forwarder. You need
to make a deliberate choice about _where_ the logs go and _how_ they
are protected in transit, both of which are deployment-specific.

## Disabling

Two ways:

```bash
# 1. Runtime (until next auditd restart): drop all rules.
auditctl -D

# 2. Permanent: remove the drop-in and reload.
rm /etc/audit/rules.d/open-bastion.rules
rm /etc/cron.daily/open-bastion-audit-rotate
augenrules --load
systemctl restart auditd
```

If you previously tuned `/etc/audit/auditd.conf` manually (as recommended
in the Tuning section), those changes are yours to revert; they are
harmless even without our rules.

## Volume and saturation

`execve` + `connect` audit rules generate a lot of events on a busy
bastion. Plan accordingly:

- A typical interactive shell session emits 50–500 `execve` events.
- A long-running rsync or ansible run can emit thousands of `connect`
  events.
- `/var/log/audit/audit.log` grows fast. With the defaults
  (`max_log_file=50`, `num_logs=7`) the on-disk footprint caps at
  ~350 MB. Keep an eye on `/var/log` free space.

If saturation becomes an issue:

- Tune `space_left` / `space_left_action` to alert before disk fills.
- Drop the `connect` rule if you don't actually need network-level
  forensics on this bastion.
- Increase `max_log_file` and decrease `num_logs` for the same total
  footprint with fewer rotations.
- Forward to a remote collector and shrink local retention.

## See also

- [Session Recording](session-recording.md) — pty-level recording, the
  other half of the traceability story.
- `auditd.conf(5)`, `auditctl(8)`, `ausearch(8)`, `aureport(8)`.
- The shipped template:
  `/usr/share/open-bastion/audit/rules.d/open-bastion.rules`.
