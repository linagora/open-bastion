# SSH Session Recording

This document describes how to set up SSH session recording on a bastion host
using `ob-session-recorder`.

## Overview

The session recorder captures all terminal I/O during SSH sessions, creating
a tamper-evident audit trail for compliance and incident investigation.

```
User SSH → Bastion → ob-session-recorder
                           │ (spawns)
                           ▼
                     ob-record-connect ──────────── Unix socket /run/open-bastion/rec.sock
                     (unprivileged)                         │
                                                            ▼
                                                   ob-record-sink [root]
                                                   (systemd socket-activated)
                                                           │
                                                           ▼
                                           /var/lib/open-bastion/sessions/<user>/
                                           (root:ob-sessions 0750, files 0640)
                                           (future: upload to LLNG)
```

The recorded user has **no access** to the session files (cannot list, read,
delete or truncate them — including their own recordings). See
[doc/design/tamper-evident-session-recording.md](design/tamper-evident-session-recording.md)
for the full design.

## Installation

The `ob-session-recorder` script is installed to `/usr/sbin/` with the
PAM module package.

### Dependencies

- `script` command (from `util-linux`, usually pre-installed)
- `jq` for JSON metadata generation
- `uuidgen` for UUID generation (fallback uses /proc/sys/kernel/random/uuid)

Note: `asciinema` and `ttyrec` are **not yet supported** over the recording
sink in v1. The sink protocol accepts only `script` (typescript) format for
now; see Recording Formats below.

```bash
# Debian/Ubuntu
apt-get install uuid-runtime jq

# RHEL/CentOS
dnf install util-linux jq
```

The `ob-record-sink` and `ob-record.socket` systemd units must be enabled on
the bastion for recording to work:

```bash
systemctl enable --now ob-record.socket
```

## Configuration

### Session Recorder Configuration

Create `/etc/open-bastion/session-recorder.conf`:

```ini
# Recording format:
#   script    - Plain text typescript (default, v1 supported format)
#   asciinema - JSON format, web-friendly (planned; not yet supported over the sink)
#   ttyrec    - Binary format, compact (planned; not yet supported over the sink)
# Any format other than "script" falls back to "script" in v1.
format = script

# Maximum session duration in seconds
# Sessions exceeding this limit are terminated by the sink (status: truncated)
# Set to 0 to disable (not recommended)
max_duration = 86400
```

Note: `sessions_dir` is no longer read by the recorder. The storage path is
owned and managed entirely by `ob-record-sink` (root).

### SSH Server Configuration

Edit `/etc/ssh/sshd_config` to force all sessions through the recorder:

#### Option A: Record all users except admins

```sshd_config
# Record all sessions except for emergency admin access
Match User *,!root,!admin
    ForceCommand /usr/sbin/ob-session-recorder
```

#### Option B: Record specific group only

```sshd_config
# Only record sessions for users in the "recorded" group
Match Group recorded
    ForceCommand /usr/sbin/ob-session-recorder
```

#### Option C: Record all sessions

```sshd_config
# Record all sessions (use with caution)
ForceCommand /usr/sbin/ob-session-recorder
```

Restart SSH after changes:

```bash
systemctl restart sshd
```

## Recording Formats

### Script (Default)

- **Format**: Plain text typescript
- **Extension**: `.typescript`
- **Advantages**: No dependencies, always available, standard Unix tool
- **Replay**: `cat recording.typescript` or `scriptreplay`

This is the default format because `script` is available on all systems.

### Asciinema (planned — not yet supported over the recording sink)

- **Format**: JSON (asciinema v2)
- **Extension**: `.cast`
- **Advantages**: Web-friendly, can be replayed in browser, human-readable
- **Replay**: `asciinema play recording.cast` or web player

Asciinema support over the root sink is planned for a future release. In v1
any `format = asciinema` setting falls back to `script`.

### ttyrec (planned — not yet supported over the recording sink)

- **Format**: Binary
- **Extension**: `.ttyrec`
- **Advantages**: Compact, efficient, standard format
- **Replay**: `ttyplay recording.ttyrec`

ttyrec support over the root sink is planned for a future release. In v1
any `format = ttyrec` setting falls back to `script`.

## Session Metadata

Each recording has an accompanying JSON metadata file (`.json`):

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user": "dwho",
  "client_ip": "192.168.1.100",
  "tty": "/dev/pts/0",
  "start_time": "2025-12-16T10:30:00Z",
  "end_time": "2025-12-16T11:45:23Z",
  "status": "completed",
  "original_command": "",
  "format": "asciinema",
  "recording_file": "20251216-103000_550e8400-e29b-41d4-a716-446655440000.cast",
  "hostname": "bastion.example.com",
  "version": "0.1.0"
}
```

### Metadata Fields

| Field              | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| `session_id`       | Unique UUID for the session                                          |
| `user`             | Unix username                                                        |
| `client_ip`        | Client IP address (from SSH_CLIENT)                                  |
| `tty`              | TTY device                                                           |
| `start_time`       | Session start (ISO 8601 UTC)                                         |
| `end_time`         | Session end (ISO 8601 UTC)                                           |
| `status`           | `active`, `completed`, `truncated`, or `aborted` (all sink-observed) |
| `original_command` | SSH_ORIGINAL_COMMAND if any                                          |
| `format`           | Recording format used                                                |
| `recording_file`   | Name of the recording file                                           |
| `hostname`         | Bastion hostname                                                     |
| `version`          | Recorder version                                                     |

## Directory Structure

```
/var/lib/open-bastion/sessions/
├── dwho/
│   ├── 20251216-103000_550e8400-...-440000.cast
│   ├── 20251216-103000_550e8400-...-440000.json
│   ├── 20251216-143052_661f9511-...-551111.cast
│   └── 20251216-143052_661f9511-...-551111.json
├── rtyler/
│   └── ...
└── jsmith/
    └── ...
```

- Sessions root: mode `0750`, owned `root:ob-sessions`
- Per-user subdirectories: mode `0750`, owned `root:ob-sessions`, created by `ob-record-sink`
- Recording and metadata files: mode `0640`, owned `root:ob-sessions`
- The recorded user is **not** a member of `ob-sessions`; every path level is
  `o-rwx`, so a user has **zero** DAC access to any recording — including their
  own. They cannot list, read, unlink or truncate.
- Auditors added to the `ob-sessions` group gain read-only access to all recordings.

## Replaying Sessions

### Asciinema format

```bash
# Terminal replay
asciinema play /var/lib/open-bastion/sessions/dwho/20251216-103000_*.cast

# Or use the web player (future LLNG integration)
```

### ttyrec format

```bash
ttyplay /var/lib/open-bastion/sessions/dwho/20251216-103000_*.ttyrec
```

### Script format

```bash
# View the raw typescript
cat /var/lib/open-bastion/sessions/dwho/20251216-103000_*.typescript

# Replay with timing (if timing file exists)
scriptreplay timing.txt recording.typescript
```

## Security Considerations

### Tamper-Evident Recording via Root Socket Sink

Session recordings are written by `ob-record-sink`, a root-privileged
systemd socket-activated service. This design replaces the previous
privilege-separation approach and provides genuine tamper-evident recordings.

Key security properties:

- `ForceCommand` points directly at `/usr/sbin/ob-session-recorder`. The
  recorder runs under the user's own uid and streams the session to the root
  sink over a Unix socket (`/run/open-bastion/rec.sock`).
- The sink obtains the connecting user's identity via kernel `SO_PEERCRED` —
  never from anything the client sends. A user cannot spoof another user's
  identity or cause path traversal.
- All files are written **root-owned** (`root:ob-sessions 0640`) inside
  `/var/lib/open-bastion/sessions/<user>/` (`root:ob-sessions 0750`). The
  recorded user is not a member of `ob-sessions` and every level is `o-rwx`,
  so the user has **no DAC right** to list, read, unlink, rename or truncate
  any recording — including their own.
- Recording is **fail-closed**: if the sink is unreachable, the session is
  refused. There is no fallback to a user-owned local file, which would
  re-introduce the deletion risk.
- A user who is root on a **backend** server cannot reach or alter the
  recordings: they live on the bastion (the mandatory transit point), root-owned.
- Root **on the bastion itself** is trusted and out of scope (see
  [Threat Model](design/tamper-evident-session-recording.md)).

For the full design, protocol, and migration details see
[`doc/design/tamper-evident-session-recording.md`](design/tamper-evident-session-recording.md).

### File Permissions

- Sessions directory: mode `0750`, owned `root:ob-sessions`
- Per-user subdirectories: mode `0750`, owned `root:ob-sessions` (created by sink)
- Recording and metadata files: mode `0640`, owned `root:ob-sessions`
- Config file: `/etc/open-bastion/session-recorder.conf`, mode `0644` (root-owned)

### Storage Security

- Store recordings on encrypted filesystem if possible
- Consider log rotation and retention policies
- Sensitive data may be captured (passwords typed in terminals)

### Complementary primary audit trace

Session recording is a faithful pty replay, not an independent audit
trail: a determined user can attempt to bypass the pty (via `setsid`,
`at`, `cron`, `nohup`, `systemd --user`). Recording files themselves
are root-owned and the user has no access to alter or delete them (see
Security Considerations above). For a kernel-level, tamper-evident
syscall log covering `execve`, outbound `connect`, and writes to
sensitive paths (including the recordings directory itself), enable the
optional auditd-based trace — see [Primary Audit Trace](audit.md). It
is opt-in (`ob-bastion-setup --enable-audit-trace`) and complementary
to session recording, not a replacement.

### Network Security

When uploading to LLNG (future feature):

- Use TLS for all transfers
- Authenticate with server token
- Consider bandwidth implications

## Troubleshooting

### Check if recording is working

```bash
# Look for session files
ls -la /var/lib/open-bastion/sessions/$USER/

# Check syslog
journalctl -t ob-session-recorder
```

### Common Issues

| Issue                | Cause                                           | Solution                                                                                 |
| -------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------- |
| No recording created | ForceCommand not active                         | Check sshd_config Match rules                                                            |
| Empty recording      | Session ended immediately                       | Check for shell issues                                                                   |
| Permission denied    | Wrong directory permissions or sink not running | Check `ob-sessions` group, directory mode `0750`, and that `ob-record.socket` is enabled |
| Format not available | asciinema/ttyrec not supported yet              | Use `format = script` (only format supported in v1)                                      |

### Debug mode

```bash
# Test the recorder manually
/usr/sbin/ob-session-recorder --help

# Check configuration
cat /etc/open-bastion/session-recorder.conf
```

## Environment Variables

| Variable               | Description                   |
| ---------------------- | ----------------------------- |
| `LLNG_RECORDER_CONFIG` | Config file path              |
| `LLNG_SESSIONS_DIR`    | Override sessions directory   |
| `LLNG_RECORDER_FORMAT` | Override recording format     |
| `LLNG_MAX_SESSION`     | Override max session duration |

## Integration with LLNG

Future releases will support:

- Automatic upload of recordings to LLNG portal
- Session listing and search in LLNG Manager
- Web-based session replay
- Session annotations and bookmarks

See issues #17-20 in the project backlog.

## Session containment

Recording the pty is necessary but not sufficient. An authenticated user
can detach work from the recorded session with `setsid nohup … &` (the
child re-parents to PID 1 and survives logout), or schedule deferred
commands with `at(1)` / `crontab(1)` that run outside the wrapper
entirely.

`ob-bastion-setup` deploys a set of host-level configuration drop-ins
that close these channels — pure system config, no new setuid binary:

- `KillUserProcesses=yes` in `systemd-logind` so any process owned by
  the user is killed when their last session ends, including
  `setsid`-detached children.
- `at.allow` (empty) and `cron.allow` (root only) so non-sudo users
  cannot schedule deferred jobs. `atd` is masked.
- `nproc` cap (256, root unlimited) in `/etc/security/limits.d/` to
  contain fork bombs.

Verify post-deploy that no user has been opted out via `loginctl
enable-linger`:

```bash
loginctl show-user <user> | grep Linger    # expected: Linger=no
```

The full rationale, deployment details, and re-enable instructions are
in [`hardening.md`](hardening.md).

> **Note:** PR2 will introduce an `auditd` ruleset as the primary
> trace, so any process that escapes the recorder still produces a
> syscall log. Tracked separately.

## See Also

- [README.md](../README.md) - Main documentation
- [Hardening](hardening.md) - Session containment configuration
- [Security Architecture](security/00-architecture.md) - Security implementation details
- [SECURITY.md](../SECURITY.md) - Security policy and reporting
- [Bastion Architecture](bastion-architecture.md) - Overall bastion design
