# SSH Session Recording

This document describes how to set up SSH session recording on a bastion host
using `llng-session-recorder`.

## Overview

The session recorder captures all terminal I/O during SSH sessions, creating
an audit trail for compliance and incident investigation.

```
User SSH → Bastion → [llng-session-recorder] → Backend Server
                              │
                              ▼
                     /var/lib/llng-sessions/
                              │
                              ▼
                    (future: upload to LLNG)
```

## Installation

The `llng-session-recorder` script is installed to `/usr/sbin/` with the
PAM module package.

### Dependencies

- `script` command (from `util-linux`, usually pre-installed)
- `jq` for JSON metadata generation
- Optional: `asciinema` for asciinema format support
- Optional: `ttyrec` for ttyrec format support
- Optional: `uuidgen` for UUID generation (fallback uses /proc/sys/kernel/random/uuid)

```bash
# Debian/Ubuntu
apt-get install uuid-runtime jq

# RHEL/CentOS
dnf install util-linux jq
```

## Configuration

### Session Recorder Configuration

Create `/etc/llng/session-recorder.conf`:

```ini
# Directory where recordings are stored
# Structure: sessions_dir/<username>/<timestamp>_<session_id>.<format>
sessions_dir = /var/lib/llng-sessions

# Recording format:
#   script    - Plain text typescript (default, always available)
#   asciinema - JSON format, web-friendly (requires asciinema)
#   ttyrec    - Binary format, compact (requires ttyrec)
format = script

# Maximum session duration in seconds
# Sessions exceeding this limit are terminated
# Set to 0 to disable (not recommended)
max_duration = 86400
```

### SSH Server Configuration

Edit `/etc/ssh/sshd_config` to force all sessions through the recorder:

#### Option A: Record all users except admins

```sshd_config
# Record all sessions except for emergency admin access
Match User *,!root,!admin
    ForceCommand /usr/sbin/llng-session-recorder
```

#### Option B: Record specific group only

```sshd_config
# Only record sessions for users in the "recorded" group
Match Group recorded
    ForceCommand /usr/sbin/llng-session-recorder
```

#### Option C: Record all sessions

```sshd_config
# Record all sessions (use with caution)
ForceCommand /usr/sbin/llng-session-recorder
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

### Asciinema

- **Format**: JSON (asciinema v2)
- **Extension**: `.cast`
- **Advantages**: Web-friendly, can be replayed in browser, human-readable
- **Replay**: `asciinema play recording.cast` or web player

Requires `asciinema` package to be installed.

Example header:
```json
{"version": 2, "width": 80, "height": 24, "timestamp": 1702742400, "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
```

### ttyrec

- **Format**: Binary
- **Extension**: `.ttyrec`
- **Advantages**: Compact, efficient, standard format
- **Replay**: `ttyplay recording.ttyrec`

Requires `ttyrec` package to be installed.


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
    "version": "1.0.0"
}
```

### Metadata Fields

| Field | Description |
|-------|-------------|
| `session_id` | Unique UUID for the session |
| `user` | Unix username |
| `client_ip` | Client IP address (from SSH_CLIENT) |
| `tty` | TTY device |
| `start_time` | Session start (ISO 8601 UTC) |
| `end_time` | Session end (ISO 8601 UTC) |
| `status` | `active`, `completed`, or `error:<code>` |
| `original_command` | SSH_ORIGINAL_COMMAND if any |
| `format` | Recording format used |
| `recording_file` | Name of the recording file |
| `hostname` | Bastion hostname |
| `version` | Recorder version |

## Directory Structure

```
/var/lib/llng-sessions/
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

- Permissions: `0700` on directories, `0600` on files
- Owner: The user who initiated the session
- Organization: One subdirectory per user

## Replaying Sessions

### Asciinema format

```bash
# Terminal replay
asciinema play /var/lib/llng-sessions/dwho/20251216-103000_*.cast

# Or use the web player (future LLNG integration)
```

### ttyrec format

```bash
ttyplay /var/lib/llng-sessions/dwho/20251216-103000_*.ttyrec
```

### Script format

```bash
# View the raw typescript
cat /var/lib/llng-sessions/dwho/20251216-103000_*.typescript

# Replay with timing (if timing file exists)
scriptreplay timing.txt recording.typescript
```

## Security Considerations

### File Permissions

- Session directory: `0700` (user-owned)
- Recording files: `0600` (user-owned)
- Config file: `0644` (root-owned)

### Storage Security

- Store recordings on encrypted filesystem if possible
- Consider log rotation and retention policies
- Sensitive data may be captured (passwords typed in terminals)

### Network Security

When uploading to LLNG (future feature):
- Use TLS for all transfers
- Authenticate with server token
- Consider bandwidth implications

## Troubleshooting

### Check if recording is working

```bash
# Look for session files
ls -la /var/lib/llng-sessions/$USER/

# Check syslog
journalctl -t llng-session-recorder
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No recording created | ForceCommand not active | Check sshd_config Match rules |
| Empty recording | Session ended immediately | Check for shell issues |
| Permission denied | Wrong directory permissions | `chmod 700 /var/lib/llng-sessions` |
| Format not available | ttyrec not installed | Install ttyrec or use asciinema |

### Debug mode

```bash
# Test the recorder manually
/usr/sbin/llng-session-recorder --help

# Check configuration
cat /etc/llng/session-recorder.conf
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LLNG_RECORDER_CONFIG` | Config file path |
| `LLNG_SESSIONS_DIR` | Override sessions directory |
| `LLNG_RECORDER_FORMAT` | Override recording format |
| `LLNG_MAX_SESSION` | Override max session duration |

## Integration with LLNG

Future releases will support:

- Automatic upload of recordings to LLNG portal
- Session listing and search in LLNG Manager
- Web-based session replay
- Session annotations and bookmarks

See issues #17-20 in the project backlog.

## See Also

- [README.md](../README.md) - Main documentation
- [SECURITY.md](../SECURITY.md) - Security considerations
- [Bastion Architecture](bastion-architecture.md) - Overall bastion design
