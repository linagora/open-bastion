# Design: tamper-evident session recording (root socket sink)

Status: **proposed**.
Issues: [#151] (a user can delete/alter their own recordings), [#150] (`who`
does not show bastion sessions — solved as a side effect, see §11).
Repo: `open-bastion` only (no LLNG change).

## Threat model (agreed)

- **In scope:** an *unprivileged* user (no `sudo`/root) must not be able to
  delete, rename, truncate or otherwise alter the recording of their own
  session.
- **Out of scope:** root / a sudoer can always tamper. We do not try to defend
  against root (impossible without append-only media or remote shipping, which
  is a separate, later concern).

## Why the current mechanism cannot satisfy this

`ob-session-recorder` runs under the **user's own uid** (sshd drops privileges
before `ForceCommand`; the setgid wrapper only borrows gid `ob-sessions` to
create the directory, then `setregid()`s back to the user). So:

- the per-user dir is `user:ob-sessions 2770` — **owned by the user** → the user
  has `rwx` → can `unlink`/`rename` any entry (proven live: `CREATE/DELETE/RENAME OK`);
- the files are **owned by the user** → the user can `O_TRUNC` and rewrite them.

No permission-bit scheme fixes this: as long as the writing process shares the
user's uid, the bytes are born in the user's privilege domain. The owner can
always `chmod` the dir back, and `unlink` needs only write+exec on the *parent*
dir regardless of file ownership. On Linux the directory `setuid` bit is ignored
and `setgid` transfers only the *group*, never the owner. `chattr +a` on the dir
stops deletion but not truncation, and arming `+a`/`+i` on each file needs root
anyway (race + breaks `script`'s `O_TRUNC`). Conclusion: the data must cross into
a higher-privilege domain **at write time**.

## Chosen design: a root, socket-activated recording sink

Reuse the proven `ob-cert-daemon` pattern (systemd `Accept=yes` socket
activation + `SO_PEERCRED`). The user-side recorder produces the PTY stream as
today, but instead of writing a user-owned file it **streams to a Unix socket**;
a per-connection **root** handler writes the real file into a root-only tree the
user cannot touch.

```
  session (uid = user)                       systemd / root domain
  ┌───────────────────────────┐
  │ sshd → ob-session-recorder │
  │   connect /run/open-bastion/rec.sock ───▶ rec.socket (0666, Accept=yes)
  │   ① send header line (JSON)               └─▶ ob-record-sink  (root, per conn)
  │   ② script -q -e -f /dev/fd/3 -c $shell        - peer uid via SO_PEERCRED  ◀── authority
  │      (fd 3 = the socket) ─────────────▶        - resolve username from uid
  │                                                - mkdir .../sessions/<user> (root 0700)
  │   user types … rm, : > file … ✗ no access      - open <id>.cast (root 0600)
  └───────────────────────────┘                    - copy stream → file
                                                    - on EOF: write <id>.json (status/exit)
                                                    - (optionally) utmp/wtmp register
```

### Why this satisfies the threat model

- The recording file is created and owned by **root**, mode `0600`, inside
  `/var/lib/open-bastion/sessions/<user>/` owned `root:ob-sessions 0750` and the
  parent `0700 root`. The user's uid has **no DAC right** to list, read, unlink,
  rename or truncate it. The boundary is the kernel uid check — the most
  portable, hardest-to-misconfigure mechanism we have.
- It is **fail-closed-capable**: if the sink/socket is unavailable, the recorder
  can refuse the session (configurable, see §9) rather than silently dropping to
  an unprotected local file.
- No setuid, no new privilege model, no LSM dependency. Works identically on
  Debian and RHEL/Rocky.

## §1. The `SO_PEERCRED` authority (key security property)

The socket is world-connectable (`0666`) but the sink does **not** trust
anything the client says about *who* it is. It calls `getsockopt(SO_PEERCRED)`
to obtain the connecting process's kernel-verified `uid`, resolves it to a
username with `getpwuid`, and derives the storage path **from that** — exactly
as `ob-cert-daemon` derives the cert user. Therefore a user cannot write into
another user's session directory, spoof the `user` field, or path-traverse:
the `<user>` path component never comes from client input.

The username is validated against `^[a-z_][a-z0-9_.-]*$` (same regex as the
recorder/wrapper) before being used in a path; reject otherwise.

## §2. Wire protocol

A connection carries one session. It is **header line + opaque stream**:

1. **Header**: a single `\n`-terminated JSON object (cap **8 KiB**), e.g.
   ```json
   {"v":1,"client_ip":"203.0.113.5","ssh_tty":"/dev/pts/3",
    "format":"script","original_command":"...", "start":"2026-06-16T17:43:42Z"}
   ```
   The sink uses these only as **metadata** (never for the path or uid). Fields
   are length-checked and the JSON is parsed defensively; a malformed/oversized
   header → the sink logs and closes (fail-closed for that session).
2. **Stream**: everything after the first `\n` is the recording payload
   (typescript bytes for `format:"script"`, asciinema JSON for `"asciinema"`,
   etc.), copied verbatim to the output file until EOF (the user side closing
   the write half, `shutdown(SHUT_WR)`).

The sink imposes an overall **per-session byte cap** and an **idle/total
timeout** (mirrors `MAX_SESSION` and the `MAX_RESP`/`SO_RCVTIMEO` guards already
in `ob-cert-daemon`), to bound a hostile or runaway client. Exceeding the cap
finalizes the file as `status:"truncated-by-limit"` rather than letting it grow
unbounded (a DoS, explicitly logged).

## §3. How `script(1)` writes to the socket — the `/dev/fd` trick

`script` writes its typescript to a *file path* argument, not a stream. We give
it the socket connection as a file descriptor:

```sh
exec 3<>/run/open-bastion/rec.sock     # or socat/ob-record-connect opens fd 3
printf '%s\n' "$header_json" >&3       # ① header
script -q -e -f -c "$shell" /dev/fd/3  # ② script fopen()s the socket fd
```

`script` `fopen()`s `/dev/fd/3`, which on Linux resolves to the already-connected
socket — writes go straight to the sink. `-f` flushes after each write so the
sink (and any live `tail`-style monitor) sees output promptly. `-e` propagates
the child exit status (already adopted, commit `5c327f1`).

To keep this robust and avoid relying on the shell's `/dev/fd` handling, a tiny
unprivileged helper **`ob-record-connect`** (sibling of `ob-cert-request`) may
own the socket connect + header write, then `exec script … /dev/fd/3`. Decision
deferred to implementation; both are viable.

> Note: timing files. Plain `script` keeps timing in a separate `-t` stream.
> For v1 we record the typescript only (as today). asciinema/ttyrec, which embed
> timing in one stream, map cleanly onto "header + stream" and can be added
> without protocol change.

## §4. File-transfer sessions (scp / sftp / rsync — no PTY)

`is_file_transfer()` already detects these and runs them raw (no PTY) because a
PTY corrupts the binary protocol. They have **no stream to record**, only
metadata. In the new model the recorder still opens a connection and sends the
header with `format:"transfer"` and **no payload** (`shutdown(SHUT_WR)`
immediately after the header). The sink writes the `<id>.json` (command,
start/end, exit status) and a zero-byte placeholder, exactly like today's
`record_transfer`. The transfer itself continues to run on the user side with
raw stdio.

## §5. Metadata & exit status

The metadata file is owned by the **sink** (root), so it is tamper-evident like
the recording. The challenge is conveying the child's *exit status*, which is
only known on the user side after `script` returns — i.e. after the data stream
has already been sent. The data stream is opaque, so we cannot simply append a
status line to it (it would be indistinguishable from payload).

**Decision: a separate status connection.** After `script` returns, the recorder
opens a second connection to a dedicated `/run/open-bastion/rec-status.sock`
(also `Accept=yes`, root) and sends one small JSON line
`{"session_id":"…","end":"…","status":"completed"|"error:N"}`. The status sink
re-verifies the peer uid via `SO_PEERCRED` and updates **only** the matching
`<id>.json` it previously created for that same uid (no path or user from the
client). This keeps the recording stream pure and the metadata authoritative.

Lifecycle:

1. recorder → `rec.sock`: header (start metadata) + stream; the data sink writes
   `<id>.json` with `status:"active"` immediately, then the `.cast`/`.typescript`.
2. on stream EOF the data sink stamps `status:"completed"` (best-effort default,
   in case step 3 never arrives — e.g. the session was killed).
3. recorder → `rec-status.sock`: final `{session_id,status}`; the status sink
   overwrites `end`/`status` with the real child exit.

The session-id is generated by the recorder and sent in the header, so both
connections agree on which file to touch.

Alternative considered and rejected: a single length-prefixed framed protocol
(status as a trailing frame). Cleaner on the wire but less "rustique" and harder
to drive from `script`. This §5 status path is the main review point.

## §6. Storage layout & admin access

```
/var/lib/open-bastion/sessions/            root:root        0700   (parent, not traversable by users)
/var/lib/open-bastion/sessions/<user>/     root:ob-sessions 0750   (created by sink)
/var/lib/open-bastion/sessions/<user>/<ts>_<id>.cast   root:ob-sessions 0640
/var/lib/open-bastion/sessions/<user>/<ts>_<id>.json   root:ob-sessions 0640
```

- The **user** is not in `ob-sessions` and the parent is `0700 root`, so users
  have zero access to any recording (including their own).
- **Auditors** are added to the `ob-sessions` group → read-only access to all
  recordings (files `0640`, per-user dirs `0750`). A future `ob-sessions`
  review CLI can read them without root.
- Tighten further to `0600 root:root` if even group-read is undesirable; group
  read is the recommended default for practical audit.

## §7. systemd units

```ini
# ob-record.socket
[Socket]
ListenStream=/run/open-bastion/rec.sock
SocketMode=0666
Accept=yes

# ob-record@.service
[Service]
ExecStart=/usr/sbin/ob-record-sink
StandardInput=socket
StandardOutput=journal
User=root
# sandbox like ob-cert@.service:
ProtectSystem=strict
ReadWritePaths=/var/lib/open-bastion/sessions
PrivateTmp=yes
ProtectHome=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
```

`/run/open-bastion` stays `0711` (traverse-only) as already set by
`ob-bastion-setup`; the socket node is `0666`. A `tmpfiles.d` entry recreates
the directory across `/run` wipes (mirrors the cert socket).

## §8. Components & build

| Component | Priv | Role |
|---|---|---|
| `ob-session-recorder` (existing, modified) | user | produce the stream, open the socket, send header, stream via `script`, report status |
| `ob-record-connect` (new, optional) | user | connect socket + write header, `exec script … /dev/fd/3` |
| `ob-record-sink` (new) | root (socket-activated) | `SO_PEERCRED` → user, write root-owned files + metadata, enforce caps/timeouts |
| `ob-record.socket` / `ob-record@.service` (new) | — | socket activation |

Shared validators (`ob_valid_username`, `ob_read_line`, size caps) reuse
`ob_cert_proto.c`/`.h`. CMake/debian/rpm install the new binary + units + man
pages exactly like the `ob-cert-*` set (template already merged in #145).

## §9. Fail-open vs fail-closed (config knob)

`session_recording_required` (default **true** on Mode E, **false** otherwise):

- **required=true (fail-closed):** if the recorder cannot connect to the sink or
  the header is rejected, the session is **refused** (non-zero exit before the
  shell starts). No unrecorded shell on a host that promises recording.
- **required=false (fail-open):** log loudly and fall back to the *legacy*
  user-owned local file (today's behavior) so a sink outage doesn't lock anyone
  out. This is strictly weaker (the fallback file is user-deletable) and is for
  non-audit deployments only.

This knob is the operational counterpart to AppArmor's *inherent* fail-open,
and is the main reason the sink is preferred for an audit control.

## §10. Security considerations

- **Path safety:** `<user>` derived only from `SO_PEERCRED` + regex-validated;
  open the per-user dir with `O_DIRECTORY|O_NOFOLLOW` and create files with
  `O_CREAT|O_EXCL|O_NOFOLLOW` (no symlink following, no overwrite) — same
  hardening as the wrapper's `ensure_user_session_dir`.
- **Resource bounds:** header ≤ 8 KiB; per-session byte cap; idle + total
  timeouts; the `Accept=yes` model gives one process per connection so a stuck
  session cannot block others. (DoS is explicitly *out* of the security-review
  exclusions, but bounding it is good hygiene.)
- **No secrets in the stream:** the recording may capture whatever the user
  typed; files are `0640 root:ob-sessions` and never world-readable.
- **Concurrency:** session-id is a UUID; `O_EXCL` create avoids collisions.

## §11. Bonus: this also fixes #150 (`who`)

Because the sink runs as **root**, it (or a small helper it calls) can register
the session in `utmp`/`wtmp` at start and `DEAD_PROCESS` at end — something the
user-side recorder cannot do (no `utmp` group). With `ForceCommand`, OpenSSH
never writes a utmp entry (every session is a "command" execution, and `script`
hides the pty), so `who`/`w`/`last` show nothing today. Registering from the
sink, keyed on the session's `ssh_tty` (from the header) and the
`SO_PEERCRED` user, makes native session tooling work again **without** a
setgid-utmp binary. #150 thus folds into this work instead of needing its own
privileged component.

## §12. Defense-in-depth (optional, later)

AppArmor (Debian/SUSE) / SELinux (RHEL) profiles denying write/unlink on
`/var/lib/open-bastion/sessions/**` to everything except the sink add a second
layer. Not required (DAC already fully covers the threat model) and explicitly
*not* a substitute (LSMs fail-open). Track separately.

## §13. Migration

1. Ship `ob-record-sink` + units + recorder changes behind
   `session_recording_required=false` (fail-open) so existing hosts keep working.
2. `ob-bastion-setup`/`ob-backend-setup`: `systemctl enable --now
   ob-record.socket`; create the `root:root 0700` parent and `ob-sessions`
   group; migrate any legacy user-owned dirs to `root` ownership.
3. Flip Mode E to `required=true`.
4. Remove the user-owned-dir code path once all hosts are migrated.

## Open questions

- §5 status transport: second control connection vs framed protocol — pick one
  in review.
- `ob-record-connect` helper vs shell `/dev/fd` — measure reliability.
- utmp line naming for `who` (the script pty vs the sshd `SSH_TTY`).
- Keep timing data (separate `-t` stream / asciinema) in v1 or v2?

[#150]: https://github.com/linagora/open-bastion/issues/150
[#151]: https://github.com/linagora/open-bastion/issues/151
