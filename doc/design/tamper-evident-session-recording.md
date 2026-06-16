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
  │                                                - mkdir .../sessions/<user> (root:ob-sessions 0750)
  │   user types … rm, : > file … ✗ no access      - open <id>.cast (root:ob-sessions 0640)
  └───────────────────────────┘                    - copy stream → file
                                                    - on EOF: write <id>.json (status/exit)
                                                    - (optionally) utmp/wtmp register
```

### Why this satisfies the threat model

- The recording file is created and **owned by root**, group `ob-sessions`, mode
  `0640`, inside `/var/lib/open-bastion/sessions/<user>/` (`root:ob-sessions
  0750`) under a parent that is also `root:ob-sessions 0750` (see §6 for the
  canonical layout and the stricter `root:root 0700/0600` variant). The recorded
  user is **not** a member of `ob-sessions`, so its uid has **no DAC right** to
  list, read, unlink, rename or truncate any recording — its own included. The
  boundary is the kernel uid check — the most portable, hardest-to-misconfigure
  mechanism we have.
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
it the socket connection as a file descriptor.

> **A POSIX shell cannot open an AF_UNIX socket.** `exec 3<>/path/to.sock` opens
> a regular file/FIFO, not a connected stream socket — it does **not** work for a
> Unix-domain socket. The connect therefore lives in a small C helper, not in the
> recorder shell script.

The canonical path is a tiny **unprivileged** helper **`ob-record-connect`**
(sibling of `ob-cert-request`): it `connect()`s the socket, writes the header
line, then `exec`s `script` with the connected fd:

```sh
# ob-session-recorder calls the helper, which connects + sends the header and
# then exec()s script onto the connected fd (passed as /dev/fd/N):
ob-record-connect "$header_json" -- \
    script -q -e -f -c "$shell" /dev/fd/3   # script fopen()s the socket fd
```

Inside `ob-record-connect` (C): `socket(AF_UNIX)` + `connect()` → fd 3,
`write(3, header)`, then `execvp` the trailing command. `script` `fopen()`s
`/dev/fd/3`, which on Linux resolves to the already-connected socket — writes go
straight to the sink. `-f` flushes after each write so the sink (and any live
monitor) sees output promptly; `-e` propagates the child exit status (already
adopted, commit `5c327f1`).

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

The metadata *file* is owned by the **sink** (root), so a user cannot edit it
after the fact. But we must be precise about what is sink-authoritative versus
client-reported:

- **Sink-authoritative** (the sink observes these directly): the *existence* of
  the recording, the recorded *stream bytes*, the *user* (`SO_PEERCRED`), the
  *start* (header receipt) and the *end* (stream EOF / connection close).
- **Client-reported** (inherently trusted only as much as the client): the
  child's **exit status**. It is only known on the user side after `script`
  returns — i.e. after the stream has already been sent — and any unprivileged
  user can connect to the status socket and report an arbitrary status for *their
  own* `session_id`. So the exit status is an *advisory* field, **not** a
  security guarantee. (The user can also just exit their shell with any code they
  like, so this leaks no authority they don't already have.)

**Decision: a separate status connection for the advisory exit code.** After
`script` returns, the recorder opens a second connection to a dedicated
`/run/open-bastion/rec-status.sock` (also `Accept=yes`, root) and sends one small
JSON line `{"session_id":"…","end":"…","status":"completed"|"error:N"}`. The
status sink re-verifies the peer uid via `SO_PEERCRED` and updates **only** a
`<id>.json` it previously created for that **same uid** (path derived from uid +
session-id, never from the client) — so a user can at worst rewrite the advisory
status of their *own* session, never another's, and never the stream. The data
stream stays pure.

Lifecycle:

1. recorder → `rec.sock`: header (start metadata) + stream; the data sink writes
   `<id>.json` with `status:"active"` immediately, then the `.cast`/`.typescript`.
2. on stream EOF the data sink stamps `status:"completed"` (sink-authoritative
   "session ended"; the default if step 3 never arrives — e.g. the session was
   killed).
3. recorder → `rec-status.sock`: advisory `{session_id,status}`; the status sink
   overwrites the `status` field with the client-reported child exit.

The session-id is a UUID generated by the recorder and sent in the header, so
both connections agree on which file to touch; being a UUID, another user cannot
guess it to target someone else's record (and the uid check blocks that anyway).

Alternative considered and rejected: a single length-prefixed framed protocol
(status as a trailing frame). Cleaner on the wire but less "rustique" and harder
to drive from `script`. This §5 status path is the main review point.

## §6. Storage layout & admin access

**Default layout (auditor group read):**

```
/var/lib/open-bastion/sessions/            root:ob-sessions 0750   (parent; o-rwx → users excluded)
/var/lib/open-bastion/sessions/<user>/     root:ob-sessions 0750   (created by sink)
/var/lib/open-bastion/sessions/<user>/<ts>_<id>.cast   root:ob-sessions 0640
/var/lib/open-bastion/sessions/<user>/<ts>_<id>.json   root:ob-sessions 0640
```

- The recorded **user is not in `ob-sessions`**, and every level is `o-rwx`
  (`0750`/`0640`), so a normal user has **zero access** to any recording,
  including their own — they cannot traverse the parent, list, read, unlink or
  truncate.
- **Auditors** are added to the `ob-sessions` group → read-only access. The
  parent **must** be group-traversable (`0750`, group `ob-sessions`) for this to
  work — a `0700 root:root` parent would block group members from reaching any
  `<user>/` dir. A future `ob-sessions` review CLI can then read recordings
  without root.

**Strict variant (no group read):** parent + per-user dirs `0700 root:root`,
files `0600 root:root`. Only root reads recordings. Choose this if even
auditor-group read is undesirable; it costs convenient non-root audit. The
group-read default is recommended for practical audit. **Pick one and apply it
consistently** in the sink and the setup scripts (the sink hard-codes the chosen
modes/owner; do not leave it configurable in a way that could relax to user
access).

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
# Must allow AF_INET/AF_INET6, not only AF_UNIX: the sink calls getpwuid(), which
# can resolve over the network via NSS (libnss_openbastion / SSSD / LDAP). The
# existing ob-cert@.service allows these for the same reason — mirror it, or
# username resolution breaks on real deployments.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
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

Being able to choose **fail-closed** is the main reason the sink is preferred for
an audit control: the integrity guarantee never silently disappears.

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
- **Migration symlink hijack (one-shot):** legacy per-user dirs are currently
  *user-writable*, so a user can pre-plant a symlink (`…/sessions/<me>` →
  `/etc`, say) before the migration step runs as root. A naïve `chown -R` /
  `install` would then have root write or chown *through* the symlink. The
  migration (§12) must apply the same `O_NOFOLLOW` discipline: refuse any
  per-user entry that is a symlink or not a directory, and recreate the tree
  root-owned rather than chown-in-place. After migration the parent is `0750`
  `o-rwx`, so the planting vector is closed for steady state.
- **Recordings are forgeable by their *own* purported owner (accepted limit):**
  because the socket is world-connectable and authenticated only by uid, a user
  can connect directly and stream arbitrary bytes that the sink persists as a
  root-owned recording *under their own name*, with no real SSH session. They
  cannot forge *another* user's recording (uid authority, §1) and they can
  already emit arbitrary terminal content in a genuine session, so impact is
  bounded — but "a recording exists / shows X" is **not** proof a real session
  occurred. Document this as a known non-repudiation limit; if stronger
  guarantees are needed, restrict the socket to a dedicated group and/or have
  `ForceCommand` inject a per-session nonce the sink correlates with sshd.

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

## §12. Migration

1. Ship `ob-record-sink` + units + recorder changes behind
   `session_recording_required=false` (fail-open) so existing hosts keep working.
2. `ob-bastion-setup`/`ob-backend-setup`: `systemctl enable --now
   ob-record.socket`; create the `ob-sessions` group and the `root:ob-sessions
   0750` parent; migrate any legacy user-owned dirs to root ownership **safely**
   — reject symlinked/non-dir entries (`O_NOFOLLOW`) and recreate root-owned
   rather than chown-in-place (see §10, migration symlink hijack).
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
