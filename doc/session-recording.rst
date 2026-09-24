SSH Session Recording
=====================

This document describes how to set up SSH session recording on a bastion host using ``ob-session-recorder``.

Overview
--------

The session recorder captures all terminal I/O during SSH sessions, creating a tamper-evident audit trail for compliance and incident investigation.

::

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

The recorded user has **no access** to the session files (cannot list, read, delete or truncate them — including their own recordings). See :doc:`/design/tamper-evident-session-recording` for the full design.

Installation
------------

The ``ob-session-recorder`` script is installed to ``/usr/sbin/`` with the PAM module package.

Dependencies
~~~~~~~~~~~~

- ``script`` command (from ``util-linux``, usually pre-installed)
- ``jq`` for JSON metadata generation
- ``uuidgen`` for UUID generation (fallback uses /proc/sys/kernel/random/uuid)

Note: ``asciinema`` and ``ttyrec`` are **not yet supported** over the recording sink in v1. The sink protocol accepts only ``script`` (typescript) format for now; see Recording Formats below.

.. code:: bash

   # Debian/Ubuntu
   apt-get install uuid-runtime jq

   # RHEL/CentOS
   dnf install util-linux jq

The ``ob-record-sink`` and ``ob-record.socket`` systemd units must be enabled on the bastion for recording to work:

.. code:: bash

   systemctl enable --now ob-record.socket

Configuration
-------------

Session Recorder Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create ``/etc/open-bastion/session-recorder.conf``:

.. code:: ini

   # Recording format:
   #   script    - Plain text typescript (default, v1 supported format)
   #   asciinema - JSON format, web-friendly (planned; not yet supported over the sink)
   #   ttyrec    - Binary format, compact (planned; not yet supported over the sink)
   # Any format other than "script" falls back to "script" in v1.
   format = script

   # Maximum session duration in seconds (default 86400; ob-bastion-setup
   # writes 28800, 8 hours).
   # Enforced by ob-session-recorder: at the limit it hangs the session up, as
   # a client disconnect would, and kills what is left 5 s later. The stream
   # is fully delivered, so the recording is "completed"; the timeout itself
   # is logged (journalctl -t ob-session-recorder). A value that is not a
   # number of seconds falls back to the default, with an error in the log.
   # Set to 0 to disable (not recommended)
   max_duration = 86400

Note: ``sessions_dir`` is no longer read by the recorder. The storage path is owned and managed entirely by ``ob-record-sink`` (root).

The ``max_duration`` watchdog runs as the recorded user, like the rest of the recorder, and that user can kill it. The bound they cannot lift is the sink's own: ``ob-record-sink`` finalizes any recording as ``truncated`` after seven days (``OB_RECORD_MAX_SEC`` in the unit's environment, see ``ob-record-sink(8)``), and a session whose recording has ended is cut at its next output. Keep ``max_duration`` below that cap. Before 0.7.0 the watchdog did not work at all: it was a signal trap that bash deferred until the session itself had ended (`#287 <https://github.com/linagora/open-bastion/issues/287>`__).

SSH Server Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Edit ``/etc/ssh/sshd_config`` to force all sessions through the recorder:

Option A: Record all users except admins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: text

   # Record all sessions except for emergency admin access
   Match User *,!root,!admin
       ForceCommand /usr/sbin/ob-session-recorder

Option B: Record specific group only
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: text

   # Only record sessions for users in the "recorded" group
   Match Group recorded
       ForceCommand /usr/sbin/ob-session-recorder

Option C: Record all sessions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: text

   # Record all sessions (use with caution)
   ForceCommand /usr/sbin/ob-session-recorder

Restart SSH after changes:

.. code:: bash

   systemctl restart sshd

Recording Formats
-----------------

Script (Default)
~~~~~~~~~~~~~~~~

- **Format**: Plain text typescript
- **Extension**: ``.typescript``
- **Advantages**: No dependencies, always available, standard Unix tool
- **Replay**: ``cat recording.typescript`` or ``scriptreplay``

This is the default format because ``script`` is available on all systems.

.. _session-recording-asciinema-planned--not-yet-supported-over-the-recording-sink:

Asciinema (planned — not yet supported over the recording sink)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Format**: JSON (asciinema v2)
- **Extension**: ``.cast``
- **Advantages**: Web-friendly, can be replayed in browser, human-readable
- **Replay**: ``asciinema play recording.cast`` or web player

Asciinema support over the root sink is planned for a future release. In v1 any ``format = asciinema`` setting falls back to ``script``.

.. _session-recording-ttyrec-planned--not-yet-supported-over-the-recording-sink:

ttyrec (planned — not yet supported over the recording sink)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Format**: Binary
- **Extension**: ``.ttyrec``
- **Advantages**: Compact, efficient, standard format
- **Replay**: ``ttyplay recording.ttyrec``

ttyrec support over the root sink is planned for a future release. In v1 any ``format = ttyrec`` setting falls back to ``script``.

File transfers
--------------

``scp``, ``rsync`` and ``sftp`` speak a binary protocol that a terminal would corrupt, so they cannot run under ``script``: they run with raw input and output, and the sink records their **metadata only** (``"format": "transfer"``, an empty ``.typescript``). Because that means *not* recording the session's stream, the recorder only treats a command as a transfer when it is exactly what a genuine client sends:

+-----------------------------------+--------------------------------------------------------------------------------------------------------------------------+
| Client                            | ``SSH_ORIGINAL_COMMAND`` accepted                                                                                        |
+===================================+==========================================================================================================================+
| ``rsync`` 3.x                     | ``rsync --server [--sender] -FLAGS [--long-option[=value]...] . PATH...`` — rrsync's option list, without ``--daemon``   |
|                                   | and without ``-s`` (``--secluded-args`` would carry the real arguments past the check)                                   |
+-----------------------------------+--------------------------------------------------------------------------------------------------------------------------+
| ``scp -O`` (legacy protocol)      | ``scp [-v] [-r] [-p] [-d] -t|-f [--] PATH...``, one word per flag                                                        |
+-----------------------------------+--------------------------------------------------------------------------------------------------------------------------+
| ``scp``, ``sftp`` (sftp protocol) | the ``Subsystem sftp`` command sshd passes under ``ForceCommand``: ``internal-sftp`` or an ``sftp-server`` system path,  |
|                                   | with ``sftp-server``'s ``-e -R -f -l -u -d -p -P`` options                                                               |
+-----------------------------------+--------------------------------------------------------------------------------------------------------------------------+

Paths may carry what those clients send for the remote shell: backslash escapes (``my\ file``), a leading ``~`` and wildcards, which the recorder expands itself (pathname expansion only). Any unescaped shell metacharacter (``; & | < > ( ) $ ` ' " { } ! #``), any control character, or anything appended to one of these forms, and the command is **recorded as an ordinary session** instead, with a warning in the log (``journalctl -t ob-session-recorder``). A session that requested a terminal is never a transfer. A command that passes is executed as an argument vector, never through a shell, and the program is taken from a fixed root-owned path (``/usr/bin/rsync``, ``/usr/bin/scp``, the distribution's ``sftp-server``), never from the user's ``PATH``. ``internal-sftp`` runs that ``sftp-server`` binary.

A transfer client this does not recognise therefore fails the way any binary protocol fails in a terminal. ``rsync`` with ``--secluded-args`` (``-s``, or ``RSYNC_PROTECT_ARGS`` set) is the known case; so is a remote path using shell syntax (``$HOME``, quotes) rather than plain escaping.

Session Metadata
----------------

Each recording has an accompanying JSON metadata file (``.json``):

.. code:: json

   {
     "session_id": "550e8400-e29b-41d4-a716-446655440000",
     "user": "dwho",
     "client_ip": "192.168.1.100",
     "tty": "/dev/pts/0",
     "start_time": "2025-12-16T10:30:00Z",
     "end_time": "2025-12-16T11:45:23Z",
     "status": "completed",
     "original_command": "",
     "format": "script",
     "recording_file": "20251216-103000_550e8400-e29b-41d4-a716-446655440000.typescript",
     "hostname": "bastion.example.com",
     "version": "0.2.0"
   }

Metadata Fields
~~~~~~~~~~~~~~~

+----------------------+------------------------------------------------------------------------------+
| Field                | Description                                                                  |
+======================+==============================================================================+
| ``session_id``       | Unique UUID for the session                                                  |
+----------------------+------------------------------------------------------------------------------+
| ``user``             | Unix username                                                                |
+----------------------+------------------------------------------------------------------------------+
| ``client_ip``        | Client IP address (from SSH_CLIENT)                                          |
+----------------------+------------------------------------------------------------------------------+
| ``tty``              | TTY device                                                                   |
+----------------------+------------------------------------------------------------------------------+
| ``start_time``       | Session start (ISO 8601 UTC)                                                 |
+----------------------+------------------------------------------------------------------------------+
| ``end_time``         | Session end (ISO 8601 UTC)                                                   |
+----------------------+------------------------------------------------------------------------------+
| ``status``           | ``active``, ``completed``, ``truncated``, or ``aborted`` (all sink-observed) |
+----------------------+------------------------------------------------------------------------------+
| ``original_command`` | SSH_ORIGINAL_COMMAND if any                                                  |
+----------------------+------------------------------------------------------------------------------+
| ``format``           | Recording format used                                                        |
+----------------------+------------------------------------------------------------------------------+
| ``recording_file``   | Name of the recording file                                                   |
+----------------------+------------------------------------------------------------------------------+
| ``hostname``         | Bastion hostname                                                             |
+----------------------+------------------------------------------------------------------------------+
| ``version``          | ``ob-record-sink`` version (0.2.0: framed stream, see ``status``)            |
+----------------------+------------------------------------------------------------------------------+

What ``status`` means, as observed by the sink:

- ``completed``: the forwarder read the end of ``script``'s output and sent the end-of-stream marker, so the recording is whole. It says nothing about how the session ended -- logout, disconnect or ``max_duration`` -- nor about the last command's exit code.
- ``truncated``: the recording reached the 1 GiB byte cap or the sink's duration cap (7 days by default); the session loses its recording channel and is cut at its next output.
- ``aborted``: the stream stopped without its end-of-stream marker (the forwarder was killed or crashed, or the framing was malformed), or the process that opened the connection died while something else held it open. Before 0.7.0 a killed forwarder produced ``completed``, and a session silent for 30 s produced ``aborted`` (`#287 <https://github.com/linagora/open-bastion/issues/287>`__).
- ``active``: the session is still open, or the sink itself was killed.

Directory Structure
-------------------

::

   /var/lib/open-bastion/sessions/
   ├── dwho/
   │   ├── 20251216-103000_550e8400-...-440000.typescript
   │   ├── 20251216-103000_550e8400-...-440000.json
   │   ├── 20251216-143052_661f9511-...-551111.typescript
   │   └── 20251216-143052_661f9511-...-551111.json
   ├── rtyler/
   │   └── ...
   └── jsmith/
       └── ...

- Sessions root: mode ``0750``, owned ``root:ob-sessions``
- Per-user subdirectories: mode ``0750``, owned ``root:ob-sessions``, created by ``ob-record-sink``
- Recording and metadata files: mode ``0640``, owned ``root:ob-sessions``
- The recorded user is **not** a member of ``ob-sessions``; every path level is ``o-rwx``, so a user has **zero** DAC access to any recording — including their own. They cannot list, read, unlink or truncate.
- Auditors added to the ``ob-sessions`` group gain read-only access to all recordings.

Replaying Sessions
------------------

v1 writes ``.typescript`` payloads and a ``.json`` metadata file, and nothing else: ``ob-record-sink`` names every recording ``<ts>_<session-id>.typescript`` / ``.json``. There are no ``.cast`` or ``.ttyrec`` files to replay, whatever ``format`` is set to.

Script format (the only format in v1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   # View the raw typescript
   cat /var/lib/open-bastion/sessions/dwho/20251216-103000_*.typescript

   # Recordings older than recording_compress_after_days are gzipped
   zcat /var/lib/open-bastion/sessions/dwho/20251216-103000_*.typescript.gz

``scriptreplay`` needs a timing file, which the sink does not produce; the typescript is a plain byte stream of the session.

.. _session-recording-asciinema--ttyrec-planned:

Asciinema / ttyrec (planned)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the sink protocol carries them, ``asciinema play <file>.cast`` and ``ttyplay <file>.ttyrec`` will apply. Until then ``format = asciinema`` and ``format = ttyrec`` fall back to ``script`` with a warning in the log.

Security Considerations
-----------------------

Tamper-Evident Recording via Root Socket Sink
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Session recordings are written by ``ob-record-sink``, a root-privileged systemd socket-activated service. This design replaces the previous privilege-separation approach and provides genuine tamper-evident recordings.

Key security properties:

- ``ForceCommand`` points directly at ``/usr/sbin/ob-session-recorder``. The recorder runs under the user's own uid and streams the session to the root sink over a Unix socket (``/run/open-bastion/rec.sock``).
- The sink obtains the connecting user's identity via kernel ``SO_PEERCRED`` — never from anything the client sends. A user cannot spoof another user's identity or cause path traversal.
- All files are written **root-owned** (``root:ob-sessions 0640``) inside ``/var/lib/open-bastion/sessions/<user>/`` (``root:ob-sessions 0750``). The recorded user is not a member of ``ob-sessions`` and every level is ``o-rwx``, so the user has **no DAC right** to list, read, unlink, rename or truncate any recording — including their own.
- Recording is **fail-closed**: if the sink is unreachable, the session is refused. There is no fallback to a user-owned local file, which would re-introduce the deletion risk.
- A user who is root on a **backend** server cannot reach or alter the recordings: they live on the bastion (the mandatory transit point), root-owned.
- Root **on the bastion itself** is trusted and out of scope (see :doc:`Threat Model </design/tamper-evident-session-recording>`).

For the full design, protocol, and migration details see :doc:` </design/tamper-evident-session-recording>`.

Availability: fail-closed recording requires out-of-band rescue access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Recording is **fail-closed**, and ``ob-bastion-setup`` forces **every** session through the recorder (a global ``ForceCommand``, root included — Option C above). The consequence is an availability trade-off you must plan for: **anything that prevents a session from being recorded prevents the session itself.**

In particular, **a full disk is a lockout risk**. The recordings are written by the root sink under ``/var/lib/open-bastion/sessions``; when that filesystem fills up (including the root-reserved blocks the sink can use), writes fail with ``ENOSPC``. Depending on timing, a new connection is then either refused (fail-closed) or its recording is lost — and this applies to **interactive shells and ``scp``/``sftp`` transfers** (file transfers are fail-closed too). You can therefore be locked out of SSH exactly when you need to log in to free space.

**Always keep an administrative path that does not transit sshd's ``ForceCommand``** — a serial console, BMC/IPMI, or hypervisor / cloud-provider console (e.g. OVH KVM). Open Bastion only wires the recorder into sshd's ``ForceCommand``, and only reconfigures the ``sshd`` / ``sudo`` / ``sudo-i`` PAM stacks — it does **not** touch ``/etc/pam.d/login`` or ``/etc/pam.d/su``. A console login (and ``su -`` from it) therefore bypasses recording and remains usable to free space, restart ``ob-record.socket``, or otherwise recover. (The in-SSH alternative — exempting an admin account with ``Match User …,!admin``, Option A — leaves that account's sessions **unrecorded**, an audit/trust trade-off, and is not what ``ob-bastion-setup`` configures.)

Operational recommendations:

- **Monitor free space** on the recordings filesystem and alert well before full.
- Recordings are compressed and expired automatically — see :ref:`Retention and disk management <session-recording-retention-and-disk-management>` below.
- Put ``/var/lib/open-bastion/sessions`` on a **dedicated partition** so a full recordings store cannot also take down the host's root filesystem.

.. _session-recording-retention-and-disk-management:

Retention and disk management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because recording is fail-closed, unbounded recordings are an availability risk. ``ob-session-prune`` bounds the recordings store and runs daily from ``ob-session-prune.timer`` (enabled at install time; it no-ops on hosts without recordings). It has two stages, both configured in ``/etc/open-bastion/session-recorder.conf``:

+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+
| Key                               | Default | Effect                                                                                               |
+===================================+=========+======================================================================================================+
| ``recording_compress_after_days`` | ``1``   | ``gzip`` closed recording payloads older than N days (typescripts compress ~10–20×). ``0`` disables. |
+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+
| ``recording_retention_days``      | ``365`` | Delete recordings (payload + ``.json``) older than N days. ``0`` keeps them forever.                 |
+-----------------------------------+---------+------------------------------------------------------------------------------------------------------+

Notes:

- The ``.json`` metadata is left **uncompressed** so the index stays greppable; the recording payload (``.typescript``/``.cast``/``.ttyrec``) is what gets gzipped. ``gzip`` preserves the file mtime, so expiry still sees the true age.
- Deletion drops audit evidence, so every run that deletes anything is logged at ``notice`` level (``journalctl -t ob-session-prune``). The retention default is deliberately long; in a regulated context (e.g. SecNumCloud) set ``recording_retention_days`` to match your log-retention obligation, or ``0`` to never auto-delete and rely on capacity planning / archival instead.
- The job runs as root from a sandboxed oneshot service and only writes under ``/var/lib/open-bastion/sessions``, preserving the tamper-evident layout.

See ` <https://github.com/linagora/open-bastion/blob/main/man/ob-session-prune.8>`__.

File Permissions
~~~~~~~~~~~~~~~~

- Sessions directory: mode ``0750``, owned ``root:ob-sessions``
- Per-user subdirectories: mode ``0750``, owned ``root:ob-sessions`` (created by sink)
- Recording and metadata files: mode ``0640``, owned ``root:ob-sessions``
- Config file: ``/etc/open-bastion/session-recorder.conf``, mode ``0644`` (root-owned)

Storage Security
~~~~~~~~~~~~~~~~

- Store recordings on encrypted filesystem if possible
- Retention and compression are automatic — see :ref:`Retention and disk management <session-recording-retention-and-disk-management>`. Do **not** add a ``logrotate`` rule for the recordings tree: renaming root-owned recordings conflicts with the tamper-evident layout.
- Sensitive data may be captured (passwords typed in terminals)

Complementary primary audit trace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Session recording is a faithful pty replay, not an independent audit trail: a determined user can attempt to bypass the pty (via ``setsid``, ``at``, ``cron``, ``nohup``, ``systemd --user``). Recording files themselves are root-owned and the user has no access to alter or delete them (see Security Considerations above). For a kernel-level, tamper-evident syscall log covering ``execve``, outbound ``connect``, and writes to sensitive paths (including the recordings directory itself), enable the optional auditd-based trace — see :doc:`Primary Audit Trace </audit>`. It is opt-in (``ob-bastion-setup --enable-audit-trace``) and complementary to session recording, not a replacement.

Network Security
~~~~~~~~~~~~~~~~

When uploading to LLNG (future feature):

- Use TLS for all transfers
- Authenticate with server token
- Consider bandwidth implications

Troubleshooting
---------------

Check if recording is working
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   # Look for session files
   ls -la /var/lib/open-bastion/sessions/$USER/

   # Check syslog
   journalctl -t ob-session-recorder

Common Issues
~~~~~~~~~~~~~

+----------------------+-------------------------------------------------+------------------------------------------------------------------------------------------------+
| Issue                | Cause                                           | Solution                                                                                       |
+======================+=================================================+================================================================================================+
| No recording created | ForceCommand not active                         | Check sshd_config Match rules                                                                  |
+----------------------+-------------------------------------------------+------------------------------------------------------------------------------------------------+
| Empty recording      | Session ended immediately                       | Check for shell issues                                                                         |
+----------------------+-------------------------------------------------+------------------------------------------------------------------------------------------------+
| Permission denied    | Wrong directory permissions or sink not running | Check ``ob-sessions`` group, directory mode ``0750``, and that ``ob-record.socket`` is enabled |
+----------------------+-------------------------------------------------+------------------------------------------------------------------------------------------------+
| Format not available | asciinema/ttyrec not supported yet              | Use ``format = script`` (only format supported in v1)                                          |
+----------------------+-------------------------------------------------+------------------------------------------------------------------------------------------------+

Debug mode
~~~~~~~~~~

.. code:: bash

   # Test the recorder manually
   /usr/sbin/ob-session-recorder --help

   # Check configuration
   cat /etc/open-bastion/session-recorder.conf

Environment Variables
---------------------

**None, since 0.7.0.** The recorder runs as the recorded user, and a setting that user's environment could change is not a control: ``OB_MAX_SESSION=0`` switched the ``max_duration`` watchdog off, and ``OB_RECORDER_CONFIG`` let the session pick a configuration other than the administrator's (`#287 <https://github.com/linagora/open-bastion/issues/287>`__). ``OB_RECORDER_CONFIG``, ``OB_RECORDER_FORMAT``, ``OB_MAX_SESSION`` and ``OB_SESSIONS_DIR`` are therefore ignored. Settings come from the root-owned ``/etc/open-bastion/session-recorder.conf``, or from options on the ``ForceCommand`` line (``-c FILE``, ``-f FORMAT``), which only the administrator writes. The ``LLNG_*`` names documented before 0.5.0 were never read either.

For the same reason the recorder does not trust the user's ``PATH``, nor anything bash would import from the environment: it runs under ``bash -p`` (which ignores ``BASH_ENV``, ``SHELLOPTS``, exported functions and the like), sets ``PATH`` to the system directories before running any helper, takes ``ob-record-connect`` only from a root-owned ``/usr/bin`` or ``/usr/local/bin``, and passes the sink's socket path to it explicitly, so ``OB_RECORD_SOCKET`` in the session's environment is ignored as well.

Integration with LLNG
---------------------

Future releases will support:

- Automatic upload of recordings to LLNG portal
- Session listing and search in LLNG Manager
- Web-based session replay
- Session annotations and bookmarks

See issues #17-20 in the project backlog.

.. _session-recording-session-containment:

Session containment
-------------------

Recording the pty is necessary but not sufficient. An authenticated user can detach work from the recorded session with ``setsid nohup … &`` (the child re-parents to PID 1 and survives logout), or schedule deferred commands with ``at(1)`` / ``crontab(1)`` that run outside the wrapper entirely.

``ob-bastion-setup`` deploys a set of host-level configuration drop-ins that close these channels — pure system config, no new setuid binary:

- ``KillUserProcesses=yes`` in ``systemd-logind`` so any process owned by the user is killed when their last session ends, including ``setsid``-detached children.
- ``at.allow`` (empty) and ``cron.allow`` (root only) so non-sudo users cannot schedule deferred jobs. ``atd`` is masked.
- ``nproc`` cap (256, root unlimited) in ``/etc/security/limits.d/`` to contain fork bombs.

Verify post-deploy that no user has been opted out via ``loginctl enable-linger``:

.. code:: bash

   loginctl show-user <user> | grep Linger    # expected: Linger=no

The full rationale, deployment details, and re-enable instructions are in :doc:` </hardening>`.

   **Note:** the ``auditd`` primary trace shipped in v0.2.0. Enable it with ``ob-bastion-setup --enable-audit-trace`` (opt-in) so any process that escapes the recorder still produces a syscall log. See :doc:`Primary audit trace </audit>`.

See Also
--------

- `README.md <https://github.com/linagora/open-bastion/blob/main/README.md>`__ - Main documentation
- :doc:`Hardening </hardening>` - Session containment configuration
- :doc:`Security Architecture </security/00-architecture>` - Security implementation details
- `SECURITY.md <https://github.com/linagora/open-bastion/blob/main/SECURITY.md>`__ - Security policy and reporting
- :doc:`Bastion Architecture </bastion-architecture>` - Overall bastion design
