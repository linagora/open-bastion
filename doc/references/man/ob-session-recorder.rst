ob-session-recorder
===================

Synopsis
--------

::

   ob-session-recorder [-c FILE] [-f FORMAT] [-d DIR]
   ob-session-recorder -h|-v

Description
-----------

``ob-session-recorder`` is run by :manpage:`sshd(8)` as ``ForceCommand``
for every recorded session; it is not meant to be run by hand. It runs as
the recorded user. The recording itself is written by
:doc:`ob-record-sink(8) <ob-record-sink>`, a root service the user cannot
reach, so the user can neither read, alter nor delete it.

For an interactive session, or a command (``SSH_ORIGINAL_COMMAND``), it
starts :doc:`ob-record-connect(1) <ob-record-connect>`, which connects to
the sink and sends a one-line JSON header, then runs the user's shell or
command under :manpage:`script(1)`, whose typescript goes through a FIFO
to the connector and on to the sink. If the sink cannot be reached, the
session is refused: recording is mandatory.

A genuine file transfer cannot run under a terminal — its binary protocol
would be corrupted — so it runs with raw input and output, and the sink
records its metadata only (format ``transfer``). Because that means not
recording the session's stream, a command is only treated as a transfer
when it is exactly what a genuine client sends:

``rsync --server [--sender] FLAGS [--long-option[=value]...] . PATH...``
   with the option list of :manpage:`rrsync(1)`, minus ``--daemon`` and
   ``-s`` (``--secluded-args``).

``scp [-v] [-r] [-p] [-d] -t|-f [--] PATH...``
   the legacy protocol (``scp -O``), one word per flag.

``internal-sftp | sftp-server path [options]``
   the sftp subsystem, which sshd passes as ``SSH_ORIGINAL_COMMAND``
   under ``ForceCommand``; modern :manpage:`scp(1)` uses it too.
   ``internal-sftp`` runs the system ``sftp-server`` binary.

A receiving ``rsync`` or ``scp -t`` takes one path, a sender one or more.
Paths may use backslash escapes, a leading ``~`` and wildcards, which the
recorder expands itself (pathname expansion only). Any unescaped shell
metacharacter or control character, anything appended to these forms, or a
session that requested a terminal, and the command is recorded as an
ordinary session, with a warning in the log. A transfer is run as an
argument vector, never through a shell, and the program is taken from a
fixed root-owned path, never from ``PATH``.

Options
-------

.. option:: -c FILE, --config FILE

   Read the configuration from ``FILE`` instead of
   ``/etc/open-bastion/session-recorder.conf``.

.. option:: -f FORMAT, --format FORMAT

   Recording format. Only ``script`` is supported; ``asciinema`` and
   ``ttyrec`` fall back to it.

.. option:: -d DIR, --dir DIR

   Ignored. The storage path belongs to
   :doc:`ob-record-sink(8) <ob-record-sink>`. Accepted for compatibility.

.. option:: -h, --help

   Print a usage summary.

.. option:: -v, --version

   Print the version.

Configuration
-------------

``/etc/open-bastion/session-recorder.conf`` is read only if it is owned
by root and not writable by group or others.

``format``
   As ``-f``.

``max_duration``
   Maximum session duration in seconds (default 86400;
   :doc:`ob-bastion-setup(8) <ob-bastion-setup>` writes 28800). ``0``
   disables it. A value that is not a number of seconds falls back to the
   default, with an error in the log. At the limit the recorder kills
   :manpage:`script(1)` — or the transfer program — which closes the
   session's terminal as a client disconnect would; the recorder itself
   is killed if it has not finished 5 seconds later. The recording is
   delivered in full and ends ``completed``; the timeout is logged.

``sessions_dir``
   Ignored (see ``-d``).

``recording_compress_after_days`` and ``recording_retention_days`` belong
to :doc:`ob-session-prune(8) <ob-session-prune>`.

Environment
-----------

The recorder reads what sshd sets for the session:
``SSH_ORIGINAL_COMMAND``, ``SSH_CLIENT`` (client address, informational),
``SSH_TTY`` (whether a terminal was requested), ``HOME`` and ``SHELL``.

Nothing in the environment changes how, or whether, the session is
recorded. ``OB_RECORDER_CONFIG``, ``OB_RECORDER_FORMAT``,
``OB_MAX_SESSION`` and ``OB_SESSIONS_DIR`` are ignored since 0.7.0; so is
``OB_RECORD_SOCKET``, which the recorder sets itself for the connector.
The script runs under ``bash -p`` (no ``BASH_ENV``, no functions or shell
options imported from the environment), sets ``PATH`` to the system
directories, and takes ``ob-record-connect`` only from a root-owned
``/usr/bin`` or ``/usr/local/bin``. The username comes from the real uid,
never from ``USER``.

Files
-----

``/etc/open-bastion/session-recorder.conf``
   Configuration.

``/run/open-bastion/rec.sock``
   The sink's socket.

``/var/lib/open-bastion/sessions/USER/TIMESTAMP_ID.typescript``
   The recording, written by :doc:`ob-record-sink(8) <ob-record-sink>`,
   root-owned.

``/var/lib/open-bastion/sessions/USER/TIMESTAMP_ID.json``
   Its metadata, including the sink-observed status: ``completed``,
   ``truncated`` (byte or duration cap) or ``aborted`` (the stream
   stopped without its end-of-stream marker).

``/tmp/ob-rec.XXXXXXXXXX/stream``
   The FIFO between ``script`` and the connector, in a private directory
   removed when the session ends.

Limits
------

The recorder, the connector and ``script`` run as the recorded user, who
can kill them. Killing the connector is detected (the recording ends
``aborted``, and ``script`` dies at its next output); killing the
``max_duration`` watchdog is not prevented. The bound the user cannot
lift is the sink's own duration cap (see
:doc:`ob-record-sink(8) <ob-record-sink>`). A process detached from the
session with ``setsid`` escapes the terminal recording; see the session
containment settings of :doc:`ob-bastion-setup(8) <ob-bastion-setup>`.

Exit status
-----------

The exit status of the shell, command or transfer; 1 when the session is
refused because it cannot be recorded; 129 when the session was hung up
(client gone); 137 when ``max_duration`` ended it.

See also
--------

:doc:`ob-record-sink(8) <ob-record-sink>`,
:doc:`ob-record-connect(1) <ob-record-connect>`,
:doc:`ob-session-prune(8) <ob-session-prune>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:manpage:`script(1)`,
:manpage:`rrsync(1)`,
:manpage:`sshd_config(5)`

Author
------

Xavier Guimard <xguimard@linagora.com>
