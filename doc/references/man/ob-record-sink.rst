ob-record-sink
==============

Synopsis
--------

::

   ob-record-sink

Description
-----------

``ob-record-sink`` is the privileged half of the tamper-evident
session-recording flow. It is socket-activated by systemd (one short-lived
instance per connection, ``ob-record.socket``) and is not run by hand. It runs
as ``root`` so that the recordings it writes cannot be read, deleted or
altered by the recorded (unprivileged) user.

For each connection it:

1. derives the recorded user from the connection's ``SO_PEERCRED``
   (kernel-verified). This is the only source of identity — never the header —
   so a caller can only ever record under its own name, and the ``<user>``
   path component is never client-controlled (no cross-user write, no path
   traversal).

2. reads a one-line JSON metadata header followed by the opaque recording
   stream (typescript bytes) until EOF, sent by
   :doc:`ob-record-connect(1) <ob-record-connect>`.

3. writes the recording and its metadata under
   ``/var/lib/open-bastion/sessions/<user>/`` — directory
   ``root:ob-sessions 0750``, files ``0640``. The recording file is created
   with ``O_NOFOLLOW`` and ``O_EXCL`` (no symlink, no clobber); the JSON
   metadata is created with ``O_NOFOLLOW`` and rewritten (``O_TRUNC``) when
   the session is finalized.

4. sends a one-byte acknowledgement to the connector once that metadata and
   recording file exist, and only then reads the stream. Every rejection
   before this point (oversized or malformed header, unsupported version,
   duplicate session id, a directory it cannot create) closes the connection
   without the ack, so :doc:`ob-record-connect(1) <ob-record-connect>` fails
   and the recorder refuses the session — recording can never be skipped by a
   header the sink declines.

The sink records only what it observes: status ``active`` then ``completed``
(clean EOF), ``truncated`` (byte cap or duration cap reached) or ``aborted``
(abnormal drop, or the connecting process died while the connection was held
open by something else). The child command's exit code is deliberately not
recorded — it would be entirely client-reported.

Silence is not an abnormal end: an interactive session may print nothing for
hours, so the stream has no idle timeout. The sink instead watches the process
that connected (the ``SO_PEERCRED`` pid, through a pidfd when the kernel
offers one, else :manpage:`kill(2)` with signal 0 at each idle wake-up), and
bounds every recording by a 1 GiB byte cap and a total duration cap. Only the
header must arrive within 30 seconds of the connection.

Threat model
------------

Root is trusted; the sink defends only against the unprivileged user
tampering with its own recordings. Defending against root requires an LSM,
append-only media or remote log shipping, which are out of scope.

Environment
-----------

``OB_SESSIONS_DIR``
   Override the base sessions directory (default
   ``/var/lib/open-bastion/sessions``). Read from the daemon's own
   environment, which is set by the systemd unit (never by the connecting
   client); intended for tests.

``OB_RECORD_MAX_SEC``
   Total duration cap of one recording, in seconds (default 604800, seven
   days). A recording that reaches it is finalized as ``truncated``, and the
   session loses its recording channel. Set it with a drop-in
   (``systemctl edit ob-record@.service``) if sessions may legitimately last
   longer; it should not be shorter than the recorder's ``max_duration``.

``OB_RECORD_POLL_SEC``
   How often, in seconds, an idle stream wakes the sink to check the peer and
   the duration cap (default 30). The tests set it to 1.

Files
-----

``/run/open-bastion/rec.sock``
   The session-recording socket (``ob-record.socket``).

``/var/lib/open-bastion/sessions/<user>/``
   Recordings and metadata (root-owned).

See also
--------

:doc:`ob-record-connect(1) <ob-record-connect>`,
:doc:`ob-session-recorder(8) <ob-session-recorder>`,
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`
