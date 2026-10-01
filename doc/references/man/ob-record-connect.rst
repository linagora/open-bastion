ob-record-connect
=================

Synopsis
--------

::

   ob-record-connect HEADER_JSON STREAM_PATH

Description
-----------

``ob-record-connect`` is the unprivileged half of the tamper-evident
session-recording flow. It is invoked by
:doc:`ob-session-recorder(8) <ob-session-recorder>` (running as the logged-in
user); you do not normally run it by hand.

It connects to the local Unix socket served by
:doc:`ob-record-sink(8) <ob-record-sink>` (default
``/run/open-bastion/rec.sock``). If it cannot connect it exits non-zero
**before** reading any stream, so the recorder can fail closed (refuse the
session) before a shell starts. On success it writes the one-line JSON
metadata ``HEADER_JSON`` to the socket and waits for a one-byte
acknowledgement the sink sends only once it has created the session's metadata
and recording file. If the sink closes without it — because it rejected the
header (oversized, wrong version, a duplicate session id) or could not create
the files — the connector exits non-zero **without** opening
``STREAM_PATH``, and prints nothing on stdout, so the recorder refuses the
session. On the ACK it prints ``OB_READY`` on stdout (which the recorder waits
for), then opens ``STREAM_PATH`` and copies it to the socket in
length-prefixed frames until EOF. After a clean EOF, and only then, it sends
an empty end-of-stream frame and half-closes the connection; the sink
finalizes the recording as ``completed`` only when that frame arrives, so a
forwarder that is killed or crashes leaves an ``aborted`` recording rather
than one that looks whole.

``SIGHUP``, ``SIGINT`` and ``SIGQUIT`` are ignored: a hang-up is how a session
normally ends, and the forwarder must outlive it long enough to drain the
stream and send the end-of-stream frame. It still exits as soon as the writer
closes ``STREAM_PATH``; ``SIGTERM`` stops it.

For a PTY session, ``STREAM_PATH`` is a FIFO that :manpage:`script(1)` writes
the typescript to; for a metadata-only transfer session it is ``-`` (no
stream: the connector opens no path and sends only the end-of-stream frame, so
it can never read back a file it also writes to). A FIFO is used rather than
handing ``script`` the socket directly because ``script`` ``re-open()s`` its
typescript path and a Unix-domain socket cannot be opened via a path or
``/dev/fd`` (open() returns ``ENXIO``); a real FIFO inode opens fine. This
helper carries no privilege and holds no secret: the sink derives the recorded
user from the connection's ``SO_PEERCRED`` (kernel-verified), so the header
cannot make the sink write under another user's name.

Environment
-----------

``OB_RECORD_SOCKET``
   Override the socket path (default ``/run/open-bastion/rec.sock``).
   :doc:`ob-session-recorder(8) <ob-session-recorder>` always sets it to the
   system socket when it starts the connector, so a value in the recorded
   user's environment never reaches it.

``OB_RECORD_ACK_TIMEOUT``
   Seconds to wait for the sink's acknowledgement (default 15, clamped 1..60);
   intended for tests. The wait only bounds an unresponsive sink; the PTY path
   is additionally bounded by the recorder's own timeout.

Exit status
-----------

``0``
   The stream was forwarded, the end-of-stream frame sent, and the connection
   half-closed.

``1``
   Could not reach the sink, or an I/O error occurred. Recording is mandatory,
   so the caller fails closed.

``2``
   Usage error.

Files
-----

``/run/open-bastion/rec.sock``
   The session-recording socket (``ob-record.socket``).

See also
--------

:doc:`ob-record-sink(8) <ob-record-sink>`,
:doc:`ob-session-recorder(8) <ob-session-recorder>`

Author
------

Linagora
