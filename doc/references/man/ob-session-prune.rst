ob-session-prune
================

Synopsis
--------

::

   ob-session-prune

Description
-----------

``ob-session-prune`` bounds the disk used by SSH session recordings. It
runs daily from the ``ob-session-prune.timer`` unit and performs two
stages:

1. Compress closed recording payloads (``*.typescript``, ``*.cast``,
   ``*.ttyrec``) older than ``recording_compress_after_days`` with
   :manpage:`gzip(1)`. The paired ``*.json`` metadata is left uncompressed
   so the index stays greppable.
2. Delete recordings (payload and ``*.json``) older than
   ``recording_retention_days``. Empty per-user directories are then
   removed.

Session recording is fail-closed: when recording is enabled, a full disk
refuses new logins. Unbounded recordings are therefore an availability
risk, which this tool mitigates. Expiry also drops audit evidence, so each
run that deletes anything is logged at ``notice`` level via
:manpage:`syslog(3)` (tag ``ob-session-prune``) for accountability, and the
retention default is deliberately long.

Configuration
-------------

Settings are read from the session-recorder configuration file
(``/etc/open-bastion/session-recorder.conf``, shared with
:doc:`ob-session-recorder(8) <ob-session-recorder>`):

``sessions_dir``
   Recordings tree (default ``/var/lib/open-bastion/sessions``). Must be an
   absolute path with a parent directory (it cannot be the filesystem
   root); otherwise the tool refuses to run.

``recording_compress_after_days``
   Compress payloads older than this many days (default ``1``). Set to
   ``0`` to disable compression.

``recording_retention_days``
   Delete recordings older than this many days (default ``365``). Set to
   ``0`` to keep recordings forever (compression still applies).

Files
-----

``/etc/open-bastion/session-recorder.conf``
   Configuration file.

``/var/lib/open-bastion/sessions/``
   Recordings tree, owned ``root:ob-sessions``, mode ``0750``.

Security
--------

Recordings are root-owned (``root:ob-sessions``, ``0640``) under a
root-owned tree. This tool runs as root from a sandboxed oneshot service,
so the tamper-evident layout is preserved: the recorded user never has
access to its own recordings.

See also
--------

:doc:`ob-session-recorder(8) <ob-session-recorder>`,
:doc:`ob-record-sink(8) <ob-record-sink>`,
:manpage:`gzip(1)`
