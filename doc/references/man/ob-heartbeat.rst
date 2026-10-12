ob-heartbeat
============

Synopsis
--------

::

   ob-heartbeat [OPTIONS]

Description
-----------

``ob-heartbeat`` sends a heartbeat signal to the LemonLDAP::NG server to
report that this server is still active and using PAM authentication.

The heartbeat allows administrators to monitor enrolled servers and detect
"ghost" servers that have uninstalled the PAM module without proper
unenrollment.

Each heartbeat also reports the open-bastion client version and the node
role (``node_role``: bastion, standalone or backend) so the SSO can track
what runs where.

Each heartbeat also reports the list of users currently connected on this
machine (user, source host, tty and login time), collected via
:manpage:`loginctl(1)` when systemd-logind is available, otherwise via
:manpage:`who(1)`. The SSO stores this list per machine so administrators
can see "who is connected" across the fleet. Reporting can be disabled
with the ``report_sessions`` configuration setting, and the number of
sessions sent in a single heartbeat is capped by ``max_reported_sessions``
(default 200; extra sessions are dropped and a warning is logged).

This script is typically run by a systemd timer (``ob-heartbeat.timer``)
every 5 minutes.

Signed answers and key rotation
-------------------------------

The ``POST`` to ``/pam/heartbeat`` is signed like every ``/pam/`` call
(``request_signing_secret``), and its answer is checked according to
``response_signing`` in :doc:`openbastion.conf(5) <openbastion.conf>`,
through :doc:`ob-verify-response(8) <ob-verify-response>`, with the same
rules as the PAM module: under ``required`` an unsigned or invalid answer
is refused and the access token is not updated; under ``prefer`` an
unsigned answer is used with a warning in syslog, a signed one that does
not verify is refused. A signed answer without ``aud`` is only accepted as
a refusal.

A verified heartbeat answer — signed by a key of ``sso_jwks_file``,
addressed to this host's ``client_id``, HTTP 200 — carries the portal's
current signature keys. When they differ from ``sso_jwks_file``, and at
least one of them is usable, ``ob-heartbeat`` replaces the file
atomically (a temporary file in the same directory, ``root:root``, mode
``0644``, in canonical form, renamed over it) and logs at ``auth.info``
the old and new key ids and fingerprints — the SHA-256 of the canonical
form, which ``jq -S -c . sso-jwks.json | sha256sum`` gives and the
``--sso-jwks-sha256`` of :doc:`ob-bastion-setup(8) <ob-bastion-setup>`
takes. Nothing else ever replaces it: not an unsigned answer, not an
answer signed by an unknown key (no JWKS is ever fetched on an unknown
``kid``), not an answer without ``aud``, and nothing at all under
``response_signing = off`` or when the file does not exist yet.

``ob-heartbeat.service`` may only write under ``/var/lib/open-bastion``
(``ProtectSystem=strict``, ``ReadWritePaths=/var/lib/open-bastion``), so
only a ``sso_jwks_file`` there — the default,
``/var/lib/open-bastion/jwks/sso-jwks.json`` — can be rotated. One placed
elsewhere (under ``/etc``, for instance) is still read, but a rotation
fails: the run exits 1 with ``Cannot create a file in <directory>`` in
syslog and the file is kept. Any key set that cannot be installed fails
the run likewise: the host would otherwise lock itself out at the
portal's next key switch.

Without ``/usr/lib/open-bastion/ob-sign-lib.sh`` (a broken install),
nothing can check an answer: under ``response_signing = off``, or with
no such key, the heartbeat is sent unsigned and its answer used as before
signed answers existed, so that the host keeps its token; under any
other value, including an unknown one or an unreadable configuration, no
heartbeat is sent and the run exits 1.

Runs are serialised by a lock on the token file's directory; a run that
cannot take it within 60 seconds gives up and exits 1.

Options
-------

.. option:: -c, --config FILE

   Read settings from config file. Default:
   /etc/open-bastion/openbastion.conf

.. option:: -t, --token-file FILE

   Server token file. Default: ``/var/lib/open-bastion/token``

.. option:: -d, --debug

   Enable debug logging.

.. option:: -h, --help

   Show help message and exit.

.. option:: -V, --version

   Show version and exit.

Examples
--------

Send a heartbeat manually:

::

   sudo ob-heartbeat

Check heartbeat timer status:

::

   systemctl status ob-heartbeat.timer

Files
-----

``/etc/open-bastion/openbastion.conf``
   Main configuration file for the PAM module.

``/var/lib/open-bastion/token``
   Server token file containing access and refresh tokens.

``/var/lib/open-bastion/``
   Directory for storing statistics and state.

``/var/lib/open-bastion/jwks/sso-jwks.json``
   The portal's signature keys (``sso_jwks_file``): read to verify the
   answer, replaced on a verified key rotation.

Exit status
-----------

``0``
   Heartbeat sent successfully.

``1``
   Heartbeat failed (missing token, network error, refused or unverifiable
   answer, a rotated JWKS that could not be installed, etc.)

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-verify-response(8) <ob-verify-response>`,
``pam_openbastion``,
:manpage:`systemd.timer(5)`

LemonLDAP::NG documentation: https://lemonldap-ng.org/
