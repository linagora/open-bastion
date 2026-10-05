ob-session-monitor
==================

Synopsis
--------

::

   ob-session-monitor

Not run directly. Started by :manpage:`systemd(1)` as the
``ob-session-monitor.service`` unit, installed with the Desktop SSO
components.

Description
-----------

``ob-session-monitor`` revalidates sessions that were opened offline. A
desktop login served from the offline credential cache leaves a marker
under ``/run/open-bastion/offline_sessions/`` naming the user and the
moment of the login; the marker is what tells the desktop stack that the
session was not authorized by the portal.

Every 60 seconds the service checks that the network is up and that the
portal answers, then walks the markers:

* when the user has no session left, the marker is removed without asking
  the portal anything;

* when the portal reports the user as valid, the session is left alone —
  but once the marker is older than ``offline_revalidation_grace``, the
  user is appended to the force-online file, so that user's next
  authorization goes to the portal instead of the cache;

* when the portal reports the user as gone, every session of that user is
  terminated with :manpage:`loginctl(1)` and the marker is removed.

Only a positive answer terminates a session. An unreachable portal, an
HTTP error, an expired server token (``401``/``403``) or a reply that
cannot be parsed all count as "no answer": the session is left alone and
the marker stays. That tolerance is itself bounded — after
``offline_max_sso_unreachable``, all offline sessions are terminated. The
same bound applies when the network is up but the portal stays
unreachable, which may be a firewall bypass rather than an outage.

The ``POST`` to the portal's ``/pam/userinfo`` endpoint is signed and
carries the host's server token as a Bearer credential, like the other
``/pam/`` calls; see :doc:`openbastion.conf(5) <openbastion.conf>` for the
settings involved.

Each decision is logged through :manpage:`syslog(3)` under the
``ob-session-monitor`` tag: informational lines at ``auth.info``,
transient failures at ``auth.warning`` and terminations at ``auth.crit``,
so every session the service ends is accounted for.

Configuration
-------------

Settings are read from ``/etc/open-bastion/openbastion.conf``:

``portal_url``
   Base URL of the portal. Required; the service exits 1 when it is
   missing or does not start with ``http://`` or ``https://``.

``offline_revalidation_enabled``
   Set to ``false``, ``0`` or ``no`` to leave offline sessions alone; the
   service then exits 0.

``offline_revalidation_grace``
   Age past which an offline session's next authorization is forced
   online. Default: ``14400`` seconds (four hours).

``offline_max_sso_unreachable``
   Longest time the portal may be unusable before offline sessions are
   terminated. Default: ``3600`` seconds (one hour).

``server_token_file``
   File holding the host's server token, sent as a Bearer credential on
   each request. Without it the request goes unauthenticated and the
   portal's refusal is handled as "no answer".

``auth_cache_force_online``
   Path of the force-online file the service appends to. Default:
   ``/etc/open-bastion/force_online``.

Exit status
-----------

``0``
   revalidation is disabled in the configuration

``1``
   ``curl``, ``jq`` or :manpage:`loginctl(1)` is missing, or
   ``portal_url`` is missing or malformed

Files
-----

``/etc/open-bastion/openbastion.conf``
   Configuration file.

``/run/open-bastion/offline_sessions/``
   Markers of sessions opened offline, one file per user, mode ``0700``.
   Written by the PAM module and removed when the session ends, by it or
   by this service.

``/etc/open-bastion/force_online``
   Default force-online file, appended under an exclusive lock on
   ``/run/open-bastion/force_online.lock`` so concurrent appends cannot
   duplicate or interleave lines. An empty file forces every user online,
   a file listing usernames forces only those users.

Security
--------

The service runs as root from a unit that keeps ``/etc`` read-only except
for ``/etc/open-bastion`` — where the force-online file lives — and
``/run/open-bastion``. It never terminates a session on a guess: only the
portal answering that the user is gone counts as a revocation, and an
expired server token is reported as unusable credentials, distinguishable
in the logs from a real revocation. When the portal stays unusable past
``offline_max_sso_unreachable``, the service ends the offline sessions
rather than keep them alive indefinitely.

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-desktop-setup(8) <ob-desktop-setup>`,
:doc:`ob-cache-admin(8) <ob-cache-admin>`,
:manpage:`loginctl(1)`

Author
------

Xavier Guimard <xguimard@linagora.com>
