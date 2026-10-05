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

Exit status
-----------

``0``
   Heartbeat sent successfully.

``1``
   Heartbeat failed (missing token, network error, etc.)

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
:doc:`ob-enroll(8) <ob-enroll>`,
``pam_openbastion``,
:manpage:`systemd.timer(5)`

LemonLDAP::NG documentation: https://lemonldap-ng.org/

Author
------

Xavier Guimard <xguimard@linagora.com>
