Session containment hardening
=============================

When :doc:`ssh-session-recording` is enabled, an authenticated user can
still step out of the recorded session: detach a process from the pty
(``setsid nohup … &``), queue work with ``at`` or ``cron``, or fork-bomb
the host.

The ``--enable-hardening`` option of
:doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>` closes those
three channels with plain system configuration: no setuid binary, no patch
to PAM or ``sshd``.

It is opt-in, because it changes global system behaviour (``logind``,
``at``, ``cron``, process limits), which a setup script must not do
silently. Recommended on a dedicated bastion; leave it off on a
multi-purpose host.

What it deploys
---------------

.. list-table::
   :header-rows: 1
   :widths: 34 20 46

   * - File or setting
     - Written under
     - What it closes
   * - ``KillUserProcesses=yes``
     - ``/etc/systemd/logind.conf.d/open-bastion.conf``
     - ``logind`` reaps every process of a user when their last
       session ends, children re-parented to init included: a
       backgrounded shell does not survive ``exit``.
   * - ``nproc`` at 256
     - ``/etc/security/limits.d/open-bastion.conf``
     - A fork bomb saturates the host's process table for other users.
       Root is unlimited.
   * - An empty allow-list
     - ``/etc/at.allow``
     - Non-root users cannot queue a command with ``at(1)``; it would run
       later, outside the session.
   * - ``root`` and nothing else
     - ``/etc/cron.allow``
     - The same for ``crontab(1)``. Add the admins who need it.
   * - ``systemctl mask atd``
     - —
     - Takes the ``at`` daemon out of the picture, in case a distribution
       shipped it enabled.

The templates are installed by the package under
``/usr/share/open-bastion/hardening/``; the setup script reads them
there and writes the four files above, then reloads ``logind``. The
reload is non-disruptive: ``KillUserProcesses`` is consulted when a
session ends, so open sessions are not touched.

The service ``cron.service`` is not masked. It's not required by Open
Bastion but the host may have jobs of its own, and the allow-list is
enough to keep users out.

Linger defeats the reaping
--------------------------

A user with ``Linger=yes`` (``loginctl enable-linger``) keeps processes
after logout and can queue work with ``systemd-run --user --on-active=…``,
which escapes both ``KillUserProcesses`` and the allow-lists. The setup
therefore refuses to apply the hardening while any non-root user has
linger enabled, and lists them:

.. code:: bash

   loginctl disable-linger <user>          # for each user it listed
   ob-bastion-setup --portal https://… --enable-hardening

Service accounts and the nproc cap
----------------------------------

Build and CI accounts routinely exceed 256 processes (``make -j``,
``pytest -n auto``, container builds). The limits file exempts members of
the ``ob-service`` group:

::

   @ob-service hard nproc unlimited

The package does not create that group on purpose — an operator might
unknowingly add accounts to it later. To opt in:

.. code:: bash

   groupadd --system ob-service
   gpasswd -a ansible ob-service       # repeat for each service account

If the group does not exist, ``pam_limits`` ignores the line and everyone
but root stays capped.

Verifying
---------

.. code:: bash

   # logind picked the setting up (expect: b true)
   busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
       org.freedesktop.login1.Manager KillUserProcesses

   ulimit -u               # as a non-root user → ≤ 256
   cat /etc/at.allow /etc/cron.allow
   systemctl is-enabled atd 2>&1   # masked / not-found
   loginctl list-users     # nobody should have Linger=yes

The containment acceptance test, end to end:

.. code:: bash

   # From a workstation
   ssh user@bastion
   setsid nohup sleep 3600 &
   exit

   # From root on the bastion
   ps -u user | grep sleep        # → no output

If the process is still there, either ``logind`` was not reloaded or
the user has linger enabled.

Lifecycle of the deployed files
-------------------------------

The four files under ``/etc/`` are deployment artefacts of
``--enable-hardening``, not package configuration files:

- ``apt purge`` (or ``rpm -e``) does not remove them; delete them by hand
  if you no longer want the hardening;
- a package upgrade does not overwrite them either: re-run
  ``--enable-hardening`` to pick up a changed template (the script backs
  the existing file up first);
- the templates under ``/usr/share/open-bastion/hardening/`` are
  reinstalled on upgrade and must not be edited.

Turning parts back on
---------------------

Edit the deployed file in ``/etc/``, then reload what reads it:

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - To give back
     - Do this
   * - ``at(1)`` to a user
     - Add the user to ``/etc/at.allow``, then
       ``systemctl unmask atd && systemctl enable --now atd``.
   * - ``crontab`` to a user
     - Add the user to ``/etc/cron.allow``; ``cron.service`` is already
       running.
   * - Background processes
     - Remove ``/etc/systemd/logind.conf.d/open-bastion.conf`` and
       ``systemctl reload systemd-logind``. Discouraged on a bastion.
   * - A higher process cap
     - Add a drop-in that sorts after ``open-bastion.conf``
       (e.g. ``99-build.conf``).
