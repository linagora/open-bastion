Primary audit trace
===================

Session recording gives a faithful, replayable view of what a user did in
their pty. It is not an independent trail: it covers only what happens
inside that pty, it can be bypassed (``setsid``, ``at``, ``cron``,
``systemd --user`` — the :doc:`containment hardening </hardening>` closes
most of those paths), and a crash or a full disk can leave it partial.

The optional audit trace adds the kernel's own record. ``auditd`` logs the
syscalls of every PAM-authenticated user, tagged with the audit user id
(``auid``), which is set at login and survives ``setuid`` and deferred
execution: a child started by ``at`` two hours later still points back to
the original login. Recording answers "what did the user see and type?",
auditd answers "what did the kernel run on behalf of this login?". You
want both.

What it covers
--------------

- Every ``execve`` by a logged-in non-system user (``auid`` at least
  1000), including programs started by ``at``, ``cron`` or
  ``systemd --user``. The command line, working directory and credentials
  are logged before the program runs.

- Every outbound ``connect`` by such a user: reverse shells, back
  connections, unusual destinations.

- Writes and attribute changes on the sensitive files (``/etc/passwd``,
  ``/etc/shadow``, ``/etc/group``, ``/etc/gshadow``, ``/etc/sudoers`` and
  ``/etc/sudoers.d/``, ``/etc/ssh/sshd_config`` and its drop-ins), on the
  recordings directory and on ``/etc/open-bastion/`` — a user trying to
  rewrite their own ``.typescript`` lands there.

What it does not cover
----------------------

- File contents, and keystrokes inside an already running program: the
  rules record the syscall, not the data, which is what recording is for.

- Anything before login, and system processes (``auid`` under 1000 or
  unset): the rules exclude them on purpose, or they would drown the
  trail.

- Outbound UDP (``sendto``/``sendmsg``, the DNS-tunnel pattern) and
  traffic over ``io_uring``: only ``connect`` is traced, by design.
  Operators who need the rest can add ``-S sendto -S sendmsg`` to the
  rules and accept the volume.

Activation
----------

The audit trace is opt-in and off by default, like the hardening:

.. code:: bash

   sudo ob-bastion-setup \
       --portal https://auth.example.com \
       --enable-audit-trace

What the step does, in order:

1. Warns and skips if the ``auditd`` package is not installed (``apt
   install auditd``, or ``dnf install audit``); ``auditd`` is a
   ``Recommends``, never a hard dependency, so installing Open Bastion
   alone never flips a global system knob. Install it and re-run.

2. Asks for confirmation, unless ``--yes`` was given.

3. Enables ``ob-audit-rotate.timer``, the daily rotation, before anything
   else: with ``num_logs=7`` it gives about a week of logs, and if the
   timer cannot be armed the step stops before touching ``auditd``.

4. Installs ``/etc/audit/rules.d/open-bastion.rules`` from the template
   under ``/usr/share/open-bastion/audit/rules.d/``.

5. Loads the rules (``augenrules --load``) and restarts ``auditd``, which
   does not disturb active SSH sessions.

``/etc/audit/auditd.conf`` is deliberately left alone — a single
admin-tunable file owned by the distribution's ``audit`` package, where a
patch would turn the next package upgrade into a conffile prompt. Tuning
it is a manual step, below.

Verifying
---------

.. code:: bash

   auditctl -l                      # rules loaded
   ausearch -k ob-exec -ts recent | head -40
   ls -lh /var/log/audit/audit.log  # present and growing
   systemctl status auditd          # running, enabled at boot

Then log in as a non-system user, run any command, and look for the
record:

.. code:: bash

   ausearch -k ob-exec -x /usr/bin/whoami -ts today

There should be one ``type=EXECVE`` record per invocation.

Retention
---------

This is a required manual step: the distribution's defaults (often
``num_logs=5``, ``max_log_file=8``) keep only a few days on a busy
bastion. For about a week:

.. code:: bash

   sudo sed -i \
     -e 's/^max_log_file = .*/max_log_file = 50/' \
     -e 's/^num_logs = .*/num_logs = 7/' \
     -e 's/^max_log_file_action = .*/max_log_file_action = ROTATE/' \
     /etc/audit/auditd.conf
   sudo systemctl restart auditd

Further tuning, in the same file:

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Want
     - Setting
   * - A longer history
     - Raise ``num_logs`` (``num_logs = 30``).
   * - Bigger files
     - Raise ``max_log_file``, in MB.
   * - A warning before the disk fills
     - ``space_left = 500`` with ``space_left_action = SYSLOG``.
   * - Refuse to go on when full
     - ``disk_full_action = HALT`` (paranoid; the default is
       ``SUSPEND``).

Rotation is daily; on a quiet host, weekly gives a seven-times-longer
window for the same ``num_logs``:

.. code:: bash

   sudo systemctl edit ob-audit-rotate.timer
   # [Timer]
   # OnCalendar=
   # OnCalendar=weekly

The empty ``OnCalendar=`` is required: without it the drop-in adds a
weekly trigger to the daily one instead of replacing it.

Files
-----

.. list-table::
   :header-rows: 1
   :widths: 44 20 36

   * - Path
     - Comes from
     - Notes
   * - ``/usr/share/open-bastion/audit/rules.d/open-bastion.rules``
     - the package
     - Read-only template; do not edit, it is replaced on upgrade.
   * - ``/etc/audit/rules.d/open-bastion.rules``
     - the audit-trace step
     - The live copy. Edit this one if the rules must change.
   * - ``ob-audit-rotate.timer`` and ``.service``
     - the package
     - Shipped disabled, enabled by the step; schedule overridable with
       ``systemctl edit``.
   * - ``/etc/audit/auditd.conf``
     - the ``audit`` package
     - Yours to tune; Open Bastion never writes it.

As with the hardening drop-ins, the deployed copy and the timer's
enablement are deployment artefacts, not package conffiles: a purge does
not remove them, and an upgrade does not overwrite them.

Upgrading from the cron.daily script
------------------------------------

Up to 0.6 the rotation was a ``/etc/cron.daily/open-bastion-audit-rotate``
script that the package had copied there, and that copy keeps working
after an upgrade. ``ob-post-upgrade`` (or a new ``--enable-audit-trace``
run) replaces it with the timer, at the same daily or weekly schedule, and
deletes the script once the timer is active. A script without its
``Installed by ob-bastion-setup`` marker line is treated as yours and left
in place, with a warning: until it is removed, the log rotates twice.

Forwarding to a remote collector
--------------------------------

A bastion that can be compromised should not keep its only audit trail
locally. The ``audit`` package ships the ``audispd`` plugin framework:
``audisp-syslog`` (in ``audisp-plugins`` on Debian) forwards every record
to syslog, from where rsyslog or ``systemd-journal-upload`` can ship it
off-host, and vendor collectors for Splunk, Elastic or Wazuh hook into the
same socket. Open Bastion installs and configures none of this: where the
logs go, and how they are protected in transit, is a deployment decision.

Disabling
---------

.. code:: bash

   auditctl -D                        # until the next auditd restart

   rm /etc/audit/rules.d/open-bastion.rules
   systemctl disable --now ob-audit-rotate.timer
   augenrules --load
   systemctl restart auditd

Retention changes you made to ``auditd.conf`` are yours to revert, and are
harmless without the rules.

Volume
------

``execve`` and ``connect`` produce a lot of events on a busy bastion: an
interactive shell emits 50 to 500 ``execve``, a long ``rsync`` or Ansible
run thousands of ``connect``. With the recommended settings the audit log
caps around 350 MB; watch the free space under ``/var/log``. If that is
too much, drop the ``connect`` rule, alert earlier with ``space_left``,
trade ``max_log_file`` against ``num_logs``, or forward off-host and keep
less locally.

See also
--------

- :doc:`/ssh-session-recording` — the pty-level recording, the other half
  of the traceability story.
- ``auditd.conf(5)``, ``auditctl(8)``, ``ausearch(8)``, ``aureport(8)``.
