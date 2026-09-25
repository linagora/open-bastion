Canonical names and paths
=========================

A single place to check a path, a unit name or a package name before writing it into a document or a runbook. Every row here was read out of the source that produces it — the file named in the last column is the authority. **If a document disagrees with this table, this table is right and the document is a bug.**

Packages
--------

+--------------------------+-----------------------------------------------+----------------------------------------------------------------------+
| Name                     | Where                                         | Contents                                                             |
+==========================+===============================================+======================================================================+
| ``open-bastion``         | ``debian/control``, ``rpm/open-bastion.spec`` | Everything: PAM module, **NSS module**, setup scripts, user commands |
+--------------------------+-----------------------------------------------+----------------------------------------------------------------------+
| ``open-bastion-builder`` | ``debian/control``                            | ``ob-builder`` (fleet installer generator)                           |
+--------------------------+-----------------------------------------------+----------------------------------------------------------------------+
| ``open-bastion-desktop`` | ``debian/control``, ``%package desktop``      | LightDM greeter for Desktop SSO                                      |
+--------------------------+-----------------------------------------------+----------------------------------------------------------------------+

There is **no** ``libnss-openbastion``, ``nss-openbastion`` or ``lightdm-openbastion-greeter`` package. ``libnss_openbastion.so`` ships inside ``open-bastion`` (``debian/open-bastion.install``), so ``apt install open-bastion`` is the whole install.

.. _reference-paths-ssh--certificate-paths:

SSH / certificate paths
-----------------------

+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| Path                                                    | What                                                                                      | Written by                                  |
+=========================================================+===========================================================================================+=============================================+
| ``/etc/ssh/open-bastion_ca.pub``                        | LLNG CA public key (``TrustedUserCAKeys``)                                                | ``ob-bastion-setup``, ``ob-backend-setup``  |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/etc/ssh/revoked_keys``                               | KRL (``RevokedKeys``), Mode E                                                             | ``ob-krl-refresh`` (setup, then its timer)  |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/etc/ssh/sshd_config.d/00-open-bastion-bastion.conf`` | bastion sshd drop-in — also the **role marker** the postinst looks for                    | ``ob-bastion-setup``                        |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/etc/ssh/sshd_config.d/00-open-bastion-backend.conf`` | backend sshd drop-in                                                                      | ``ob-backend-setup``                        |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/usr/local/sbin/ob-ssh-principals``                   | ``AuthorizedPrincipalsCommand`` helper — **generated at setup time, not a packaged file** | ``ob-bastion-setup``, ``ob-backend-setup``  |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/run/open-bastion/ssh-fp.sock``                       | deposit socket the helper reaches through ``ob-fp-submit``                                | ``ob-fp.socket`` (systemd)                  |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+
| ``/run/open-bastion/ssh-fp/<sshd-session-pid>.fp``      | fingerprint spool read by ``pam_openbastion`` — **``0700 root`` since #249**              | ``ob-fp-daemon``                            |
+---------------------------------------------------------+-------------------------------------------------------------------------------------------+---------------------------------------------+

``AuthorizedPrincipalsCommand`` takes **two** tokens on a bastion and **three** on a backend:

::

   # bastion
   AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f
   # backend  (%i = cert key-id, carries bastion=<id>)
   AuthorizedPrincipalsCommand /usr/local/sbin/ob-ssh-principals %u %f %i
   AuthorizedPrincipalsCommandUser nobody

Configuration and state
-----------------------

+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| Path                                                            | What                                                                             |
+=================================================================+==================================================================================+
| ``/etc/open-bastion/openbastion.conf``                          | main PAM/client configuration                                                    |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/open-bastion/nss_openbastion.conf``                      | NSS module configuration                                                         |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/open-bastion/session-recorder.conf``                     | ``ob-session-recorder`` configuration                                            |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/open-bastion/service-accounts.conf``                     | non-SSO automation accounts                                                      |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/open-bastion/service-accounts.d/<name>.pub``             | service-account public key, served to sshd by ``ob-service-account-keys``        |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/open-bastion/allowed_bastions``                          | backend allowlist of bastion ids (checked by ``ob-ssh-principals``, **pre-PAM**) |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/sudoers.d/open-bastion``                                 | ``%open-bastion-sudo ALL=(ALL) ALL`` — **regenerated by the setups**             |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/pam.d/sshd``, ``/etc/pam.d/sudo``, ``/etc/pam.d/sudo-i`` | PAM stacks — **regenerated by the setups**                                       |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/etc/pam.d/systemd-user``                                     | small account bridge **inserted** ahead of the distro stack (not regenerated)    |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/var/lib/open-bastion/token``                                 | enrolled server token (runtime state, refreshed by the heartbeat)                |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/var/lib/open-bastion/sessions/<user>/``                      | session recordings, ``root:ob-sessions`` ``0750``, owned by ``ob-record-sink``   |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+
| ``/var/log/open-bastion/audit.json``                            | structured audit log                                                             |
+-----------------------------------------------------------------+----------------------------------------------------------------------------------+

Templates shipped by the package
--------------------------------

+----------------------------------------+-----------------------+-------------------------------------------+
| Installed under                        | Source in this repo   | Consumed by                               |
+========================================+=======================+===========================================+
| ``/usr/share/open-bastion/hardening/`` | ``config/hardening/`` | ``ob-bastion-setup --enable-hardening``   |
+----------------------------------------+-----------------------+-------------------------------------------+
| ``/usr/share/open-bastion/audit/``     | ``config/audit/``     | ``ob-bastion-setup --enable-audit-trace`` |
+----------------------------------------+-----------------------+-------------------------------------------+
| ``/usr/share/open-bastion/logrotate/`` | ``config/logrotate/`` | copy to ``/etc/logrotate.d/`` (audit log) |
+----------------------------------------+-----------------------+-------------------------------------------+

systemd units
-------------

All unit names use the ``ob-`` prefix. There is no ``open-bastion-*.timer`` or ``open-bastion-*.service``.

+-----------------------------------------------+----------------------------------------------------------------------------------+
| Unit                                          | Role                                                                             |
+===============================================+==================================================================================+
| ``ob-heartbeat.timer`` / ``.service``         | keeps the server token fresh — **must be armed**, or the token expires overnight |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-record.socket`` / ``ob-record@.service`` | session-recording sink (``ob-record-sink``)                                      |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-cert.socket`` / ``ob-cert@.service``     | hop-certificate minting daemon (``ob-cert-daemon``)                              |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-session-prune.timer`` / ``.service``     | recording compression and retention                                              |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-krl-refresh.timer`` / ``.service``       | Mode E key revocation list refresh (``ob-krl-refresh``), every 30 min            |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-audit-rotate.timer`` / ``.service``      | daily auditd log rotation (``--enable-audit-trace``)                             |
+-----------------------------------------------+----------------------------------------------------------------------------------+
| ``ob-session-monitor.service``                | connected-session reporting                                                      |
+-----------------------------------------------+----------------------------------------------------------------------------------+

``ob-cert.socket`` and ``ob-record.socket`` ship disabled (the package cannot know a host's role); ``ob-bastion-setup`` enables them, and the Debian ``postinst`` re-asserts them on upgrade for hosts that already carry the bastion sshd drop-in.

``ob-krl-refresh.timer`` and ``ob-audit-rotate.timer`` ship disabled too: the setup enables the first under ``--max-security`` and the second under ``--enable-audit-trace``. They replace the two cron jobs of 0.6 (``/etc/cron.d/open-bastion-krl``, ``/etc/cron.daily/open-bastion-audit-rotate``); no Open Bastion job runs from cron any more. A non-default schedule is a drop-in, ``/etc/systemd/system/<timer>.d/schedule.conf``.

Commands
--------

+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| Command                             | Package path  | Notes                                                                                                      |
+=====================================+===============+============================================================================================================+
| ``ob-bastion-setup``                | ``/usr/sbin`` | node setup, every role; defaults to ``bastion``                                                            |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-standalone-setup``             | ``/usr/sbin`` | **symlink to ``ob-bastion-setup``**; under this name the script defaults ``--node-role`` to ``standalone`` |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-backend-setup``                | ``/usr/sbin`` | **symlink to ``ob-bastion-setup``**; under this name the script defaults ``--node-role`` to ``backend``    |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-enroll``                       | ``/usr/sbin`` | device-authorization enrolment                                                                             |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-heartbeat``                    | ``/usr/sbin`` | token refresh (driven by ``ob-heartbeat.timer``)                                                           |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-session-recorder``             | ``/usr/sbin`` | ``ForceCommand`` wrapper                                                                                   |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-record-sink``                  | ``/usr/sbin`` | root recording sink                                                                                        |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-cert-daemon``                  | ``/usr/sbin`` | hop-certificate minting (socket-activated, ``SO_PEERCRED``)                                                |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-cache-admin``                  | ``/usr/sbin`` | offline cache inspection                                                                                   |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-session-prune``                | ``/usr/sbin`` | recording retention                                                                                        |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-krl-refresh``                  | ``/usr/sbin`` | Mode E key revocation list refresh (driven by ``ob-krl-refresh.timer``)                                    |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-ssh``, ``ob-scp``, ``ob-sftp`` | ``/usr/bin``  | bastion→backend hop with cert vouching                                                                     |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-ssh-cert``                     | ``/usr/bin``  | sign a user key at the portal                                                                              |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-bastion-id``                   | ``/usr/bin``  | print this bastion's server-assigned ``bastion_id``                                                        |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-cert-request``                 | ``/usr/bin``  | client of ``ob-cert-daemon``                                                                               |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+
| ``ob-record-connect``               | ``/usr/bin``  | recorder→sink connector                                                                                    |
+-------------------------------------+---------------+------------------------------------------------------------------------------------------------------------+

See also
--------

- :doc:`Administrator Guide </admin-guide>`
- :doc:`PAM Authentication Modes </pam-modes>`
- :doc:`Permissions map </permissions>`
