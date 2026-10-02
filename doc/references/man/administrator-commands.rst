Administrator man pages
=======================

The commands an administrator runs on a bastion, on a backend, or — for
``ob-builder`` — on a workstation, to deploy a host, operate it and take it
out of service, and the file the PAM module reads its settings from. Each
has a man page of the same name.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Page
     - What it documents
   * - :doc:`openbastion.conf(5) <openbastion.conf>`
     - Every setting of ``/etc/open-bastion/openbastion.conf``: the portal
       and its client credentials, the authorization cache, rate limiting,
       user creation, the SSH key policy, CrowdSec, and the rest.
   * - :doc:`ob-bastion-setup(8) <ob-bastion-setup>`
     - Configure a server as a bastion, a standalone host or a backend.
       ``ob-backend-setup`` and ``ob-standalone-setup`` are the same command
       under the name of the role they default to.
   * - :doc:`ob-enroll(8) <ob-enroll>`
     - Enroll the host with the portal and store its server token, the step
       every other command needs.
   * - :doc:`ob-bastion-id(1) <ob-bastion-id>`
     - Print the identifier the portal gave this host, to be listed in a
       backend's ``allowed_bastions``.
   * - :doc:`ob-heartbeat(8) <ob-heartbeat>`
     - Renew the server token and report the host's state and connected
       users to the portal; runs from ``ob-heartbeat.timer``.
   * - :doc:`ob-krl-refresh(8) <ob-krl-refresh>`
     - Download the revoked-key list and install it for ``sshd``; runs from
       ``ob-krl-refresh.timer`` under maximum security.
   * - :doc:`ob-session-prune(8) <ob-session-prune>`
     - Compress and expire session recordings; runs daily from
       ``ob-session-prune.timer``.
   * - :doc:`ob-post-upgrade(8) <ob-post-upgrade>`
     - Finish a package upgrade: helper, tmpfiles rule, sockets and spool
       ownership.
   * - :doc:`ob-uninstall(8) <ob-uninstall>`
     - Take Open Bastion off the host, ready for package removal.
   * - :doc:`ob-cache-admin(8) <ob-cache-admin>`
     - Inspect, invalidate and unlock the offline credential cache.
   * - :doc:`ob-desktop-setup(8) <ob-desktop-setup>`
     - Configure a workstation to log in through LLNG with the LightDM
       greeter, offline login included.
   * - :doc:`ob-builder(1) <ob-builder>`
     - Generate a self-extracting installer or an Ansible role from a
       questionnaire, for deploying a fleet.

.. toctree::
   :hidden:

   openbastion.conf
   ob-bastion-setup
   ob-enroll
   ob-bastion-id
   ob-heartbeat
   ob-krl-refresh
   ob-session-prune
   ob-post-upgrade
   ob-uninstall
   ob-builder
   ob-cache-admin
   ob-desktop-setup
