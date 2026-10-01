Administrator commands
======================

The commands an administrator runs on a bastion, on a backend, or — for
``ob-builder`` — on a workstation, to deploy a host, operate it and take it
out of service. Each has a man page of the same name.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Command
     - What it does
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
   * - :doc:`ob-builder(1) <ob-builder>`
     - Generate a self-extracting installer or an Ansible role from a
       questionnaire, for deploying a fleet.

.. toctree::
   :hidden:

   ob-bastion-setup
   ob-enroll
   ob-bastion-id
   ob-heartbeat
   ob-krl-refresh
   ob-session-prune
   ob-post-upgrade
   ob-uninstall
   ob-builder
