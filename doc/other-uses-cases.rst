Other use cases
===============

The documented default is a bastion, with backends behind it. This page
covers the deployments that do not follow that pattern.

Standalone hosts
----------------

A standalone host is a single server users SSH into directly, with LLNG
authentication: no jump host, no hop, no second machine to coordinate. It
runs the same stack as a bastion — the PAM and NSS modules, session
recording, the security scenario — but it has no backend behind it and no
``allowed_bastions`` list to maintain.

It is the right shape for one server, or a few independent ones: a lab, a
small team's machine, a site with no internal network to jump through.

Deploying one
~~~~~~~~~~~~~

Everything in :doc:`/deployment/index` applies; only the role changes:

- with :doc:`ob-builder(1) </references/man/ob-builder>`, answer
  ``standalone`` to the target-role question, or set ``target_role:
  standalone`` in the ``--config`` file, and run the installer or the
  Ansible role it generates on the host;

- by hand, run :doc:`ob-standalone-setup(8)
  </references/man/ob-bastion-setup>` — a symlink to ``ob-bastion-setup``.

Users then log in with their SSO certificate exactly as they would on a
bastion; they simply have nowhere to hop afterwards.

.. warning::

   Setup rewrites ``sshd``, PAM and, under maximum security, the way
   ``sshd`` accepts keys. Run it from a console session, never from the
   one you are about to reconfigure.
