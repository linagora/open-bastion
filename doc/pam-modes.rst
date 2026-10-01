Security scenario
=================

Open Bastion's default is **maximum security**: SSH access uses
certificates signed by the LLNG SSH CA, and ``sudo`` requires a temporary
LLNG token. It is the scenario the :doc:`security study </security/index>`
covers, and the default answer of the ``ob-builder`` questionnaire.

Four other scenarios trade strictness for compatibility — for a
transition period, or for a host that must keep Unix passwords or bare
SSH keys. They are described in :doc:`other-security-scenarios`.

In short
--------

* SSH accepts certificates signed by the LLNG SSH CA, and nothing else.
  Unsigned keys are refused (``AuthorizedKeysFile none``) and so are
  passwords, both by ``sshd`` and by the PAM stack.
* ``sudo`` asks for a temporary LLNG token, with the ``sudo_allowed``
  flag checked live on every elevation.
* A key revocation list is fetched at setup time and refreshed every
  30 minutes.
* Each bastion-to-backend hop uses a short-lived certificate vouched by
  the bastion, so a backend accepts only the bastion's connections.
* It is the default answer to ``ob-builder``'s "Security scenario"
  question, and ``--max-security`` on a single host.

Prerequisites
-------------

* The ``ssh-ca`` and ``pam-access`` plugins enabled on the LLNG portal.
* A key revocation list configured in LLNG (``/ssh/admin``).
* ``ob-ssh-cert`` deployed on user workstations, and one certificate per
  user.

What the setup scripts write
----------------------------

``ob-bastion-setup --max-security`` — and ``ob-backend-setup`` on a
backend — configure everything. Besides enrolling the host with LLNG:

* ``/etc/ssh/sshd_config.d/60-max-security.conf`` — the ``sshd`` drop-in
  that restricts SSH to certificates, requires the revocation list and
  wires the principals helper. Its contents are listed in
  :doc:`/references/maximum-security`.
* ``/etc/pam.d/sshd`` — LLNG authorization, home directory creation and
  session registration for SSO users.
* ``/etc/pam.d/sudo`` — LLNG token only.
* ``/etc/sudoers.d/open-bastion`` — the ``open-bastion-sudo`` group and
  its rights.
* ``/etc/ssh/revoked_keys``, refreshed by ``ob-krl-refresh.timer``.
* ``/usr/local/sbin/ob-ssh-principals`` — the
  ``AuthorizedPrincipalsCommand`` helper behind the :ref:`SSH fingerprint
  binding <pam-modes-ssh-fingerprint-binding-on-pamauthorize-and-pamverify>`.
* ``/etc/pam.d/systemd-user`` — an ``account`` bridge so SSO users can
  start ``user@.service`` (:doc:`/permissions`).

.. _pam-modes-pam-configuration-for-sshd:

PAM configuration
-----------------

The setup scripts write this stack for ``sshd`` in every scenario; only
``--max-security`` adds the ``sshd`` drop-in above, and replaces the
``sudo`` stack with the token-only one below.

.. code:: text

   # /etc/pam.d/sshd   (bastion / standalone)
   auth       required     pam_deny.so

   account    required     pam_openbastion.so ssh_cert_aware=true

   session    optional     pam_mkhomedir.so skel=/etc/skel umask=0077
   session    required     pam_unix.so
   session    optional     pam_openbastion.so
   session    optional     pam_systemd.so

On a backend the session block differs, because the module creates the
account instead of only managing groups:

.. code:: text

   # /etc/pam.d/sshd   (backend)
   session    required     pam_openbastion.so create_user=true
   session    required     pam_unix.so
   session    optional     pam_systemd.so

The ``auth`` stack denies on purpose: ``sshd`` validates certificates
itself and never calls ``pam_authenticate()`` on that path, so anything
reaching it is a password attempt, which this scenario refuses.

Two session lines are load-bearing. ``pam_openbastion`` manages the
``open-bastion-sudo`` group from the SSO's ``sudo_allowed`` flag, so
dropping it breaks ``sudo`` for SSO users. ``pam_systemd`` registers the
session with ``systemd-logind``; without it, ``who``, ``w``,
``loginctl`` and the heartbeat's connected-users report do not see the
session.

``ssh_cert_aware=true`` is accepted but ignored by the module today.

Sudo
----

.. code:: text

   # /etc/pam.d/sudo
   #
   # Unix passwords are rejected; only an LLNG temporary token is accepted.
   # pam_unix.so is deliberately absent from the account phase: SSO users
   # exist only in NSS, so its shadow check would refuse them.
   auth       sufficient   pam_openbastion.so
   auth       required     pam_deny.so

   account    required     pam_openbastion.so

   session    required     pam_unix.so

Sudo rights come from ``/etc/sudoers.d/open-bastion``, which grants the
``open-bastion-sudo`` group. The module maintains that membership from
the SSO's ``sudo_allowed`` flag while the session is set up, so a user
removed from the group in LLNG loses ``sudo`` at the next login.

``sudo`` keeps its own timestamp cache — 15 minutes by default on Debian,
re-armed on each use — so an operator working continuously is not prompted
for a token on every command. To require one at every elevation, pass
``--enable-sudo-fresh-otp`` to the setup script; see
:doc:`/references/maximum-security` for what that changes and what it
costs.

Selecting it
------------

``ob-builder`` proposes maximum security as the default answer to its
"Security scenario" question, and bakes it into the generated installer
and Ansible role. On a single host:

.. code:: bash

   sudo ob-bastion-setup --portal https://auth.example.com \
        --server-group bastion --max-security

Learn more
----------

* :doc:`/references/maximum-security` — the security model, the ``sshd``
  drop-in, the fingerprint binding, the revocation list and ``sudo``'s
  timestamp cache.
* :doc:`/admin-guide` — the deployment procedure, step by step.
* :doc:`/security` — the controls this scenario relies on, and what they
  do not cover.
