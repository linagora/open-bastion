Self-extracting installer
=========================

This guide takes you from nothing to a working bastion and backends
fleet thanks to self-extracting installers.

It uses the ``ob-builder`` command to generate one self-extracting
installer per role that administrators run on each target, bastion or
the backends host. No Ansible, no control node.
The flow is always the same three steps:

1. Generate one self-extracting installer per role — bastion or
backend — with ``ob-builder``.

2. Transfer an installer per target with ``scp``.

3. Run the installer on the targets.

``ob-builder`` runs once on your workstation. It talks to the SSO
portal to fetch the SSH CA public key and JWKS, then bakes them — plus
your scenario, ``client_id`` and package repository — into a single,
portable Bash script, the self extracting installer. The latter is
then copied to the target and run there; the targets never contact
your workstation again.

.. note::

   Looking for prefer fleet-wide, declarative deployments? Use the
   :doc:`Ansible deployment guide </deployment/ansible-deployment>`
   instead — same ``ob-builder``, same two-phase logic, driven from
   one inventory.

Prerequisites
-------------

- ``ob-builder`` on your workstation (ships in the
  ``open-bastion-builder`` package).

- A package repository (APT or YUM/DNF repository) containing
  `open-bastion` package must be reachable by the targets.

- SSO reachable from your workstation (at build-time, for OIDC
  discovery) and from the targets (at run time, for enrollment).

- SSH access from your workstation to each target as a user that can
  run ``sudo`` to obtain root privileges.

- The ``pam-access`` OIDC Relying Party configured on the LLNG portal
  for device enrollment — in particular *Allow Device Authorization*,
  *Device ownership* = ``organization``, and *Allow offline access*
  (with ``oidc-device-organization`` 0.3.3 or newer). See
  :ref:`LemonLDAP::NG configuration
  <llng-configuration-creation-of-the-oidc-relying-party>`..

.. _shell-quickstart-step-1--generate-the-installers:

Step 1 — generate the installers
--------------------------------

Just run ``ob-builder`` and answer the questions.

The questionnaire asks for a deployment slug used to name artefacts;
this documentation uses ``acme``. Then it asks for the artefacts
to generate answer `shell` (the default).

The questionnaire will also asks for: the security scenario, the URL
of the SSO portal, the OIDC ``client_id``, the ``client_secret`` mode,
the server group, and the target roles to generate (answer
``bastion`` then ``backend``).

When a self-extracting installer is requested for the backend role,
one extra prompt requests the ids of the bastion allowd to reach
backend. These only exist after the bastion is enrolled: the usual
order is to leave the prompt empty (any vouched bastion in the same
server group is then accepted). It will be set later by editing
``/etc/open-bastion/allowed_bastions`` on the backends.

The generated scripts are self-contained: they embed the SSO CA key,
the scenario, the ``client_id`` and the APT repo config. You can
inspect what is baked in with the ``info`` command (replace ``acme``
with your slug):

.. code:: bash

   ./bootstrap-acme-bastion.sh info

.. tip::

   Instead of answering prompts you can pass every answer through a
   YAML file and generate installers non-interactively:

   .. code:: bash

     ob-builder --config build.yml --output-shell …

See :doc:`ob-builder(1) </references/man/ob-builder>` for the full command
manual.

.. _shell-quickstart-step-2--deploy-the-bastion:

Step 2 — deploy the bastion
---------------------------

Copy the bastion installer to the bastion host and run it as
root. For a bastion host named `bastion-1`:

.. code:: bash

   scp bootstrap-acme-bastion.sh bastion-1:/tmp/
   ssh -t bastion-1 'sudo /tmp/bootstrap-acme-bastion.sh --yes'

The installer configures the package repository and installs
``open-bastion``, writes ``/etc/open-bastion/openbastion.conf``.

Then it runs ``ob-enroll`` which prints a URL and code to approve the
host enrollment in your browser (Device Authorization Grant flow).

Finally, it runs ``ob-bastion-setup`` which locks SSH down to
SSO-issued certificates.

Collect the ``bastion_id`` — a synthetic per-device identity assigned
by the portal at enrollment — from the ``ob-bastion-setup`` final
output. It may use it during backends configuration to limit the
accepted bastions.

.. code:: bash

   ssh bastion-1 sudo ob-bastion-id

.. warning::

   Unless you are a confirmed user, make sure you have console access
   to the target and login with an account with root privileges before
   you run the installer. The setup step lock port 22 down to SSO
   certificates, so the local admin account can no longer access
   through SSH without a signed certificate atferwards.

   You can also split the deployment in multiple steps, eg to inspect
   the host, see :ref:`usefull_installer_flags`.

.. _shell-quickstart-step-3--deploy-the-backends:

Step 3 — deploy the backends
----------------------------

Copy the backend installer to each backend host and run it there.

.. code:: bash

   for host in web-1 web-2; do
     scp bootstrap-acme-backend.sh "$host":/tmp/
     ssh -t "$host" 'sudo /tmp/bootstrap-acme-backend.sh --yes'
   done

.. _usefull_installer_flags:

Useful installer flags
----------------------

The self-extracting installer accepts the following options (see ``--help`` / ``info``):

+--------------------------+------------------------------------------------------------------------+
| Flag                     | Effect                                                                 |
+==========================+========================================================================+
| ``-y``, ``--yes``        | answer Y to all prompts — enrol and setup run automatically            |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-enroll``        | skip ``ob-enroll``; install and write config only                      |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-setup``         | enrol but skip ``ob-{bastion,backend,standalone}-setup``               |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-install``       | assume the package is already installed                                |
+--------------------------+------------------------------------------------------------------------+
| ``--client-id ID``       | override the ``client_id``                                             |
+--------------------------+------------------------------------------------------------------------+
| ``--server-group GROUP`` | override the ``server_group``                                          |
+--------------------------+------------------------------------------------------------------------+
| ``--force``              | overwrite an existing ``/etc/open-bastion`` (normally refused)         |
+--------------------------+------------------------------------------------------------------------+
| ``--insecure``           | skip TLS verification — **debug/test only**, never against prod SSO    |
+--------------------------+------------------------------------------------------------------------+

Splitting enrolment and setup is handy when you want to inspect the
host before locking SSH: ``--skip-setup`` first, verify, then re-run
with ``--skip-install --skip-enroll`` to finish.

Updating a host
---------------

Re-running the installer is idempotent for the package repository,
installed package and configuration. Bump the package in your
repository and re-run to upgrade. To reconfigure a host that setup has
already locked down, reach it over a path that setup did not close,
then run the installer with ``--force``.
