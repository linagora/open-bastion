Self-extracting installer
=========================

This is the same deployment as :doc:`Ansible deployment
</deployment/ansible-deployment>`, for when there is no Ansible control node:
``ob-builder`` runs once on your workstation and emits one self-extracting
installer per role, which you copy to each target and run there. The tool,
its questionnaire and the ``build.yml`` file that replaces it are described
on that page; this one covers what differs.

The flow is always the same three steps:

1. Generate one self-extracting installer per role — bastion or
backend — with ``ob-builder``.

2. Transfer an installer per target with ``scp``.

3. Run the installer on the targets.

Prerequisites
-------------

Those of the :doc:`Ansible path </deployment/ansible-deployment>` apply, with
one difference: there is no control node to prepare, and you need SSH access
from your workstation to each target, as a user that can run ``sudo``.

.. _shell-quickstart-step-1--generate-the-installers:

Step 1 — generate the installers
--------------------------------

Just run ``ob-builder`` and answer the questions. Two answers are
specific to the shell artefacts: at the artefacts question, answer
``shell`` (the default), and, when a self-extracting installer is
requested for the backend role, one extra prompt requests the ids of
the bastions allowed to reach the backend. Those ids only exist after
the bastion is enrolled: the usual order is to leave the prompt empty
and set the list once the backends are deployed, see
:ref:`shell-quickstart-step-3--deploy-the-backends`.

The installers are written as ``bootstrap-<slug>-<role>.sh``, next to
a ``PORTAL-CHECKLIST-<role>.md``, in the directory given at the
artefacts question (the current one by default).

The generated scripts are self-contained: they embed the SSO CA key,
the scenario, the ``client_id`` and the APT repo config. You can
inspect what is baked in with the ``info`` command (replace ``acme``
with your slug):

.. code:: bash

   ./bootstrap-acme-bastion.sh info

.. tip::

   Instead of answering prompts you can pass every answer through a
   YAML file and generate installers non-interactively, with the same
   ``build.yml`` as the :ref:`Ansible path
   <ansible-deployment-step-1--one-run>`. The questionnaire writes that
   file for you: answer yes to its last question, or start ``ob-builder``
   with ``--save-config build.yml``:

   .. code:: bash

     ob-builder --config build.yml --output-shell .

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

Then it runs :doc:`ob-enroll(8) </references/man/ob-enroll>`, which
prints a URL and code to approve the host enrollment in your browser
(Device Authorization Grant flow).

Finally, it runs
:doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`, which
locks SSH down to SSO-issued certificates.

Collect the ``bastion_id`` — a synthetic per-device identity assigned
by the portal at enrollment — from the ``ob-bastion-setup`` final
output, or later with
:doc:`ob-bastion-id(1) </references/man/ob-bastion-id>`. You may need
it when configuring the backends, to limit the accepted bastions.

.. code:: bash

   ssh bastion-1 sudo ob-bastion-id

.. warning::

   Unless you are an experienced user, make sure you have console
   access to the target and log in with an account with root
   privileges before you run the installer. The setup step locks port
   22 down to SSO certificates, so the local admin account can no
   longer access it through SSH without a signed certificate
   afterwards.

   You can also split the deployment in multiple steps, e.g. to
   inspect the host, see :ref:`usefull_installer_flags`.

.. _shell-quickstart-step-3--deploy-the-backends:

Step 3 — deploy the backends
----------------------------

Copy the backend installer to each backend host and run it there.

.. code:: bash

   for host in web-1 web-2; do
     scp bootstrap-acme-backend.sh "$host":/tmp/
     ssh -t "$host" 'sudo /tmp/bootstrap-acme-backend.sh --yes'
   done

If the allowed bastions prompt was left empty, each backend accepts a
hop from any vouched bastion of the project. Restrict it to your
bastions with their ``bastion_id`` (see
:ref:`shell-quickstart-step-2--deploy-the-bastion`):

.. code:: bash

   for host in web-1 web-2; do
     ssh -t "$host" 'sudo ob-backend-setup --allowed-bastions <id>[,<id>...]'
   done

This updates ``/etc/open-bastion/allowed_bastions`` and nothing else,
and takes effect at the next hop; see
:doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`.

.. _usefull_installer_flags:

Useful installer flags
----------------------

The self-extracting installer accepts the following options (see
``--help`` / ``info``):

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Flag
     - Effect
   * - ``-y``, ``--yes``
     - answer Y to all prompts — enrol and setup run automatically
   * - ``--skip-enroll``
     - skip ``ob-enroll``; install and write config only
   * - ``--skip-setup``
     - enrol but skip ``ob-{bastion,backend,standalone}-setup``
   * - ``--skip-install``
     - assume the package is already installed
   * - ``--client-id ID``
     - override the ``client_id``
   * - ``--server-group GROUP``
     - override the ``server_group``
   * - ``--force``
     - overwrite an existing ``/etc/open-bastion`` (normally refused)
   * - ``--insecure``
     - skip TLS verification — debug/test only, never against prod
       SSO

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
