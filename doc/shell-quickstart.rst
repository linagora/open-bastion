Quick-start: deploy Open Bastion with a shell installer
=======================================================

This guide takes you from nothing to a working bastion + backends fleet using ``ob-builder --output-shell`` to generate a **self-extracting installer** per role, then running it on each target with ``sudo``. No Ansible, no control node — just ``scp`` + ``ssh``.

The flow is always the same three steps:

1. **Generate** a self-extracting installer with ``ob-builder --output-shell`` (one questionnaire / config per role).
2. **Copy** it to each target (``scp``).
3. **Run** it on the target (``sudo ./bootstrap-….sh``).

..

   ``ob-builder`` runs **once on your workstation**. It talks to the SSO portal to fetch the SSH CA public key and JWKS, then bakes them — plus your scenario, client_id and APT repo — into a single, portable bash script. The script is then copied to the target and run there; the targets never contact your workstation again.

Prerequisites
-------------

- ``ob-builder`` on your workstation (ships in the ``open-bastion-builder`` package).
- The Open Bastion ``.deb``/``.rpm`` reachable by the targets from an APT/YUM repo (the default is the Linagora repo; override with ``--apt-url``).
- SSO reachable from your workstation (for the build-time OIDC discovery) **and** from the targets (at run time, for enrolment).
- SSH access from your workstation to each target as a user that can ``sudo``.
- The **``pam-access`` OIDC Relying Party** configured on the portal for device enrollment — in particular *Allow Device Authorization*, *Device ownership* = ``organization``, and **Allow offline access** (with ``oidc-device-organization`` 0.3.3 or newer), otherwise enrollment gets a non-renewable token and ``ob-bastion-setup`` aborts in Mode E. See :ref:`LemonLDAP::NG Configuration → Create the OIDC Relying Party <llng-configuration-step-2-create-the-oidc-relying-party>`.

.. _shell-quickstart-step-1--generate-the-installers:

Step 1 — Generate the installers
--------------------------------

Just run ``ob-builder`` and answer the questions. Do it **once per role** — a bastion and a backend differ only by a couple of answers (target role, and the backend's "accept only this bastion" allowlist).

Generate the **bastion** installer:

.. code:: bash

   ob-builder --output-shell bootstrap-bastion.sh

The questionnaire asks for: a deployment slug, the security scenario, the SSO portal URL, the OIDC ``client_id`` (use ``ob-bastion``), the client_secret mode, the server group, and the **target role** (answer ``bastion``).

   The ``client_id`` is **not** the bastion's id. A bastion's ``bastion_id`` is a synthetic per-device identity the portal assigns at enrolment, so it only exists once the bastion has been deployed — read it with ``ob-bastion-id`` on the host (see :ref:`step 2 <shell-quickstart-step-2--deploy-the-bastion>`).

Then generate the **backend** installer the same way:

.. code:: bash

   ob-builder --output-shell bootstrap-backend.sh

Answer ``backend`` to the target-role question. Backends then get one extra prompt — **"Allowed bastion ids"** — listing the bastions allowed to reach this backend. These are ``bastion_id`` values, not client ids, and they only exist after the bastion is enrolled: the usual order is to leave the prompt empty (any vouched bastion in the same server group is then accepted) or to fill it in later by editing ``/etc/open-bastion/allowed_bastions`` on the backend. ``ob-builder`` says so too: deploy the bastion first and run ``sudo ob-bastion-id`` on it to read the exact value.

Each ``bootstrap-*.sh`` is self-contained: it embeds the SSO CA key, the scenario, the client_id and the APT repo config. Inspect what is baked in without making any change:

.. code:: bash

   ./bootstrap-bastion.sh info

..

   **Reproducible / CI builds.** Instead of answering prompts you can pass every answer in a YAML file and generate non-interactively (``ob-builder --config build.yml --output-shell …``). See `admin-builder/README.md <https://github.com/linagora/open-bastion/blob/main/admin-builder/README.md>`__ for the config keys.

.. _shell-quickstart-step-2--deploy-the-bastion:

Step 2 — Deploy the bastion
---------------------------

Copy the bastion installer to the bastion host and run it as root. ``--yes`` answers every prompt (so enrolment **and** setup run unattended); the OIDC client secret is asked once on the target (if you chose the ``prompt`` secret mode):

.. code:: bash

   scp bootstrap-bastion.sh bastion-1:/tmp/        # bastion-1 = IP or DNS of the bastion
   ssh -t bastion-1 'sudo /tmp/bootstrap-bastion.sh --yes'

The installer configures the APT/YUM repo, installs ``open-bastion``, writes ``/etc/open-bastion/openbastion.conf``, runs ``ob-enroll`` (Device Authorization Grant — it prints a URL + code to approve in your browser), then runs ``ob-bastion-setup``, which locks SSH down to SSO-issued certificates.

Read the bastion's id — the value the backends must allow. It is assigned by the portal at enrolment (a synthetic per-device identity), **not** the ``client_id`` you answered earlier, so the only way to obtain it is to ask:

.. code:: bash

   ssh bastion-1 sudo ob-bastion-id   # -> e.g. 8f3c1a9e-...   (server-assigned)

Re-enrolling this bastion changes the value; update every backend's ``/etc/open-bastion/allowed_bastions`` when you do.

   **Run setup last, while port 22 still answers.** ``ob-bastion-setup`` / ``ob-backend-setup`` lock port 22 down to SSO certificates, so the local admin account can no longer log in there afterwards. Deploy with a sudo-capable account you reach **before** setup, and do any ``ob-bastion-id`` check on the still-open session. To re-deploy a host later, run the installer over a management path that setup did not lock (or rebuild the host).

.. _shell-quickstart-step-3--deploy-the-backends:

Step 3 — Deploy the backends
----------------------------

Copy the backend installer to each backend and run it the same way. Because you answered ``ob-bastion`` to the allowed-bastions prompt, each backend will only accept certificates vouched by that bastion:

.. code:: bash

   for host in web-1 web-2; do          # web-1/web-2 = IPs or DNS of the backends
     scp bootstrap-backend.sh "$host":/tmp/
     ssh -t "$host" 'sudo /tmp/bootstrap-backend.sh --yes'
   done

To allow several bastions, give the allowed-bastions prompt a comma-separated list (e.g. ``ob-bastion,ob-bastion-eu``) when generating the backend installer — the allowlist is baked in at build time, not a runtime flag. To change it on a host that is already deployed, re-run ``ob-backend-setup --allowed-bastions "…"`` directly on that host (no rebuild needed).

Standalone server (no bastion)
------------------------------

If you just want a **single, isolated server** that users SSO-authenticate into directly — no jump host, no bastion→backend hop — generate one installer with the **standalone** role and run it on that host. There is no allowlist and no second machine to coordinate:

.. code:: bash

   ob-builder --output-shell bootstrap-standalone.sh   # answer "standalone" to target role
   scp bootstrap-standalone.sh host-1:/tmp/
   ssh -t host-1 'sudo /tmp/bootstrap-standalone.sh --yes'

A standalone host is simultaneously its own bastion and backend, so it runs the same code as a bastion and the full stack applies. ``ob-standalone-setup`` **does** exist: it is a symlink to ``ob-bastion-setup``, and invoking it under that name makes the script default ``--node-role`` to ``standalone`` instead of ``bastion`` (an explicit ``--node-role`` always wins). Either command works on a standalone host; ``ob-standalone-setup`` just records the right role without extra flags. Users then log in with their SSO certificate exactly as they would on a bastion — they just don't hop anywhere afterwards. The same :ref:`port-22 lockdown note <shell-quickstart-step-2--deploy-the-bastion>` applies: run setup while you still have a working management session.

Useful installer flags
----------------------

The generated ``bootstrap-*.sh`` accepts (see ``--help`` / ``info``):

+--------------------------+------------------------------------------------------------------------+
| Flag                     | Effect                                                                 |
+==========================+========================================================================+
| ``-y``, ``--yes``        | answer Y to all prompts — enrol **and** setup run automatically        |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-enroll``        | install + write config only; skip ``ob-enroll``                        |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-setup``         | enrol but skip ``ob-{bastion,backend}-setup`` (SSH stays open)         |
+--------------------------+------------------------------------------------------------------------+
| ``--skip-install``       | assume the package is already installed                                |
+--------------------------+------------------------------------------------------------------------+
| ``--client-id ID``       | override the client_id (refused if the artefact's policy is ``fixed``) |
+--------------------------+------------------------------------------------------------------------+
| ``--server-group GROUP`` | override the server_group (likewise honours its policy)                |
+--------------------------+------------------------------------------------------------------------+
| ``--force``              | overwrite an existing ``/etc/open-bastion`` (normally refused)         |
+--------------------------+------------------------------------------------------------------------+
| ``--insecure``           | skip TLS verification — **debug/test only**, never against prod SSO    |
+--------------------------+------------------------------------------------------------------------+

Splitting enrolment and setup is handy when you want to inspect the host before locking SSH: ``--skip-setup`` first, verify, then re-run with ``--skip-enroll`` to finish.

What you get
------------

After both steps, users connect with their SSO certificate to the bastion, then hop to any backend with ``ob-ssh <backend>`` (or transfer files with ``ob-scp`` / ``ob-sftp``); the bastion mints a short-lived, CA-signed certificate for each hop. No user key ever lands on the bastion or the backends, and each backend rejects any cert not vouched by an allowed bastion.

Updating a host
---------------

Re-running the installer is idempotent for the package/repo/config; bump the package in your repo and re-run to upgrade. To reconfigure a host that setup has already locked down, reach it over a path that setup did not close (or rebuild it), then run the installer with ``--force``.

--------------

Prefer fleet-wide, declarative deployments? Use the :doc:`Ansible quick-start </ansible-quickstart>` instead — same ``ob-builder``, same two-phase logic, driven from one inventory.
