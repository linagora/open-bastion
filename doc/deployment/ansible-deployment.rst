Ansible deployment
==================

This guide takes a fleet from nothing to a working bastion and backends,
driven from an Ansible control node: ``ob-builder`` generates a role from one
questionnaire, and one ``ansible-playbook`` run applies it to every host.

The other two deployment paths drive the same tool with the same answers and
end in the same setup commands:

* the :doc:`self-extracting installer </deployment/self-extracting-installer>`
  for hosts with no control node;
* :doc:`manual configuration </deployment/manual-configuration>` where you
  would rather run the setup commands yourself.

``ob-builder``
--------------

``ob-builder`` ships in the ``open-bastion-builder`` package and runs once on
your workstation. It talks to the SSO portal to fetch the SSH CA public key
and the JWKS, then bakes them — plus your security scenario, your OIDC
``client_id`` and the package repository — into the artefacts you ask for: an
Ansible tree, a self-extracting shell installer, or both. The targets run
those artefacts and never contact your workstation again.

Run it without arguments for the questionnaire. It asks, in order: the
deployment slug used to name the artefacts; which artefacts to generate;
the :doc:`security scenario </security-scenarios/index>`; the SSO portal
URL (validated through OIDC discovery); the OIDC ``client_id`` and whether
it may be changed at deployment time; how the ``client_secret`` is
supplied; the server group; the target roles; the optional features
(bastion allowlist, hardening, audit trace, session recording); and the
package repository. Every answer can also be given on the command line or
in a YAML file, which is what makes a deployment reproducible.
:doc:`ob-builder(1) </references/man/ob-builder>` documents them all.

Non-interactive: ``build.yml``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A bastion and a backend differ by ``target_role`` and by the backend's
"accept only this bastion" allowlist. ``target_role`` takes several
roles, so one run emits the whole deployment from one ``build.yml``:

.. code:: yaml

   # build.yml
   deployment_slug: acme
   # token-only | token+unix | keys+llng | mixed | max-security
   scenario: token-only
   portal_url: https://sso.example.com
   client_id: ob-client-bastion # the bastion's OIDC client
   client_id_policy: fixed
   client_secret_mode: prompt # none | prompt | embedded
   server_group: bastion
   server_group_policy: fixed
   target_role: "bastion,backend"
   auto_enroll_setup: yes
   # Let the play approve device codes via an LLNG cookie
   ansible_auto_approve: yes
   apt_url: https://linagora.github.io/open-bastion
   apt_suite: trixie
   apt_component: main

.. code:: bash

   ob-builder --config build.yml --output-ansible ./roles-acme/

A role that needs its own OIDC client or server group takes them from
the inventory, per host or per group (:ref:`Step 2
<ansible-deployment-step-2--declare-your-hosts-and-their-ips>`).

With ``client_secret_mode: embedded``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The default is ``prompt``, which keeps the OIDC client secret out of
every generated file. ``embedded`` bakes it in clear text into each
role's ``defaults/main.yml`` and into the shell installer, so the tree
becomes a credential:

- ``ob-builder`` restricts those files to the building user
  (``0600`` and ``0700``) and drops a ``.gitignore`` at the root of the
  tree so a ``git add -A`` in a surrounding working tree cannot publish
  it;
- treat the directory as secret material — do not copy it into a
  repository, an attachment or a shared drive;
- to version it anyway, delete that ``.gitignore``, rebuild with
  ``client_secret_mode: prompt``, and supply the secret with
  ``ansible-vault encrypt_string 's3cr3t' --name ob_client_secret``;
- if such a tree has already been shared, rotate the client secret in
  the LLNG portal: it is a bearer credential for the deployment's OIDC
  client.

Prerequisites
-------------

- ``ob-builder`` on your Ansible control node. This is what
  distinguishes this path from the :doc:`self-extracting installer
  </deployment/self-extracting-installer>`, which needs no control
  node.

- A package repository (APT or YUM/DNF repository) containing the
  ``open-bastion`` package must be reachable by the targets.

- SSO reachable from your Ansible control node (at build-time, for
  OIDC discovery) and from the managed nodes (at run time, for
  enrollment).

- The ``pam-access`` OIDC Relying Party configured on the LLNG portal
  for device enrollment, with ``oidc-device-organization`` 0.3.3 or
  newer. See :ref:`LemonLDAP::NG configuration
  <llng-configuration-creation-of-the-oidc-relying-party>`.

.. _ansible-deployment-step-1--generate-the-roles:

Step 1 — generate the roles
---------------------------

.. _ansible-deployment-step-1--one-run:

One run, one tree
~~~~~~~~~~~~~~~~~

With the ``build.yml`` above (``target_role: "bastion,backend"``):

.. code:: bash

   ob-builder --config build.yml --output-ansible ./roles-acme/

The tree contains one role directory per target role, and a playbook
per role:

.. code:: text

   roles-acme/
   ├── site.yml                       # plays the roles in order
   ├── playbook-bastion.yml           # hosts: all, skips the other roles' hosts
   ├── playbook-backend.yml
   ├── inventory.yml.example
   ├── PORTAL-CHECKLIST-bastion.md    # the portal settings to make, per role
   ├── PORTAL-CHECKLIST-backend.md
   └── roles/
       ├── open-bastion-bastion/      # defaults/, tasks/, templates/, files/
       └── open-bastion-backend/

``roles/open-bastion-<role>/defaults/main.yml`` holds the baked-in
``ob_*`` values, and the role's `README
<https://github.com/linagora/open-bastion/blob/main/admin-builder/
templates/ansible/role/README.md>`__ lists every one of them. A run
producing a single role writes the same tree, minus ``site.yml``.

Generating every role in one run, rather than in two independent ones,
means the CA and the JWKS are fetched once: a rotation between two runs
would leave the bastion and its backends trusting different keys.

``auto_enroll_setup: prompt`` asks the *shell installer* whether to run
``ob-enroll`` and the setup command; the generated playbook has no such
question, so a tree built with it installs the package and stops there.
Use ``auto_enroll_setup: yes``, or answer at play time with ``-e
ob_auto_enroll=true -e ob_auto_setup=true``.

.. _ansible-deployment-step-2--declare-your-hosts-and-their-ips:

Step 2 — declare your hosts and their IPs
-----------------------------------------

This is where the IPs of the machines you are building go. Create an
``inventory.yml`` next to the tree and list every target under the
right group — the bastion(s) under ``bastions``, every backend under
``backends`` — declaring its role and its own OIDC settings. The address
of each machine is the ``ansible_host`` line:

.. code:: yaml

   # inventory.yml
   all:
     vars:
       ansible_user: admin # a sudo-capable account on the targets
       ansible_ssh_private_key_file: ~/.ssh/id_fleet

     children:
       bastions:
         vars:
           # A role tree only configures the hosts that declare its role; a
           # host without ob_role is skipped untouched.
           ob_role: bastion
           ob_server_group: bastion
           ob_client_id: ob-client-bastion
           ob_client_secret: "{{ vault_bastion_secret }}"
         hosts:
           bastion-1:
             ansible_host: 10.0.0.10 # <-- IP (or DNS name) of the bastion

       backends:
         vars:
           ob_role: backend
           ob_server_group: backend
           ob_client_id: ob-client-backend
           ob_client_secret: "{{ vault_backend_secret }}"
         hosts:
           web-1:
             ansible_host: 10.0.0.21 # <-- IP of the first backend
           web-2:
             ansible_host: 10.0.0.22 # <-- IP of the second backend

Notes:

- ``ansible_host`` accepts an IP or a resolvable hostname — use
  whichever your workstation can reach. Adding a machine to the fleet
  is just one more ``hosts:`` entry with its ``ansible_host``.
- ``ob_role`` is what a host becomes. It is required on every host you
  want configured; a host without it is skipped, and a value that is
  not ``bastion``, ``backend`` or ``standalone`` stops the play.
- Each server group enrols with its own OIDC ``client_id`` — the portal
  maps a ``client_id`` to one server group, see :ref:`Server groups
  <llng-configuration-server-groups>` — hence the per-group values
  above. They override the role's baked-in ones.
- The backend's allowlist is decided by ``build.yml``, not by the
  inventory: ``allowed_bastions: "id[,id…]"`` writes those ids, ``""``
  (or no key) accepts any vouched bastion, and ``allowed_bastions:
  null`` makes the play collect the ids from the bastions themselves.
  An ``ob_bastion_allowed_bastions`` in the inventory overrides
  whatever the build produced. See :ref:`allowed bastions
  <ansible-deployment-allowed-bastions>`.
- Keep the OIDC client secret in ``ansible-vault``, not in clear text.
  The role also never persists the LLNG approval cookie (it is asked
  per run).

.. _ansible-deployment-allowed-bastions:

The backend's allowlist
~~~~~~~~~~~~~~~~~~~~~~~

``/etc/open-bastion/allowed_bastions`` is the residual defence that
keeps a backend from accepting a hop voucher minted by a host that
merely enrolled in the project: it lists the ``bastion_id`` of every
bastion allowed to hop there, as assigned by the portal at enrolment
(``ob-bastion-id`` prints it). ``build.yml`` says where that list comes
from:

- ``allowed_bastions: "id[,id…]"`` writes exactly those ids;
- ``allowed_bastions: ""``, or no ``allowed_bastions`` key at all,
  accepts any vouched bastion — the same answer as
  ``--allow-any-bastion``, and the historical behaviour;
- ``allowed_bastions: null`` asks the Ansible role to **collect** the
  ids. They exist only on the bastions, so the play delegates
  ``ob-bastion-id`` to every host of ``ob_bastion_group`` (default
  ``bastions``) while configuring the backend. It requires an Ansible
  output — a shell installer has nowhere to collect from — and every
  host of the group must answer: the play stops otherwise, because an
  empty or a short list would accept any bastion, or deny the missing
  ones, without saying so.

``ob_bastion_allowed_bastions`` in the inventory overrides all three
(``""`` there means "any"). Re-enrolling a bastion assigns it a new id,
so re-run the play after one: the collection picks the new value up.

.. _ansible-deployment-step-3--apply:

Step 3 — apply
--------------

If you enabled ``ansible_auto_approve: yes``, fetch a short-lived LLNG
session cookie (it auto-approves the device-code enrolment for the
whole fleet — no browser needed) and pass it at run time. The ``llng``
CLI comes from `simple-oidc-client
<https://github.com/linagora/simple-oidc-client>`__:

.. code:: bash

   COOKIE=$(llng --llng-server sso.example.com --login admin \
                --password '***' llng_cookie)

   ansible-playbook -i inventory.yml site.yml \
     --ask-vault-pass \
     --extra-vars "ob_llng_cookie='$COOKIE'"

``--llng-server`` takes a server name (not a URL) and assumes HTTPS —
the production case. For a plain ``http://`` test SSO, pass the full
URL instead with ``--llng-url http://sso.test``.

If your portal is built with a choice module (a login form offering
several authentication backends), tell ``llng`` which one to use with
``--choice``, e.g. ``--choice lmAuth=1_LDAP`` (replace ``1_LDAP``
with your backend's key):

.. code:: bash

   COOKIE=$(llng --llng-server sso.example.com --choice lmAuth=1_LDAP \
                 --login admin --password '***' llng_cookie)

Without auto-approve, omit ``ob_llng_cookie``: the play prints a
device URL + code per host for manual browser approval.

``site.yml`` plays each role in turn over the whole inventory; a tree
only touches the hosts that declare its role, so nothing else is
needed. ``--limit`` narrows a run while iterating:

.. code:: bash

   ansible-playbook -i inventory.yml site.yml --limit bastions
   ansible-playbook -i inventory.yml site.yml --limit web-1

What the play does on each host
-------------------------------

1. Skips the host when its ``ob_role`` is missing or is not the tree's
   own role — the whole fleet can be listed under every tree.
2. Configures the APT/YUM repo and installs the ``open-bastion``
   package.
3. Writes ``/etc/open-bastion/openbastion.conf`` from the baked-in
   scenario.
4. Runs :doc:`ob-enroll(8) </references/man/ob-enroll>` (Device
   Authorization Grant) to obtain the server's long-lived offline
   token; ``ob-heartbeat.timer`` then keeps the short-lived access
   token fresh.
5. On a backend, reads the bastion ids from the bastions (see
   `The backend's allowlist`_).
6. Runs :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`
   / ``ob-backend-setup``, which locks SSH down to SSO-issued
   certificates and — on backends — enforces the ``allowed_bastions``
   policy. What those commands change is described in
   :doc:`manual configuration </deployment/manual-configuration>`.

After the play, users connect with their SSO certificate to a bastion,
then hop to any backend with :doc:`ob-ssh(1) </references/man/ob-ssh>`
(or transfer files with :doc:`ob-scp(1) </references/man/ob-scp>` /
:doc:`ob-sftp(1) </references/man/ob-sftp>`); the bastion mints a
short-lived, CA-signed certificate for each hop. No user key ever
lands on the bastion or the backends.

Updating the fleet
------------------

Re-running ``site.yml`` is idempotent: bump the package in your repo
and run again to upgrade, or change a host's ``ob_*`` vars and
re-apply to reconfigure. Adding a server is one new inventory entry
plus a ``--limit <newhost>`` run.

After re-enrolling a bastion — or adding or removing one — re-run
``site.yml`` so the backends collect the ids again: a backend sitting
on a stale list refuses the hops from the bastion that changed.
