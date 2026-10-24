Ansible deployment
==================

This guide takes a fleet from nothing to a working bastion and backends, from
an Ansible control node: :doc:`ob-builder(1) </references/man/ob-builder>`
turns one questionnaire into a tree of roles, and one ``ansible-playbook`` run
applies it to every host. To run the setup commands yourself instead, see
:doc:`manual configuration </deployment/manual-configuration>`.

The ob-builder command
----------------------

``ob-builder`` ships in the ``open-bastion-builder`` package and runs once, on
your workstation. It talks to the SSO portal — OIDC discovery, then the SSH CA
public key and the JWKS — and bakes your answers, with what it fetched, into
the tree the targets apply. The targets never contact your workstation again.

Interactive use
~~~~~~~~~~~~~~~

Run it without arguments. The questionnaire asks, in order: the deployment slug
used to name the artefacts; which artefacts to generate; the :doc:`security
scenario </security-scenarios/index>`; the SSO portal URL (validated through
OIDC discovery); the OIDC ``client_id`` and whether it may be changed at
deployment time; how the ``client_secret`` is supplied; the server group; the
target roles; the bastion allowlist and the optional features (hardening, audit
trace, session recording); the service accounts; whether the targets enrol and
configure themselves; the package repository; and, for an Ansible tree, whether
the play may approve the device codes on its own.

.. _ansible-deployment-non-interactive-use:

Non-interactive use
~~~~~~~~~~~~~~~~~~~

Answers are worth keeping: the questionnaire offers to save them as a
YAML file, and ``ob-builder --config`` replays that file without a
single question.

The file the questionnaire writes doubles as the key reference: every key
carries a comment, accepted values included. :doc:`ob-builder(1)
</references/man/ob-builder>` documents the command line that reads it.

Prerequisites
-------------

- ``ob-builder`` on your Ansible control node, and SSH access from it to every
  target as an account whose ``sudo`` works non-interactively, with no
  password: the playbook uses ``become: true``. Otherwise, pass
  ``--ask-become-pass`` to ``ansible-playbook``.
- A package repository (APT or YUM/DNF) carrying the ``open-bastion`` package,
  reachable by the targets.
- The SSO portal reachable from the control node (at build time, for OIDC
  discovery) and from the targets (at run time, for enrolment).
- A ``pam-access`` relying party configured for enrolment by **device code**:
  the device authorization grant enabled, the ``pam:server`` and
  ``offline_access`` scopes allowed, and ``oidc-device-organization`` 0.3.3 or
  newer so the host receives a refresh token. That grant is how a host obtains
  its server token, and the only way supported here: the host asks the portal
  for a code, someone approves that code — a browser, or the play itself with a
  session cookie — and the host exchanges it for the token. See
  :ref:`LemonLDAP::NG configuration
  <llng-configuration-creation-of-the-oidc-relying-party>`.
- The account that approves must be allowed by the portal's ``^/device`` access
  rule (:ref:`Restrict the device and the SSH CA admin routes
  <llng-configuration-restrict-device-and-the-ssh-ca-admin-routes-required>`);
  a rule that matches nobody answers 403 to everyone.

.. _ansible-deployment-step-1--generate-the-roles:

Step 1 — generate the playbook
------------------------------

Answer the questionnaire, asking for Ansible artefacts and both
bastion and backend target roles:

.. code:: bash

   ob-builder

It writes the tree to the ``ansible-<slug>`` directory:

.. code:: text

   ansible-<slug>/
   ├── site.yml                       # plays them in deployment order
   ├── playbook-bastion.yml           # hosts: all, skips the other roles' hosts
   ├── playbook-backend.yml
   ├── inventory.yml.example
   ├── PORTAL-CHECKLIST-bastion.md    # the portal settings to make, per role
   ├── PORTAL-CHECKLIST-backend.md
   └── roles/
       ├── open-bastion-bastion/      # defaults/, tasks/, templates/, files/
       └── open-bastion-backend/

Every answer — given to the questionnaire or read from the configuration file —
has its runtime counterpart in the tree: the ``ob_*`` variables held by
``roles/open-bastion-<role>/defaults/main.yml``, one such file per role, each
variable documented in that role's ``README.md``. They are ordinary role
defaults, so they can be overridden without rebuilding anything: per host or
per group in the inventory (``inventory.yml``, ``host_vars/*.yml``,
``group_vars/*.yml``), or for a single run with ``--extra-vars``. That is what
allows a fine-grained execution of the playbook — the same tree replays with
``-e ob_auto_setup=true`` to run the setup, or with one optional feature turned
on for one host, and no regeneration.

The ``PORTAL-CHECKLIST-<role>.md`` next to the playbooks lists the
portal settings that role expects.

Each role's ``files/`` directory holds what was fetched from the portal:
the SSH CA public key and the JWKS of the build's ``client_id``
(``sso-jwks.json``). The role deploys the JWKS as
``/var/lib/open-bastion/jwks/sso-jwks.json`` (root:root 0644) and writes
``response_signing`` (``ob_response_signing``, ``prefer`` unless the
build chose otherwise). The JWKS is deployed once: a later run keeps
the host's, which :doc:`ob-heartbeat(8) </references/man/ob-heartbeat>`
may have rotated since, as long as the modules load it and the host
still enrols as ``ob_client_id``. ``ob_sso_jwks_force: true`` deploys
the role's JWKS anyway, for a host that missed a rotation: rebuild the
tree first, so that it carries the portal's current keys (under
``required``, a host given a JWKS without the key the portal now signs
with refuses every answer), or add ``ob_sso_jwks_fetch: true``.

``ob_sso_jwks_fetch: true`` replaces the build-time JWKS with the one
the controller fetches at play time from ``ob_sso_jwks_url`` (default
``<ob_portal_url>/oauth2/jwks``) for each host's ``ob_client_id``, when
a JWKS is to be deployed. It trusts the portal as the build does, over
TLS from the admin side (an ``http://`` URL is refused unless
``ob_verify_ssl`` is false), refuses a JWKS holding a private key, and
``ob_sso_jwks_fetch_sha256`` pins the expected SHA-256 of its canonical
form (``jq -S -c . | sha256sum``). Whatever its
source, the file only replaces the host's once ``ob-verify-response
check-jwks --anchor`` loads it.

Non-interactively, the same build is ``ob-builder --config build.yml
--output-ansible ./ansible-acme/``.

Management of client secret
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OIDC client secret authenticates the host to the portal — for its
enrolment, and for every authorization call it makes afterwards. The
questionnaire asks where it should be kept (``client_secret_mode`` in the
configuration file):

- ``none``: the relying party is public and no secret is sent;
- ``prompt`` (the default): the secret stays out of the tree. The play reads it
  from the inventory (``ob_client_secret``, from ``ansible-vault``) and hands
  it to ``ob-enroll`` and to the setup command through the environment;
- ``embedded``: the secret is written in clear text into each role's
  ``defaults/main.yml``, which makes the tree itself a credential:

  - ``ob-builder`` restricts those files to the building user (``0600`` and
    ``0700``) and drops a ``.gitignore`` at the root of the tree, so a
    ``git add -A`` in a surrounding working tree cannot publish it;
  - treat the directory as secret material — do not copy it into a repository,
    an attachment or a shared drive;
  - to version it anyway, delete that ``.gitignore``, rebuild with
    ``client_secret_mode: prompt``, and hold the secret with
    ``ansible-vault encrypt_string 's3cr3t' --name ob_client_secret``;
  - if such a tree has already been shared, rotate the client secret in the
    LLNG portal: it is a bearer credential for the deployment's OIDC client.

.. _ansible-deployment-allowed-bastions:

The backend's allowlist
~~~~~~~~~~~~~~~~~~~~~~~

A backend keeps an allowlist of the bastions whose hop it accepts, in
``/etc/open-bastion/allowed_bastions``. It is the residual defence that keeps a
backend from accepting a hop voucher minted by a host that merely enrolled in
the project: the list holds the ``bastion_id`` the portal assigned to each
bastion at enrolment, and ``ob-bastion-id`` prints it. The questionnaire asks
for those ids; the configuration file says the same in its ``allowed_bastions``
key:

- the ids themselves — one or more, comma-separated: only those bastions may
  hop in;
- nothing at all, or an explicit empty string (``""``): any vouched bastion is
  accepted, the same answer as ``--allow-any-bastion``, and the weaker one;
- an explicit ``null`` — and a bare ``allowed_bastions:`` with nothing after
  the colon, which YAML reads as null: the play **collects** the ids. They
  exist only on the bastions, so the play reads ``ob-bastion-id`` on every host
  of ``ob_bastion_group`` (``bastions`` by default) while configuring the
  backend, and stops if one of them cannot answer: an empty or a short list
  would accept any bastion, or deny the missing ones, without saying so.

An ``ob_bastion_allowed_bastions`` in the inventory overrides whatever the
build decided (an empty value there means "any"). Re-enrolling a bastion
assigns it a new id, so re-run the play after one: the collection picks the
new value up.

A bastion that the same run did not configure (another ``ansible-playbook``
run, or one that skipped it) is first asked, without ``sudo``, for the id it
keeps in ``/var/lib/open-bastion/bastion-id``: ``ob-heartbeat`` writes it
within five minutes of the enrolment, ``sudo ob-bastion-id`` right away.
Only a bastion that keeps none is asked as root, which maximum security
forbids once the bastion is deployed: see `Updating the fleet`_.

Approving the enrolments
~~~~~~~~~~~~~~~~~~~~~~~~

The questionnaire also asks whether the play may approve the device codes on
its own (``ansible_auto_approve`` in the configuration file). The answer
defaults to no: each host starts a device grant and waits for a human, and
since Ansible shows a running task's output only once it has finished, the
code is not readable from the play — the task sits there until the code
expires. Step 3 shows the way around it: enrol those hosts by hand first.

Answering yes, with an LLNG session cookie passed at run time, has the play
approve every code itself: no browser, no waiting, nothing per host. That is
what a fleet wants.

.. _ansible-deployment-step-2--declare-your-hosts-and-their-ips:

Step 2 — declare your hosts and their IPs
-----------------------------------------

Create an ``inventory.yml`` next to the tree and list every target under the
right group — the bastion(s) under ``bastions``, every backend under
``backends`` — with its role, its own OIDC settings, and the address Ansible
connects to. The ``inventory.yml.example`` in the tree is a starting point:

.. code:: yaml

   all:
     vars:
       ansible_user: admin # an account with passwordless sudo on the targets
       ansible_ssh_private_key_file: ~/.ssh/id_fleet

     children:
       bastions:
         vars:
           # A role tree only configures the hosts that declare its role.
           ob_role: bastion
           ob_server_group: bastion
           ob_client_id: ob-client-bastion
           ob_client_secret: "{{ vault_bastion_secret }}"
         hosts:
           bastion-1:
             ansible_host: 10.0.0.10

       backends:
         vars:
           ob_role: backend
           ob_server_group: backend
           ob_client_id: ob-client-backend
           ob_client_secret: "{{ vault_backend_secret }}"
         hosts:
           web-1:
             ansible_host: 10.0.0.21
           web-2:
             ansible_host: 10.0.0.22

Notes:

- ``ansible_host`` accepts an IP or a resolvable hostname — use whichever your
  workstation can reach. Adding a machine to the fleet is one more ``hosts:``
  entry with its ``ansible_host``.
- ``ob_role`` is what a host becomes. It is required on every host you want
  configured; a host without it is skipped, and a value that is not
  ``bastion``, ``backend`` or ``standalone`` stops the play.
- Each server group enrols with its own OIDC ``client_id`` — the portal maps a
  ``client_id`` to one server group (:ref:`Server groups
  <llng-configuration-server-groups>`) — hence the per-group values above,
  which override the role's baked-in ones.
- The JWKS in each role's ``files/`` is the one of that role's ``client_id``
  at build time. Build the tree with the ``client_id`` of each role (the
  ``roles:`` block of the configuration, see :doc:`ob-builder(1)
  </references/man/ob-builder>`), here ``ob-client-bastion`` and
  ``ob-client-backend``: each role then carries the JWKS of its own relying
  party. A host whose ``ob_client_id`` differs from its role's needs its own:
  set ``ob_sso_jwks_fetch: true`` (the controller then fetches the JWKS of
  each host's ``ob_client_id`` at play time), or ``ob_sso_jwks_src``,
  ``ob_sso_jwks_sha256`` and ``ob_sso_jwks_client_id`` for it, or
  ``ob_response_signing: off``. The play stops on the first task otherwise,
  rather than deploy keys that do not sign that client's answers.
- With one relying party per role, give the secrets per group as above:
  ``--extra-vars ob_client_secret=...`` would hand the same secret to every
  playbook of ``site.yml``.
- Keep the client secret in ``ansible-vault``, not in clear text. The role
  never persists the LLNG approval cookie either: it is asked per run and kept
  in memory.

.. _ansible-deployment-step-3--apply:

Step 3 — apply
--------------

From the directory ``ob-builder`` wrote:

.. code:: bash

   cd roles-acme
   ansible-playbook -i inventory.yml site.yml --ask-vault-pass

That is the whole run. ``site.yml`` plays the roles in deployment
order — bastion first: a backend that collects the bastion ids while
it configures itself needs the bastions played
first. ``--ask-vault-pass`` is for a client secret held in
``ansible-vault``, adapt to your use case.

If the build enabled ``ansible_auto_approve``, add the LLNG session cookie so
the play approves the device codes itself. The ``llng`` CLI comes from
`simple-oidc-client <https://github.com/linagora/simple-oidc-client>`__:

.. code:: bash

   COOKIE=$(llng --llng-server sso.example.com --login admin \
                --password '***' llng_cookie)

   ansible-playbook -i inventory.yml site.yml --ask-vault-pass \
     --extra-vars "ob_llng_cookie='$COOKIE'"

``--llng-server`` takes a server name and assumes HTTPS — the production case.
For a plain ``http://`` portal, give the full URL instead: ``--llng-url
http://sso.test``. That address must be one the portal answers on, since the
cookie is only ever sent back to the host that issued it. If the portal offers
a choice of authentication backends, name the one to use with ``--choice``,
e.g. ``--choice lmAuth=1_LDAP`` (replace ``1_LDAP`` with your backend's key).

Without auto-approve, the play waits for a human on every host, and it cannot
show you the code while it waits (Ansible only prints a finished task's
output). Enrol the hosts by hand instead, once per host:

.. code:: bash

   # -k is for a plain http:// portal, and OB_CLIENT_SECRET is the
   # ob_client_secret of that host's group — needed only when the relying
   # party has a secret (client_secret_mode other than none):
   ssh -t bastion-1 'sudo OB_CLIENT_SECRET=<secret> ob-enroll -g bastion'
   ssh -t web-1     'sudo OB_CLIENT_SECRET=<secret> ob-enroll -g backend'

Then run the play with the setup turned on:

.. code:: bash

   ansible-playbook -i inventory.yml site.yml -e ob_auto_setup=true

Enrolment and setup are one answer in the questionnaire, but two variables at
play time. A build that answered ``no``, or ``prompt``, leaves
``ob_auto_enroll`` and ``ob_auto_setup`` false: the play installs the package
and writes the configuration, and stops there — hence the variable above.
A build that answered ``yes`` enrols again on every run, so add
``-e ob_auto_enroll=false`` there once the hosts are enrolled.

A run can be narrowed to one group or one host while iterating, with
``--limit``:

.. code:: bash

   ansible-playbook -i inventory.yml site.yml --limit bastions
   ansible-playbook -i inventory.yml site.yml --limit web-1

What the play does on each host
-------------------------------

1. Skips the host when its ``ob_role`` is missing or is not the tree's
   own role; the whole fleet can be listed under every tree.
2. Configures the APT/YUM repo and installs the ``open-bastion`` package.
3. Writes ``/etc/open-bastion/openbastion.conf`` from the baked-in scenario.
4. Runs :doc:`ob-enroll(8) </references/man/ob-enroll>` to obtain the server's
   long-lived offline token; ``ob-heartbeat.timer`` then keeps the short-lived
   access token fresh.
5. On a backend, reads the bastion ids from the bastions (see `The backend's
   allowlist`_).
6. Runs :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>` /
   ``ob-backend-setup``, which locks SSH down to SSO-issued certificates and —
   on backends — enforces the ``allowed_bastions`` policy. What those commands
   change is described in :doc:`manual configuration
   </deployment/manual-configuration>`.

After the play, users connect with their SSO certificate to a bastion, then hop
to any backend with :doc:`ob-ssh(1) </references/man/ob-ssh>` (or transfer
files with :doc:`ob-scp(1) </references/man/ob-scp>` / :doc:`ob-sftp(1)
</references/man/ob-sftp>`); the bastion mints a short-lived, CA-signed
certificate for each hop. No user key ever lands on the bastion or the
backends.

Updating the fleet
------------------

Re-running ``site.yml`` is idempotent: bump the package in your repo and run
again to upgrade, or change a host's ``ob_*`` vars and re-apply to reconfigure.

Adding a host is one new inventory entry plus a run narrowed to it — each role
tree only configures the hosts whose ``ob_role`` is its own, and the others are
not contacted at all:

.. code:: bash

   ansible-playbook -i inventory.yml site.yml --limit bastion-2

For a new bastion, that run stops at the bastion: the backends keep
the allowlist they have, and a backend refuses the hops from a
``bastion_id`` it does not list (see `The backend's allowlist`_). Two
ways out:

- the build asked the play to collect the ids (``allowed_bastions: null``): run
  ``site.yml`` over the whole fleet, so the backends collect them again;
- the build gave the ids: ``ob-bastion-id`` prints the new one on the bastion,
  and it is left to the administrator to give it to the backends — as
  ``ob_bastion_allowed_bastions`` in the inventory, followed by a
  ``--limit backends`` run, or in their ``/etc/open-bastion/allowed_bastions``.

An allowlist left empty accepts any vouched bastion and needs neither. The same
applies after re-enrolling a bastion, which assigns it a new id.

Under :doc:`maximum security </security-scenarios/max-security-scenario>`,
the account of the first run can no longer connect: the hosts accept
only SSO certificates, and ``sudo`` only SSO users. The role does what
needs root before the setup locks ``sudo``, so the run that deploys a
host completes; a later run finds the lock in ``/etc/pam.d/sudo`` (read
without ``sudo``) and, by default, skips the host with a warning.
Reconfigure such a host by hand from an SSO session allowed to ``sudo``,
reinstall it, or let the play take ``sudo``'s password from the SSO:
``ob_become_token_cmd`` names a command the controller runs each time
``sudo`` asks for a password, whose output is the token ``sudo`` gets.
Each task that becomes root then consumes one single-use token of the
person running the play, so that every elevation goes through the SSO
under their name, as the scenario intends. Connect as that person
(``ansible_user`` is their SSO login, and SSH authenticates them with
their SSO certificate as for an interactive session: ``sudo`` refuses a
token minted for someone else, and a service account's ``sudo`` takes
none), open the SSO session once by hand, then run the play:

.. code:: bash

   llng --llng-server sso.example.com whoami   # opens the session
   ansible-playbook -i inventory.yml site.yml \
     -e 'ob_become_token_cmd="llng --llng-server sso.example.com pam_token"'

The command only runs when ``sudo`` asks, so the portal mints and logs
one token per elevation and none for the tasks that need no root; a
command that waits for a login instead (no session in the cookie jar) is
cut after 60 seconds and fails the task. The run that deploys a host
still takes the deploy account's own password: only a host found locked
switches, for the rest of the run, and such a host is not enrolled again
(a new enrolment would give it a new id). A backend deployed by a later
run still reads the ids of those bastions, without ``sudo``, from the file
they keep, as long as Ansible can connect to them; otherwise set
``ob_bastion_allowed_bastions`` in the inventory to what ``ob-bastion-id``
prints on each of them.

A :doc:`service account </service-accounts>` keeps SSH access — create
the local account on every target and give its key in
``service_accounts:`` before you apply the scenario — but not ``sudo``,
which the play needs (``become: true``). Open Bastion does not grant a
service account ``sudo``; under maximum security it takes a ``NOPASSWD``
``sudoers`` rule **and** a hand edit of ``/etc/pam.d/sudo``, which gives
up the scenario's promise that every elevation goes through the SSO (see
:ref:`service-accounts-sudo`); ``ob_become_token_cmd`` above keeps that
promise, by connecting as a person rather than as a service account. If
you take that decision instead, the role plays the host again, but its
setup run rewrites the file and drops the edit: ``sudo`` is locked again
when the run ends, so re-apply the edit by hand.
