ob-builder
==========

Synopsis
--------

::

   ob-builder [OPTIONS]

Description
-----------

``ob-builder`` is run on an administrator workstation to produce a
self-contained deployment artefact (a self-extracting shell installer
and/or an Ansible role) that a target server can later execute to install
and configure Open Bastion against a LemonLDAP::NG SSO.

Without ``--config``, the builder asks a questionnaire covering every
option not given on the command line (artefacts to generate and their
paths, security scenario, SSO URL, OIDC client_id and client_secret
handling, server group, one or more target roles, optional bastion
whitelist for backends, optional features, service accounts, auto-launch
policy, APT repository and signing key) and then fetches the SSH CA
public key and JWKS from the chosen SSO. The generated artefacts deposit
``/etc/open-bastion/openbastion.conf``, install the ``open-bastion``
package via the bundled APT keyring, and prompt step-by-step for
:doc:`ob-enroll(8) <ob-enroll>` followed by
:doc:`ob-bastion-setup(8) <ob-bastion-setup>` or
:doc:`ob-backend-setup(8) <ob-bastion-setup>`.

Options
-------

.. option:: --config FILE

   Read all answers from a YAML config file (non-interactive). The file
   carries a comment for every key, accepted values included;
   ``--save-config`` writes one with every key, defaults included.

.. option:: --save-config PATH

   Also save the answers — defaults included, accepted values as
   comments — as a YAML file that ``--config`` replays without any
   question. The questionnaire offers it too (default
   ``./ob-builder-<slug>.yml``). The file is written before the SSO is
   contacted, never over the ``--config`` file, and not at all with
   ``--dry-run``.

   An embedded client_secret is left out, as a comment to fill in,
   unless the questionnaire is told to write it; the file is then
   created mode 0600. Service accounts entered interactively carry no
   public key: a commented ``public_key_file`` line marks where to add
   it. Since that file is meant to be completed by hand, a path typed at
   the questionnaire that already exists is only reused after
   confirmation, and replacing an existing file is announced; a
   ``--save-config`` path given on the command line is taken as consent.
   When the file is written, it is replaced wholesale; neither an
   existing save path that cannot be confirmed nor ``--dry-run`` writes
   anything at all.

.. option:: --output-shell DIR

   Write the self-extracting shell installers in the directory ``DIR``,
   created if missing. ob-builder names the files: one
   ``bootstrap-<slug>-<role>.sh`` per target role, its ``.sig`` with
   :option:`--sign-with`, and the ``PORTAL-CHECKLIST-<role>.md`` listing
   the portal settings to make. A ``DIR`` ending in ``.sh``, or naming an
   existing file, is refused: older releases took a file name there.

.. option:: --output-ansible PATH

   Write an Ansible tree to ``PATH`` (a directory), one tree per run: a
   ``playbook-<role>.yml`` and a ``roles/open-bastion-<role>/`` per target
   role, plus a ``site.yml`` playing them in deployment order — bastion,
   standalone, then backend — when there are several, whatever order they
   were asked for: a backend that collects the bastion ids needs the
   bastions played first. A generated playbook only configures the hosts
   whose ``ob_role`` is its own role; the others are skipped, which is what
   lets ``site.yml`` run over the whole inventory.

   With ``--config``, at least one output is required; the questionnaire
   asks for them otherwise (default ``.`` and ``./ansible-<slug>``).

.. option:: --repo-keyring PATH

   GPG keyring used to sign the APT repository. Defaults to the Linagora
   keyring bundled with the package
   (``/usr/share/open-bastion-builder/keyrings/open-bastion-linagora.gpg``).

.. option:: --apt-url URL

   APT repo base URL. Default:
   ``https://linagora.github.io/open-bastion``.

.. option:: --apt-suite SUITE

   APT suite/codename. Default: ``trixie``.

.. option:: --apt-component COMP

   APT component. Default: ``main``.

.. option:: --sign-with KEYID

   GPG-sign the shell output with this key (produces a ``.sig`` sidecar).

.. option:: --insecure

   Allow an ``http://`` SSO URL and skip TLS verification, both when
   fetching from the SSO and in the generated artefacts: the target
   configuration gets ``verify_ssl = false`` and ``ob-enroll`` /
   ``ob-*-setup`` run with ``-k`` (``ob_verify_ssl: false`` in the
   Ansible role). Test setups only.

.. option:: --allow-http

   Deprecated alias of ``--insecure``.

.. option:: --dry-run

   Print the actions that would be taken without writing any files.

.. option:: -h, --help

   Show help.

.. option:: -V, --version

   Print the builder version.

Service accounts
----------------

The builder can declare SSH-key-only local accounts (ansible, backup,
CI/CD, ...) that authenticate by SSH key fingerprint without OIDC. The
questionnaire prompts for them interactively; a ``--config`` YAML
provides them under a ``service_accounts:`` list (keys: ``name``,
``key_fingerprint``, ``sudo_allowed``, ``sudo_nopasswd``, ``shell``,
``home``, ``gecos``, ``uid``, ``gid``). Each entry is validated at build
time and rendered into ``/etc/open-bastion/service-accounts.conf``
(``0600 root:root``) on the target, with ``service_accounts_file`` set in
``openbastion.conf``. They apply to every role. See ``open-bastion`` and
the project's :doc:`/service-accounts`, shipped as
``/usr/share/doc/open-bastion-doc/html/service-accounts.html`` in the
HTML documentation.

Files
-----

``/usr/share/open-bastion-builder/templates/``
   Source templates for the generated shell installer and Ansible role.

``/usr/share/open-bastion-builder/keyrings/``
   Bundled APT repository keyrings (default = Linagora).

Security
--------

The generated shell installer is executed as root on the target host.
The builder validates the SSO URL character class to forbid shell
metacharacters and embeds the optional client_secret base64-encoded so
that secrets containing ``"``, ``$``, \`, or backslash cannot break out
of the generated literal. The ``--self-delete`` default is automatically
enabled when the embedded client_secret mode is chosen, so the installer
removes itself from disk after a successful run.

Examples
--------

Fully interactive run:

::

   ob-builder

Interactive run keeping the answers for the next, non-interactive, run:

::

   ob-builder --save-config build.yml

Interactive run with the shell installer directory given up front:

::

   ob-builder --output-shell /tmp/bootstrap

Replayable build from YAML (e.g. for CI):

::

   ob-builder --config build.yml --output-shell /tmp/boot --output-ansible /tmp/role

See also
--------

:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`
