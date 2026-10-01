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

   Read all answers from a YAML config file (non-interactive). The
   accepted keys are listed in the README shipped with the package.

.. option:: --output-shell PATH

   Write a self-extracting shell installer to ``PATH``.

.. option:: --output-ansible PATH

   Write an Ansible role tree to ``PATH`` (a directory).

   With ``--config``, at least one output is required; the questionnaire
   asks for them otherwise (default ``./bootstrap-<slug>.sh`` and
   ``./ansible-<slug>``). When several target roles are chosen
   interactively, each artefact gets the role as suffix
   (``bootstrap-<slug>-bastion.sh``, ``ansible-<slug>-backend``).

.. option:: --bundle

   Generate paired bastion + backend artefacts in one run, sharing the
   same SSO context.

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
the project's :doc:`/service-accounts`.

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

Interactive run with the shell installer path given up front:

::

   ob-builder --output-shell /tmp/bootstrap.sh

Replayable build from YAML (e.g. for CI):

::

   ob-builder --config build.yml --output-shell /tmp/boot.sh --output-ansible /tmp/role

See also
--------

:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`

Author
------

Open Bastion team <open-bastion@linagora.com>
