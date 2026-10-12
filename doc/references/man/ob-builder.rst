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
public key and the JWKS of the ``client_id`` relying party from the
chosen SSO. The generated artefacts deposit
``/etc/open-bastion/openbastion.conf`` and the JWKS
(``/var/lib/open-bastion/jwks/sso-jwks.json``), install the ``open-bastion``
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
   whose ``ob_role`` is its own role; the others are not contacted, which is
   what lets ``site.yml`` run over the whole inventory.

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

.. option:: --response-signing MODE

   ``off``, ``prefer`` (default) or ``required``: the
   ``response_signing`` the targets get, in ``openbastion.conf`` and
   ``nss_openbastion.conf``. Also the ``response_signing`` key of the
   ``--config`` YAML (the option wins), and written by
   ``--save-config``. See "Signed portal answers" below. ``required``
   refuses every unsigned portal answer: use it only once the portal's
   ``pam-access`` plugin signs them, or the targets refuse every SSO
   login. ``required`` needs a ``client_id``.

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
``public_key`` or ``public_key_file``, ``key_fingerprint``,
``sudo_allowed``, ``sudo_nopasswd``, ``shell``, ``home``, ``gecos``,
``uid``, ``gid``). Each entry is validated at build time and rendered into
``/etc/open-bastion/service-accounts.conf`` (``0600 root:root``) on the
target, with ``service_accounts_file`` set in ``openbastion.conf``; its key
goes to ``/etc/open-bastion/service-accounts.d/<name>.pub``. Give the key:
``key_fingerprint`` is derived from it, and on its own leaves ``sshd`` no
key to accept. They apply to every role. See ``open-bastion`` and
the project's :doc:`/service-accounts`, shipped as
``/usr/share/doc/open-bastion-doc/html/service-accounts.html`` in the
HTML documentation.

Signed portal answers
---------------------

For every role (bastion, standalone, backend), the builder
fetches the portal's JWKS from the ``jwks_uri`` of the OIDC discovery,
or ``<portal>/oauth2/jwks`` when none is advertised, with
``?client_id=<client_id>``: the keys the portal signs that relying
party's answers with. It refuses a document the hosts could not use (no
RSA, EC or OKP signature key with a ``kid``, a private key, over 256
KiB) and keeps it in canonical form (``jq -S -c .``), whose SHA-256 the
build summary and ``PORTAL-CHECKLIST*.md`` print. Anyone can reproduce
it with ``curl --tlsv1.3 -s '<portal>/oauth2/jwks?client_id=<client_id>' | jq -S
-c . | sha256sum``.

The shell installer embeds the JWKS and its SHA-256: it checks the
SHA-256 before writing ``/var/lib/open-bastion/jwks/sso-jwks.json`` (root:root
0644), then passes ``--sso-jwks`` and ``--sso-jwks-sha256`` to the setup
it runs, with ``--response-signing``. The installer's own
``--response-signing`` overrides the built-in mode. The Ansible role
carries it as ``files/sso-jwks.json``, deploys it with a task
(``ob_sso_jwks_src``, ``ob_sso_jwks_file``) and passes the same options
to the setup.

That JWKS is the one of the build. On the hosts,
:doc:`ob-heartbeat(8) <ob-heartbeat>` follows the portal's key rotations
afterwards; running the installer again with ``--force``, or the
Ansible role again, puts the build-time JWKS back over a rotated one
(re-running ``ob-*-setup`` by hand without ``--sso-jwks`` keeps the
host's). Rebuild the artefacts after a key rotation on the portal before
using them on existing hosts: under ``required``, a host given a JWKS
without the key the portal now signs with refuses every answer.

The JWKS belongs to the ``client_id`` of the build. A target enrolled
under another ``client_id`` (policy ``modifiable``) gets
``response_signing = off`` from the installer, with a warning (its
``required`` is refused); the Ansible play stops until
``ob_sso_jwks_src``, ``ob_sso_jwks_sha256`` and ``ob_sso_jwks_client_id``
are set for it, or ``ob_response_signing`` is ``off``. Without a
``client_id`` no JWKS is fetched and the artefacts get ``off``. When the
fetch fails or the portal publishes no usable key (an RSA, EC or OKP
signature key with a ``kid``) for the relying party, ``required`` stops
the build; ``prefer`` builds artefacts with ``off`` and a warning, as
the setup script does: the portal could not sign that client's answers
anyway.

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

Same, once the portal signs its answers:

::

   ob-builder --config build.yml --response-signing required --output-shell /tmp/boot

See also
--------

:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-backend-setup(8) <ob-bastion-setup>`,
:doc:`ob-bastion-id(1) <ob-bastion-id>`
