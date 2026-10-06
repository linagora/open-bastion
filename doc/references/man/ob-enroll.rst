ob-enroll
=========

Synopsis
--------

::

   ob-enroll [OPTIONS]

Description
-----------

``ob-enroll`` uses the Device Authorization Grant (RFC 8628) to obtain a
server token that allows the PAM module to check user authorizations
against a LemonLDAP::NG server.

The enrollment process requires an administrator to authenticate on the
LemonLDAP::NG portal and approve the server registration using a
displayed verification code.

Options
-------

.. option:: -p, --portal URL

   LemonLDAP::NG portal URL (required if not in config file).

.. option:: -c, --client-id ID

   OIDC client ID. Default: pam-access

.. option:: -s, --client-secret SECRET

   OIDC client secret (required if not in config file).

.. option:: -g, --server-group GROUP

   Server group name for authorization rules. Default: default

.. option:: -t, --token-file FILE

   Where to save the server token. Default:
   /var/lib/open-bastion/token

.. option:: -C, --config FILE

   Read settings from config file. Default:
   /etc/open-bastion/openbastion.conf. Options given on the command line
   override the file, and a file given with ``-C`` that cannot be read is
   an error.

.. option:: -k, --insecure

   Skip SSL certificate verification.

.. option:: -q, --quiet

   Quiet mode (less output).

.. option:: -h, --help

   Show help message and exit.

.. option:: -V, --version

   Show version and exit.

Examples
--------

Enroll using settings from config file:

::

   sudo ob-enroll

Enroll with explicit parameters:

::

   sudo ob-enroll -p https://auth.example.com -s mysecret

Enroll to a specific server group:

::

   sudo ob-enroll -g production

Files
-----

``/etc/open-bastion/openbastion.conf``
   Main configuration file for the PAM module.

``/var/lib/open-bastion/token``
   Server token file created by this script.

Security
--------

The enrollment process uses several security mechanisms:

**PKCE (RFC 7636)**
   PKCE (Proof Key for Code Exchange) is automatically used to protect
   against device_code interception attacks. A code_verifier is generated
   locally and never transmitted until the token exchange, preventing
   attackers from using an intercepted device_code.

**client_secret_jwt (RFC 7523)**
   Client authentication uses JWT assertions signed with HMAC-SHA256. The
   client_secret is never transmitted over the network; instead, it signs
   a JWT with a unique jti claim to prevent replay attacks.

**TLS**
   All communications with the LemonLDAP::NG server use HTTPS. Certificate
   verification is enabled by default (use -k to disable for testing
   only).

Exit status
-----------

``0``
   Enrollment completed successfully.

``1``
   Enrollment failed (missing parameters, network error, authorization
   denied, etc.)

See also
--------

:doc:`openbastion.conf(5) <openbastion.conf>`,
``pam_openbastion``,
:manpage:`pam.d(5)`

LemonLDAP::NG documentation: https://lemonldap-ng.org/
