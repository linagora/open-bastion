ob-ssh-cert
===========

Synopsis
--------

::

   ob-ssh-cert [OPTIONS]

Description
-----------

``ob-ssh-cert`` allows users to obtain signed SSH certificates from
LemonLDAP::NG, enabling passwordless SSH authentication to servers that
trust the LLNG CA.

The script uses the Device Authorization Grant (RFC 8628) to
authenticate the user. A verification code is displayed that must be
entered on the LemonLDAP::NG portal.

Once authenticated, the user's public key is signed by the
LemonLDAP::NG SSH CA, creating a certificate that can be used for SSH
authentication.

Options
-------

.. option:: -p, --portal URL

   LemonLDAP::NG portal URL (required).

.. option:: -v, --validity MINUTES

   Certificate validity in minutes. Default: 30

.. option:: -K, --key FILE

   Public key file to sign. Default: uses key from SSH agent.

.. option:: -o, --output FILE

   Output certificate file. Default: add to SSH agent.

.. option:: -t, --token-file FILE

   Read access token from file instead of Device Authorization flow. Use
   ``-`` for stdin.

.. option:: -c, --client-id ID

   OIDC client ID. Default: ssh-cert

.. option:: -k, --insecure

   Skip SSL certificate verification.

.. option:: -d, --debug

   Enable debug output.

.. option:: -h, --help

   Show help message and exit.

.. option:: -V, --version

   Show version and exit.

Environment
-----------

``OB_PORTAL_URL``
   Default portal URL if not specified with ``-p``.

``OB_SSH_CERT_VALIDITY``
   Default certificate validity in minutes.

``OB_SSH_CERT_CLIENT_ID``
   Default OIDC client ID.

Examples
--------

Get a 1-hour certificate using key from SSH agent:

::

   ob-ssh-cert -p https://auth.example.com -v 60

Sign a specific public key:

::

   ob-ssh-cert -p https://auth.example.com -k ~/.ssh/id_ed25519.pub

Save certificate to file:

::

   ob-ssh-cert -p https://auth.example.com -o ~/.ssh/id_ed25519-cert.pub

Files
-----

``~/.ssh/id_*-cert.pub``
   SSH certificate files.

Exit status
-----------

``0``
   Certificate obtained successfully.

``1``
   Failed (network error, authorization denied, invalid key, etc.)

See also
--------

:manpage:`ssh(1)`,
:manpage:`ssh-add(1)`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`

LemonLDAP::NG documentation: https://lemonldap-ng.org/

Author
------

Xavier Guimard <xguimard@linagora.com>
