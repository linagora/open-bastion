ob-bastion-id
=============

Synopsis
--------

::

   ob-bastion-id [OPTIONS]

Description
-----------

``ob-bastion-id`` asks the LemonLDAP::NG ``/pam/whoami`` endpoint, using
this host's enrolled server token, and prints the ``bastion_id`` assigned
by LLNG at enrolment.

Portals running plugins older than 0.6.0 have no ``/pam/whoami``. Against
those the command falls back to the legacy ``/pam/bastion-token`` probe
that upstream removed in 0.6.0. The value is the same either way.

The fallback triggers on two shapes, because absence rarely looks like a
404: a 404, and a 200 carrying no identity. LemonLDAP::NG has a catch-all
that serves the portal's own HTML login page, with a 200, for any
``/pam/*`` path no plugin registered, so that second shape is the usual
one. Any other status, 403 in particular, is reported rather than worked
around.

The ``bastion_id`` is a synthetic **per-device** identity, not the OIDC
``client_id``, which identifies a project and may enrol many machines.
Two bastions sharing a ``client_id`` therefore have different
``bastion_ids``, and re-enrolling a bastion assigns it a new one.

Backends list these values in ``/etc/open-bastion/allowed_bastions``,
normally via :doc:`ob-backend-setup(8) <ob-bastion-setup>`
``--allowed-bastions``. ``ob-ssh-principals``, run by sshd as
``AuthorizedPrincipalsCommand``, checks the certificate key-id against
that file **before** PAM runs. The administrator running
:doc:`ob-builder(1) <ob-builder>` in ``--target-role=backend`` mode is
asked to provide that list; running this utility on each enrolled bastion
is the canonical way to discover the right value (the alternative being
the LLNG Manager).

Options
-------

.. option:: -v, --verbose

   Print all JWT claims as pretty JSON instead of just the
   ``bastion_id``.

.. option:: -j, --json

   Print

   ::

      {"bastion_id": "..."}

   for machine-readable use.

.. option:: -q, --quiet

   Suppress informational logs (errors still go to stderr).

.. option:: -c, --config FILE

   Path to ``openbastion.conf`` (default:
   ``/etc/open-bastion/openbastion.conf``).

.. option:: -t, --token FILE

   Path to the server token file (default:
   ``/var/lib/open-bastion/token``).

.. option:: -h, --help

   Show help.

.. option:: -V, --version

   Print the version.

Exit status
-----------

``0``
   ``bastion_id`` printed successfully.

``1``
   Configuration or token file missing / unreadable.

``2``
   The portal request failed or was refused (network error, or an HTTP
   status other than 200 from the endpoint that was tried last).

``3``
   The portal answered, but with no identity in it (also returned when a
   legacy JWT cannot be base64url-decoded).

Security
--------

Must be run as root in order to read ``/var/lib/open-bastion/token``
(mode 0600).

See also
--------

:doc:`ob-enroll(8) <ob-enroll>`,
:doc:`ob-bastion-setup(8) <ob-bastion-setup>`,
:doc:`ob-builder(1) <ob-builder>`

Author
------

Xavier Guimard <xguimard@linagora.com>
