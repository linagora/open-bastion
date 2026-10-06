Internal commands
=================

The commands Open Bastion uses behind the scenes: ``sshd`` runs some as a
login shell, a forced command or a principals helper, ``systemd`` runs the
daemons from a socket. They are not meant to be run by hand; their man pages
are here to read a log line, audit what a unit does or check an option.
Users sign their SSH key on the portal's ``/ssh`` page, described in the
:doc:`end user guide </using-open-bastion>`; the certificate of an
:doc:`ob-ssh(1) <ob-ssh>` hop comes from
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Command
     - What it does
   * - :doc:`ob-session-recorder(8) <ob-session-recorder>`
     - The forced command of an SSH session on a recording host: it runs the
       requested command and records the terminal.
   * - :doc:`ob-login-shell(8) <ob-login-shell>`
     - The login shell of SSO users on a recording host; every path through
       it ends in the recorder.
   * - :doc:`ob-record-sink(8) <ob-record-sink>`
     - The privileged end of the recording socket: it writes the recording
       and its metadata as root.
   * - :doc:`ob-record-connect(1) <ob-record-connect>`
     - The unprivileged end of that socket, used by the recorder.
   * - :doc:`ob-cert-daemon(8) <ob-cert-daemon>`
     - Mints the short-lived certificate of a bastion-to-backend hop.
   * - :doc:`ob-cert-request(1) <ob-cert-request>`
     - The unprivileged client for that socket, used by
       :doc:`ob-ssh(1) <ob-ssh>` and :doc:`ob-scp(1) <ob-scp>`.
   * - :doc:`ob-fp-daemon(8) <ob-fp-daemon>`
     - Writes the SSH key fingerprints and key metadata that
       ``pam_openbastion`` reads.
   * - :doc:`ob-fp-submit(8) <ob-fp-submit>`
     - What the ``AuthorizedPrincipalsCommand`` helper uses to deposit them.
   * - :doc:`ob-client-jwt(8) <ob-client-jwt>`
     - Builds a ``client_secret_jwt`` assertion with the secret on stdin,
       used by :doc:`ob-enroll(8) <ob-enroll>`.
   * - :doc:`ob-sign-request(8) <ob-sign-request>`
     - Computes the signing headers of a ``/pam/`` call, with the secret on
       stdin.

.. toctree::
   :hidden:

   ob-session-recorder
   ob-login-shell
   ob-record-sink
   ob-record-connect
   ob-cert-daemon
   ob-cert-request
   ob-fp-daemon
   ob-fp-submit
   ob-client-jwt
   ob-sign-request
