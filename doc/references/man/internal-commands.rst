Internal commands
=================

The commands Open Bastion uses behind the scenes: ``sshd`` runs some as a
login shell, a forced command or a principals helper, ``systemd`` runs the
daemons from a socket. They are not meant to be run by hand; their man pages
are here to read a log line, audit what a unit does or check an option.
``ob-ssh-cert`` is the exception: it belongs to no machinery. It is the
terminal equivalent of the portal's ``/ssh`` page, signing a key with the
identity of whoever runs it, and no Open Bastion component calls it — the
certificate of an :doc:`ob-ssh(1) <ob-ssh>` hop comes from
:doc:`ob-cert-daemon(8) <ob-cert-daemon>`. Run it by hand to test
certificate authentication from a host that has the packages, or to sign a
key where there is no browser; the :doc:`end user guide
</using-open-bastion>` sends users to the portal instead.

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
   * - :doc:`ob-session-monitor(8) <ob-session-monitor>`
     - Revalidates sessions opened offline: ends the ones the portal reports
       gone, and forces the others back online after the grace period.
   * - :doc:`ob-client-jwt(8) <ob-client-jwt>`
     - Builds a ``client_secret_jwt`` assertion with the secret on stdin,
       used by :doc:`ob-enroll(8) <ob-enroll>`.
   * - :doc:`ob-sign-request(8) <ob-sign-request>`
     - Computes the signing headers of a ``/pam/`` call, with the secret on
       stdin.
   * - :doc:`ob-ssh-cert(8) <ob-ssh-cert>`
     - Asks the portal to sign an SSH key over the Device Authorization
       Grant, and installs the certificate in the SSH agent or next to the
       key. The terminal equivalent of the portal's ``/ssh`` page; not used
       by any component.

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
   ob-session-monitor
   ob-client-jwt
   ob-sign-request
   ob-ssh-cert
