Open Bastion Documentation
==========================

Open Bastion provides centralized SSH and ``sudo`` access control with
SSO integration.

.. toctree::
   :caption: Administrator guide
   :hidden:
   :maxdepth: 2

   overview
   deployment/index
   Admin guide<admin-guide>
   PAM authentication modes <pam-modes>
   Permissions <permissions>
   service-accounts
   offline-mode
   offline-cache-admin
   hardening
   security
   ssh-session-recording
   Primary audit trace <audit>
   Crowdsec integration <crowdsec>
   troubleshooting
   competitors


.. toctree::
   :caption: References
   :hidden:
   :maxdepth: 2

   references/configuration
   references/llng-plugins-parameters
   references/security-reference
   references/reference-paths
   references/bastion-architecture
   references/bastion-cert-vouching
   references/tamper-evident-session-recording
   

.. toctree::
   :caption: Security Analysis (EBIOS RM)
   :hidden:
   :maxdepth: 2
   :glob:

   Introduction <security/index>
   security/[0-9]*
