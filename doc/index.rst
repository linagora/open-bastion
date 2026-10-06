Open Bastion Documentation
==========================

Grouped by theme, roughly in reading order: **try it → deploy it → understand the connection model → manage access → record & audit → operate → go deep.** New here? Start with a quick-start, then skim :doc:`Bastion Architecture </bastion-architecture>` and :doc:`Access & Permissions </permissions>`.

Start here
----------

+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| Document                                                                                            | Description                                            |
+=====================================================================================================+========================================================+
| `Docker demo <https://github.com/linagora/open-bastion/blob/main/quick-start/README.md>`__          | LLNG portal + a self-enrolling SSH server in ~2 min    |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| :doc:`Configure your SSO </llng-configuration>`                                                     | Install the plugins + create the OIDC client(s)        |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| :doc:`Shell installer quick-start </shell-quickstart>`                                              | Generate + run a self-extracting installer per host    |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| :doc:`Ansible quick-start </ansible-quickstart>`                                                    | Generate + apply bastion/backend roles to a fleet      |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| `Deployment builder <https://github.com/linagora/open-bastion/blob/main/admin-builder/README.md>`__ | ``ob-builder`` — produce the shell / Ansible artefacts |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+
| :doc:`Admin guide </admin-guide>`                                                                   | End-to-end manual walkthrough per role                 |
+-----------------------------------------------------------------------------------------------------+--------------------------------------------------------+

.. _index-connections--architecture:

Connections & architecture
--------------------------

How users reach servers, and how the bastion→backend hop is secured.

+---------------------------------------------------------------------+-------------------------------------------------------------------------+
| Document                                                            | Description                                                             |
+=====================================================================+=========================================================================+
| :doc:`Bastion architecture </bastion-architecture>`                 | Bastion→backend certificate vouching; ``ob-ssh``/``ob-scp``/``ob-sftp`` |
+---------------------------------------------------------------------+-------------------------------------------------------------------------+
| :doc:`PAM authentication modes </pam-modes>`                        | The A–E matrix (token / key / password / cert)                          |
+---------------------------------------------------------------------+-------------------------------------------------------------------------+
| :doc:`LemonLDAP::NG configuration </llng-configuration>`            | Server-side: OIDC RP, plugins, SSH CA, server groups                    |
+---------------------------------------------------------------------+-------------------------------------------------------------------------+
| :doc:`LemonLDAP::NG plugin parameters </llng-plugin-parameters>`    | Reference: optional ``[portal]`` parameters (indicative)                |
+---------------------------------------------------------------------+-------------------------------------------------------------------------+
| :doc:`Design: certificate vouching </design/bastion-cert-vouching>` | Why and how the ephemeral-cert hop works                                |
+---------------------------------------------------------------------+-------------------------------------------------------------------------+

.. _index-access--permissions:

Access & permissions
--------------------

Who can do what, where — and which knob lives on the SSO vs the server.

+---------------------------------------------+--------------------------------------------------------------------+
| Document                                    | Description                                                        |
+=============================================+====================================================================+
| :doc:`Access & permissions </permissions>`  | SSO-side vs Open-Bastion-side controls; the "where do I set X" map |
+---------------------------------------------+--------------------------------------------------------------------+
| :doc:`Service accounts </service-accounts>` | Key-only local accounts (ansible, backup, CI/CD)                   |
+---------------------------------------------+--------------------------------------------------------------------+

.. _index-session-recording--audit:

Session recording & audit
-------------------------

+------------------------------------------------------------------------------------+-----------------------------------------+
| Document                                                                           | Description                             |
+====================================================================================+=========================================+
| :doc:`Session recording </session-recording>`                                      | Tamper-evident terminal I/O capture     |
+------------------------------------------------------------------------------------+-----------------------------------------+
| :doc:`Primary audit trace </audit>`                                                | Optional ``auditd``-based syscall trail |
+------------------------------------------------------------------------------------+-----------------------------------------+
| :doc:`Design: tamper-evident recording </design/tamper-evident-session-recording>` | Why recordings stream to a root sink    |
+------------------------------------------------------------------------------------+-----------------------------------------+

.. _index-offline--resilience:

Offline & resilience
--------------------

+------------------------------------------------------------+-------------------------------------------------+
| Document                                                   | Description                                     |
+============================================================+=================================================+
| :doc:`Offline mode </offline-mode>`                        | Cached authorization when LLNG is unreachable   |
+------------------------------------------------------------+-------------------------------------------------+
| :doc:`Offline cache administration </offline-cache-admin>` | Cache config, TTLs, lockout, ``ob-cache-admin`` |
+------------------------------------------------------------+-------------------------------------------------+

.. _index-security--hardening:

Security & hardening
--------------------

+---------------------------------------------------+----------------------------------------------------+
| Document                                          | Description                                        |
+===================================================+====================================================+
| :doc:`Security features </security>`              | Key policy, rate limiting, cache protection, audit |
+---------------------------------------------------+----------------------------------------------------+
| :doc:`Security reference </security-reference>`   | Every control, its configuration, and its limits   |
+---------------------------------------------------+----------------------------------------------------+
| :doc:`Session containment hardening </hardening>` | logind kill, process limits, at/cron allow-lists   |
+---------------------------------------------------+----------------------------------------------------+
| :doc:`CrowdSec integration </crowdsec>`           | Pre-auth IP blocking + post-auth reporting         |
+---------------------------------------------------+----------------------------------------------------+

Reference
---------

+--------------------------------------------------------------------------------+---------------------------------------------------------+
| Document                                                                       | Description                                             |
+================================================================================+=========================================================+
| :doc:`Canonical names and paths </reference-paths>`                            | Authoritative paths, unit names and package names       |
+--------------------------------------------------------------------------------+---------------------------------------------------------+
| :doc:`Configuration reference </configuration>`                                | Every ``openbastion.conf`` key                          |
+--------------------------------------------------------------------------------+---------------------------------------------------------+
| :doc:`Troubleshooting </troubleshooting>`                                      | Logs, debug mode, endpoint tests, common issues         |
+--------------------------------------------------------------------------------+---------------------------------------------------------+
| :doc:`Desktop SSO </desktop-sso>`                                              | LightDM greeter + LLNG login **(experimental / alpha)** |
+--------------------------------------------------------------------------------+---------------------------------------------------------+
| :doc:`Competitors </competitors>`                                              | Comparison with other solutions                         |
+--------------------------------------------------------------------------------+---------------------------------------------------------+
| `Slide deck <https://github.com/linagora/open-bastion/tree/main/doc/slides>`__ | HTML meetup talk; a snapshot, not a reference           |
+--------------------------------------------------------------------------------+---------------------------------------------------------+

Security analysis (EBIOS Risk Manager)
--------------------------------------

Full risk study following the ANSSI EBIOS RM method, for audits and compliance (French). Start at **:doc:`/security/index`**, which maps each document to its workshop.

+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| Workshop                    | Document                                                                                                                                | Description                                                                                          |
+=============================+=========================================================================================================================================+======================================================================================================+
| —                           | :doc:`Architecture </security/00-architecture>`                                                                                         | Security target and architecture overview                                                            |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| **1** Scope and baseline    | :doc:`Atelier 1 </security/04-atelier1-cadrage-socle>`                                                                                  | Perimeter, business values, **scales**, feared events, baseline                                      |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| **2** Risk origins          | :doc:`Atelier 2 </security/05-atelier2-sources-de-risque>`                                                                              | Risk sources, target objectives, retained pairs                                                      |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| **3** Strategic scenarios   | :doc:`Atelier 3 </security/06-atelier3-scenarios-strategiques>`                                                                         | Ecosystem mapping and seven strategic scenarios                                                      |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| **4** Operational scenarios | :doc:`Enrollment </security/01-enrollment>` · :doc:`SSH </security/02-ssh-connection>` · :doc:`LLNG portal </security/09-portail-llng>` | 47 risk sheets with initial and residual scores, including eight for the LLNG portal and its plugins |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| **5** Treatment             | :doc:`Treatment plan </security/07-plan-de-traitement>` · :doc:`Risk reduction </security/99-risk-reduce>`                              | Dated, owned plan; consolidated residual matrix                                                      |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| Decision                    | :doc:`Homologation dossier </security/08-dossier-homologation>`                                                                         | Perimeter, **conditions of use**, residual risk acceptance                                           |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+
| Operational                 | :doc:`Offboarding </security/03-offboarding>`                                                                                           | User and server offboarding procedure                                                                |
+-----------------------------+-----------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+

..

   Deploying? The twenty **conditions of use** in :ref:`the homologation dossier <security-08-dossier-homologation-2-conditions-demploi>` are the assumptions the residual scores depend on — and that the product does not all enforce for you.

.. Navigation only. The tables above stay the curated reading order; these
   toctrees feed the sidebar and the next/previous links.

.. toctree::
   :caption: Start here
   :maxdepth: 2
   :hidden:

   presentation
   llng-configuration
   shell-quickstart
   ansible-quickstart
   admin-guide

.. toctree::
   :caption: Connections & architecture
   :maxdepth: 2
   :hidden:

   bastion-architecture
   pam-modes
   llng-plugin-parameters
   design/bastion-cert-vouching

.. toctree::
   :caption: Access & permissions
   :maxdepth: 2
   :hidden:

   permissions
   service-accounts

.. toctree::
   :caption: Session recording & audit
   :maxdepth: 2
   :hidden:

   session-recording
   audit
   design/tamper-evident-session-recording

.. toctree::
   :caption: Offline & resilience
   :maxdepth: 2
   :hidden:

   offline-mode
   offline-cache-admin

.. toctree::
   :caption: Security & hardening
   :maxdepth: 2
   :hidden:

   security
   security-reference
   hardening
   crowdsec

.. toctree::
   :caption: Reference
   :maxdepth: 2
   :hidden:

   reference-paths
   configuration
   troubleshooting
   desktop-sso
   competitors

.. toctree::
   :caption: Security study (EBIOS RM)
   :maxdepth: 2
   :hidden:

   security/index
