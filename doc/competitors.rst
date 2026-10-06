Competitors and alternatives
============================

This document compares Open Bastion with alternative solutions for SSH
authentication, authorization, and session management.

Solution categories
-------------------

There are two distinct meanings of "PAM" in the security industry:

- PAM (Pluggable Authentication Modules): the Linux authentication
  framework.
- PAM (Privileged Access Management): an enterprise security product
  category.

Open Bastion addresses both: it is the PAM and NSS module of a
LemonLDAP::NG deployment, and with the portal's bastion features —
session recording, hop vouching, key-only service accounts — it covers,
for SSH, what a Privileged Access Management product covers.

Direct competitors: PAM modules for SSO
---------------------------------------

These are alternative PAM modules for centralizing SSH authentication:

.. list-table::
   :header-rows: 1
   :widths: 22 20 32 26

   * - Solution
     - Protocol
     - Features
     - Limitations
   * - pam_sss (SSSD)
     - LDAP, Kerberos
     - Widely deployed, FreeIPA integration
     - No web SSO, complex setup
   * - pam_krb5
     - Kerberos
     - Strong enterprise auth
     - Requires Kerberos infrastructure
   * - pam_ldap
     - LDAP
     - Simple, direct LDAP auth
     - No SSO, no MFA integration
   * - pam_cas
     - CAS
     - Apereo CAS integration
     - Limited to CAS protocol
   * - pam_oauth2
     - OAuth2
     - Modern protocol
     - Community-maintained, limited features

Open Bastion advantages
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Unified web SSO and system authentication
- Built-in MFA support via LemonLDAP::NG
- Server groups for granular access control
- Token-based authentication (no password exposure)
- Session recording via bastion mode

IAM/SSO solutions comparison
----------------------------

Complete Identity and Access Management solutions with system
integration:

.. list-table::
   :header-rows: 1
   :widths: 34 14 18 14 20

   * - Solution
     - Type
     - PAM integration
     - Web SSO
     - Session recording
   * - Open Bastion (with LemonLDAP::NG)
     - Open source
     - Native
     - ✅
     - ✅ (bastion)
   * - FreeIPA
     - Open source
     - Via SSSD
     - Limited
     - ❌
   * - Keycloak
     - Open source
     - Third-party
     - ✅
     - ❌
   * - Authentik
     - Open source
     - Limited
     - ✅
     - ❌
   * - Apereo CAS
     - Open source
     - pam_cas
     - ✅
     - ❌

Key differentiators
~~~~~~~~~~~~~~~~~~~

Open Bastion, on LemonLDAP::NG, is unique in providing:

1. A single solution for web SSO and system access.
2. A native PAM module designed specifically for the SSO.
3. A bastion with session recording for audit compliance.
4. Centralized policy management for both web and SSH access.

Privileged access management (PAM) solutions
--------------------------------------------

Enterprise solutions focused on privileged access control and session
recording:

.. list-table::
   :header-rows: 1
   :widths: 24 14 8 10 22 12

   * - Solution
     - License
     - Cost
     - Web SSO
     - Session recording
     - SSH auth
   * - Open Bastion
     - AGPL
     - Free
     - ✅
     - ✅
     - ✅
   * - Wallix Bastion
     - Proprietary
     - €€€
     - ❌
     - ✅
     - ✅
   * - CyberArk
     - Proprietary
     - €€€
     - ❌
     - ✅
     - ✅
   * - BeyondTrust
     - Proprietary
     - €€€
     - ❌
     - ✅
     - ✅
   * - Delinea (Thycotic)
     - Proprietary
     - €€€
     - ❌
     - ✅
     - ✅

Feature comparison with Wallix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Wallix is a French company whose Wallix Bastion product is often
considered in the same market. The table compares the two.

=============================== ================= =================
Feature                         Open Bastion      Wallix Bastion
=============================== ================= =================
SSH Session Recording           ✅                ✅
Session Playback                ✅                ✅
Multi-Factor Authentication     ✅                ✅ (add-on)
Web Single Sign-On              ✅                ❌
SAML/OIDC Provider              ✅                Limited
Centralized Access Policies     ✅                ✅
Password Vault                  Unneeded (SSH CA) ✅
RDP Recording                   ❌                ✅
License                         AGPL (Free)       Proprietary
Typical Cost                    Free              50-100€/user/year
=============================== ================= =================

When to choose Open Bastion
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Choose Open Bastion when you need:

- Web SSO and system access in a unified solution
- Open source with no licensing costs
- French sovereignty with open source flexibility
- SSH-focused privileged access management
- Custom integration capabilities

When to consider Wallix/CyberArk
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider commercial PAM solutions when you need:

- RDP session recording (Windows servers)
- A built-in password vault with rotation
- Vendor support contracts required by policy
- Pre-certified compliance (some regulations accept specific vendors)

Migration paths
---------------

From pam_ldap or pam_krb5
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Deploy LemonLDAP::NG with your existing LDAP/AD backend
2. Install Open Bastion alongside the existing PAM configuration
3. Test with a pilot group using LLNG tokens
4. Gradually migrate users to LLNG authentication
5. Remove legacy PAM modules

From commercial PAM solutions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Assess current session recording requirements
2. Deploy Open Bastion for SSH access
3. Migrate SSH servers first, where Open Bastion is strongest
4. Keep commercial solution for RDP if needed
5. Evaluate cost savings after migration

Summary
-------

Open Bastion, on LemonLDAP::NG, provides a unique combination: web SSO,
SSH access and a bastion with session recording, under an open source
license, where commercial PAM solutions charge per user per year. For
organizations whose infrastructure is mostly Linux and SSH and that need
web SSO, the Open Bastion stack is the most comprehensive and
cost-effective answer.
