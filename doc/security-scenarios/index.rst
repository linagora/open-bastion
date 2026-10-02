Security scenarios
==================

A scenario decides what a host accepts for SSH — certificates signed by the
LLNG authority, an LLNG token, a Unix password, a bare key — and whether
``sudo`` is gated by the portal. Open Bastion's default is maximum
security; the four others trade strictness for compatibility, for a
transition period or for a host that must keep Unix passwords or bare SSH
keys.

.. list-table:: The five scenarios
   :header-rows: 1
   :widths: 24 16 25 25

   * - Scenario
     - ``ob-builder`` questionnaire
     - SSH accepts
     - ``sudo`` asks for
   * - Max security (default scenario)
     - ``max-security``
     - certificates signed by the LLNG CA
     - LLNG token
   * - Token only
     - ``token-only``
     - LLNG token
     - LLNG token
   * - Token + Unix password
     - ``token+unix``
     - LLNG token, Unix password
     - LLNG token or Unix password
   * - SSH keys + LLNG authorization
     - ``keys+llng``
     - SSH keys, authorized by LLNG
     - nothing, LLNG still authorizes
   * - Mixed
     - ``mixed``
     - LLNG token, Unix password, SSH keys
     - LLNG token or Unix password

Two pages describe the scenarios in detail:

.. toctree::
   :maxdepth: 1

   max-security-scenario
   other-security-scenarios

.. note::

  Those scenarios used to be designated with letters A, B, C, D, E in
  the above table row order. This documentation no longer names
  scenarios that way, but generated files and the French security
  study still carry them.

How a scenario is selected
--------------------------

* In :doc:`ob-builder(1) </references/man/ob-builder>`, the "Security
  scenario" question — maximum security is the default answer — records
  the choice in the generated ``openbastion.conf`` and Ansible role.
* In a ``build.yml``, the ``scenario`` key takes the same values
  (:doc:`/deployment/ansible-deployment`).
* On a host installed from the package, the ``open-bastion/pam-mode``
  question writes the PAM stacks of the four scenarios other than the
  default. Maximum security is not offered there; it comes from
  :doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>`
  ``--max-security``.

