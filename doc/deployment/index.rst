Deployment
==========

.. toctree::
   :maxdepth: 2
   :hidden:

   install
   llng-configuration
   ansible-deployment
   self-extracting-installer
   manual-configuration

The deployment of Open Bastion starts with standard :doc:`installation
steps </deployment/install>`:

* :ref:`Installation of Open Bastion <open_bastion_installation>`
  for the bastion itself and on each backend server

* :ref:`Installation of LLNG plugins <mandatory-lemonldap-ng-plugins>`

Since Open Bastion has a policy of not modifying global system state
without an explicit administrator decision, the installation steps
must be followed by configuration steps. The first of them is on the
portal:

* :doc:`Configuration of LLNG and its plugins
  </deployment/llng-configuration>`

Then configure the hosts. One questionnaire to
:doc:`ob-builder(1) </references/man/ob-builder>` produces the whole
deployment — the security scenario, the OIDC client, the package
repository and the SSH CA key are asked once — and what applies it to
the targets is what you choose here:

* :doc:`Ansible deployment </deployment/ansible-deployment>` — generate an
  Ansible role, declare the hosts, apply with one ``ansible-playbook`` run.
  The path to a fleet.

* :doc:`Self-extracting installer </deployment/self-extracting-installer>` —
  the same answers, applied by one generated script per target, for hosts
  with no Ansible control node.

Both end in the same setup commands on each host. To run them yourself, or
to know what they change before they do it:

* :doc:`Manual configuration </deployment/manual-configuration>`

Whichever route you take, the hosts end up in the same state; the
:doc:`security scenario </security-scenarios/index>` you chose decides
how strict it is.
