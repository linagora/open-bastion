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

A host takes one of three roles. A standalone server authenticates its
users directly with LLNG, with no jump host in front of it. A bastion
records the sessions opened through it and hops to the servers behind.
A backend accepts connections only from its bastions. The three are
described in :doc:`Other use cases </other-uses-cases>` (standalone) and
:doc:`ob-bastion-setup(8) </references/man/ob-bastion-setup>` (all
three).

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

* :doc:`Ansible deployment </deployment/ansible-deployment>` — generate the
  Ansible tree, declare the hosts, apply with one ``ansible-playbook`` run.
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
