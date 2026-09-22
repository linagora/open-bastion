Deployment
==========
.. toctree::
   :maxdepth: 2
   :hidden:

   install
   llng-configuration
   bastion-configuration
   backend-configuration
   fleet-deployment
   ansible-deployment

The deployment of Open Bastion starts with standard :doc:`installation
steps </deployment/install>`:

* :ref:`Installations of Open Bastion <open_bastion_installation>` (on the
  bastion itself and on each backend server)

* :ref:`Installation of LLNG plugins <mandatory-lemonldap-ng-plugins>`

Since Open Bastion has a policy of not modifying global system state
without an explicit administrator decision, the installation steps
must be followed by configuration steps:

* :doc:`Configuration of LLNG and its plugins
  </deployment/llng-configuration>`

* :doc:`Configuration and enrollment of the bastion
  </deployment/bastion-configuration>`

* :doc:`Configuration and enrollement of backend servers
  </deployment/backend-configuration>`
	    
.. tip::

   If you find the deployment process tedious, we have good news for
   you!

   Two ways to automate the deployment proces, based on a shell tool
   or the `Ansible Automation Platform
   <https://github.com/ansible/ansible>`_ are supported:
   
   * :doc:`/deployment/fleet-deployment`
   
   * :doc:`/deployment/ansible-deployment`
   
