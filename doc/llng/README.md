# LLNG plugins

The portal side of Open Bastion is four LemonLDAP::NG plugins. They are
maintained under `llng/plugins/` in this repository, and packaged for the
LLNG store by
[lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins).

Each page below is the plugin's own `README.md`, rendered from the source
tree: it is the authoritative reference for the plugin's endpoints,
parameters and their defaults. {doc}`/references/llng-plugins-parameters`
summarises the parameters an Open Bastion deployment may set, and
{doc}`/deployment/llng-configuration` walks through the portal
configuration.

```{toctree}
:maxdepth: 1

pam-access <plugins/pam-access/README>
ssh-ca <plugins/ssh-ca/README>
oidc-device-authorization <plugins/oidc-device-authorization/README>
oidc-device-organization <plugins/oidc-device-organization/README>
```

## Installation with Debian packages

The plugins are installed on the portal from Linagora's LLNG store, or
from its Debian packages: see {ref}`mandatory-lemonldap-ng-plugins`.
