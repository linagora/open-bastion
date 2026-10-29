# LLNG plugins

The four LemonLDAP::NG plugins Open Bastion provides — `pam-access`,
`ssh-ca`, `oidc-device-authorization` and `oidc-device-organization` — are
maintained here.
[lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins)
packages them for the LLNG store.

Note they are GPL-2+, not AGPL-3.0 as the rest of Open Bastion: see
[COPYING](./COPYING) in this directory.

## Installation with Debian packages

The plugins are installed on the portal from Linagora's LLNG store, or from
its Debian packages: see [the installation
page](../doc/deployment/install.rst) of the documentation, section
"Mandatory LLNG plugins". The HTML documentation renders the README of each
plugin as its reference page.

## Two editable copies, until the submodule lands

`lemonldap-ng-plugins` still carries its own `plugins/<plugin>` copy of this
code, and no submodule points here yet. The one that will
(linagora/lemonldap-ng-plugins#106) embeds the **whole** Open Bastion
repository, as `open-bastion`, and is pinned to a sha of this repository.

Until it lands, neither copy is authoritative on its own: a change merged in
one repository has to be merged in the other in the same breath. When #106
merges, its pin must move to the sha of the merge, or it dangles.

## Working on them

The plugins are grafted into a LemonLDAP::NG tree to be built and tested, and
that environment lives in `lemonldap-ng-plugins`: follow its `CONTRIBUTING.md`
for the development environment and for running the `t/` suites.

Nothing in this repository exercises them: no CI job runs the 34 `t/` files,
ShellCheck scans `./scripts` only, and the packaging ignores this directory. An
edit that breaks a plugin still merges green here — run the suites in the
`lemonldap-ng-plugins` checkout before merging.
