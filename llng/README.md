# LLNG plugins

The four LemonLDAP::NG plugins the security study covers — `pam-access`,
`ssh-ca`, `oidc-device-authorization` and `oidc-device-organization` — are
maintained here. `lemonldap-ng-plugins` still packages them, and embeds this
directory as a submodule.

## Working on them

The plugins are grafted into a LemonLDAP::NG tree to be built and tested, and
that environment lives in
[lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins): work
in its `open-bastion` submodule, and follow its `CONTRIBUTING.md` for the
development environment and for running the `t/` suites.
