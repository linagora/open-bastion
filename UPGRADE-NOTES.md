# Upgrade notes

What you have to do so nothing stops. [CHANGELOG.md](CHANGELOG.md) lists the
changes; this is the subset that needs an action or a decision. Only versions
that need something are listed.

Open Bastion and the LemonLDAP::NG plugins
([linagora/lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins))
move independently, so each part below says when it applies.

## 0.7.0

**Part A — on every bastion and backend. Required, whatever your portal runs.**

**Part B — the portal. Required for a production deployment of 0.7.0.** It used
to be "only if you are also moving the portal"; from 0.7.0 the two portal
settings in [B0](#b0-required-before-070-goes-to-production) are a release
prerequisite, and they exist only on plugins 0.6.0.

If you are doing both: Part A first, on every host, then Part B.

---

## Part A — on every host

### A1. Finish the upgrade

```sh
sudo ob-post-upgrade
```

**Installing the package is not enough.** The sshd principals helper is
generated on the host, not shipped, so an upgrade replaces the daemon it talks
to and leaves the helper as it was. Until you run this, the SSH fingerprint
binding stays on the old `nobody`-owned spool, and you will see:

```
SSH fp spool /run/open-bastion/ssh-fp is owned by uid 65534, not root
```

`ob-post-upgrade` takes no arguments and asks nothing. It does **not** enrol,
and does not touch `openbastion.conf`, your server token, `sshd_config` or any
PAM stack — so you do not need to remember how this host was set up, and it is
safe to run again at any time. Add `--dry-run` to see what it would change.

You can still use `ob-bastion-setup` / `ob-backend-setup` instead if you have
your original arguments; you need them only to _change_ a decision.

If it cannot enable `ob-fp.socket` it stops and says so. Logins would still
succeed, but with **no fingerprint binding** — and on a host with
`fingerprint_required = true`, or against a portal with
`pamAccessRequireFingerprint`, they would be refused instead.

### A2. Check the sshd PAM stack refuses passwords

```sh
grep '^auth' /etc/pam.d/sshd     # expect: auth required pam_deny.so
```

If you see `pam_permit` instead, that host accepts **any password for any
authorized account**. `apt upgrade` does not fix it: the postinst leaves a
stack written by the setup scripts alone. Re-run `ob-bastion-setup` /
`ob-backend-setup` (they back the file up first), or edit the line by hand.

Only `/etc/pam.d/sshd`. In mode-c, `/etc/pam.d/sudo` is meant to permit — leave
it alone.

### A3. Check the permissions of `cache.key`

```sh
ls -l /etc/open-bastion/cache.key     # expect: -rw------- root root
```

A world- or group-readable key is now rejected rather than used with a warning.
If yours is `0644` — which is what the `dd` recipe in older documentation
produced — fix it:

```sh
chown root:root /etc/open-bastion/cache.key && chmod 600 /etc/open-bastion/cache.key
```

Until you do, desktop-SSO users need one online re-authentication each: the
existing offline cache entries can no longer be read. No lockout, nothing to
clean up. The rejection is logged to syslog with that same command.

---

## Part B — before moving the portal to plugins 0.6.0

### B0. Required before 0.7.0 goes to production

Two settings in the LLNG Manager. Until both are set, **any host enrolled in
this project that is compromised can declare itself a bastion** on
`/pam/authorize` and obtain a hop voucher (12 h by default) for a user — a test
machine, a workstation, any backend. That is risk R-P1, and it is the shipped
default: `pamAccessServerGroups` empty makes `server_group` a value read from
the request body, and `pamAccessAllowedRps` empty means "no change", so the
plugin's audience binding does nothing.

1. **`pamAccessServerGroups`** — the authoritative `client_id → server_group`
   mapping. Once set, `server_group` stops being something a caller can
   declare.
2. **`pamAccessAllowedRps`** — the RPs allowed on `/pam/*`. This requires your
   bastions to be enrolled under a `client_id` of their own, not the
   project-wide one, so plan that first.

And on the hosts, the residual defence if the two above are ever undone:

3. **`allowed_bastions` non-empty on every backend** —
   `ob-backend-setup --allowed-bastions <bastion_id>[,<id>...]`. An empty file
   accepts a voucher from any bastion the SSO vouched for.

No command on a host can check 1 or 2: they are portal state, and reading it
back would need an API that publishes your bastions, server groups and RPs. So
the setup scripts and `ob-post-upgrade` print this list on every run, and
`ob-builder` writes a `PORTAL-CHECKLIST.md` next to each artefact, pre-filled
with that deployment's `client_id` and `server_group`. Those are reminders, not
checks — verifying it is yours.

Background: `doc/security/09-portail-llng.md` (R-P1) and
`doc/security/08-dossier-homologation.md` (CE03, CE06, CE16, CE21).

### B1. Upgrade Open Bastion everywhere first

Plugin 0.6.0 removes an endpoint that older `ob-bastion-id` depends on. 0.7.0
handles both, so deploying it everywhere first makes the order stop mattering.

```sh
ob-bastion-id --verbose
```

The device id is **unchanged** across the upgrade, so `allowed_bastions` files
do not need rewriting. **Do not re-enrol a bastion to "refresh" it** — that
changes its id and breaks the backends' allowlists.

### B2. Check the fingerprint spool

From 0.6.0, a hop voucher with no SSH fingerprint expires after 15 minutes
instead of 12 hours. Where the spool is not being written, `ob-ssh` hops start
failing a quarter of an hour into a session with `reason: voucher_expired`.

On every bastion and backend: log in with a public key (a password login writes
nothing), then, **as root** — the spool is `0700`, an ordinary `ls` only gets
`Permission denied`:

```sh
sudo find /run/open-bastion/ssh-fp -name '*.fp' -newermt '-2 min'
```

It has to be a _fresh_ drop: old ones are never cleaned up, so a listing that
is merely non-empty proves nothing. No output means the spool is broken — fix
it with [A1](#a1-finish-the-upgrade) before the portal moves.

### B3. Turn on request signing, in this order

Plugin 0.6.0 can require every `/pam/*` call to be signed. All of Open Bastion's
callers sign from 0.7.0.

An older portal has no signature check at all, so it accepts the headers and
ignores them: setting `request_signing_secret` on your hosts buys nothing until
the portal is upgraded. It costs nothing either — do it whenever suits you.

Once you are on 0.6.0, the order is not negotiable:

1. Upgrade every host to 0.7.0.
2. Set `pamAccessRequestSigningMode = optional` on the portal. This already
   refuses a _bad_ signature; it only waives the requirement to sign.
3. Roll `request_signing_secret` out to every host — one portal-wide secret,
   the same value everywhere.
4. Confirm every host signs.
5. Only then set `required`.

Skipping step 4 is how this breaks badly instead of visibly. `/pam/heartbeat`
is how each host renews its access token, so a host left unsigned keeps working
when you flip the switch and goes down hours later, when the token it still
holds expires — the whole fleet together.

The signature is defence in depth on top of TLS, not a substitute. Do not relax
`verify_ssl` because of it.

### B4. Check your PAM scope spelling

The plugin now matches the scope exactly (`pam`, `pam:server`). A relying party
granted `pam-prod` or `x-pam` in `oidcRPMetaDataScopeRules` loses `/pam/*` on
upgrade. Check the RP your hosts enrol against.

### B5. Set `sshCaAdminRule`

```json
"sshCaAdminRule": "$groups =~ /\\bob-ssh-admins\\b/"
```

Unset, `/ssh/admin`, `/ssh/certs` and `/ssh/revoke` answer **403 to everyone**
from 0.6.0 — including whoever is handling an incident. On 0.5.x those routes
had no check at all, so leaving this unset swaps "anyone can revoke anyone's
certificate" for "nobody can revoke anything", the moment you restart the
portal.

Set it **alongside** your vhost `locationRules`, not instead of them; the two
regimes are in
[doc/llng-configuration.md](doc/llng-configuration.md), step 3b.

### B6. Everything else

Nothing here is optional any more: what used to be listed here,
`pamAccessAllowedRps`, is [B0](#b0-required-before-070-goes-to-production).

---

The portal-side list, including settings that only affect the portal, is in the
plugins' own
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).
