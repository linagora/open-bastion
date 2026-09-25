# Upgrade notes

What you have to do so nothing stops. [CHANGELOG.md](CHANGELOG.md) lists the
changes; this is the subset that needs an action or a decision. Only versions
that need something are listed.

Open Bastion and the LemonLDAP::NG plugins
([linagora/lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins))
move independently, so each part below says when it applies.

## 0.7.0

**Part A — on every bastion and backend.** Always required.

**Part B — the portal.** Required for production: the two settings in
[B0](#b0-required-before-070-goes-to-production) exist only on plugins 0.6.0.

If you do both: Part A on every host first, then Part B.

---

## Part A — on every host

### A1. Finish the upgrade

```sh
sudo ob-post-upgrade
```

Installing the package is not enough: until this runs, the SSH fingerprint
binding stays on the old `nobody`-owned spool, and the logs show:

```
SSH fp spool /run/open-bastion/ssh-fp is owned by uid 65534, not root
```

It takes no arguments and is safe to re-run. It does not enrol and does not
touch `openbastion.conf`, the server token, `sshd_config` or PAM stacks.
`--dry-run` shows what it would change. Re-running the setup script works too.

If it cannot enable `ob-fp.socket` it stops and says so: logins would have no
fingerprint binding, and would be refused with `fingerprint_required = true` or
a portal enforcing `pamAccessRequireFingerprint`.

### A2. Check the sshd PAM stack refuses passwords

```sh
grep '^auth' /etc/pam.d/sshd     # expect: auth required pam_deny.so
```

`pam_permit` there means the host accepts **any password for any authorized
account**, and the upgrade does not fix it. Re-run the setup script (it backs
the file up) or edit the line by hand. Only `/etc/pam.d/sshd`: in mode-c,
`/etc/pam.d/sudo` is meant to permit.

### A3. Check the permissions of `cache.key`

```sh
ls -l /etc/open-bastion/cache.key     # expect: -rw------- root root
```

A group- or world-readable key is now rejected (and logged). Fix it with:

```sh
chown root:root /etc/open-bastion/cache.key && chmod 600 /etc/open-bastion/cache.key
```

Until then, each desktop-SSO user needs one online re-authentication, as
existing offline cache entries cannot be read. No lockout.

### A4. Before re-running a setup script with `--node-role`

**`--node-role` now configures the role it names**; it used to set only the
label. Re-running a command whose `--node-role` does not match the host
switches the host's role. Check that label and configuration agree:

```sh
grep '^node_role' /etc/open-bastion/openbastion.conf
ls /etc/ssh/sshd_config.d/*-open-bastion-*.conf   # -bastion.conf or -backend.conf
```

`-backend.conf` goes with `node_role = backend`, `-bastion.conf` with
`bastion` or `standalone`. If they disagree, fix your command: the drop-in is
what the host really is.

**A role switch** (bastion or standalone ↔ backend):

- The old role's sshd drop-in is backed up and removed. Without
  `/etc/ssh/sshd_config.d`, the switch is refused: remove the old block from
  `sshd_config` by hand first.
- The principals helper is replaced just before sshd restarts. Until sshd
  restarts, certificate logins through the other role's configuration are
  denied: restart sshd if the setup could not.
- **Bastion → backend:** `ob-cert.socket` and `ob-record.socket` are disabled
  and `/etc/open-bastion/ssh-proxy.conf` removed. Kept: `session-recorder.conf`,
  the recordings in `/var/lib/open-bastion/sessions` and
  `ob-session-prune.timer`, which keeps expiring them.
- **Backend → bastion:** `/etc/pam.d/sudo`, `/etc/pam.d/sudo-i` and
  `/etc/sudoers.d/open-bastion` are kept (unless `--max-security`), so SSO users
  authorized for sudo can still elevate; the run warns. If they must not,
  restore your distribution's PAM files and delete the sudoers drop-in.
  `allowed_bastions` is kept but unused.

Now refused, before any change:

- `ob-backend-setup --no-sudo --max-security`;
- an option of one role with `--node-role` naming another, e.g.
  `ob-backend-setup --node-role standalone --allowed-bastions ...`;
- `--yes` under a command name other than `ob-bastion-setup`,
  `ob-backend-setup` or `ob-standalone-setup`, without `--node-role`.

### A5. Check the cron jobs moved to systemd timers

Only on hosts set up with `--max-security` or `--enable-audit-trace`.
`/etc/cron.d/open-bastion-krl` and `/etc/cron.daily/open-bastion-audit-rotate`
(or `cron.weekly`) keep running after the upgrade, and the postinst says when a
host still has them. The `ob-post-upgrade` of [A1](#a1-finish-the-upgrade), or
a new setup run, replaces them with `ob-krl-refresh.timer` and
`ob-audit-rotate.timer` on the same schedule, and removes each job only once
its timer is active. If a timer cannot be armed, the job is kept and
`ob-post-upgrade` exits 1.

```sh
systemctl list-timers ob-krl-refresh.timer ob-audit-rotate.timer
ls /etc/cron.d/open-bastion-krl /etc/cron.daily/open-bastion-audit-rotate  # expect: gone
```

A job you edited (restricted hours, several jobs in the file, another user, a
modified audit script) is left in place next to its timer, with a warning; until
you delete it, both run. Port the change with `systemctl edit` on the timer,
then delete the old file.

Afterwards, the refresh uses `timeout` from `openbastion.conf` (10 s as the
setup writes it) instead of 30 s, and a failed refresh fails
`ob-krl-refresh.service` (`systemctl is-failed ob-krl-refresh.service`).
`--enable-hardening` no longer asks for `root` in `/etc/cron.allow`; an
existing file is left as it is.

### A6. Check session recording on bastions

- **Sessions are cut after `max_duration`**: 8 hours on a bastion set up by
  `ob-bastion-setup`, 24 hours where the file has no value. Check
  `grep max_duration /etc/open-bastion/session-recorder.conf` and raise it if
  needed (`0` disables it). A recording also ends after 7 days: to raise that,
  `systemctl edit ob-record@.service` and set
  `Environment=OB_RECORD_MAX_SEC=<seconds>`.
- **`OB_RECORDER_CONFIG`, `OB_RECORDER_FORMAT`, `OB_MAX_SESSION` and
  `OB_SESSIONS_DIR` are ignored.** If you set any of them (`/etc/environment`,
  a pam_env file, `SetEnv` in `sshd_config`), move the setting to
  `session-recorder.conf` or to the `ForceCommand` line (`-c FILE`,
  `-f FORMAT`).
- **Only genuine scp, rsync and sftp commands run as transfers**; anything else
  is recorded as a terminal session, where a binary protocol fails. Known
  cases: rsync with `--secluded-args` (`-s`, or `RSYNC_PROTECT_ARGS` on the
  client), and remote paths written with shell syntax (`$HOME`, quotes) rather
  than backslash escapes. Refusals are logged:
  `journalctl -t ob-session-recorder | grep transfer-like`.
- **A user's 17th concurrent recorded session is refused** (systemd 256 or
  newer). Raise `MaxConnectionsPerSource` with `systemctl edit ob-record.socket`
  if your users need more.

Sessions open during the upgrade finish normally.

---

## Part B — before moving the portal to plugins 0.6.0

### B0. Required before 0.7.0 goes to production

Until both portal settings are set, **any compromised enrolled host can pose as
a bastion** on `/pam/authorize` and obtain hop vouchers (risk R-P1). This is the
default.

1. **`pamAccessServerGroups`**: the authoritative `client_id → server_group`
   mapping.
2. **`pamAccessAllowedRps`**: the RPs allowed on `/pam/*`. Bastions then need a
   `client_id` of their own, not the project-wide one: plan that first.

And on the hosts:

3. **`allowed_bastions` non-empty on every backend**:
   `ob-backend-setup --allowed-bastions <bastion_id>[,<id>...]`. Empty accepts
   a voucher from any bastion.

Hosts cannot check 1 and 2. The setup scripts and `ob-post-upgrade` print this
list on every run, and `ob-builder` writes a pre-filled `PORTAL-CHECKLIST.md`;
checking it is up to you. Details: `doc/security/09-portail-llng.rst` (R-P1)
and `doc/security/08-dossier-homologation.rst` (CE03, CE06, CE16, CE21).

### B1. Upgrade Open Bastion everywhere first

Plugin 0.6.0 removes the endpoint older `ob-bastion-id` uses; 0.7.0 handles
both. Check with:

```sh
ob-bastion-id --verbose
```

The device id does not change, so `allowed_bastions` stays valid. **Do not
re-enrol a bastion**: that changes its id and breaks the backends' allowlists.

### B2. Check the fingerprint spool

From plugin 0.6.0, a hop voucher without an SSH fingerprint expires after 15
minutes instead of 12 hours: where the spool is not written, `ob-ssh` hops fail
with `reason: voucher_expired`.

On every host, log in with a public key, then as root:

```sh
sudo find /run/open-bastion/ssh-fp -name '*.fp' -newermt '-2 min'
```

No output means the spool is broken: fix it with
[A1](#a1-finish-the-upgrade) before moving the portal. Old drops are never
cleaned up, so only a fresh one proves anything.

### B3. Turn on request signing, in this order

1. Upgrade every host to 0.7.0.
2. Set `pamAccessRequestSigningMode = optional` on the portal (bad signatures
   are already refused).
3. Deploy the same `request_signing_secret` on every host.
4. Confirm every host signs.
5. Only then set `required`.

Skipping step 4 fails late: an unsigned host keeps working until its access
token expires, hours later (`/pam/heartbeat` renews it), and the whole fleet
fails together. Setting the secret before the portal upgrade is harmless. Keep
`verify_ssl` on: signing does not replace TLS.

### B4. Check your PAM scope spelling

The plugin matches the scope exactly (`pam`, `pam:server`). An RP granted
`pam-prod` or `x-pam` in `oidcRPMetaDataScopeRules` loses `/pam/*`. Check the
RP your hosts enrol against.

### B5. Set `sshCaAdminRule`

```json
"sshCaAdminRule": "$groups =~ /\\bob-ssh-admins\\b/"
```

Unset, `/ssh/admin`, `/ssh/certs` and `/ssh/revoke` answer **403 to everyone**
once the portal restarts on 0.6.0. Set it **alongside** the vhost
`locationRules`, not instead: see
[doc/llng-configuration.rst](doc/llng-configuration.rst), step 3b.

---

The full portal-side list is in the plugins'
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).
