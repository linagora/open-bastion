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

**Part C — scripts that call `ob-builder`.** Only if they pass `--output-shell`.

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
On a bastion that records sessions it also changes the login shell of SSO users:
see [A7](#a7-sso-users-log-in-through-ob-login-shell-on-a-recording-host).

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

### A7. SSO users log in through `ob-login-shell` on a recording host

Bastions and standalone hosts that record sessions (set up without
`--disable-session-recorder`). Not backends.

The package alone does not switch an existing host; its postinst says when one
needs it. Run `sudo ob-post-upgrade` ([A1](#a1-finish-the-upgrade)), or re-run
the setup script. Either one:

- adds `force_shell = /usr/sbin/ob-login-shell` to
  `/etc/open-bastion/nss_openbastion.conf`. `ob-post-upgrade` changes nothing
  else in the file, and leaves a `force_shell` you set yourself alone, with a
  warning. `default_shell` becomes the shell of the recorded session;
- lists the launcher in `/etc/shells`;
- restarts `nscd` if it runs. No NSS cache needs purging.

A setup run also adds `PermitUserEnvironment no` to the sshd drop-in.

Check it:

```sh
getent passwd <an SSO user> | cut -d: -f7   # expect: /usr/sbin/ob-login-shell
grep ^force_shell /etc/open-bastion/nss_openbastion.conf
```

What changes for SSO users on a recording host:

- **The portal's per-user shell no longer applies**: every recorded session
  runs `default_shell`. Backends still honour the portal's shell.
- **A `Match` block in `sshd_config` no longer exempts them from recording.**
  Exemptions work for local accounts only.
- **`su - <sso user>`, `sudo -i -u <sso user>` and their console logins are
  recorded**, and fail like SSH when the recording sink is down. Keep a local
  account, root on the console for instance, as your rescue path.
- **Their session environment is rebuilt**: only `TERM`, the `SSH_*` variables
  sshd sets, locale names, `XDG_RUNTIME_DIR` and `XDG_SESSION_*` are kept, and
  `PATH` is `/usr/local/bin:/usr/bin:/bin:/usr/games`. Variables set through
  `pam_env`, `SetEnv` or `AcceptEnv` (`TZ`, for instance) no longer arrive: set
  them in the shell's system-wide startup files.

Local accounts keep their shell. To give one that logs in over SSH the same
protection: `chsh -s /usr/sbin/ob-login-shell <user>`.

### A8. `openbastion.conf.example` is gone

`/etc/open-bastion/openbastion.conf.example` is no longer shipped: the upgrade
removes it, or keeps it as `.dpkg-bak` (Debian) or `.rpmsave` (RPM) if you
edited it. Every option, commented out with its default, is now in
`/usr/share/open-bastion/openbastion.conf.reference`; read it there, not in a
copy you keep under `/etc`. Your `openbastion.conf` is not touched.

### A9. The portal must speak TLS 1.3

Every connection to the portal now requires TLS 1.3: the PAM and NSS modules,
`ob-cert-daemon` and the commands, `ob-enroll` and `ob-heartbeat` included.
Until now only the PAM module did, so a portal limited to TLS 1.2 enrolled
hosts and kept their tokens alive while every login failed. Check from one
host, before upgrading:

```sh
curl --tlsv1.3 -sS -o /dev/null https://auth.example.com/ && echo OK
```

A portal that fails it goes behind a TLS 1.3 terminator; there is no setting
to lower the minimum. `min_tls_version` is no longer one: an existing line is
ignored, and logged when it asks for anything but `13`.

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
[doc/deployment/llng-configuration.rst](doc/deployment/llng-configuration.rst), Step 3.

---

The full portal-side list is in the plugins'
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).

### B6. Optional: signed portal answers (`response_signing`)

Needs a portal on plugins with signed responses (lemonldap-ng-plugins#101).
The default is `off`: skip this and nothing changes. Provisioning the JWKS is
manual in this release; automatic distribution comes later.

1. On each host, fetch the portal's keys over a trusted channel from
   `/oauth2/jwks?client_id=<client_id>` and install them as root:
   `install -D -m 0644 -o root -g root jwks.json /var/lib/open-bastion/jwks/sso-jwks.json`
   (not a symlink, not group/world writable). Set `client_id` too.
2. Set `response_signing = prefer` in `openbastion.conf` and
   `nss_openbastion.conf`.
3. Log in, run `getent passwd <sso-user>` and `sudo`, and watch syslog for
   `unsigned answer ... accepted` and `signed answer ... rejected`. Both must
   stay silent.
4. Only then set `required`.

A wrong, stale or unreadable JWKS under `required` refuses every portal
answer: no new SSO login, no NSS lookup, no token refresh, only the offline
cache lets known users in. Keep a root session open while switching, and
re-provision the JWKS after any portal key change (rotation is not automatic
yet).

---

## Part C — scripts that call `ob-builder`

### C1. `--output-shell` takes a directory

```sh
ob-builder --config build.yml --output-shell out/
# writes out/bootstrap-<slug>-<role>.sh, its .sig, out/PORTAL-CHECKLIST-<role>.md
```

It used to be a file name, with the role inserted when there were several. A
path ending in `.sh`, or naming an existing file, is now refused, so a script
still passing `--output-shell bootstrap.sh` stops with:

```
--output-shell takes a directory, not a file name: ...
```

Pass the directory instead, and take the installer from
`<dir>/bootstrap-<slug>-<role>.sh`: the role is in the name even for a single
role.
