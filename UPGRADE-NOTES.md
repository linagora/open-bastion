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

### A4. Before re-running a setup script with `--node-role`

Only if your automation passes `--node-role`, or you run a setup script again
later. `ob-backend-setup` is now a symlink to `ob-bastion-setup` (#288), and
**`--node-role` configures the role it names** instead of only writing it into
`openbastion.conf`. Until now, `ob-bastion-setup --node-role backend` produced
a bastion labelled `backend`, and `ob-backend-setup --node-role bastion` or
`--node-role standalone` a backend labelled otherwise. Re-running such a
command now turns the host into what the label says.

Check that the label and the configuration agree:

```sh
grep '^node_role' /etc/open-bastion/openbastion.conf
ls /etc/ssh/sshd_config.d/*-open-bastion-*.conf   # -bastion.conf or -backend.conf
```

A `-backend.conf` drop-in goes with `node_role = backend`; a `-bastion.conf`
one with `bastion` or `standalone`. If they disagree, fix the command before
the next run — the drop-in says what the host really is — or the run will
switch the host's role.

**What a role switch does, and does not do.** It is supported between a
bastion (or standalone host) and a backend, in both directions:

- The sshd drop-in of the old role is removed (backed up) and the new one
  written. On an sshd **without `/etc/ssh/sshd_config.d`**, where the setup
  appends a block to `sshd_config` and never rewrites one, a switch is refused
  before anything is touched: remove the old block by hand, then run again.
- The principals helper is replaced at the end of the run, right before sshd is
  restarted, not before enrollment. In between, and if sshd is not restarted,
  either helper **denies** a login made through the other role's sshd
  configuration — a certificate login fails rather than bypasses the vouching
  or the recording. Restart sshd if the setup could not.
- **Bastion → backend:** `ob-cert.socket` (hop-certificate minting with this
  host's token) and `ob-record.socket` are disabled, and
  `/etc/open-bastion/ssh-proxy.conf` is removed. Left in place:
  `session-recorder.conf`, the recordings under `/var/lib/open-bastion/sessions`
  and `ob-session-prune.timer`, which keeps expiring them.
- **Backend → bastion:** the backend's LLNG sudo stack is **left in place**:
  `/etc/pam.d/sudo`, `/etc/pam.d/sudo-i` and `/etc/sudoers.d/open-bastion`. SSO
  users LLNG authorizes for sudo can still elevate on the bastion. The run warns
  about it; if they must not, restore your distribution's two PAM files and
  delete the sudoers drop-in. (With `--max-security` the sudo stack is rewritten
  anyway.) `/etc/open-bastion/allowed_bastions` is also left; a bastion does
  not read it.

Three command lines that used to be accepted are now refused, before anything
is touched: `ob-backend-setup --no-sudo --max-security` (Mode E rewrites the
sudo stack regardless, and the run left SSO users with no sudoers rule); any
option of one role combined with `--node-role` naming the other, such as
`ob-backend-setup --node-role standalone --allowed-bastions ...`; and a `--yes`
run of a copy of the script under a name other than `ob-bastion-setup`,
`ob-backend-setup` or `ob-standalone-setup`, unless it passes `--node-role`.

### A5. The KRL refresh and the audit rotation are systemd timers

Only on hosts set up with `--max-security` (Mode E) or `--enable-audit-trace`.
Up to 0.6 the setup scheduled them with cron (#281):

| 0.6 (cron)                                                                 | 0.7.0 (systemd)         |
| -------------------------------------------------------------------------- | ----------------------- |
| `/etc/cron.d/open-bastion-krl` + `/usr/local/bin/open-bastion-refresh-krl` | `ob-krl-refresh.timer`  |
| `/etc/cron.daily/open-bastion-audit-rotate` (or `cron.weekly`)             | `ob-audit-rotate.timer` |

**Nothing stops at the upgrade.** The old jobs are self-contained and keep
running; the package does not touch them, and its postinst says when a host
still has them. The `sudo ob-post-upgrade` of [A1](#a1-finish-the-upgrade)
moves them over (so does a new setup run with the same options):

- the KRL job's interval is carried over — any `*/N` in the minute field
  becomes `/etc/systemd/system/ob-krl-refresh.timer.d/schedule.conf` when it is
  not the default 30; a rotation moved to `cron.weekly` becomes a weekly timer;
- the timer is enabled and started, and **the old job is removed only once the
  timer is enabled and active**. If the timer cannot be armed, `ob-post-upgrade`
  keeps the job, says why and exits 1: a host is never left with neither;
- a job you reshaped (hours restricted, several jobs in the file, another user)
  or an audit script you edited is not translated and not removed: the timer
  is armed next to it and a warning tells you what to port. Port it, then
  delete the old file.

Check the result:

```sh
systemctl list-timers ob-krl-refresh.timer ob-audit-rotate.timer
ls /etc/cron.d/open-bastion-krl /etc/cron.daily/open-bastion-audit-rotate  # expect: gone
```

Two behaviour changes come with it. The refresh reads `portal_url`,
`verify_ssl`, `timeout` and `ca_cert` from `openbastion.conf` at every run
instead of the values frozen into the old script, so its connection timeout is
now that file's `timeout` (10 s as written by the setup) rather than 30 s. And a
failed refresh now shows as a failed `ob-krl-refresh.service` rather than
nothing: if you monitored the age of `/etc/ssh/revoked_keys`, that still works
(the file's date is updated at every successful refresh), and
`systemctl is-failed ob-krl-refresh.service` is the more direct check.

With `--enable-hardening`, the setup no longer asks for `root` in
`/etc/cron.allow`: nothing of ours runs from cron. Your `cron.allow` is left as
it is, and `cron` itself is still not masked.

### A6. Session recording: what now actually applies (#287)

Bastions only. Four behaviours change because controls that were documented
but did not work now do:

- **`max_duration` ends sessions.** It never did: the watchdog could not fire
  before the session was over. `ob-bastion-setup` writes `max_duration = 28800`,
  so on a bastion it set up **sessions are now cut after 8 hours** (24 hours
  where the file has no value). Check
  `grep max_duration /etc/open-bastion/session-recorder.conf`, and raise it if
  that is too short for your users (`0` disables it).
- **`OB_RECORDER_CONFIG`, `OB_RECORDER_FORMAT`, `OB_MAX_SESSION` and
  `OB_SESSIONS_DIR` are no longer read.** They came from the recorded user's
  environment. If you set any of them (in `/etc/environment`, a pam_env file,
  `SetEnv` in `sshd_config`), move the setting to the config file or to the
  `ForceCommand` line (`-c FILE`, `-f FORMAT`).
- **Only genuine scp, rsync and sftp commands skip the terminal recording**
  (they are recorded as metadata only, as before). Anything else that merely
  looks like a transfer is now recorded as an ordinary session, so
  a transfer client the recorder does not recognise fails the way a binary
  protocol fails in a terminal. The known case is rsync with `--secluded-args`
  (`-s`, or `RSYNC_PROTECT_ARGS` set on the client); remote paths written with
  shell syntax (`$HOME`, quotes) rather than backslash escapes are the other.
  Refusals are logged: `journalctl -t ob-session-recorder | grep transfer-like`.
- **A recording lasts at most 7 days** (`ob-record-sink`'s new cap; it had no
  bound but a 30 s idle timeout that cut silent sessions). Longer sessions:
  `systemctl edit ob-record@.service`, then
  `Environment=OB_RECORD_MAX_SEC=<seconds>`.

The recorder, `ob-record-connect` and `ob-record-sink` now speak a framed
protocol (v2), and the sink refuses the old one. They ship in the same
package; sessions open during the upgrade keep the processes they started
with and finish normally.

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

Background: `doc/security/09-portail-llng.rst` (R-P1) and
`doc/security/08-dossier-homologation.rst` (CE03, CE06, CE16, CE21).

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
[doc/llng-configuration.rst](doc/llng-configuration.rst), step 3b.

### B6. Everything else

Nothing here is optional any more: what used to be listed here,
`pamAccessAllowedRps`, is [B0](#b0-required-before-070-goes-to-production).

---

The portal-side list, including settings that only affect the portal, is in the
plugins' own
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).
