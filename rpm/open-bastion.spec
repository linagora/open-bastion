Name:           open-bastion
Version:        0.2.0
Release:        1%{?dist}
Summary:        Open Bastion PAM/NSS module for SSH bastion authentication

License:        AGPL-3.0-or-later
URL:            https://github.com/linagora/open-bastion
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.10
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pam-devel
BuildRequires:  libcurl-devel
BuildRequires:  pkgconfig(json-c)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(libsodium)
BuildRequires:  pkgconfig
BuildRequires:  systemd-rpm-macros

Requires:       pam
Requires:       libcurl
Requires:       json-c
Requires:       openssl-libs
Requires:       libsodium
Requires:       curl
Requires:       jq
Requires:       nscd
Requires:       systemd
Requires:       util-linux

# Soft dependency: needed only when admin opts in via
# `ob-bastion-setup --enable-audit-trace`. The audit templates ship in this
# package; the auditd daemon itself is pulled in only by Recommends.
Recommends:     audit

%description
Open Bastion PAM/NSS module for SSH bastion authentication supporting
token-based and key-based authorization with server groups.

%package desktop
Summary:        Open Bastion LightDM greeter for Desktop SSO
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       lightdm
Requires:       lightdm-webkit2-greeter

%description desktop
A LightDM webkit2 greeter theme that enables desktop workstations to
authenticate users via LemonLDAP::NG Single Sign-On.

Features:
 - SSO authentication via embedded LLNG portal iframe
 - Offline mode with cached credentials when server is unreachable
 - Multi-factor authentication support (TOTP, WebAuthn, etc.)
 - Session selection for multiple desktop environments
 - Modern, responsive design

%prep
%autosetup

%build
%set_build_flags
%cmake \
    -DENABLE_CACHE=ON \
    -DUSE_LIBSODIUM=ON \
    -DBUILD_TESTING=ON \
    -DINSTALL_DESKTOP=ON \
    -DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir}
%cmake_build

%check
cd %{_vpath_builddir}
ctest --output-on-failure --verbose

%install
%cmake_install

%files
%license LICENSE
%doc README.md
%{_libdir}/security/pam_openbastion.so*
%{_libdir}/libnss_openbastion.so*
%dir %{_sysconfdir}/open-bastion
%config(noreplace) %{_sysconfdir}/open-bastion/openbastion.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/nss_openbastion.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/service-accounts.conf.example
%{_sbindir}/ob-enroll
%{_sbindir}/ob-heartbeat
%{_sbindir}/ob-session-recorder
%attr(2755,root,ob-sessions) %{_sbindir}/ob-session-recorder-wrapper
%{_sbindir}/ob-bastion-setup
%{_sbindir}/ob-backend-setup
%{_sbindir}/ob-cache-admin
%{_bindir}/ob-ssh-cert
%{_bindir}/ob-ssh-proxy
%config(noreplace) %{_sysconfdir}/open-bastion/session-recorder.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/ssh-proxy.conf.example
%dir %{_datadir}/open-bastion
%dir %{_datadir}/open-bastion/audit
%dir %{_datadir}/open-bastion/audit/rules.d
%dir %{_datadir}/open-bastion/audit/cron.daily
%{_datadir}/open-bastion/audit/rules.d/open-bastion.rules
%{_datadir}/open-bastion/audit/cron.daily/open-bastion-audit-rotate
%{_unitdir}/ob-heartbeat.service
%{_unitdir}/ob-heartbeat.timer
%{_mandir}/man1/ob-ssh-cert.1*
%{_mandir}/man8/ob-enroll.8*
%{_mandir}/man8/ob-heartbeat.8*
%{_mandir}/man8/ob-bastion-setup.8*
%{_mandir}/man8/ob-backend-setup.8*
%{_mandir}/man8/ob-session-recorder.8*
%{_mandir}/man1/ob-ssh-proxy.1*
# Hardening templates (session containment - deployed by ob-bastion-setup)
%dir %{_datadir}/open-bastion
%dir %{_datadir}/open-bastion/hardening
%dir %{_datadir}/open-bastion/hardening/logind.conf.d
%dir %{_datadir}/open-bastion/hardening/security
%dir %{_datadir}/open-bastion/hardening/security/limits.d
%{_datadir}/open-bastion/hardening/logind.conf.d/open-bastion.conf
%{_datadir}/open-bastion/hardening/security/limits.d/open-bastion.conf
%{_datadir}/open-bastion/hardening/at.allow
%{_datadir}/open-bastion/hardening/cron.allow
%exclude %{_docdir}/open-bastion/README.md

%files desktop
%{_sbindir}/ob-desktop-setup
%{_sbindir}/ob-session-monitor
%config(noreplace) %{_sysconfdir}/open-bastion/lightdm-openbastion.conf.example
%dir %{_datadir}/lightdm-webkit
%dir %{_datadir}/lightdm-webkit/themes
%dir %{_datadir}/lightdm-webkit/themes/open-bastion
%{_datadir}/lightdm-webkit/themes/open-bastion/greeter.js
%{_datadir}/lightdm-webkit/themes/open-bastion/index.html
%{_datadir}/lightdm-webkit/themes/open-bastion/index.theme
%{_datadir}/lightdm-webkit/themes/open-bastion/style.css
%{_unitdir}/ob-session-monitor.service

%pre
# Create ob-sessions group for session recording privilege separation
getent group ob-sessions >/dev/null 2>&1 || groupadd --system ob-sessions
# Create open-bastion-sudo group for defense-in-depth sudo authorization (Mode E)
getent group open-bastion-sudo >/dev/null 2>&1 || groupadd --system open-bastion-sudo

%post
%systemd_post ob-heartbeat.timer
# Create required directories
mkdir -p /etc/open-bastion
chmod 755 /etc/open-bastion
mkdir -p /var/cache/open-bastion
chmod 700 /var/cache/open-bastion
mkdir -p /var/lib/open-bastion
chmod 711 /var/lib/open-bastion
mkdir -p /var/lib/open-bastion/sessions
chgrp ob-sessions /var/lib/open-bastion/sessions
chmod 1770 /var/lib/open-bastion/sessions

%preun
%systemd_preun ob-heartbeat.timer

%postun
%systemd_postun_with_restart ob-heartbeat.timer

%post desktop
%systemd_post ob-session-monitor.service
# Create cache directory for offline credentials
mkdir -p /var/cache/open-bastion/credentials
chmod 0700 /var/cache/open-bastion/credentials

%preun desktop
%systemd_preun ob-session-monitor.service

%postun desktop
%systemd_postun_with_restart ob-session-monitor.service
# Clean up cache and runtime directories on purge
if [ "$1" = "0" ]; then
    rm -rf /var/cache/open-bastion/credentials
    rm -rf /run/open-bastion/offline_sessions
fi

%changelog
* Thu Apr 30 2026 Xavier Guimard <xguimard@linagora.com> - 0.2.0-1
- Three independent opt-in features (none changes existing behaviour;
  v0.1.5 → v0.2.0 with no flag set runs identically). v0.1.6 was
  prepared internally but never published; its content is folded here.
- Service accounts (machine accounts): local Unix accounts declared in
  /etc/open-bastion/service-accounts.conf (0600 root:root) that
  LemonLDAP::NG never sees, for CI agents and headless tooling.
  pam_openbastion materialises the Unix user on first login
  (create_user = true) with forced uid/gid; libnss_openbastion
  resolves them so sshd's pre-auth getpwnam() succeeds. Mode E
  support via /usr/local/sbin/ob-service-account-keys
  (AuthorizedKeysCommand helper). New docker-demo-token-svc/ variant
  and integration tests
- Session-containment hardening (ob-bastion-setup --enable-hardening,
  off by default): closes setsid/nohup orphans (KillUserProcesses=yes
  via /etc/systemd/logind.conf.d/), at(1) and crontab(1) for non-root
  users (at.allow empty + atd masked, cron.allow root-only),
  systemd-run --user --on-active timers (linger pre-flight refusal),
  and fork bombs (nproc cap 256, @ob-service group exempt). No new
  setuid binary. Templates ship under
  /usr/share/open-bastion/hardening/, deployed into /etc/ at runtime.
  New doc/hardening.md + 20 integration tests
- Primary audit trace via auditd (ob-bastion-setup
  --enable-audit-trace, off by default): execve+execveat, connect,
  watches on /etc/passwd, /etc/shadow, /etc/sudoers(.d),
  /etc/ssh/sshd_config(.d), /var/lib/open-bastion/sessions/,
  /etc/open-bastion/. Daily SIGUSR1 rotation cron for ~1 week local
  retention. /etc/audit/auditd.conf intentionally not modified
  (admin-tunable). Warns and skips if auditd is absent. auditd
  declared as Recommends:, never installed silently. New doc/audit.md
  + 11 tests
- Security analysis updated (doc/security/02-ssh-connection.md +
  99-risk-reduce.md): R-S18 score corrected (P=2, I=1; the wrapper
  setgid + sticky bit provide cross-user isolation, not own-file
  immutability — syslog and the new auditd watch preserve traceability).
  R-S19/20/21 added (containment evasion, deferred action,
  syscalls-not-captured); residual scores assume both --enable-hardening
  and --enable-audit-trace activated
- Security: strict 0600 root:root enforced on service-accounts.conf in
  libnss_openbastion; service-account entries not persisted to the
  on-disk NSS cache. The hardening linger pre-flight is a security
  gate (fails the step under --yes too)
- Upgrade notes: all features opt-in; recommended on dedicated
  bastions: --enable-hardening --enable-audit-trace. apt install
  --no-install-recommends will not pull auditd; install it explicitly
  if you want the audit trace

* Mon Apr 20 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.5-1
- SSH key fingerprint binding on /pam/authorize and /pam/verify
  (requires LemonLDAP::NG PamAccess >= 0.1.16 and SSHCA >= 0.1.16);
  LLNG cross-checks the fingerprint against the user's persistent
  session (_sshCerts) and rejects on unknown/revoked/expired cert,
  independently of the local sshd KRL
- New helper /usr/local/sbin/ob-ssh-principals (deployed by
  ob-bastion-setup / ob-backend-setup as AuthorizedPrincipalsCommand
  "%u %f"); drops the fingerprint atomically to
  /run/open-bastion/ssh-fp/<sshd-session-pid>.fp. pam_openbastion walks
  /proc to the sshd-session ancestor and reads the file with strict
  validation (owner/mode/nlink/size/format). systemd-tmpfiles drop-in
  recreates the spool directory at boot.
- Spool directory hardened: 0700, owned by AuthorizedPrincipalsCommand
  user; pam_openbastion refuses group/world-writable directories and
  any drop file whose owner/mode/nlink does not match (uid == dir uid,
  mode 0600, nlink == 1)
- Strict SHA256 filter: only SHA256:<base64> fingerprints are
  forwarded, preventing HTTP 400 when sshd uses FingerprintHash md5
- New integration tests covering fingerprint match/unknown/malformed
  on /pam/authorize, /ssh/myrevoke revocation without KRL refresh, and
  an end-to-end SSH refusal at PAM account phase
- Re-run ob-bastion-setup / ob-backend-setup after upgrade

* Sat Apr 18 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.4-1
- NSS config path fix: libnss_openbastion reads from
  /etc/open-bastion/nss_openbastion.conf (previously hard-coded to
  /etc/nss_llng.conf, silently broke user resolution); re-run
  ob-bastion-setup/ob-backend-setup after upgrade
- Session recorder wrapper hardened: explicit gid drop before exec,
  directory setgid (2770), dangerous env vars stripped, PATH hardened,
  username regex-validated, username from getpwuid() instead of env
- ob-session-recorder: SESSION_USER from "id -un", not user-controllable $USER
- NSS config and token file: O_NOFOLLOW, fstat-based perm checks (root
  owner, regular file, not group/world-writable; token not group/world-readable)
- NSS write_callback: overflow check and 256 KB response size cap
- Defense-in-depth sudo: open-bastion-sudo system group, dynamic
  membership sync by pam_openbastion based on sudo_allowed, nscd cache
  invalidated after change; ob-bastion-setup writes
  %open-bastion-sudo ALL=(ALL) ALL in /etc/sudoers.d/open-bastion
- TOCTOU races in session directory creation fixed (fchown/fchmod on fd)
- quick-start/ demo added for fast evaluation

* Wed Apr 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.3-1
- Mode E hardening: tested end-to-end deployment
- Session recording privilege separation (setgid wrapper, ob-sessions group)
- Fix PAM module name (pam_llng.so -> pam_openbastion.so)
- Fix NSS module symbols (_nss_llng_ -> _nss_openbastion_)
- Fix ob-enroll client_secret handling (optional)
- Fix setup scripts: Include directive, AuthorizedPrincipalsCommand,
  PermitRootLogin no, NSS config, token path, session recorder paths
- Fix sudo Mode E: remove pam_unix.so, add sudoers.d/open-bastion
- Add pam_mkhomedir.so for automatic home directory creation
- New risk R-S18: session recording tampering (mitigated)

* Sat Feb 07 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.1-1
- Supplementary groups synchronization via managed_groups
- Local whitelist for managed groups (allowed_managed_groups)
- CrowdSec IP/CIDR whitelist for trusted IPs/networks
- Fixed TOCTOU race condition in cache_key.c

* Sat Dec 14 2025 Xavier Guimard <xguimard@linagora.com> - 0.1.0-1
- Initial RPM package
- Renamed project from pam-llng to open-bastion
