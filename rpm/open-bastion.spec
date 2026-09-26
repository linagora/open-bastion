Name:           open-bastion
Version:        0.6.3
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
Requires:       glibc-langpack-en
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

# debian/open-bastion.dirs provisions the same two directories on the Debian
# side; without this an RPM host would keep hitting LLNG over HTTPS for every
# getpwnam() from a short-lived process.
mkdir -p %{buildroot}/var/cache/nss_llng/byname

%files
%license LICENSE
%doc README.md
%{_libdir}/security/pam_openbastion.so*
%{_libdir}/libnss_openbastion.so*
%dir %{_sysconfdir}/open-bastion
%config(noreplace) %{_sysconfdir}/open-bastion/openbastion.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/nss_openbastion.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/service-accounts.conf.example
%dir %attr(0755,root,root) %{_sysconfdir}/open-bastion/service-accounts.d
%{_sbindir}/ob-enroll
%{_sbindir}/ob-heartbeat
%{_sbindir}/ob-session-recorder
# ob-standalone-setup and ob-backend-setup are symlinks to this script, made
# by CMake, which choose the default node role.
%{_sbindir}/ob-bastion-setup
%{_sbindir}/ob-standalone-setup
%{_sbindir}/ob-backend-setup
%{_sbindir}/ob-cert-daemon
%{_sbindir}/ob-fp-daemon
%{_sbindir}/ob-fp-submit
%{_sbindir}/ob-sign-request
%{_sbindir}/ob-client-jwt
%{_sbindir}/ob-post-upgrade
%{_sbindir}/ob-uninstall
%{_sbindir}/ob-service-account-keys
%{_sbindir}/ob-record-sink
%{_sbindir}/ob-cache-admin
%{_sbindir}/ob-session-prune
%{_sbindir}/ob-krl-refresh
%{_bindir}/ob-ssh-cert
%{_bindir}/ob-ssh
%{_bindir}/ob-scp
%{_bindir}/ob-sftp
%{_bindir}/ob-cert-request
%{_bindir}/ob-record-connect
%{_bindir}/ob-bastion-id
%dir %{_prefix}/lib/open-bastion
%{_prefix}/lib/open-bastion/ob-cert-lib.sh
%{_prefix}/lib/open-bastion/ob-sign-lib.sh
%{_prefix}/lib/open-bastion/ob-timers-lib.sh
%{_prefix}/lib/open-bastion/ob-ssh-principals.bastion
%{_prefix}/lib/open-bastion/ob-ssh-principals.backend
%{_prefix}/lib/open-bastion/ob-fp-spool.tmpfiles
%{_prefix}/lib/open-bastion/ob-portal-prerequisites.txt
# 0711 = traversable but NOT listable. Entries are 0644 so an unprivileged
# getpwnam()/getpwuid() can read its own record, but no local account can
# readdir() and enumerate the SSO user directory wholesale -- matters most for
# byname/, whose filenames are the login names themselves.
%attr(0711,root,root) %dir /var/cache/nss_llng
%attr(0711,root,root) %dir /var/cache/nss_llng/byname
%config(noreplace) %{_sysconfdir}/open-bastion/session-recorder.conf.example
%config(noreplace) %{_sysconfdir}/open-bastion/ssh-proxy.conf.example
%dir %{_datadir}/open-bastion
%dir %{_datadir}/open-bastion/audit
%dir %{_datadir}/open-bastion/audit/rules.d
%{_datadir}/open-bastion/audit/rules.d/open-bastion.rules
# Not %config: audit_log_file is configurable.
%dir %{_datadir}/open-bastion/logrotate
%{_datadir}/open-bastion/logrotate/open-bastion
%{_unitdir}/ob-heartbeat.service
%{_unitdir}/ob-heartbeat.timer
%{_unitdir}/ob-cert.socket
%{_unitdir}/ob-fp.socket
%{_unitdir}/ob-fp@.service
%{_unitdir}/ob-cert@.service
%{_unitdir}/ob-record.socket
%{_unitdir}/ob-record@.service
%{_unitdir}/ob-session-prune.service
%{_unitdir}/ob-session-prune.timer
%{_unitdir}/ob-krl-refresh.service
%{_unitdir}/ob-krl-refresh.timer
%{_unitdir}/ob-audit-rotate.service
%{_unitdir}/ob-audit-rotate.timer
%{_mandir}/man1/ob-ssh-cert.1*
%{_mandir}/man1/ob-bastion-id.1*
%{_mandir}/man8/ob-enroll.8*
%{_mandir}/man8/ob-heartbeat.8*
%{_mandir}/man8/ob-bastion-setup.8*
%{_mandir}/man8/ob-standalone-setup.8*
%{_mandir}/man8/ob-backend-setup.8*
%{_mandir}/man8/ob-session-recorder.8*
%{_mandir}/man8/ob-session-prune.8*
%{_mandir}/man8/ob-krl-refresh.8*
%{_mandir}/man8/ob-cert-daemon.8*
%{_mandir}/man8/ob-fp-daemon.8*
%{_mandir}/man8/ob-fp-submit.8*
%{_mandir}/man8/ob-record-sink.8*
%{_mandir}/man8/ob-sign-request.8*
%{_mandir}/man8/ob-client-jwt.8*
%{_mandir}/man8/ob-post-upgrade.8*
%{_mandir}/man8/ob-uninstall.8*
%{_mandir}/man1/ob-ssh.1*
%{_mandir}/man1/ob-scp.1*
%{_mandir}/man1/ob-sftp.1*
%{_mandir}/man1/ob-cert-request.1*
%{_mandir}/man1/ob-record-connect.1*
# Deployed by ob-bastion-setup.
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
getent group ob-sessions >/dev/null 2>&1 || groupadd --system ob-sessions
getent group open-bastion-sudo >/dev/null 2>&1 || groupadd --system open-bastion-sudo

%post
%systemd_post ob-heartbeat.timer
%systemd_post ob-session-prune.timer
mkdir -p /etc/open-bastion
chmod 755 /etc/open-bastion
mkdir -p /var/cache/open-bastion
chmod 700 /var/cache/open-bastion
mkdir -p /var/lib/open-bastion
chmod 711 /var/lib/open-bastion
# Re-assert 0711 on upgrade from a version that shipped it 0755 (the module
# also does this at runtime on its next write).
mkdir -p /var/cache/nss_llng/byname
chmod 711 /var/cache/nss_llng /var/cache/nss_llng/byname
mkdir -p /var/lib/open-bastion/sessions
# Tamper-evident layout: root:ob-sessions 0750. The recorded user is NOT in
# ob-sessions, so it has no access to any recording (incl. its own); auditors
# in ob-sessions get group read. ob-bastion-setup re-asserts this and migrates
# any legacy user-owned per-user subdirs.
chown root:ob-sessions /var/lib/open-bastion/sessions
chmod 0750 /var/lib/open-bastion/sessions
rm -f %{_sbindir}/ob-session-recorder-wrapper
# Migrates the server token out of /etc into /var/lib (runtime state) so the
# heartbeat sandbox can keep /etc read-only. Idempotent.
if [ -f /etc/open-bastion/token ] && [ ! -e /var/lib/open-bastion/token ]; then
    mv /etc/open-bastion/token /var/lib/open-bastion/token
    chown root:root /var/lib/open-bastion/token
    chmod 600 /var/lib/open-bastion/token
fi
for _cf in /etc/open-bastion/openbastion.conf /etc/open-bastion/nss_openbastion.conf; do
    [ -f "$_cf" ] && sed -i 's#^\([[:space:]]*server_token_file[[:space:]]*=[[:space:]]*\)/etc/open-bastion/token#\1/var/lib/open-bastion/token#' "$_cf"
done
[ -f /etc/open-bastion/ssh-proxy.conf ] && sed -i 's#^\([[:space:]]*SERVER_TOKEN_FILE=\)"\{0,1\}/etc/open-bastion/token"\{0,1\}#\1"/var/lib/open-bastion/token"#' /etc/open-bastion/ssh-proxy.conf
# Enabled by default with no ConditionPathExists gate; the explicit enable
# guarantees it regardless of the distro's systemd preset policy. On upgrade
# ($1 > 1) we respect the admin's choice and leave it alone.
if [ $1 -eq 1 ]; then
    systemctl --no-reload enable ob-session-prune.timer >/dev/null 2>&1 || :
    systemctl start ob-session-prune.timer >/dev/null 2>&1 || :
fi
# Repair/migration parity with the Debian postinst: nothing in these
# scriptlets disables the sockets on upgrade, and there is no RPM analogue of
# the deb-systemd-helper state layer that dropped them on Debian, so a host
# whose ob-cert.socket or ob-record.socket ended up inactive is repaired by
# reinstalling or upgrading the package.
#
# ob-cert.socket and ob-record.socket are deliberately not enabled at
# install: the package cannot know a host's role, so ob-bastion-setup is what
# enables them. Act only when this host is ALREADY a bastion -- the sshd
# drop-in written by ob-bastion-setup is the role marker. Failures are
# non-fatal.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    for _ob_dropin in /etc/ssh/sshd_config.d/*-open-bastion-bastion.conf; do
        [ -f "$_ob_dropin" ] || continue
        systemctl enable --now ob-cert.socket >/dev/null 2>&1 || :
        # Only when recording is enabled (the ForceCommand is absent under
        # ob-bastion-setup --disable-session-recorder).
        if grep -Eq '^[[:space:]]*ForceCommand[[:space:]]+.*ob-session-recorder' "$_ob_dropin"; then
            systemctl enable --now ob-record.socket >/dev/null 2>&1 || :
        fi
        break
    done
fi
# Needed on BOTH roles: a backend runs an AuthorizedPrincipalsCommand too, so
# this gets its own loop rather than riding along with the bastion-only block
# above. Without it the principals helper has nowhere to deposit and the
# fingerprint binding disappears with no error at login time.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    for _ob_role in /etc/ssh/sshd_config.d/*-open-bastion-bastion.conf \
                    /etc/ssh/sshd_config.d/*-open-bastion-backend.conf; do
        [ -f "$_ob_role" ] || continue
        systemctl enable --now ob-fp.socket >/dev/null 2>&1 || :
        break
    done
fi

# Legacy cron jobs keep working until ob-post-upgrade replaces them with timers.
if [ -e /etc/cron.d/open-bastion-krl ] \
   || [ -e /etc/cron.daily/open-bastion-audit-rotate ] \
   || [ -e /etc/cron.weekly/open-bastion-audit-rotate ]; then
    echo "open-bastion: this host still runs the cron jobs of 0.6 (KRL refresh and/or" >&2
    echo "  audit rotation). They keep working; run 'ob-post-upgrade' to replace them" >&2
    echo "  with ob-krl-refresh.timer / ob-audit-rotate.timer, same schedule." >&2
fi

%preun
%systemd_preun ob-heartbeat.timer
%systemd_preun ob-session-prune.timer
# Enabled by ob-bastion-setup (not at install); disable on removal.
%systemd_preun ob-krl-refresh.timer
%systemd_preun ob-audit-rotate.timer
# Cert/record sockets are enabled by ob-bastion-setup (not at install); disable
# on removal.
%systemd_preun ob-cert.socket
%systemd_preun ob-record.socket
%systemd_preun ob-fp.socket

%postun
%systemd_postun_with_restart ob-heartbeat.timer
%systemd_postun_with_restart ob-session-prune.timer
%systemd_postun_with_restart ob-krl-refresh.timer
%systemd_postun_with_restart ob-audit-rotate.timer
%systemd_postun_with_restart ob-cert.socket
%systemd_postun_with_restart ob-fp.socket
%systemd_postun_with_restart ob-record.socket

%post desktop
%systemd_post ob-session-monitor.service
mkdir -p /var/cache/open-bastion/credentials
chmod 0700 /var/cache/open-bastion/credentials

%preun desktop
%systemd_preun ob-session-monitor.service

%postun desktop
%systemd_postun_with_restart ob-session-monitor.service
# $1 = 0 means final removal (purge), not a mere upgrade.
if [ "$1" = "0" ]; then
    rm -rf /var/cache/open-bastion/credentials
    rm -rf /run/open-bastion/offline_sessions
fi

%changelog
* Mon Sep 21 2026 Xavier Guimard <xguimard@linagora.com> - 0.6.3-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Thu Jun 25 2026 Xavier Guimard <xguimard@linagora.com> - 0.6.2-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Thu Jun 25 2026 Xavier Guimard <xguimard@linagora.com> - 0.6.1-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Mon Jun 22 2026 Xavier Guimard <xguimard@linagora.com> - 0.6.0-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Wed Jun 17 2026 Xavier Guimard <xguimard@linagora.com> - 0.5.1-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Tue Jun 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.5.0-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Tue Jun 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.4.1-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Tue Jun 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.4.0-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Tue Jun 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.3.2-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Mon Jun 15 2026 Xavier Guimard <xguimard@linagora.com> - 0.3.1-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Sat Jun 13 2026 Xavier Guimard <xguimard@linagora.com> - 0.3.0-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Sat May 23 2026 Xavier Guimard <xguimard@linagora.com> - 0.2.3-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Thu May 21 2026 Xavier Guimard <xguimard@linagora.com> - 0.2.2-1
- See https://github.com/linagora/open-bastion/blob/main/CHANGELOG.md
* Wed May 20 2026 Xavier Guimard <xguimard@linagora.com> - 0.2.1-1
- See CHANGELOG.md
* Thu Apr 30 2026 Xavier Guimard <xguimard@linagora.com> - 0.2.0-1
- See CHANGELOG.md
* Mon Apr 20 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.5-1
- See CHANGELOG.md
* Sat Apr 18 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.4-1
- See CHANGELOG.md
* Wed Apr 16 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.3-1
- See CHANGELOG.md
* Sat Feb 07 2026 Xavier Guimard <xguimard@linagora.com> - 0.1.1-1
- See CHANGELOG.md
* Sat Dec 14 2025 Xavier Guimard <xguimard@linagora.com> - 0.1.0-1
- Initial release
