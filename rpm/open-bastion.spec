Name:           open-bastion
Version:        0.2.3
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
%{_sbindir}/ob-bastion-cert-helper
%{_sbindir}/ob-cache-admin
%{_bindir}/ob-ssh-cert
%{_bindir}/ob-ssh-proxy
%{_bindir}/ob-bastion-id
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
%{_mandir}/man1/ob-bastion-id.1*
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
# Mode 3771 (drwxrws--t root:ob-sessions): setgid so per-user subdirs inherit
# group ob-sessions; sticky so users only unlink their own entries; o+x (NO
# o+r) so a connecting user — who is NOT in ob-sessions and whose elevated gid
# the recorder wrapper deliberately drops before exec — can still traverse into
# its own subdir created by the wrapper. Without o+x the recorder fails with
# "session directory ... does not exist and could not be created".
chmod 3771 /var/lib/open-bastion/sessions
# Migrate the server token out of /etc (config) into /var/lib (runtime state,
# FHS) so the heartbeat sandbox can keep /etc read-only. Idempotent.
if [ -f /etc/open-bastion/token ] && [ ! -e /var/lib/open-bastion/token ]; then
    mv /etc/open-bastion/token /var/lib/open-bastion/token
    chown root:root /var/lib/open-bastion/token
    chmod 600 /var/lib/open-bastion/token
fi
for _cf in /etc/open-bastion/openbastion.conf /etc/open-bastion/nss_openbastion.conf; do
    [ -f "$_cf" ] && sed -i 's#^\([[:space:]]*server_token_file[[:space:]]*=[[:space:]]*\)/etc/open-bastion/token#\1/var/lib/open-bastion/token#' "$_cf"
done
[ -f /etc/open-bastion/ssh-proxy.conf ] && sed -i 's#^\([[:space:]]*SERVER_TOKEN_FILE=\)"\{0,1\}/etc/open-bastion/token"\{0,1\}#\1"/var/lib/open-bastion/token"#' /etc/open-bastion/ssh-proxy.conf

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
