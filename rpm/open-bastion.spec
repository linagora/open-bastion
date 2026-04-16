Name:           open-bastion
Version:        0.1.3
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
%{_unitdir}/ob-heartbeat.service
%{_unitdir}/ob-heartbeat.timer
%{_mandir}/man1/ob-ssh-cert.1*
%{_mandir}/man8/ob-enroll.8*
%{_mandir}/man8/ob-heartbeat.8*
%{_mandir}/man8/ob-bastion-setup.8*
%{_mandir}/man8/ob-backend-setup.8*
%{_mandir}/man8/ob-session-recorder.8*
%{_mandir}/man1/ob-ssh-proxy.1*
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
