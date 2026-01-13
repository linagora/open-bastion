Name:           pam-llng
Version:        1.0.0
Release:        1%{?dist}
Summary:        PAM module for LemonLDAP::NG authentication

License:        AGPL-3.0-or-later
URL:            https://github.com/LemonLDAPNG/llng-pam-module
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.10
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pam-devel
BuildRequires:  libcurl-devel
BuildRequires:  pkgconfig(json-c)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig
BuildRequires:  systemd-rpm-macros

Requires:       pam
Requires:       libcurl
Requires:       json-c
Requires:       openssl-libs
Requires:       curl
Requires:       jq
Requires:       nscd
Requires:       systemd
Requires:       util-linux

%description
PAM module for LemonLDAP::NG authentication supporting token-based
and key-based authorization with server groups.

%prep
%autosetup

%build
%set_build_flags
%cmake \
    -DENABLE_CACHE=ON \
    -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir}
%cmake_build

%install
%cmake_install

%files
%license LICENSE
%doc README.md
%{_libdir}/security/pam_llng.so*
%{_libdir}/libnss_llng.so*
%config(noreplace) %{_sysconfdir}/security/pam_llng.conf.example
%config(noreplace) %{_sysconfdir}/nss_llng.conf.example
%{_sbindir}/llng-pam-enroll
%{_sbindir}/llng-pam-heartbeat
%{_sbindir}/llng-session-recorder
%{_sbindir}/llng-bastion-setup
%{_sbindir}/llng-backend-setup
%{_bindir}/llng-ssh-cert
%{_bindir}/llng-ssh-proxy
%dir %{_sysconfdir}/llng
%config(noreplace) %{_sysconfdir}/llng/session-recorder.conf.example
%config(noreplace) %{_sysconfdir}/llng/ssh-proxy.conf.example
%{_unitdir}/pam-llng-heartbeat.service
%{_unitdir}/pam-llng-heartbeat.timer
%{_mandir}/man1/llng-ssh-cert.1*
%{_mandir}/man8/llng-pam-enroll.8*
%{_mandir}/man8/llng-pam-heartbeat.8*
%{_mandir}/man8/llng-bastion-setup.8*
%{_mandir}/man8/llng-backend-setup.8*
%{_mandir}/man8/llng-session-recorder.8*
%{_mandir}/man1/llng-ssh-proxy.1*
%exclude %{_docdir}/pam_llng/README.md

%post
%systemd_post pam-llng-heartbeat.timer

%preun
%systemd_preun pam-llng-heartbeat.timer

%postun
%systemd_postun_with_restart pam-llng-heartbeat.timer

%changelog
* Sat Dec 14 2025 Xavier Guimard <xguimard@linagora.com> - 1.0.0-1
- Initial RPM package
