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
Requires:       systemd

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
%config(noreplace) %{_sysconfdir}/security/pam_llng.conf.example
%{_sbindir}/llng-pam-enroll
%{_sbindir}/llng-pam-heartbeat
%{_unitdir}/pam-llng-heartbeat.service
%{_unitdir}/pam-llng-heartbeat.timer
%{_mandir}/man8/llng-pam-enroll.8*
%exclude %{_docdir}/pam_llng/README.md

%post
%systemd_post pam-llng-heartbeat.timer

%preun
%systemd_preun pam-llng-heartbeat.timer

%postun
%systemd_postun_with_restart pam-llng-heartbeat.timer

%changelog
* Sat Dec 14 2024 LemonLDAP::NG Team <lemonldap-ng@ow2.org> - 1.0.0-1
- Initial RPM package
