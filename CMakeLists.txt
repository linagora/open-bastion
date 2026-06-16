cmake_minimum_required(VERSION 3.10)
project(open-bastion VERSION 0.4.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(ENABLE_CACHE "Enable token caching" ON)
option(BUILD_TESTING "Build tests" ON)
option(INSTALL_SYSTEMD "Install systemd unit files" ON)
option(INSTALL_DESKTOP "Install Desktop SSO components (LightDM greeter)" OFF)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JSON_C REQUIRED json-c)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Find PAM
find_path(PAM_INCLUDE_DIR security/pam_modules.h
    PATHS /usr/include /usr/local/include
)
find_library(PAM_LIBRARY pam
    PATHS /lib /usr/lib /usr/local/lib
)

if(NOT PAM_INCLUDE_DIR OR NOT PAM_LIBRARY)
    message(FATAL_ERROR "PAM library not found")
endif()

# Source files
set(PAM_MODULE_SOURCES
    src/pam_openbastion.c
    src/ob_client.c
    src/config.c
    src/audit_log.c
    src/rate_limiter.c
    src/client_context.c
    src/token_manager.c
    src/jwt_utils.c
    src/notify.c
    src/secret_store.c
    src/auth_cache.c
    src/cache_key.c
    src/crowdsec.c
    src/service_account.c
    src/ssh_key_policy.c
    src/str_utils.c
)

if(ENABLE_CACHE)
    list(APPEND PAM_MODULE_SOURCES src/token_cache.c)
    add_definitions(-DENABLE_CACHE)
endif()

# Desktop SSO components (offline credential cache, OAuth2 introspection)
# When INSTALL_DESKTOP=OFF, none of this code is compiled into pam_openbastion.so.
# This ensures the core SSH module has zero desktop code paths.
if(INSTALL_DESKTOP)
    list(APPEND PAM_MODULE_SOURCES src/offline_cache.c)
    add_definitions(-DENABLE_DESKTOP_SSO)
endif()

if(INSTALL_DESKTOP)
    # Optional libsodium for Argon2id (preferred) - fallback to OpenSSL 3.0+
    option(USE_LIBSODIUM "Use libsodium for Argon2id (recommended)" OFF)

    if(USE_LIBSODIUM)
        pkg_check_modules(SODIUM REQUIRED libsodium)
        add_definitions(-DHAVE_LIBSODIUM)
    else()
        # Check OpenSSL version >= 3.0 for Argon2id support
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
        check_c_source_compiles("
            #include <openssl/opensslv.h>
            #if OPENSSL_VERSION_NUMBER < 0x30000000L
            #error OpenSSL 3.0+ required
            #endif
            int main() { return 0; }
        " HAVE_OPENSSL_3)

        if(NOT HAVE_OPENSSL_3)
            message(FATAL_ERROR
                "Offline credential cache requires either:\n"
                "  - libsodium (recommended): cmake -DUSE_LIBSODIUM=ON ..\n"
                "  - OpenSSL 3.0+ (detected version is too old)\n"
                "Please install libsodium-dev or upgrade OpenSSL.")
        endif()
    endif()
endif()

# Build the PAM module as a shared library
add_library(pam_openbastion SHARED ${PAM_MODULE_SOURCES})

# Set output name without "lib" prefix
set_target_properties(pam_openbastion PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pam_openbastion"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Include directories
target_include_directories(pam_openbastion PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_INCLUDE_DIRS}>
)

# Link libraries
target_link_libraries(pam_openbastion
    ${PAM_LIBRARY}
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_LIBRARIES}>
)

# Compiler flags
target_compile_options(pam_openbastion PRIVATE
    -Wall -Wextra -Werror
    -fPIC
    -D_GNU_SOURCE
    # Security hardening flags
    -fstack-protector-strong      # Stack buffer overflow protection
    -Wformat -Wformat-security    # Format string vulnerability detection
    -fvisibility=hidden           # Hide internal symbols, reduce attack surface
    # Link-Time Optimization for Release builds
    $<$<CONFIG:Release>:-flto>
)

# Note: _FORTIFY_SOURCE is set by distribution build systems (Debian hardening)
# Do not set it here to avoid redefinition warnings with -Werror

# Linker security flags (Full RELRO = relro + now)
target_link_options(pam_openbastion PRIVATE
    -Wl,-z,relro                  # RELRO (with -z,now = Full RELRO)
    -Wl,-z,now                    # Resolve symbols at load time (completes Full RELRO)
    -Wl,-z,noexecstack            # Non-executable stack
    # Link-Time Optimization for Release builds
    $<$<CONFIG:Release>:-flto>
)

# Installation
include(GNUInstallDirs)

# Install PAM module
install(TARGETS pam_openbastion
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/security
)

# Install configuration files
install(FILES ${CMAKE_SOURCE_DIR}/config/openbastion.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
    RENAME openbastion.conf.example
)
install(FILES ${CMAKE_SOURCE_DIR}/config/service-accounts.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Install documentation
install(FILES ${CMAKE_SOURCE_DIR}/README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Install enrollment script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-enroll
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install heartbeat script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-heartbeat
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install session recorder script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-session-recorder
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Build and install session recorder setgid wrapper
add_executable(ob-session-recorder-wrapper
    src/ob-session-recorder-wrapper.c
)
target_compile_options(ob-session-recorder-wrapper PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-session-recorder-wrapper PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-session-recorder-wrapper
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install session recorder config example
install(FILES ${CMAKE_SOURCE_DIR}/scripts/session-recorder.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Shared cert-vouching library, sourced by ob-ssh / ob-scp. Installed to a
# fixed (non-multiarch) /usr/lib/open-bastion path that the scripts look up.
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ob-cert-lib.sh
    DESTINATION lib/open-bastion
)

# Bastion-to-backend SSH / SCP connectors (cert vouching).
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-ssh
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-scp
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Bastion identity helper (used when configuring backend whitelists)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-bastion-id
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install SSH proxy config example
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ssh-proxy.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Bastion certificate minting: socket-activated daemon + unprivileged client.
# Replaces the old `sudo ob-bastion-cert-helper` bridge. ob-cert-daemon (root,
# socket-activated) holds the server token and derives the certificate's user
# from the connection's SO_PEERCRED; ob-cert-request is the unprivileged client
# that ob-ssh / ob-scp invoke — no sudo, no setuid.
add_executable(ob-cert-daemon src/ob-cert-daemon.c src/ob_cert_proto.c)
target_include_directories(ob-cert-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
)
target_compile_options(ob-cert-daemon PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_libraries(ob-cert-daemon
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
)
target_link_options(ob-cert-daemon PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-cert-daemon
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

add_executable(ob-cert-request src/ob-cert-request.c)
target_compile_options(ob-cert-request PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-cert-request PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-cert-request
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install SSH certificate tool (user-facing)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-ssh-cert
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install hardening templates (session containment - PR1)
# These are deployed by ob-bastion-setup into /etc/{systemd/logind.conf.d,security/limits.d,at.allow,cron.allow}
# See doc/hardening.md for rationale.
install(FILES ${CMAKE_SOURCE_DIR}/config/hardening/logind.conf.d/open-bastion.conf
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/hardening/logind.conf.d
)
install(FILES ${CMAKE_SOURCE_DIR}/config/hardening/security/limits.d/open-bastion.conf
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/hardening/security/limits.d
)
install(FILES ${CMAKE_SOURCE_DIR}/config/hardening/at.allow
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/hardening
)
install(FILES ${CMAKE_SOURCE_DIR}/config/hardening/cron.allow
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/hardening
)

# Install setup scripts (admin-facing)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-bastion-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ob-standalone-setup is a symlink to ob-bastion-setup: invoked under that name
# the script defaults --node-role to "standalone", giving admins a clearer,
# self-documenting command for combined bastion+backend hosts.
install(CODE "
    set(_sbindir \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_SBINDIR}\")
    execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
        ob-bastion-setup \"\${_sbindir}/ob-standalone-setup\")
")

# Install auditd templates (consumed by `ob-bastion-setup --enable-audit-trace`).
# Read-only templates under /usr/share/open-bastion/audit/. The setup function
# copies them into /etc/audit/rules.d/ and /etc/cron.daily/ at deployment time.
# These are NOT dpkg conffiles / rpm config(noreplace) — see doc/audit.md.
install(FILES ${CMAKE_SOURCE_DIR}/config/audit/rules.d/open-bastion.rules
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/audit/rules.d
)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/config/audit/cron.daily/open-bastion-audit-rotate
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/audit/cron.daily
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-backend-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install cache admin tool (useful for both SSH and Desktop offline modes)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-cache-admin
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install man pages (section 8 - admin commands)
install(FILES
    ${CMAKE_SOURCE_DIR}/man/ob-enroll.8
    ${CMAKE_SOURCE_DIR}/man/ob-heartbeat.8
    ${CMAKE_SOURCE_DIR}/man/ob-bastion-setup.8
    ${CMAKE_SOURCE_DIR}/man/ob-backend-setup.8
    ${CMAKE_SOURCE_DIR}/man/ob-session-recorder.8
    ${CMAKE_SOURCE_DIR}/man/ob-cert-daemon.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)

# Man page for the ob-standalone-setup symlink (points at ob-bastion-setup.8).
install(CODE "
    set(_man8dir \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_MANDIR}/man8\")
    execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
        ob-bastion-setup.8 \"\${_man8dir}/ob-standalone-setup.8\")
")

# Install man pages (section 1 - user commands)
install(FILES
    ${CMAKE_SOURCE_DIR}/man/ob-ssh-cert.1
    ${CMAKE_SOURCE_DIR}/man/ob-ssh.1
    ${CMAKE_SOURCE_DIR}/man/ob-scp.1
    ${CMAKE_SOURCE_DIR}/man/ob-bastion-id.1
    ${CMAKE_SOURCE_DIR}/man/ob-cert-request.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

# Install systemd units (disabled for Debian packaging which uses dh_installsystemd)
if(INSTALL_SYSTEMD)
    install(FILES
        ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.timer
        ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-cert.socket
        ${CMAKE_SOURCE_DIR}/systemd/ob-cert@.service
        DESTINATION lib/systemd/system
    )
    # Desktop-specific systemd service
    if(INSTALL_DESKTOP)
        install(FILES
            ${CMAKE_SOURCE_DIR}/systemd/ob-session-monitor.service
            DESTINATION lib/systemd/system
        )
    endif()
endif()

# Desktop SSO components (LightDM greeter, session monitor)
if(INSTALL_DESKTOP)
    # Install session monitor script
    install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-session-monitor
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )

    # Install desktop setup script
    install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-desktop-setup
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )

    # Install LightDM greeter theme to standard lightdm-webkit theme location
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/lightdm/greeter/
        DESTINATION ${CMAKE_INSTALL_DATADIR}/lightdm-webkit/themes/open-bastion
    )

    # Install LightDM configuration example
    install(FILES ${CMAKE_SOURCE_DIR}/lightdm/config/lightdm-openbastion.conf
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
        RENAME lightdm-openbastion.conf.example
    )
endif()

# Build NSS module
add_subdirectory(nss)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "open-bastion")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Bastion - Secure SSH bastion with PAM/NSS modules")
set(CPACK_PACKAGE_VENDOR "Linagora")
set(CPACK_PACKAGE_CONTACT "Open Bastion team <open-bastion@linagora.com>")

# Debian package
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpam0g, libcurl4, libjson-c5 | libjson-c5t64, libssl3 | libssl3t64, libkeyutils1, curl, jq")
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")

# RPM package
set(CPACK_RPM_PACKAGE_LICENSE "AGPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Base")
set(CPACK_RPM_PACKAGE_REQUIRES "pam, libcurl, json-c, openssl-libs, keyutils-libs, curl, jq")

include(CPack)

# ── open-bastion-builder package ────────────────────────────────────────────
# The builder is an admin workstation tool: pure bash, no dependency on the
# open-bastion runtime package. It is packaged separately so it can be
# installed on machines that never run the PAM/NSS module.
#
# We deliberately avoid CPACK_DEB_COMPONENT_INSTALL here because enabling it
# would rename every existing install() destination to *-unspecified, breaking
# the main open-bastion package. Instead we stage the builder files into the
# build tree and invoke dpkg-deb (Debian) / rpmbuild (RPM) directly via a
# custom target.
# ────────────────────────────────────────────────────────────────────────────
option(BUILD_BUILDER "Build the open-bastion-builder package" ON)

# Auto-disable when the admin-builder/ tree is absent — typical for Docker
# integration tests that COPY only the runtime source paths.
if(BUILD_BUILDER AND NOT EXISTS "${CMAKE_SOURCE_DIR}/admin-builder/debian/control")
    message(STATUS "admin-builder/ tree not present — disabling BUILD_BUILDER")
    set(BUILD_BUILDER OFF)
endif()

if(BUILD_BUILDER)
    set(BUILDER_PKG_NAME "open-bastion-builder")
    set(BUILDER_PKG_VERSION ${PROJECT_VERSION})
    set(BUILDER_STAGE_DIR "${CMAKE_BINARY_DIR}/builder-pkg")

    # ── Debian package ───────────────────────────────────────────────────
    # Stage directory mirrors the final filesystem layout:
    #   usr/bin/ob-builder
    #   usr/share/open-bastion-builder/lib/*.sh
    #   usr/share/open-bastion-builder/templates/...
    #   DEBIAN/control
    #   DEBIAN/postinst

    set(BUILDER_DEB_DIR "${BUILDER_STAGE_DIR}/deb")
    set(BUILDER_DEB_ROOT "${BUILDER_DEB_DIR}/root")

    # CMake's configure_file does create missing parent directories on
    # recent versions, but be explicit: ensures correctness on older
    # CMake and silences static-analysis tooling that flags the implicit
    # behaviour.
    file(MAKE_DIRECTORY "${BUILDER_DEB_ROOT}/DEBIAN")

    # Generate DEBIAN/control with the real version substituted
    configure_file(
        "${CMAKE_SOURCE_DIR}/admin-builder/debian/control"
        "${BUILDER_DEB_ROOT}/DEBIAN/control"
        @ONLY
    )

    # Copy postinst verbatim; chmod 0755 is applied by the custom command below
    configure_file(
        "${CMAKE_SOURCE_DIR}/admin-builder/debian/postinst"
        "${BUILDER_DEB_ROOT}/DEBIAN/postinst"
        COPYONLY
    )

    # Produce the .deb via a custom target (requires dpkg-deb at build time)
    set(BUILDER_DEB_OUTPUT
        "${CMAKE_BINARY_DIR}/${BUILDER_PKG_NAME}_${BUILDER_PKG_VERSION}_all.deb")

    find_program(DPKG_DEB_EXECUTABLE dpkg-deb)
    if(NOT DPKG_DEB_EXECUTABLE)
        message(STATUS "dpkg-deb not found — skipping open-bastion-builder DEB target")
    else()
    add_custom_target(builder-deb ALL
        # Install the main script
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/bin"
        COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_SOURCE_DIR}/admin-builder/ob-builder"
            "${BUILDER_DEB_ROOT}/usr/bin/ob-builder"
        COMMAND chmod 0755
            "${BUILDER_DEB_ROOT}/usr/bin/ob-builder"

        # Install lib scripts
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/lib"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/lib"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/lib"

        # Install templates
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/templates"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/templates"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/templates"

        # Install bundled GPG keyrings (default = Linagora)
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/keyrings"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/keyrings"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/keyrings"

        # Install man page
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/man/man1"
        COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_SOURCE_DIR}/admin-builder/man/ob-builder.1"
            "${BUILDER_DEB_ROOT}/usr/share/man/man1/ob-builder.1"

        # Fix permissions: DEBIAN scripts must be 0755
        COMMAND chmod 0755
            "${BUILDER_DEB_ROOT}/DEBIAN/postinst"

        # Build the .deb
        COMMAND dpkg-deb --build --root-owner-group
            "${BUILDER_DEB_ROOT}"
            "${BUILDER_DEB_OUTPUT}"

        COMMENT "Building ${BUILDER_PKG_NAME} Debian package"
        VERBATIM
    )
    endif()

    # ── RPM package ──────────────────────────────────────────────────────
    # Only attempted when rpmbuild is available; silently skipped otherwise.
    find_program(RPMBUILD_EXECUTABLE rpmbuild)
    if(RPMBUILD_EXECUTABLE)
        set(BUILDER_RPM_OUTPUT
            "${CMAKE_BINARY_DIR}/${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}-1.noarch.rpm")

        # Generate the spec from the .in template
        configure_file(
            "${CMAKE_SOURCE_DIR}/admin-builder/rpm/open-bastion-builder.spec.in"
            "${CMAKE_BINARY_DIR}/open-bastion-builder.spec"
            @ONLY
        )

        # rpmbuild needs a proper SOURCES tree; we build a tarball of the admin-builder dir
        set(BUILDER_RPM_TARBALL "${CMAKE_BINARY_DIR}/builder-pkg/rpm/${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}.tar.gz")
        add_custom_target(builder-rpm ALL
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "${CMAKE_BINARY_DIR}/builder-pkg/rpm"
            COMMAND tar -czf "${BUILDER_RPM_TARBALL}"
                -C "${CMAKE_SOURCE_DIR}"
                --transform "s|^admin-builder|${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}|"
                admin-builder
            COMMAND ${RPMBUILD_EXECUTABLE}
                --define "_topdir ${CMAKE_BINARY_DIR}/builder-pkg/rpm/rpmbuild"
                --define "_sourcedir ${CMAKE_BINARY_DIR}/builder-pkg/rpm"
                --define "_rpmdir ${CMAKE_BINARY_DIR}"
                -bb "${CMAKE_BINARY_DIR}/open-bastion-builder.spec"
            COMMENT "Building ${BUILDER_PKG_NAME} RPM package"
            VERBATIM
        )
    else()
        message(STATUS "rpmbuild not found — skipping open-bastion-builder RPM target")
    endif()
endif()
