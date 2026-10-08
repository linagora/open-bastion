cmake_minimum_required(VERSION 3.10)
project(open-bastion VERSION 0.6.3 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_TESTING "Build tests" ON)
option(INSTALL_SYSTEMD "Install systemd unit files" ON)
option(INSTALL_DESKTOP "Install Desktop SSO components (LightDM greeter)" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JSON_C REQUIRED json-c)
pkg_check_modules(OPENSSL REQUIRED openssl)

find_path(PAM_INCLUDE_DIR security/pam_modules.h
    PATHS /usr/include /usr/local/include
)
find_library(PAM_LIBRARY pam
    PATHS /lib /usr/lib /usr/local/lib
)

if(NOT PAM_INCLUDE_DIR OR NOT PAM_LIBRARY)
    message(FATAL_ERROR "PAM library not found")
endif()

set(PAM_MODULE_SOURCES
    src/pam_openbastion.c
    src/ob_client.c
    src/ob_jws.c
    src/ob_sign.c
    src/config.c
    src/audit_log.c
    src/rate_limiter.c
    src/token_manager.c
    src/jwt_utils.c
    src/notify.c
    src/auth_cache.c
    src/cache_key.c
    src/crowdsec.c
    src/service_account.c
    src/ssh_key_policy.c
    src/sshd_anchor.c
    src/str_utils.c
)

# Desktop SSO components (offline credential cache, OAuth2 introspection)
if(INSTALL_DESKTOP)
    list(APPEND PAM_MODULE_SOURCES src/offline_cache.c)
    add_definitions(-DENABLE_DESKTOP_SSO)
endif()

if(INSTALL_DESKTOP)
    option(USE_LIBSODIUM "Use libsodium for Argon2id (recommended)" OFF)

    if(USE_LIBSODIUM)
        pkg_check_modules(SODIUM REQUIRED libsodium)
        add_definitions(-DHAVE_LIBSODIUM)
    else()
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

add_library(pam_openbastion SHARED ${PAM_MODULE_SOURCES})

# PAM modules are loaded by basename; keep the conventional lib-less name.
set_target_properties(pam_openbastion PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pam_openbastion"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

target_include_directories(pam_openbastion PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_INCLUDE_DIRS}>
)

target_link_libraries(pam_openbastion
    ${PAM_LIBRARY}
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_LIBRARIES}>
)

target_compile_options(pam_openbastion PRIVATE
    -Wall -Wextra -Werror
    -fPIC
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    -fvisibility=hidden
    $<$<CONFIG:Release>:-flto>
)

# _FORTIFY_SOURCE is set by distribution build systems (Debian hardening);
# setting it here too triggers a redefinition warning under -Werror.

# -z,relro and -z,now together give Full RELRO; either alone is partial.
target_link_options(pam_openbastion PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)

include(GNUInstallDirs)

install(TARGETS pam_openbastion
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/security
)

install(FILES ${CMAKE_SOURCE_DIR}/config/openbastion.conf.reference
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion
)
install(FILES ${CMAKE_SOURCE_DIR}/config/service-accounts.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

install(FILES ${CMAKE_SOURCE_DIR}/README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

find_program(SPHINX_BUILD NAMES sphinx-build sphinx-build-3)

# The man pages are generated from doc/references/man/, the same
# sources the HTML documentation is built from. Default depends on
# sphinx-build being found or not.
if(NOT DEFINED BUILD_MAN)
    if(SPHINX_BUILD)
        set(_ob_build_man_default ON)
    else()
        set(_ob_build_man_default OFF)
    endif()
    option(BUILD_MAN "Generate the man pages with Sphinx" ${_ob_build_man_default})
    unset(_ob_build_man_default)
endif()

if(BUILD_MAN)
    if(NOT SPHINX_BUILD)
        message(FATAL_ERROR
            "BUILD_MAN=ON but sphinx-build was not found — install python3-sphinx, "
            "or configure with -DBUILD_MAN=OFF to build without man pages")
    endif()

    set(MAN_OUT_DIR ${CMAKE_BINARY_DIR}/man)
    add_custom_target(man ALL
        COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
                ${SPHINX_BUILD} -q -b man
                -d ${CMAKE_BINARY_DIR}/doc/doctrees-man
                ${CMAKE_SOURCE_DIR}/doc ${MAN_OUT_DIR}
        COMMENT "Generating the man pages with Sphinx"
        VERBATIM
    )

    # One page documents the three roles of the setup command; the aliases are
    # installed as links to it, as they always were.
    foreach(_ob_setup_alias ob-standalone-setup ob-backend-setup)
        add_custom_command(TARGET man POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E create_symlink
                ob-bastion-setup.8 ${MAN_OUT_DIR}/${_ob_setup_alias}.8
            VERBATIM
        )
    endforeach()
endif()

# Off by default so the ordinary build needs no Python; debian/rules enables it.
option(BUILD_DOC "Build the HTML documentation with Sphinx" OFF)

if(BUILD_DOC)
    if(NOT SPHINX_BUILD)
        message(FATAL_ERROR "BUILD_DOC=ON but sphinx-build was not found")
    endif()

    set(DOC_HTML_DIR ${CMAKE_BINARY_DIR}/doc/html)
    add_custom_target(doc ALL
        COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
                ${SPHINX_BUILD} -q -b html
                -d ${CMAKE_BINARY_DIR}/doc/doctrees
                ${CMAKE_SOURCE_DIR}/doc ${DOC_HTML_DIR}
        COMMENT "Building HTML documentation with Sphinx"
        VERBATIM
    )

    # .buildinfo and _sources are Sphinx build artefacts, not doc content.
    install(DIRECTORY ${DOC_HTML_DIR}/
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/html
        PATTERN ".buildinfo" EXCLUDE
        PATTERN "_sources" EXCLUDE
    )
endif()

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-enroll
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-heartbeat
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-session-recorder
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Run by ob-session-prune.timer.
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-session-prune
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Run by ob-krl-refresh.timer.
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-krl-refresh
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(FILES ${CMAKE_SOURCE_DIR}/scripts/session-recorder.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Fixed (non-multiarch) path: ob-ssh / ob-scp / ob-sftp source it from there.
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ob-cert-lib.sh
    DESTINATION lib/open-bastion
)

# Same fixed path as ob-cert-lib.sh; sourced by every shell caller of a
# /pam/ endpoint (ob-heartbeat, ob-bastion-id, ob-enroll, ob-session-monitor).
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ob-sign-lib.sh
    DESTINATION lib/open-bastion
)

# Same fixed path; sourced by the setup script and ob-post-upgrade.
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ob-timers-lib.sh
    DESTINATION lib/open-bastion
)

# Same fixed path; sourced by the setup script and ob-post-upgrade.
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ob-login-shell-lib.sh
    DESTINATION lib/open-bastion
)

# The generated sshd principals helper, and the tmpfiles rule that recreates its
# spool at boot. One copy, installed as data: ob-bastion-setup, ob-backend-setup
# and ob-post-upgrade all read these rather than each carrying a heredoc (#254).
#
# Plain lib/, not CMAKE_INSTALL_LIBDIR: that expands to the multiarch
# lib/x86_64-linux-gnu on Debian, but the .install file and the scripts'
# OB_DATA_DIR default both name /usr/lib/open-bastion.
install(FILES
    ${CMAKE_SOURCE_DIR}/share/ob-ssh-principals.bastion
    ${CMAKE_SOURCE_DIR}/share/ob-ssh-principals.backend
    ${CMAKE_SOURCE_DIR}/share/ob-fp-spool.tmpfiles
    ${CMAKE_SOURCE_DIR}/share/ob-portal-prerequisites.txt
    DESTINATION lib/open-bastion
)

# Bastion-to-backend SSH / SCP / SFTP connectors (cert vouching).
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-ssh
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-scp
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-sftp
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-bastion-id
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# sshd AuthorizedKeysCommand helper: serves a service account's public key
# without the Unix account having to exist yet.
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-service-account-keys
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Must be readable/traversable by AuthorizedKeysCommandUser (nobody), or the
# helper above is inert.
#
# Absolute, not ${CMAKE_INSTALL_SYSCONFDIR}: under CMAKE_INSTALL_PREFIX=/usr
# GNUInstallDirs leaves SYSCONFDIR relative, landing this in /usr/etc/ instead.
# `cmake --install --prefix <dir>` therefore ignores this DESTINATION and would
# touch the real /etc; DESTDIR staging (.deb/.rpm builds) is unaffected.
install(DIRECTORY
    DESTINATION /etc/open-bastion/service-accounts.d
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                          GROUP_READ GROUP_EXECUTE
                          WORLD_READ WORLD_EXECUTE
)

# Post-upgrade repair. Takes no configuration and never enrols, so an operator
# who no longer remembers the setup arguments can still finish an upgrade.
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-post-upgrade
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-uninstall
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install SSH proxy config example
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ssh-proxy.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# ob-cert-daemon (root, socket-activated) holds the server token; ob-cert-request
# is the unprivileged client ob-ssh / ob-scp / ob-sftp invoke -- no sudo, no
# setuid. See doc/references/bastion-cert-vouching.rst.
add_executable(ob-cert-daemon
    src/ob-cert-daemon.c
    src/ob_cert_proto.c
    src/ob_sign.c
    src/str_utils.c
)
target_include_directories(ob-cert-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
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
    ${OPENSSL_LIBRARIES}
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

# ob-fp-daemon (root) owns a 0700 spool and derives the sshd anchor from the
# depositing process's own /proc ancestry; ob-fp-submit is what the
# AuthorizedPrincipalsCommand helper pipes to -- no sudo, no setuid.
add_executable(ob-fp-daemon src/ob-fp-daemon.c src/sshd_anchor.c)
target_include_directories(ob-fp-daemon PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_options(ob-fp-daemon PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-fp-daemon PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-fp-daemon
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

add_executable(ob-fp-submit src/ob-fp-submit.c)
target_compile_options(ob-fp-submit PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-fp-submit PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-fp-submit
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Root-only: reads request_signing_secret from openbastion.conf so callers
# never pass it on an `openssl dgst -hmac` command line, where
# /proc/<pid>/cmdline would expose it.
add_executable(ob-sign-request
    src/ob-sign-request.c
    src/ob_sign.c
    src/str_utils.c
)
target_include_directories(ob-sign-request PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_compile_options(ob-sign-request PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_libraries(ob-sign-request
    ${OPENSSL_LIBRARIES}
)
target_link_options(ob-sign-request PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-sign-request
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Same /proc/<pid>/cmdline concern as ob-sign-request, for the OIDC client
# secret: it arrives on stdin, never as a command-line argument.
add_executable(ob-client-jwt
    src/ob-client-jwt.c
    src/jwt_utils.c
)
target_include_directories(ob-client-jwt PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_compile_options(ob-client-jwt PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_libraries(ob-client-jwt
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
target_link_options(ob-client-jwt PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-client-jwt
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ob-record-sink (root, socket-activated) writes recordings root-owned so the
# recorded user cannot touch them. See doc/references/tamper-evident-session-recording.rst.
add_executable(ob-record-sink src/ob-record-sink.c src/ob_cert_proto.c)
target_include_directories(ob-record-sink PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
)
target_compile_options(ob-record-sink PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_libraries(ob-record-sink
    ${JSON_C_LIBRARIES}
)
target_link_options(ob-record-sink PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-record-sink
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

add_executable(ob-record-connect src/ob-record-connect.c)
target_compile_options(ob-record-connect PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-record-connect PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-record-connect
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Login shell of SSO users on a recording host; see ob-login-shell(8).
add_executable(ob-login-shell src/ob-login-shell.c)
target_include_directories(ob-login-shell PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_options(ob-login-shell PRIVATE
    -Wall -Wextra -Werror
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    $<$<CONFIG:Release>:-flto>
)
target_link_options(ob-login-shell PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    $<$<CONFIG:Release>:-flto>
)
install(TARGETS ob-login-shell
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Deployed by ob-bastion-setup; see doc/hardening.rst.
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

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-bastion-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ob-standalone-setup and ob-backend-setup are symlinks to ob-bastion-setup:
# the name it is invoked under chooses the default node role.
#
# The links are made in the build tree and installed like any other file, so
# they follow the install-time prefix rather than baking in a configure-time
# CMAKE_INSTALL_FULL_* path.
foreach(_ob_setup_alias ob-standalone-setup ob-backend-setup)
    execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
        ob-bastion-setup "${CMAKE_BINARY_DIR}/${_ob_setup_alias}")
    install(FILES ${CMAKE_BINARY_DIR}/${_ob_setup_alias}
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )
endforeach()

# Read-only templates, not dpkg conffiles / rpm config(noreplace); consumed by
# `ob-bastion-setup --enable-audit-trace`. See doc/audit.rst.
install(FILES ${CMAKE_SOURCE_DIR}/config/audit/rules.d/open-bastion.rules
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/audit/rules.d
)

# NOT a conffile: the log path (audit_log_file) is configurable.
install(FILES ${CMAKE_SOURCE_DIR}/config/logrotate/open-bastion
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/open-bastion/logrotate
)

# The man pages are generated into ${MAN_OUT_DIR} by the `man` target, which
# reads the reStructuredText under doc/references/man/. ob-standalone-setup.8
# and ob-backend-setup.8 document the same program as ob-bastion-setup.8 and
# are generated from its document (see man_pages in doc/conf.py).
if(BUILD_MAN)
    install(FILES
        ${MAN_OUT_DIR}/ob-enroll.8
        ${MAN_OUT_DIR}/ob-heartbeat.8
        ${MAN_OUT_DIR}/ob-bastion-setup.8
        ${MAN_OUT_DIR}/ob-standalone-setup.8
        ${MAN_OUT_DIR}/ob-backend-setup.8
        ${MAN_OUT_DIR}/ob-session-recorder.8
        ${MAN_OUT_DIR}/ob-login-shell.8
        ${MAN_OUT_DIR}/ob-session-prune.8
        ${MAN_OUT_DIR}/ob-krl-refresh.8
        ${MAN_OUT_DIR}/ob-cert-daemon.8
        ${MAN_OUT_DIR}/ob-fp-daemon.8
        ${MAN_OUT_DIR}/ob-fp-submit.8
        ${MAN_OUT_DIR}/ob-record-sink.8
        ${MAN_OUT_DIR}/ob-sign-request.8
        ${MAN_OUT_DIR}/ob-client-jwt.8
        ${MAN_OUT_DIR}/ob-post-upgrade.8
        ${MAN_OUT_DIR}/ob-uninstall.8
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
    )

    # Desktop SSO commands: shipped in open-bastion-desktop, with the commands.
    if(INSTALL_DESKTOP)
        install(FILES
            ${MAN_OUT_DIR}/ob-cache-admin.8
            ${MAN_OUT_DIR}/ob-desktop-setup.8
            ${MAN_OUT_DIR}/ob-session-monitor.8
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
        )
    endif()

    install(FILES
        ${MAN_OUT_DIR}/ob-ssh.1
        ${MAN_OUT_DIR}/ob-scp.1
        ${MAN_OUT_DIR}/ob-sftp.1
        ${MAN_OUT_DIR}/ob-bastion-id.1
        ${MAN_OUT_DIR}/ob-cert-request.1
        ${MAN_OUT_DIR}/ob-record-connect.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    )

    install(FILES
        ${MAN_OUT_DIR}/openbastion.conf.5
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man5
    )
endif()

# Disabled for Debian packaging, which uses dh_installsystemd instead.
if(INSTALL_SYSTEMD)
    install(FILES
        ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.timer
        ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-cert.socket
        ${CMAKE_SOURCE_DIR}/systemd/ob-cert@.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-record.socket
        ${CMAKE_SOURCE_DIR}/systemd/ob-record@.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-fp.socket
        ${CMAKE_SOURCE_DIR}/systemd/ob-fp@.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-session-prune.timer
        ${CMAKE_SOURCE_DIR}/systemd/ob-session-prune.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-krl-refresh.timer
        ${CMAKE_SOURCE_DIR}/systemd/ob-krl-refresh.service
        ${CMAKE_SOURCE_DIR}/systemd/ob-audit-rotate.timer
        ${CMAKE_SOURCE_DIR}/systemd/ob-audit-rotate.service
        DESTINATION lib/systemd/system
    )
    if(INSTALL_DESKTOP)
        install(FILES
            ${CMAKE_SOURCE_DIR}/systemd/ob-session-monitor.service
            DESTINATION lib/systemd/system
        )
    endif()
endif()

if(INSTALL_DESKTOP)
    install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-session-monitor
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )

    install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-desktop-setup
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )

    # Administers the credential cache, which only Desktop SSO writes.
    install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-cache-admin
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
    )

    install(DIRECTORY ${CMAKE_SOURCE_DIR}/lightdm/greeter/
        DESTINATION ${CMAKE_INSTALL_DATADIR}/lightdm-webkit/themes/open-bastion
    )

    install(FILES ${CMAKE_SOURCE_DIR}/lightdm/config/lightdm-openbastion.conf
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
        RENAME lightdm-openbastion.conf.example
    )
endif()

add_subdirectory(nss)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

set(CPACK_PACKAGE_NAME "open-bastion")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Bastion - Secure SSH bastion with PAM/NSS modules")
set(CPACK_PACKAGE_VENDOR "Linagora")
set(CPACK_PACKAGE_CONTACT "Open Bastion team <open-bastion@linagora.com>")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpam0g, libcurl4, libjson-c5 | libjson-c5t64, libssl3 | libssl3t64, libkeyutils1, curl, jq")
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

set(CPACK_RPM_PACKAGE_LICENSE "AGPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Base")
set(CPACK_RPM_PACKAGE_REQUIRES "pam, libcurl, json-c, openssl-libs, keyutils-libs, curl, jq")

# A package built from a tree without man pages ships without them.
set(OB_NO_MAN_WARNING_SCRIPT "")
if(NOT BUILD_MAN)
    set(OB_NO_MAN_WARNING_SCRIPT "${CMAKE_BINARY_DIR}/no-man-pages.cmake")
    file(WRITE "${OB_NO_MAN_WARNING_SCRIPT}"
        "message(WARNING \"BUILD_MAN=OFF — this package is built without man pages; install Sphinx (python3-sphinx) and reconfigure to include them\")\n")
    set(CPACK_INSTALL_SCRIPTS "${OB_NO_MAN_WARNING_SCRIPT}")
endif()

include(CPack)

# open-bastion-builder is packaged separately (no dependency on the runtime
# package) via dpkg-deb/rpmbuild directly, not CPACK_DEB_COMPONENT_INSTALL:
# that would rename every existing install() destination to *-unspecified,
# breaking the main open-bastion package.
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

    set(BUILDER_DEB_DIR "${BUILDER_STAGE_DIR}/deb")
    set(BUILDER_DEB_ROOT "${BUILDER_DEB_DIR}/root")

    file(MAKE_DIRECTORY "${BUILDER_DEB_ROOT}/DEBIAN")

    configure_file(
        "${CMAKE_SOURCE_DIR}/admin-builder/debian/control"
        "${BUILDER_DEB_ROOT}/DEBIAN/control"
        @ONLY
    )

    # chmod 0755 is applied by the custom command below.
    configure_file(
        "${CMAKE_SOURCE_DIR}/admin-builder/debian/postinst"
        "${BUILDER_DEB_ROOT}/DEBIAN/postinst"
        COPYONLY
    )

    set(BUILDER_DEB_OUTPUT
        "${CMAKE_BINARY_DIR}/${BUILDER_PKG_NAME}_${BUILDER_PKG_VERSION}_all.deb")

    find_program(DPKG_DEB_EXECUTABLE dpkg-deb)
    if(NOT DPKG_DEB_EXECUTABLE)
        message(STATUS "dpkg-deb not found — skipping open-bastion-builder DEB target")
    else()
    set(_ob_builder_man_warning)
    if(OB_NO_MAN_WARNING_SCRIPT)
        set(_ob_builder_man_warning
            COMMAND ${CMAKE_COMMAND} -P "${OB_NO_MAN_WARNING_SCRIPT}")
    endif()
    set(_ob_builder_deb_man_cmds)
    if(BUILD_MAN)
        list(APPEND _ob_builder_deb_man_cmds
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "${BUILDER_DEB_ROOT}/usr/share/man/man1"
            COMMAND ${CMAKE_COMMAND} -E copy
                "${MAN_OUT_DIR}/ob-builder.1"
                "${BUILDER_DEB_ROOT}/usr/share/man/man1/ob-builder.1")
    endif()
    add_custom_target(builder-deb ALL
        ${_ob_builder_man_warning}
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/bin"
        COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_SOURCE_DIR}/admin-builder/ob-builder"
            "${BUILDER_DEB_ROOT}/usr/bin/ob-builder"
        COMMAND chmod 0755
            "${BUILDER_DEB_ROOT}/usr/bin/ob-builder"

        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/lib"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/lib"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/lib"

        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/templates"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/templates"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/templates"

        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/keyrings"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/admin-builder/keyrings"
            "${BUILDER_DEB_ROOT}/usr/share/open-bastion-builder/keyrings"

        ${_ob_builder_deb_man_cmds}

        # DEBIAN maintainer scripts must be 0755.
        COMMAND chmod 0755
            "${BUILDER_DEB_ROOT}/DEBIAN/postinst"

        COMMAND dpkg-deb --build --root-owner-group
            "${BUILDER_DEB_ROOT}"
            "${BUILDER_DEB_OUTPUT}"

        COMMENT "Building ${BUILDER_PKG_NAME} Debian package"
        VERBATIM
    )
    if(BUILD_MAN)
        add_dependencies(builder-deb man)
    endif()
    endif()

    find_program(RPMBUILD_EXECUTABLE rpmbuild)
    if(RPMBUILD_EXECUTABLE)
        # Release is 1%{?dist}, as in the spec.
        execute_process(
            COMMAND ${RPMBUILD_EXECUTABLE} --eval "%{?dist}"
            OUTPUT_VARIABLE _ob_rpm_dist
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(BUILDER_RPM_OUTPUT
            "${CMAKE_BINARY_DIR}/${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}-1${_ob_rpm_dist}.noarch.rpm")

        # The tarball carries the generated man page only when there is one.
        set(_ob_builder_tar_man)
        if(BUILD_MAN)
            list(APPEND _ob_builder_tar_man
                -C "${CMAKE_BINARY_DIR}"
                --transform "s|^man/ob-builder\.1|${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}/man/ob-builder.1|"
                man/ob-builder.1)
        endif()

        # The spec's two ob-builder(1) lines vanish when there is no man page to
        # put in the package; a comment is inert in %install and %files alike.
        if(BUILD_MAN)
            set(BUILDER_MAN_INSTALL "install -Dm 0644 man/ob-builder.1 %{buildroot}/usr/share/man/man1/ob-builder.1")
            set(BUILDER_MAN_FILES "%{_mandir}/man1/ob-builder.1*")
        else()
            set(BUILDER_MAN_INSTALL "# no man page (built without Sphinx)")
            set(BUILDER_MAN_FILES "# no man page (built without Sphinx)")
        endif()

        configure_file(
            "${CMAKE_SOURCE_DIR}/admin-builder/rpm/open-bastion-builder.spec.in"
            "${CMAKE_BINARY_DIR}/open-bastion-builder.spec"
            @ONLY
        )

        # rpmbuild requires a SOURCES tarball, not a plain directory tree.
        set(BUILDER_RPM_TARBALL "${CMAKE_BINARY_DIR}/builder-pkg/rpm/${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}.tar.gz")
        add_custom_target(builder-rpm ALL
            ${_ob_builder_man_warning}
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "${CMAKE_BINARY_DIR}/builder-pkg/rpm"
            # The second -C and --transform put the generated man page where
            # the spec expects it inside the tarball.
            COMMAND tar -czf "${BUILDER_RPM_TARBALL}"
                -C "${CMAKE_SOURCE_DIR}"
                --transform "s|^admin-builder|${BUILDER_PKG_NAME}-${BUILDER_PKG_VERSION}|"
                admin-builder
                ${_ob_builder_tar_man}
            COMMAND rm -f "${BUILDER_RPM_OUTPUT}"
            # --nodeps: the spec has no BuildRequires, and the check would
            # open the host rpmdb, which a non-RPM host (Debian) does not have.
            # _build_name_fmt drops the default %{ARCH}/ subdirectory so the
            # package lands next to the .deb.
            COMMAND ${RPMBUILD_EXECUTABLE} --nodeps
                --define "_topdir ${CMAKE_BINARY_DIR}/builder-pkg/rpm/rpmbuild"
                --define "_sourcedir ${CMAKE_BINARY_DIR}/builder-pkg/rpm"
                --define "_rpmdir ${CMAKE_BINARY_DIR}"
                --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm"
                -bb "${CMAKE_BINARY_DIR}/open-bastion-builder.spec"
            COMMAND ls -l "${BUILDER_RPM_OUTPUT}"
            COMMENT "Building ${BUILDER_PKG_NAME} RPM package"
            VERBATIM
        )
        if(BUILD_MAN)
            add_dependencies(builder-rpm man)
        endif()
    else()
        message(STATUS "rpmbuild not found — skipping open-bastion-builder RPM target")
    endif()
endif()
