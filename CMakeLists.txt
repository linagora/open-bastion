cmake_minimum_required(VERSION 3.10)
project(open-bastion VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(ENABLE_CACHE "Enable token caching" ON)
option(BUILD_TESTING "Build tests" ON)

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
    src/bastion_jwt.c
    src/jwks_cache.c
    src/jti_cache.c
    src/crowdsec.c
    src/service_account.c
    src/str_utils.c
    src/offline_cache.c
)

if(ENABLE_CACHE)
    list(APPEND PAM_MODULE_SOURCES src/token_cache.c)
    add_definitions(-DENABLE_CACHE)
endif()

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
)

# _FORTIFY_SOURCE requires optimization (-O1 or higher) to be effective
# Only enable for Release/RelWithDebInfo builds to avoid warnings in Debug
target_compile_definitions(pam_openbastion PRIVATE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:_FORTIFY_SOURCE=2>
)

# Linker security flags (Full RELRO = relro + now)
target_link_options(pam_openbastion PRIVATE
    -Wl,-z,relro                  # RELRO (with -z,now = Full RELRO)
    -Wl,-z,now                    # Resolve symbols at load time (completes Full RELRO)
    -Wl,-z,noexecstack            # Non-executable stack
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

# Install session recorder config example
install(FILES ${CMAKE_SOURCE_DIR}/scripts/session-recorder.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Install SSH proxy for bastion
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-ssh-proxy
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install SSH proxy config example
install(FILES ${CMAKE_SOURCE_DIR}/scripts/ssh-proxy.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)

# Install SSH certificate tool (user-facing)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-ssh-cert
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install setup scripts (admin-facing)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-bastion-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-backend-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install man pages (section 8 - admin commands)
install(FILES
    ${CMAKE_SOURCE_DIR}/man/ob-enroll.8
    ${CMAKE_SOURCE_DIR}/man/ob-heartbeat.8
    ${CMAKE_SOURCE_DIR}/man/ob-bastion-setup.8
    ${CMAKE_SOURCE_DIR}/man/ob-backend-setup.8
    ${CMAKE_SOURCE_DIR}/man/ob-session-recorder.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)

# Install man pages (section 1 - user commands)
install(FILES
    ${CMAKE_SOURCE_DIR}/man/ob-ssh-cert.1
    ${CMAKE_SOURCE_DIR}/man/ob-ssh-proxy.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

# Install systemd units
install(FILES
    ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.timer
    ${CMAKE_SOURCE_DIR}/systemd/ob-heartbeat.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)

# Install desktop setup script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/ob-desktop-setup
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install LightDM greeter theme
install(DIRECTORY ${CMAKE_SOURCE_DIR}/lightdm/greeter/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/open-bastion/lightdm/greeter
)

# Install LightDM configuration example
install(FILES ${CMAKE_SOURCE_DIR}/lightdm/config/lightdm-openbastion.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
    RENAME lightdm-openbastion.conf.example
)

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
