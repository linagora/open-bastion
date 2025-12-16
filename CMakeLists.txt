cmake_minimum_required(VERSION 3.10)
project(pam_llng VERSION 1.0.0 LANGUAGES C)

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
    src/pam_llng.c
    src/llng_client.c
    src/config.c
    src/audit_log.c
    src/rate_limiter.c
    src/client_context.c
    src/token_manager.c
    src/notify.c
    src/secret_store.c
    src/auth_cache.c
)

if(ENABLE_CACHE)
    list(APPEND PAM_MODULE_SOURCES src/token_cache.c)
    add_definitions(-DENABLE_CACHE)
endif()

# Build the PAM module as a shared library
add_library(pam_llng SHARED ${PAM_MODULE_SOURCES})

# Set output name without "lib" prefix
set_target_properties(pam_llng PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pam_llng"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Include directories
target_include_directories(pam_llng PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(pam_llng
    ${PAM_LIBRARY}
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Compiler flags
target_compile_options(pam_llng PRIVATE
    -Wall -Wextra -Werror
    -fPIC
    -D_GNU_SOURCE
)

# Installation
include(GNUInstallDirs)

# Install PAM module
install(TARGETS pam_llng
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/security
)

# Install configuration file
install(FILES ${CMAKE_SOURCE_DIR}/config/pam_llng.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/security
    RENAME pam_llng.conf.example
)

# Install documentation
install(FILES ${CMAKE_SOURCE_DIR}/README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Install enrollment script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/llng-pam-enroll
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install heartbeat script
install(PROGRAMS ${CMAKE_SOURCE_DIR}/scripts/llng-pam-heartbeat
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install man pages
install(FILES
    ${CMAKE_SOURCE_DIR}/man/llng-pam-enroll.8
    ${CMAKE_SOURCE_DIR}/man/llng-pam-heartbeat.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)

# Install systemd units
install(FILES
    ${CMAKE_SOURCE_DIR}/systemd/pam-llng-heartbeat.timer
    ${CMAKE_SOURCE_DIR}/systemd/pam-llng-heartbeat.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)

# Build NSS module
add_subdirectory(nss)

# Tests
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "pam-llng")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PAM module for LemonLDAP::NG authentication")
set(CPACK_PACKAGE_VENDOR "Linagora")
set(CPACK_PACKAGE_CONTACT "LemonLDAP::NG team <lemonldap-ng@ow2.org>")

# Debian package
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpam0g, libcurl4, libjson-c5 | libjson-c5t64, libssl3 | libssl3t64, libkeyutils1, curl, jq")
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")

# RPM package
set(CPACK_RPM_PACKAGE_LICENSE "AGPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Base")
set(CPACK_RPM_PACKAGE_REQUIRES "pam, libcurl, json-c, openssl-libs, keyutils-libs, curl, jq")

include(CPack)
