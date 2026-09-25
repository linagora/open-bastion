# str_utils.c is shared with the PAM module: the NSS config loader reuses
# str_parse_bool_strict() so both parsers agree on what a boolean is.
add_library(nss_openbastion SHARED
    libnss_openbastion.c
    ../src/str_utils.c
)

target_include_directories(nss_openbastion PRIVATE
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(nss_openbastion
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
)

# NSS modules must follow the libnss_NAME.so.2 naming convention.
set_target_properties(nss_openbastion PROPERTIES
    OUTPUT_NAME "nss_openbastion"
    VERSION 2
    SOVERSION 2
    PREFIX "lib"
)

target_compile_options(nss_openbastion PRIVATE
    -Wall -Wextra -fPIC
    -D_GNU_SOURCE
    -fstack-protector-strong
    -Wformat -Wformat-security
    -fvisibility=hidden
)

# _FORTIFY_SOURCE is set by distribution build systems (Debian hardening);
# setting it here too triggers a redefinition warning under -Werror.

# -z,relro and -z,now together give Full RELRO; either alone is partial.
target_link_options(nss_openbastion PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# NAMELINK_SKIP: NSS modules are loaded by the versioned name
# (libnss_NAME.so.2), so the development .so symlink is not needed.
install(TARGETS nss_openbastion
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    NAMELINK_SKIP
)

install(FILES ${CMAKE_SOURCE_DIR}/config/nss_openbastion.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)
