# CMakeLists.txt for libnss_openbastion

# NSS library
add_library(nss_openbastion SHARED libnss_openbastion.c)

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

# NSS modules have specific naming convention: libnss_NAME.so.2
set_target_properties(nss_openbastion PROPERTIES
    OUTPUT_NAME "nss_openbastion"
    VERSION 2
    SOVERSION 2
    PREFIX "lib"
)

# Compiler flags
target_compile_options(nss_openbastion PRIVATE
    -Wall -Wextra -fPIC
    -D_GNU_SOURCE
    # Security hardening flags
    -fstack-protector-strong      # Stack buffer overflow protection
    -Wformat -Wformat-security    # Format string vulnerability detection
    -fvisibility=hidden           # Hide internal symbols, reduce attack surface
)

# _FORTIFY_SOURCE requires optimization (-O1 or higher) to be effective
# Only enable for Release/RelWithDebInfo builds to avoid warnings in Debug
target_compile_definitions(nss_openbastion PRIVATE
    $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:_FORTIFY_SOURCE=2>
)

# Linker security flags (Full RELRO = relro + now)
target_link_options(nss_openbastion PRIVATE
    -Wl,-z,relro                  # RELRO (with -z,now = Full RELRO)
    -Wl,-z,now                    # Resolve symbols at load time (completes Full RELRO)
    -Wl,-z,noexecstack            # Non-executable stack
)

# Install NSS module to the same libdir as PAM module
# NAMELINK_SKIP prevents installing the .so symlink (only needed for development)
# NSS modules are loaded by versioned name (libnss_NAME.so.2)
install(TARGETS nss_openbastion
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    NAMELINK_SKIP
)

# Install config file template
install(FILES ${CMAKE_SOURCE_DIR}/config/nss_openbastion.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/open-bastion
)
