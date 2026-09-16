# Tests for pam_openbastion

# Test configuration parsing
add_executable(test_config test_config.c ../src/config.c ../src/str_utils.c)
target_include_directories(test_config PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_config COMMAND test_config)

# Config line syntax: inline comments and quoting (follow-up to #183).
# Includes config.c directly to reach the per-line parser, since config_load()
# requires a root-owned file that CI cannot create.
add_executable(test_config_line test_config_line.c ../src/str_utils.c)
target_include_directories(test_config_line PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_config_line COMMAND test_config_line)

# Test rate limiter
add_executable(test_rate_limiter test_rate_limiter.c ../src/rate_limiter.c)
target_include_directories(test_rate_limiter PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_rate_limiter ${OPENSSL_LIBRARIES})
add_test(NAME test_rate_limiter COMMAND test_rate_limiter)

# Test audit logging
add_executable(test_audit_log test_audit_log.c ../src/audit_log.c)
target_include_directories(test_audit_log PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_audit_log pthread ${JSON_C_LIBRARIES} ${OPENSSL_LIBRARIES})
add_test(NAME test_audit_log COMMAND test_audit_log)

# Test NSS module helper functions
add_executable(test_nss_openbastion test_nss_openbastion.c)
target_include_directories(test_nss_openbastion PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_nss_openbastion COMMAND test_nss_openbastion)

# Regression test for the NSS in-memory LRU cache (expire-then-evict double free).
# Includes libnss_openbastion.c directly to drive the static cache helpers, so it
# needs the same libs as the module itself (curl/json-c/pthread).
add_executable(test_nss_cache test_nss_cache.c ../src/str_utils.c)
target_compile_definitions(test_nss_cache PRIVATE _GNU_SOURCE)
target_include_directories(test_nss_cache PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
)
target_link_libraries(test_nss_cache
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
)
add_test(NAME test_nss_cache COMMAND test_nss_cache)

# Fail-closed boolean parsing in the NSS config loader (#183). Same pattern as
# test_nss_cache: includes libnss_openbastion.c directly to reach the static
# helper, so it needs the module's own libs.
add_executable(test_nss_config test_nss_config.c ../src/str_utils.c)
# Same -D_GNU_SOURCE the shipped module is built with (nss/CMakeLists.txt): the
# file cache opens its directories with O_PATH, which glibc only declares under
# _GNU_SOURCE. Including libnss_openbastion.c without it fails to compile.
target_compile_definitions(test_nss_config PRIVATE _GNU_SOURCE)
target_include_directories(test_nss_config PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
)
target_link_libraries(test_nss_config
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
)
add_test(NAME test_nss_config COMMAND test_nss_config)

# Test path validation
add_executable(test_path_validator test_path_validator.c ../src/config.c ../src/str_utils.c)
target_include_directories(test_path_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_path_validator COMMAND test_path_validator)

# Test username validation
add_executable(test_username_validator test_username_validator.c)
target_include_directories(test_username_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_username_validator COMMAND test_username_validator)

# Bastion cert socket protocol: validators + line reader (CRLF, overflow, EOF)
add_executable(test_ob_cert_proto test_ob_cert_proto.c ../src/ob_cert_proto.c)
target_include_directories(test_ob_cert_proto PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_ob_cert_proto COMMAND test_ob_cert_proto)

# Test ob_client structures and functions
add_executable(test_ob_client test_ob_client.c ../src/ob_client.c ../src/jwt_utils.c ../src/ob_sign.c)
target_include_directories(test_ob_client PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_ob_client
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
)
add_test(NAME test_ob_client COMMAND test_ob_client)

# Request signing: the wire format the portal verifies (#247)
add_executable(test_ob_sign test_ob_sign.c ../src/ob_sign.c ../src/str_utils.c)
target_include_directories(test_ob_sign PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_compile_definitions(test_ob_sign PRIVATE _GNU_SOURCE)
target_link_libraries(test_ob_sign ${OPENSSL_LIBRARIES})
add_test(NAME test_ob_sign COMMAND test_ob_sign)

# What src/cache_key.c refuses as a key file (#268). Includes the .c to reach
# key_file_rejected(), the same way test_nss_cache.c reaches the NSS cache
# helpers; the six refusals 4cbe85c added shipped with no test at all.
add_executable(test_cache_key test_cache_key.c)
target_include_directories(test_cache_key PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_cache_key ${OPENSSL_LIBRARIES})
add_test(NAME test_cache_key COMMAND test_cache_key)
# A fifo that read_key_file() opens blocking would hang rather than fail, so the
# suite must not be allowed to wait forever for it.
set_tests_properties(test_cache_key PROPERTIES TIMEOUT 60)

# Test authorization cache
add_executable(test_auth_cache test_auth_cache.c ../src/auth_cache.c ../src/cache_key.c)
target_include_directories(test_auth_cache PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_auth_cache
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_auth_cache COMMAND test_auth_cache)

# Desktop SSO components (offline credential cache, OAuth2 introspection)
# When INSTALL_DESKTOP=OFF, none of this code is compiled into pam_openbastion.so.
# This ensures the core SSH module has zero desktop code paths.
if(INSTALL_DESKTOP)

# Test offline credential cache (Argon2id + AES-256-GCM)
add_executable(test_offline_cache test_offline_cache.c ../src/offline_cache.c ../src/str_utils.c ../src/cache_key.c)
target_compile_definitions(test_offline_cache PRIVATE
    _GNU_SOURCE
    $<$<BOOL:${USE_LIBSODIUM}>:HAVE_LIBSODIUM>
)
target_include_directories(test_offline_cache PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_INCLUDE_DIRS}>
)
target_link_libraries(test_offline_cache
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_LIBRARIES}>
)
add_test(NAME test_offline_cache COMMAND test_offline_cache)

# Test offline cache security properties (timing, encryption, tampering)
add_executable(test_offline_security test_offline_security.c ../src/offline_cache.c ../src/str_utils.c ../src/cache_key.c)
target_compile_definitions(test_offline_security PRIVATE
    _GNU_SOURCE
    $<$<BOOL:${USE_LIBSODIUM}>:HAVE_LIBSODIUM>
)
target_include_directories(test_offline_security PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_INCLUDE_DIRS}>
)
target_link_libraries(test_offline_security
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    $<$<BOOL:${USE_LIBSODIUM}>:${SODIUM_LIBRARIES}>
)
add_test(NAME test_offline_security COMMAND test_offline_security)

endif() # INSTALL_DESKTOP

# Test JWT utility functions
add_executable(test_token_manager test_token_manager.c ../src/jwt_utils.c)
target_compile_definitions(test_token_manager PRIVATE JWT_UTILS_TEST)
target_include_directories(test_token_manager PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_token_manager
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_token_manager COMMAND test_token_manager)

# Test CrowdSec integration
add_executable(test_crowdsec test_crowdsec.c ../src/crowdsec.c)
target_compile_definitions(test_crowdsec PRIVATE _GNU_SOURCE)
target_include_directories(test_crowdsec PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_crowdsec
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_crowdsec COMMAND test_crowdsec)

# Test service account management
add_executable(test_service_account test_service_account.c ../src/service_account.c ../src/config.c ../src/str_utils.c)
target_include_directories(test_service_account PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_service_account COMMAND test_service_account)

# Test token manager file I/O (load/save, symlink rejection)
add_executable(test_token_manager_io test_token_manager_io.c ../src/token_manager.c ../src/jwt_utils.c)
target_include_directories(test_token_manager_io PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_token_manager_io
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_token_manager_io COMMAND test_token_manager_io)

# Test webhook notifications
add_executable(test_notify test_notify.c ../src/notify.c ../src/audit_log.c)
target_include_directories(test_notify PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_notify
    pthread
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_notify COMMAND test_notify)

# The sshd anchor walk (#268). ob-fp-daemon and pam_openbastion must derive the
# SAME pid from the same process tree, from different depths of it; they used to
# do so from two copies of the walk that agreed only by inspection. There is one
# implementation now, and this drives it over a synthetic /proc.
add_executable(test_sshd_anchor test_sshd_anchor.c ../src/sshd_anchor.c)
target_include_directories(test_sshd_anchor PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_sshd_anchor COMMAND test_sshd_anchor)

# Test SSH key policy
add_executable(test_ssh_key_policy test_ssh_key_policy.c ../src/ssh_key_policy.c)
target_include_directories(test_ssh_key_policy PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_ssh_key_policy COMMAND test_ssh_key_policy)

# Note: Integration tests require a running Open Bastion instance
# and are meant to be run manually

# ── Runtime PAM stack test (issue #180) ─────────────────────────────────────
# tests/test_ob_pam_runtime.sh builds tests/pam_stack_probe.c and calls
# pam_authenticate() on every auth stack the project generates, asserting that
# the certificate-mode sshd stacks deny and the mode-c sudo stack still
# succeeds. The other tests/test_ob_*.sh suites only check the TEXT of those
# stacks, which is what let an inverted stack ship once already.
#
# It exits 77 (and is reported as skipped) when a C compiler, libpam0g-dev or
# pam_start_confdir() is unavailable, so it never turns a build red on a host
# that cannot run it. CI installs libpam0g-dev, so it runs there.
find_program(BASH_EXECUTABLE bash)
if(BASH_EXECUTABLE)
    add_test(NAME test_ob_pam_runtime
             COMMAND ${BASH_EXECUTABLE}
                     "${CMAKE_CURRENT_SOURCE_DIR}/test_ob_pam_runtime.sh")
    set_tests_properties(test_ob_pam_runtime PROPERTIES SKIP_RETURN_CODE 77)
else()
    message(STATUS "bash not found — skipping test_ob_pam_runtime")
endif()

# A build of ob-fp-daemon whose compiled-in paths point into the build tree.
# The shipped binary hard-codes /run/open-bastion/{ssh-fp,ssh-fp.sock}, which a
# test can only reach through a mount namespace -- and unprivileged namespaces
# are restricted on Ubuntu 24.04, so a test that needed one would SKIP in CI and
# a skip reads as a pass. Same source, same logic, different constants.
add_executable(ob-fp-daemon-testbuild ${CMAKE_SOURCE_DIR}/src/ob-fp-daemon.c
                                    ${CMAKE_SOURCE_DIR}/src/sshd_anchor.c)
target_include_directories(ob-fp-daemon-testbuild PRIVATE ${CMAKE_SOURCE_DIR}/include)
# OB_FP_PRIV_UID is 0 in the shipped binary, so the production code carries no
# test affordance; here it becomes the uid running the suite, which is what lets
# these paths be exercised without root.
target_compile_definitions(ob-fp-daemon-testbuild PRIVATE
    OB_FP_SPOOL_DIR="${CMAKE_CURRENT_BINARY_DIR}/fp-spool"
    OB_FP_SOCKET="${CMAKE_CURRENT_BINARY_DIR}/fp.sock"
    OB_FP_PRIV_UID_IS_EUID
)
target_compile_options(ob-fp-daemon-testbuild PRIVATE -Wall -Wextra -Werror -D_GNU_SOURCE)

# Same build-tree paths, but WITHOUT OB_FP_PRIV_UID_IS_EUID: the anchor-owner
# check is the literal "must be root" the shipped binary enforces. The suite
# uses this to prove that control is live -- with the relaxed build the suite's
# own fake anchor satisfies it either way, so deleting the check outright would
# otherwise go unnoticed (verified by mutation).
add_executable(ob-fp-daemon-strictuid ${CMAKE_SOURCE_DIR}/src/ob-fp-daemon.c
                                    ${CMAKE_SOURCE_DIR}/src/sshd_anchor.c)
target_include_directories(ob-fp-daemon-strictuid PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(ob-fp-daemon-strictuid PRIVATE
    OB_FP_SPOOL_DIR="${CMAKE_CURRENT_BINARY_DIR}/fp-spool-strict"
    OB_FP_SOCKET="${CMAKE_CURRENT_BINARY_DIR}/fp-strict.sock"
)
target_compile_options(ob-fp-daemon-strictuid PRIVATE -Wall -Wextra -Werror -D_GNU_SOURCE)
