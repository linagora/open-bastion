# Tests for pam_openbastion

# Test configuration parsing
add_executable(test_config test_config.c ../src/config.c ../src/str_utils.c)
target_include_directories(test_config PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_config COMMAND test_config)

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
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_audit_log pthread ${OPENSSL_LIBRARIES})
add_test(NAME test_audit_log COMMAND test_audit_log)

# Test client context
add_executable(test_client_context test_client_context.c ../src/client_context.c)
target_include_directories(test_client_context PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_client_context ${PAM_LIBRARY} ${OPENSSL_LIBRARIES})
add_test(NAME test_client_context COMMAND test_client_context)

# Test secret store
add_executable(test_secret_store test_secret_store.c ../src/secret_store.c)
target_include_directories(test_secret_store PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_secret_store ${OPENSSL_LIBRARIES})
add_test(NAME test_secret_store COMMAND test_secret_store)

# Test NSS module helper functions
add_executable(test_nss_openbastion test_nss_openbastion.c)
target_include_directories(test_nss_openbastion PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_nss_openbastion COMMAND test_nss_openbastion)

# Test path validation
add_executable(test_path_validator test_path_validator.c ../src/config.c ../src/str_utils.c)
target_include_directories(test_path_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_path_validator COMMAND test_path_validator)

# Test username validation
add_executable(test_username_validator test_username_validator.c)
target_include_directories(test_username_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_username_validator COMMAND test_username_validator)

# Test ob_client structures and functions
add_executable(test_ob_client test_ob_client.c ../src/ob_client.c ../src/jwt_utils.c)
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

# Test authorization cache
add_executable(test_auth_cache test_auth_cache.c ../src/auth_cache.c ../src/str_utils.c)
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

# Test offline credential cache (Argon2id + AES-256-GCM)
add_executable(test_offline_cache test_offline_cache.c ../src/offline_cache.c ../src/str_utils.c)
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

# Test bastion JWT verification
add_executable(test_bastion_jwt test_bastion_jwt.c ../src/bastion_jwt.c ../src/jwks_cache.c ../src/jti_cache.c)
target_compile_definitions(test_bastion_jwt PRIVATE BASTION_JWT_TEST)
target_include_directories(test_bastion_jwt PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_bastion_jwt
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
)
add_test(NAME test_bastion_jwt COMMAND test_bastion_jwt)

# Test JWKS cache rate limiting
add_executable(test_jwks_cache test_jwks_cache.c ../src/jwks_cache.c)
target_compile_definitions(test_jwks_cache PRIVATE JWKS_CACHE_TEST)
target_include_directories(test_jwks_cache PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_jwks_cache
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_jwks_cache COMMAND test_jwks_cache)

# Test JTI cache for replay detection
add_executable(test_jti_cache test_jti_cache.c ../src/jti_cache.c)
target_include_directories(test_jti_cache PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(test_jti_cache pthread)
add_test(NAME test_jti_cache COMMAND test_jti_cache)

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

# Note: Integration tests require a running Open Bastion instance
# and are meant to be run manually
