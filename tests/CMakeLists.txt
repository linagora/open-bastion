# Tests for pam_llng

# Test configuration parsing
add_executable(test_config test_config.c ../src/config.c)
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
add_executable(test_nss_llng test_nss_llng.c)
target_include_directories(test_nss_llng PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_nss_llng COMMAND test_nss_llng)

# Test path validation
add_executable(test_path_validator test_path_validator.c ../src/config.c)
target_include_directories(test_path_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_path_validator COMMAND test_path_validator)

# Test username validation
add_executable(test_username_validator test_username_validator.c)
target_include_directories(test_username_validator PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_username_validator COMMAND test_username_validator)

# Test llng_client structures and functions
add_executable(test_llng_client test_llng_client.c ../src/llng_client.c)
target_include_directories(test_llng_client PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_llng_client
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
)
add_test(NAME test_llng_client COMMAND test_llng_client)

# Test authorization cache
add_executable(test_auth_cache test_auth_cache.c ../src/auth_cache.c)
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

# Test token manager JWT functions
add_executable(test_token_manager test_token_manager.c ../src/token_manager.c)
target_compile_definitions(test_token_manager PRIVATE TOKEN_MANAGER_TEST)
target_include_directories(test_token_manager PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_token_manager
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
add_test(NAME test_token_manager COMMAND test_token_manager)

# Note: Integration tests require a running LLNG instance
# and are meant to be run manually
