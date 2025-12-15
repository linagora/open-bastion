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
target_include_directories(test_audit_log PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_audit_log pthread)
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

# Note: Integration tests require a running LLNG instance
# and are meant to be run manually
