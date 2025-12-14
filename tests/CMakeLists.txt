# Tests for pam_llng

# Test configuration parsing
add_executable(test_config test_config.c ../src/config.c)
target_include_directories(test_config PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_config COMMAND test_config)

# Note: Integration tests require a running LLNG instance
# and are meant to be run manually
