# CMakeLists.txt for libnss_llng

cmake_minimum_required(VERSION 3.10)
project(libnss_llng VERSION 1.0.0 LANGUAGES C)

# Find required packages
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSON_C REQUIRED json-c)

# NSS library
add_library(nss_llng SHARED libnss_llng.c)

target_include_directories(nss_llng PRIVATE
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(nss_llng
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
)

# NSS modules have specific naming convention: libnss_NAME.so.2
set_target_properties(nss_llng PROPERTIES
    OUTPUT_NAME "nss_llng"
    VERSION 2
    SOVERSION 2
    PREFIX "lib"
)

# Compiler flags
target_compile_options(nss_llng PRIVATE
    -Wall -Wextra -fPIC
    -D_GNU_SOURCE
)

# Install to /lib/x86_64-linux-gnu (or equivalent)
include(GNUInstallDirs)

# Determine NSS library path
if(EXISTS "/lib/x86_64-linux-gnu")
    set(NSS_LIB_DIR "/lib/x86_64-linux-gnu")
elseif(EXISTS "/lib64")
    set(NSS_LIB_DIR "/lib64")
else()
    set(NSS_LIB_DIR "/lib")
endif()

install(TARGETS nss_llng
    LIBRARY DESTINATION ${NSS_LIB_DIR}
)

# Install config file template
install(FILES nss_llng.conf.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
    RENAME nss_llng.conf
    COMPONENT config
)
