cmake_minimum_required(VERSION 3.2)

project(tandem)

# Set install path
set(TANDEM_INSTALL_BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(TANDEM_INSTALL_LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(TANDEM_SRC_DIR ${PROJECT_SOURCE_DIR}/src)

# Find dependencies
find_library(RELIC librelic_s.a librelic)
find_package(OpenSSL REQUIRED)
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message("RELIC location: ${RELIC}")

# TODO: set compiler flags
add_definitions("-march=native -Wall -Werror -O0 -g -no-pie")

# Set include path
include_directories(include)
include_directories(extern/bhjl/include)
include_directories(extern/paillier/include)

add_subdirectory(extern)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(bench)
