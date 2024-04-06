cmake_minimum_required(VERSION 3.10)
project(vpn-firewall VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)

pkg_check_modules(ROCKSDB REQUIRED rocksdb)

include_directories(${ROCKSDB_INCLUDE_DIRS})

add_executable(vpn-firewall src/main.cpp)

target_link_libraries(vpn-firewall ${ROCKSDB_LIBRARIES} CURL::libcurl)
