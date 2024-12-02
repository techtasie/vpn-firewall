cmake_minimum_required(VERSION 3.10)
project(vpn-firewall VERSION 0.1)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

include_directories(${ROCKSDB_INCLUDE_DIRS})

add_executable(read src/read.cpp src/db.cpp)
add_executable(write src/write.cpp src/db.cpp)
add_executable(vpn-firewall src/main.cpp src/capture.cpp src/router.cpp
  src/db.cpp)

target_link_libraries(vpn-firewall CURL::libcurl ${PCAP_LIBRARY})

add_custom_command(TARGET vpn-firewall POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Setting capabilities for vpn-firewall..."
    COMMAND sudo setcap cap_net_raw,cap_net_admin+eip "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/vpn-firewall"
    COMMENT "Assigning capabilities to vpn-firewall (requires sudo)"
)
