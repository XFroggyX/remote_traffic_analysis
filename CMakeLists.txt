cmake_minimum_required(VERSION 3.17)
project(remote_traffic_analysis)

set(CMAKE_CXX_STANDARD 20)

add_executable(rta main.cpp)
if(WIN32)
    target_link_libraries(rta ws2_32 Iphlpapi)
endif()
