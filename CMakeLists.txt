cmake_minimum_required(VERSION 3.10)
project(amtms)

set(CMAKE_CXX_STANDARD 11)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)



add_executable(amtms main.cpp
        ipv4.cpp
        udp.cpp
        send.cpp
        send.h
        tool.cpp
        tool.h
        capture.cpp
        capture.h
        data_structure.h
        tcp.cpp
        tcp.h
        icmp.cpp
        icmp.h
        start.cpp
        start.h
)

include_directories(${PCAP_INCLUDE_DIR})

target_link_libraries(amtms ${PCAP_LIBRARY} Threads::Threads)