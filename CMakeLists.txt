cmake_minimum_required(VERSION 3.17)
project(router3)

set(CMAKE_CXX_STANDARD 11)

#指定 Winpcap 的 include 目录和链接目录
set(INC_DIR D:\\WpdPack\\Include)
set(LINK_DIR D:\\WpdPack\\Lib\\x64)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})

#指定 C++库的路径，链接 ws2_32 和 wpcap 库
include_directories(E:\\MinGW\\include)
link_libraries(ws2_32)
link_libraries(wpcap)

add_executable(router3 main.cpp routeTable.h ipmacTableEntry.h frame.h cksum.h)