cmake_minimum_required(VERSION 3.10.2)
project(AFIT-CSCE689-HW4)

set(CMAKE_CXX_STANDARD 17)

add_executable(HW4 src/repsvr_main.cpp
               src/ALMgr.cpp                include/ALMgr.h
               src/LogMgr.cpp               include/LogMgr.h
               src/TCPConn.cpp              include/TCPConn.h
               src/DronePlotDB.cpp          include/DronePlotDB.h
               src/FileDesc.cpp             include/FileDesc.h
               src/Server.cpp               include/Server.h
               src/QueueMgr.cpp             include/QueueMgr.h
               src/TCPServer.cpp            include/TCPServer.h
               src/ReplServer.cpp           include/ReplServer.h
               src/ReplicationManager.cpp   include/ReplicationManager.h
               src/AntennaSim.cpp           include/AntennaSim.h
               src/strfuncts.cpp            include/strfuncts.h
               )

target_include_directories(HW4 PRIVATE src include)
INCLUDE(FindPkgConfig)
pkg_search_module(CRYPTOPP REQUIRED libcrypto++ >= 6)

target_link_libraries(HW4 pthread ${CRYPTOPP_LIBRARIES})