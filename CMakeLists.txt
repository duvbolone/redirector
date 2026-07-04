cmake_minimum_required(VERSION 3.12)
include(CheckCXXSourceCompiles)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(redirector)

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

set(SOURCES src/server.cpp src/utils.cpp src/rid.cpp)
add_executable(redirector ${SOURCES})

target_include_directories(redirector PRIVATE "include")
target_link_libraries(redirector PRIVATE OpenSSL::SSL OpenSSL::Crypto SQLite3::SQLite3)
