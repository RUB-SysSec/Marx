
cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(marx)

set(CMAKE_CXX_COMPILER "//usr/bin/clang++-3.6")

add_definitions("-std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -pedantic -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow -Wpointer-arith -Wcast-qual")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wstrict-prototypes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-braces")

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")

file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB HDR_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(lib_vex STATIC IMPORTED GLOBAL)
set_property(TARGET lib_vex PROPERTY
             IMPORTED_LOCATION /usr/local/lib/valgrind/libvex-amd64-linux.a)

add_executable(marx ${SRC_FILES} ${HDR_FILES})
target_link_libraries(marx lib_vex pthread)
