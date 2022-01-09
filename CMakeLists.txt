cmake_minimum_required(VERSION 3.16)
project(ckptfs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG")

add_subdirectory(src)
