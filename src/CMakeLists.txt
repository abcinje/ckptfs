# daemon

add_executable(drainer drainer.cpp)
set_target_properties(drainer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

target_link_libraries(drainer rt)

# library

add_library(ckpt SHARED hook.cpp util.cpp)
set_target_properties(ckpt PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSCALL_INTERCEPT libsyscall_intercept REQUIRED)
include_directories(${SYSCALL_INTERCEPT_INCLUDE_DIRS})

target_link_libraries(ckpt rt ${SYSCALL_INTERCEPT_LIBRARIES})
