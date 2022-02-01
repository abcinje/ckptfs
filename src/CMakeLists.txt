###################
# => Packages
###################

# thread
find_package(Threads REQUIRED)

# boost
find_package(Boost COMPONENTS system REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

# pkg-config
find_package(PkgConfig REQUIRED)

# syscall_intercept
pkg_check_modules(SYSCALL_INTERCEPT libsyscall_intercept REQUIRED)
include_directories(${SYSCALL_INTERCEPT_INCLUDE_DIRS})



###################
# => Targets
###################

# drainer
add_executable(drainer drainer.cpp drainer_syscall.cpp message.cpp)
set_target_properties(drainer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
target_link_libraries(drainer Threads::Threads rt ${Boost_LIBRARIES})

# libckpt.so
add_library(ckpt SHARED ckpt.cpp ckpt_syscall.cpp message.cpp random.cpp util.cpp)
set_target_properties(ckpt PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
target_link_libraries(ckpt Threads::Threads rt ${Boost_LIBRARIES} ${SYSCALL_INTERCEPT_LIBRARIES})
