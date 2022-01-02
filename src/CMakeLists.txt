# daemon
add_executable(drainer drainer.cpp)
set_target_properties(drainer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# library
add_library(ckpt SHARED hook.cpp)
set_target_properties(ckpt PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
