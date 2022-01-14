#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(void)
{
}

message::message(long syscall, pid_t pid, int fd, off_t offset, size_t len, shm_handle handle)
		: syscall(syscall), pid(pid), fd(fd), offset(offset), len(len), handle(handle)
{
}
