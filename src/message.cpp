#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(void) : message(-1, nullptr, 0, 0, 0, 0)
{
}

message::message(long syscall, const char *path, pid_t pid, int fd, off_t offset, size_t len)
		: syscall(syscall), pid(pid), fd(fd), offset(offset), len(len)
{
	if (syscall == SYS_open)
		strncpy(this->path, path, PATH_MAX);
}

message::message(const message &copy)
		: syscall(copy.syscall), pid(copy.pid), fd(copy.fd), offset(copy.offset), len(copy.len)
{
	if (syscall == SYS_open)
		strncpy(path, copy.path, PATH_MAX);
}
