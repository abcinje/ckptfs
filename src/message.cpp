#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(long syscall, const char *path, pid_t pid, int fd, off_t offset, size_t len)
		: syscall(syscall), pid(pid), fd(fd), offset(offset), len(len)
{
	if (syscall == SYS_open)
		strncpy(this->path, path, PATH_MAX);
}
