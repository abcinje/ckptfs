#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(void)
{
}

message::message(long syscall, off_t offset, size_t len, shm_handles handles, int flags, mode_t mode)
		: syscall(syscall), offset(offset), len(len), handles(handles), flags(flags), mode(mode)
{
}
