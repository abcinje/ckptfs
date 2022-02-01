#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(void)
{
}

message::message(long syscall, uint64_t ofid, off_t offset, size_t len, handle_vec handles)
		: syscall(syscall), ofid(ofid), offset(offset), len(len), handles(handles)
{
}
