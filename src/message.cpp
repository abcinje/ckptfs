#include <cstring>

#include <syscall.h>

#include "message.hpp"

message::message(void)
{
}

message::message(long syscall, uint64_t ofid, off_t offset, size_t len, shm_handle handle0, shm_handle handle1, shm_handle handle2)
		: syscall(syscall), ofid(ofid), offset(offset), len(len), handle0(handle0), handle1(handle1), handle2(handle2)
{
}
