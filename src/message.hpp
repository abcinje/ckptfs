#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;
using shm_handle = bi::managed_shared_memory::handle_t;

class message {
public:
	long syscall;
	uint64_t ofid;
	off_t offset;
	size_t len;
	shm_handle handle0, handle1, handle2;

	message(void);
	message(long syscall, uint64_t ofid, off_t offset, size_t len, shm_handle handle0 = 0, shm_handle handle1 = 0, shm_handle handle2 = 0);
};

#endif //CKPTFS_MESSAGE_HPP
