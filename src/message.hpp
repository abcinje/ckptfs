#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

#include <boost/interprocess/managed_shared_memory.hpp>

#include "syscall_flag.hpp"

namespace bi = boost::interprocess;
using shm_handle = bi::managed_shared_memory::handle_t;

class message {
public:
	long syscall;
	uint64_t ofid;
	off_t offset;
	size_t len;
	struct handle_vec {
		shm_handle fq_handle, pathname_handle, synced_handle;
	} handles;
	syscall_flag flags;

	message(void);
	message(long syscall, uint64_t ofid, off_t offset, size_t len, handle_vec handles = {}, syscall_flag flags = syscall_flag::FSYNC_NORMAL);
};

#endif //CKPTFS_MESSAGE_HPP
