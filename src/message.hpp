#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;
using shm_handle = bi::managed_shared_memory::handle_t;

enum {
	CKPT_SYNCLOSE_WAIT	= 0x1,
	CKPT_SYNCLOSE_NOWAIT	= 0x2,
	CKPT_SYNCLOSE_DATA	= 0x4,
};

class message {
public:
	long syscall;
	off_t offset;
	size_t len;
	struct shm_handles {
		shm_handle fq_handle, pathname_handle, synced_handle;
	} handles;
	int flags;
	mode_t mode;

	message(void);
	message(long syscall, off_t offset, size_t len, shm_handles handles = {}, int flags = 0, mode_t mode = 0);
};

#endif //CKPTFS_MESSAGE_HPP
