#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;
using shm_handle = bi::managed_shared_memory::handle_t;

enum {
	CKPT_S_NORMAL		= 0x01,	// fsync_lazy_level == 0
	CKPT_S_CLOSEWAIT	= 0x02,	// fsync_lazy_level == 1
	CKPT_S_CLOSENOWAIT	= 0x04,	// fsync_lazy_level == 2
	CKPT_S_IGNORE		= 0x08,	// fsync_lazy_level == 3 (unused)
	CKPT_S_DATAONLY		= 0x10,	// fdatasync()
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
