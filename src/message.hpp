#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;
using shm_handle = bi::managed_shared_memory::handle_t;

#define FSYNC_NORMAL		0x1	// fsync_lazy_level == 0
#define FSYNC_CLOSE_WAIT	0x2	// fsync_lazy_level == 1
#define FSYNC_CLOSE_NOWAIT	0x4	// fsync_lazy_level == 2
#define FSYNC_IGNORE		0x8	// fsync_lazy_level == 3

class message {
public:
	long syscall;
	uint64_t ofid;
	off_t offset;
	size_t len;
	struct shm_handles {
		shm_handle fq_handle, pathname_handle, synced_handle;
	} handles;
	int flags;

	message(void);
	message(long syscall, uint64_t ofid, off_t offset, size_t len, shm_handles handles = {}, int flags = 0);
};

#endif //CKPTFS_MESSAGE_HPP
