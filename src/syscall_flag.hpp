#ifndef CKPTFS_SYSCALL_FLAG_HPP
#define CKPTFS_SYSCALL_FLAG_HPP

enum class syscall_flag {
	FSYNC_NORMAL,
	FSYNC_CLOSE_WAIT,
	FSYNC_CLOSE_NOWAIT,
	FSYNC_IGNORE,
};

#endif //CKPTFS_SYSCALL_FLAG_HPP
