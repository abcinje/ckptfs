#ifndef CKPTFS_CKPT_SYSCALL_HPP
#define CKPTFS_CKPT_SYSCALL_HPP

#include <sys/types.h>

namespace ckpt
{
	int write(int fd, const void *buf, size_t count, ssize_t *result);
	int open(const char *pathname, int flags, mode_t mode, int *result);
	int close(int fd, int *result);
	int fsync(int fd, int *result);
	int openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result);
}

#endif //CKPTFS_CKPT_SYSCALL_HPP