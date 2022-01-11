#ifndef CKPTFS_CKPT_SYSCALL_HPP
#define CKPTFS_CKPT_SYSCALL_HPP

#include <sys/types.h>

namespace ckpt
{
	int read(int fd, void *buf, size_t count, ssize_t *result);
	int write(int fd, const void *buf, size_t count, ssize_t *result);
	int open(const char *pathname, int flags, mode_t mode, int *result);
	int close(int fd, int *result);
	int stat(const char *pathname, struct stat *statbuf, int *result);
	int fstat(int fd, struct stat *statbuf, int *result);
	int lstat(const char *pathname, struct stat *statbuf, int *result);
	int lseek(int fd, off_t offset, int whence, off_t *result);
	int pread(int fd, void *buf, size_t count, off_t offset, ssize_t *result);
	int pwrite(int fd, const void *buf, size_t count, off_t offset, ssize_t *result);
	int readv(int fd, const struct iovec *iov, int iovcnt, ssize_t *result);
	int writev(int fd, const struct iovec *iov, int iovcnt, ssize_t *result);
	int fsync(int fd, int *result);
	int fdatasync(int fd, int *result);
	int openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result);
	int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags, int *result);
}

#endif //CKPTFS_CKPT_SYSCALL_HPP
