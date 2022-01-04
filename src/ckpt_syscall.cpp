#include "ckpt_syscall.hpp"
#include "util.hpp"

int ckpt::write(int fd, const void *buf, size_t count, ssize_t *result)
{
	return 1;
}

int ckpt::open(const char *pathname, int flags, mode_t mode, int *result)
{
	return 1;
}

int ckpt::close(int fd, int *result)
{
	return 1;
}

int ckpt::fsync(int fd, int *result)
{
	return 1;
}

int ckpt::openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result)
{
	if (dirfd != AT_FDCWD)
		error("ckpt::openat() failed (only operations for the current working directory are supported)");

	return open(pathname, flags, mode, result);
}
