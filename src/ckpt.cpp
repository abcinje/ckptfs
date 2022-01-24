#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#include <syscall.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "config.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

std::string *ckpt_dir, *bb_dir, *pfs_dir;
bi::managed_shared_memory *segment;
config *shm_cfg;
message_queue *mq;

static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
{
	switch (syscall_number) {
		case SYS_read:
			return ckpt::read((int)arg0, (void *)arg1, (size_t)arg2, (ssize_t *)result);
		case SYS_write:
			return ckpt::write((int)arg0, (const void *)arg1, (size_t)arg2, (ssize_t *)result);
		case SYS_open:
			return ckpt::open((const char *)arg0, (int)arg1, (mode_t)arg2, (int *)result);
		case SYS_close:
			return ckpt::close((int)arg0, (int *)result);
		case SYS_stat:
			return ckpt::stat((const char *)arg0, (struct stat *)arg1, (int *)result);
		case SYS_fstat:
			return ckpt::fstat((int)arg0, (struct stat *)arg1, (int *)result);
		case SYS_lstat:
			return ckpt::lstat((const char *)arg0, (struct stat *)arg1, (int *)result);
		case SYS_lseek:
			return ckpt::lseek((int)arg0, (off_t)arg1, (int)arg2, (off_t *)result);
		case SYS_pread64:
			return ckpt::pread((int)arg0, (void *)arg1, (size_t)arg2, (off_t)arg3, (ssize_t *)result);
		case SYS_pwrite64:
			return ckpt::pwrite((int)arg0, (const void *)arg1, (size_t)arg2, (off_t)arg3, (ssize_t *)result);
		case SYS_readv:
			return ckpt::readv((int)arg0, (const struct iovec *)arg1, (int)arg2, (ssize_t *)result);
		case SYS_writev:
			return ckpt::writev((int)arg0, (const struct iovec *)arg1, (int)arg2, (ssize_t *)result);
		case SYS_fsync:
			return ckpt::fsync((int)arg0, (int *)result);
		case SYS_fdatasync:
			return ckpt::fdatasync((int)arg0, (int *)result);
		case SYS_openat:
			return ckpt::openat((int)arg0, (const char *)arg1, (int)arg2, (mode_t)arg3, (int *)result);
		case SYS_newfstatat:
			return ckpt::fstatat((int)arg0, (const char *)arg1, (struct stat *)arg2, (int)arg3, (int *)result);
		case SYS_symlink:
		case SYS_symlinkat:
		case SYS_preadv:
		case SYS_pwritev:
		case SYS_preadv2:
		case SYS_pwritev2:
			*result = -ENOTSUP;
			return 0;
		default:
			return 1;
	}
}

static void init_path(void)
{
	char *ckpt, *bb, *pfs;

	if (!(ckpt = getenv("CKPT")) || !(bb = getenv("BB")) || !(pfs = getenv("PFS")))
		error("Environment variables named 'CKPT', 'BB', and 'PFS' must be specified.");

	if (!(ckpt = realpath(ckpt, NULL)) || !(bb = realpath(bb, NULL)) || !(pfs = realpath(pfs, NULL)))
		error("realpath() failed (" + std::string(strerror(errno)) + ")");

	ckpt_dir = new std::string(ckpt);
	bb_dir = new std::string(bb);
	pfs_dir = new std::string(pfs);

	free(ckpt);
	free(bb);
	free(pfs);
}

static void exit_path(void)
{
	delete ckpt_dir;
	delete bb_dir;
	delete pfs_dir;
}

static __attribute__((constructor)) void init(void)
{
	init_path();

	segment = new bi::managed_shared_memory(bi::open_only, "ckptfs");
	shm_cfg = segment->find<config>("cfg").first;
	mq = segment->find<message_queue>("q").first;

	intercept_hook_point = hook;
}

static __attribute__((destructor)) void exit(void)
{
	delete segment;

	exit_path();
}
