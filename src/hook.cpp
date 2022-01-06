#include <cerrno>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

#define SHM_NAME "ckptfs"
#define SHM_SIZE sizeof(message_queue)

std::string *ckpt_dir, *bb_dir, *pfs_dir;
message_queue *mq;

static int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
{
	switch (syscall_number) {
		case SYS_write:
			return ckpt::write((int)arg0, (const void *)arg1, (size_t)arg2, (ssize_t *)result);
		case SYS_open:
			return ckpt::open((const char *)arg0, (int)arg1, (mode_t)arg2, (int *)result);
		case SYS_close:
			return ckpt::close((int)arg0, (int *)result);
		case SYS_lseek:
			return ckpt::lseek((int)arg0, (off_t)arg1, (int)arg2, (off_t *)result);
		case SYS_pwrite64:
			return ckpt::pwrite((int)arg0, (const void *)arg1, (size_t)arg2, (off_t)arg3, (ssize_t *)result);
		case SYS_fsync:
			return ckpt::fsync((int)arg0, (int *)result);
		case SYS_openat:
			return ckpt::openat((int)arg0, (const char *)arg1, (int)arg2, (mode_t)arg3, (int *)result);
		case SYS_read:
		case SYS_pread64:
		case SYS_readv:
		case SYS_writev:
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

static void init_shm(void)
{
	int shm_fd;

	shm_fd = shm_open(SHM_NAME, O_RDWR, 0664);
	if (shm_fd == -1)
		error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	mq = static_cast<message_queue *>(mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0));
	if (mq == MAP_FAILED)
		error("mmap() failed (" + std::string(strerror(errno)) + ")");

	if (close(shm_fd) == -1)
		error("close() failed (" + std::string(strerror(errno)) + ")");
}

static void exit_shm(void)
{
	if (munmap(static_cast<void *>(mq), SHM_SIZE) == -1)
		error("munmap() failed (" + std::string(strerror(errno)) + ")");
}

static __attribute__((constructor)) void init(void)
{
	init_path();
	init_shm();

	intercept_hook_point = hook;
}

static __attribute__((destructor)) void exit(void)
{
	exit_shm();
	exit_path();
}
