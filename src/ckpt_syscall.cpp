#include <cerrno>
#include <csignal>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>

#include <fcntl.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;
extern message_queue *mq;

static std::unordered_map<int, off_t> fmap; // fmap: fd -> offset

int ckpt::write(int fd, const void *buf, size_t count, ssize_t *result)
{
	pid_t pid;
	off_t *offset;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		offset = &it->second;
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_write, fd, buf, count)) == -1)
		error("write() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_write, pid, fd, *offset, *result, 0));

	*offset += *result;

	return 0;
}

int ckpt::open(const char *pathname, int flags, mode_t mode, int *result)
{
	void *shm_pathname;
	shm_handle handle;
	pid_t pid;
	int fd;

	if (pathname[0] != '/')
		error("ckpt::open() failed (only absolute paths are supported)");

	std::string ckpt_file(pathname);
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		return 1;

	if (flags & O_APPEND)
		error("ckpt::open() failed (the O_APPEND flag is unsupported)");

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string bb_file(*bb_dir + file);

	if ((fd = syscall_no_intercept(SYS_open, bb_file.c_str(), flags, mode)) == -1)
		error("open() failed (" + std::string(strerror(errno)) + ")");

	shm_pathname = segment->allocate(strlen(pathname) + 1);
	std::memcpy(shm_pathname, pathname, strlen(pathname) + 1);
	handle = segment->get_handle_from_address(shm_pathname);

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_open, pid, fd, 0, 0, handle));

	if (!fmap.insert({fd, 0}).second)
		error("ckpt::open() failed (the same key already exists)");

	*result = fd;
	return 0;
}

int ckpt::close(int fd, int *result)
{
	pid_t pid;

	auto it = fmap.find(fd);
	if (it == fmap.end())
		return 1;

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_close, pid, fd, 0, 0, 0));

	fmap.erase(it);

	if (syscall_no_intercept(SYS_close, fd) == -1)
		error("close() failed");

	*result = 0;
	return 0;
}

int ckpt::lseek(int fd, off_t offset, int whence, off_t *result)
{
	off_t *file_offset;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		file_offset = &it->second;
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_lseek, fd, offset, whence)) == -1)
		error("lseek() failed (" + std::string(strerror(errno)) + ")");

	*file_offset = *result;

	return 0;
}

int ckpt::pwrite(int fd, const void *buf, size_t count, off_t offset, ssize_t *result)
{
	pid_t pid;

	if (fmap.find(fd) == fmap.end())
		return 1;

	if ((*result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset)) == -1)
		error("pwrite() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_pwrite64, pid, fd, offset, *result, 0));

	return 0;
}

int ckpt::fsync(int fd, int *result)
{
	void *shm_synced;
	shm_handle handle;
	pid_t pid;

	if (fmap.find(fd) == fmap.end())
		return 1;

	shm_synced = segment->allocate(sizeof(bool));
	*static_cast<bool *>(shm_synced) = false;
	handle = segment->get_handle_from_address(shm_synced);

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_fsync, pid, fd, 0, 0, handle));
	while (!(*static_cast<bool *>(shm_synced)));

	segment->deallocate(shm_synced);

	*result = 0;
	return 0;
}

int ckpt::openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result)
{
	if (dirfd != AT_FDCWD)
		error("ckpt::openat() failed (only operations for the current working directory are supported)");

	return open(pathname, flags, mode, result);
}
