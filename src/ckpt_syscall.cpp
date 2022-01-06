#include <cerrno>
#include <csignal>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
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
	mq->issue(message(SYS_write, nullptr, pid, fd, *offset, *result));

	*offset += *result;

	return 0;
}

int ckpt::open(const char *pathname, int flags, mode_t mode, int *result)
{
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

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_open, pathname, pid, fd, 0, 0));

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
	mq->issue(message(SYS_close, nullptr, pid, fd, 0, 0));

	fmap.erase(it);

	if (syscall_no_intercept(SYS_close, fd) == -1)
		error("close() failed");

	*result = 0;
	return 0;
}

int ckpt::fsync(int fd, int *result)
{
	static bool sigusr1_handler_installed;
	static bool signaled;
	struct sigaction action;
	void (*sigusr1_handler)(int);

	pid_t pid;

	if (fmap.find(fd) == fmap.end())
		return 1;

	sigusr1_handler = [](int signum) {
		signaled = true;
	};

	if (!sigusr1_handler_installed) {
		action.sa_handler = sigusr1_handler;
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		if (sigaction(SIGUSR1, &action, nullptr) == -1)
			error("sigaction() failed (" + std::string(strerror(errno)) + ")");

		sigusr1_handler_installed = true;
	}

	signaled = false;
	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_fsync, nullptr, pid, fd, 0, 0));
	while (!signaled);

	*result = 0;
	return 0;
}

int ckpt::openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result)
{
	if (dirfd != AT_FDCWD)
		error("ckpt::openat() failed (only operations for the current working directory are supported)");

	return open(pathname, flags, mode, result);
}
