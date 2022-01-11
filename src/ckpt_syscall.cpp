#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <semaphore>
#include <string>
#include <tuple>
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

static std::unordered_map<int, std::tuple<int, off_t, off_t>> fmap; // fmap: bb_fd -> (pfs_fd, offset, len)



/*******************
 * => Syscalls
 *******************/

int ckpt::read(int fd, void *buf, size_t count, ssize_t *result)
{
	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		/* TODO */
		*result = -ENOTSUP;
		return 0;
	} else {
		return 1;
	}
}

int ckpt::write(int fd, const void *buf, size_t count, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *offset, *len;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		pfs_fd = std::get<0>(it->second);
		offset = &std::get<1>(it->second);
		len = &std::get<2>(it->second);
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_write, fd, buf, count)) == -1)
		error("write() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_write, pid, fd, *offset, *result, 0));

	*offset += *result;
	if (*len < *offset) {
		if (syscall_no_intercept(SYS_ftruncate, pfs_fd, *offset) == -1)
			error("ftruncate() failed (" + std::string(strerror(errno)) + ")");
		*len = *offset;
	}

	return 0;
}

int ckpt::open(const char *pathname, int flags, mode_t mode, int *result)
{
	void *shm_pathname;
	shm_handle handle;
	pid_t pid;
	int bb_fd, pfs_fd;
	struct stat statbuf;
	off_t len;

	std::string abspath;
	if (pathname[0] != '/') {
		char cwd[PATH_MAX];
		if (!syscall_no_intercept(SYS_getcwd, cwd, PATH_MAX))
			error("getcwd() failed (" + std::string(strerror(errno)) + ")");
		abspath = std::string(cwd) + '/' + std::string(pathname);
	} else {
		abspath = std::string(pathname);
	}

	std::string ckpt_file(resolve_abspath(abspath));
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		return 1;

	if (flags & O_APPEND)
		error("ckpt::open() failed (the O_APPEND flag is unsupported)");

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string bb_file(*bb_dir + file);
	std::string pfs_file(*pfs_dir + file);

	if ((bb_fd = syscall_no_intercept(SYS_open, bb_file.c_str(), flags, mode)) == -1)
		error("open() failed (" + std::string(strerror(errno)) + ")");

	if ((pfs_fd = syscall_no_intercept(SYS_open, pfs_file.c_str(), (flags | O_CREAT) & ~O_EXCL, mode)) == -1)
		error("open() failed (" + std::string(strerror(errno)) + ")");

	shm_pathname = segment->allocate(ckpt_file.size() + 1);
	std::memcpy(shm_pathname, ckpt_file.data(), ckpt_file.size() + 1);
	handle = segment->get_handle_from_address(shm_pathname);

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_open, pid, bb_fd, 0, 0, handle));

	if (syscall_no_intercept(SYS_fstat, pfs_file.c_str(), &statbuf) == -1)
		error("fstat() failed (" + std::string(strerror(errno)) + ")");
	len = statbuf.st_size;

	if (!fmap.insert({bb_fd, {pfs_fd, 0, len}}).second)
		error("ckpt::open() failed (the same key already exists)");

	*result = bb_fd;
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
		error("close() failed (" + std::string(strerror(errno)) + ")");

	*result = 0;
	return 0;
}

int ckpt::stat(const char *pathname, struct stat *statbuf, int *result)
{
	std::string abspath;
	if (pathname[0] != '/') {
		char cwd[PATH_MAX];
		if (!syscall_no_intercept(SYS_getcwd, cwd, PATH_MAX))
			error("getcwd() failed (" + std::string(strerror(errno)) + ")");
		abspath = std::string(cwd) + '/' + std::string(pathname);
	} else {
		abspath = std::string(pathname);
	}

	std::string ckpt_file(resolve_abspath(abspath));
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		return 1;

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string pfs_file(*pfs_dir + file);

	if ((*result = syscall_no_intercept(SYS_stat, pfs_file.c_str(), statbuf)) == -1)
		error("stat() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::fstat(int fd, struct stat *statbuf, int *result)
{
	int pfs_fd;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		pfs_fd = std::get<0>(it->second);
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_fstat, pfs_fd, statbuf)) == -1)
		error("fstat() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::lstat(const char *pathname, struct stat *statbuf, int *result)
{
	std::string abspath;
	if (pathname[0] != '/') {
		char cwd[PATH_MAX];
		if (!syscall_no_intercept(SYS_getcwd, cwd, PATH_MAX))
			error("getcwd() failed (" + std::string(strerror(errno)) + ")");
		abspath = std::string(cwd) + '/' + std::string(pathname);
	} else {
		abspath = std::string(pathname);
	}

	std::string ckpt_file(resolve_abspath(abspath));
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		return 1;

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string pfs_file(*pfs_dir + file);

	if ((*result = syscall_no_intercept(SYS_lstat, pfs_file.c_str(), statbuf)) == -1)
		error("lstat() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::lseek(int fd, off_t offset, int whence, off_t *result)
{
	off_t *file_offset;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		file_offset = &std::get<1>(it->second);
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_lseek, fd, offset, whence)) == -1)
		error("lseek() failed (" + std::string(strerror(errno)) + ")");

	*file_offset = *result;

	return 0;
}

int ckpt::pread(int fd, void *buf, size_t count, off_t offset, ssize_t *result)
{
	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		/* TODO */
		*result = -ENOTSUP;
		return 0;
	} else {
		return 1;
	}
}

int ckpt::pwrite(int fd, const void *buf, size_t count, off_t offset, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *len;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		pfs_fd = std::get<0>(it->second);
		len = &std::get<2>(it->second);
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset)) == -1)
		error("pwrite() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_pwrite64, pid, fd, offset, *result, 0));

	offset += *result;
	if (*len < offset) {
		if (syscall_no_intercept(SYS_ftruncate, pfs_fd, offset) == -1)
			error("ftruncate() failed (" + std::string(strerror(errno)) + ")");
		*len = offset;
	}

	return 0;
}

int ckpt::readv(int fd, const struct iovec *iov, int iovcnt, ssize_t *result)
{
	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		/* TODO */
		*result = -ENOTSUP;
		return 0;
	} else {
		return 1;
	}
}

int ckpt::writev(int fd, const struct iovec *iov, int iovcnt, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *offset, *len;

	auto it = fmap.find(fd);
	if (it != fmap.end()) {
		pfs_fd = std::get<0>(it->second);
		offset = &std::get<1>(it->second);
		len = &std::get<2>(it->second);
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_writev, fd, iov, iovcnt)) == -1)
		error("writev() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_writev, pid, fd, *offset, *result, 0));

	*offset += *result;
	if (*len < *offset) {
		if (syscall_no_intercept(SYS_ftruncate, pfs_fd, *offset) == -1)
			error("ftruncate() failed (" + std::string(strerror(errno)) + ")");
		*len = *offset;
	}

	return 0;
}

int ckpt::fsync(int fd, int *result)
{
	void *shm_synced;
	shm_handle handle;
	pid_t pid;

	if (fmap.find(fd) == fmap.end())
		return 1;

	shm_synced = segment->allocate(sizeof(std::binary_semaphore));
	new (shm_synced) std::binary_semaphore(0);
	handle = segment->get_handle_from_address(shm_synced);

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_fsync, pid, fd, 0, 0, handle));
	(static_cast<std::binary_semaphore *>(shm_synced))->acquire();

	segment->deallocate(shm_synced);

	*result = 0;
	return 0;
}

int ckpt::openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result)
{
	std::string file;

	if (dirfd != AT_FDCWD && pathname[0] != '/') {
		char dirpath[PATH_MAX];
		ssize_t dirpath_len;
		
		pid_t pid = syscall_no_intercept(SYS_getpid);
		std::string symlink("/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd));

		if ((dirpath_len = syscall_no_intercept(SYS_readlink, symlink.c_str(), dirpath, PATH_MAX - 1)) == -1)
			error("readlink() failed (" + std::string(strerror(errno)) + ")");
		dirpath[dirpath_len] != '\0';

		file = resolve_abspath(std::string(dirpath) + '/' + std::string(pathname));
		pathname = file.c_str();
	}

	return open(pathname, flags, mode, result);
}

int ckpt::fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags, int *result)
{
	std::string file;

	if (flags)
		error("ckpt::fstatat() failed (nonzero flags are unsupported)");

	if (dirfd != AT_FDCWD && pathname[0] != '/') {
		char dirpath[PATH_MAX];
		ssize_t dirpath_len;

		pid_t pid = syscall_no_intercept(SYS_getpid);
		std::string symlink("/proc/" + std::to_string(pid) + "/fd/" + std::to_string(dirfd));

		if ((dirpath_len = syscall_no_intercept(SYS_readlink, symlink.c_str(), dirpath, PATH_MAX - 1)) == -1)
			error("readlink() failed (" + std::string(strerror(errno)) + ")");
		dirpath[dirpath_len] != '\0';

		file = resolve_abspath(std::string(dirpath) + '/' + std::string(pathname));
		pathname = file.c_str();
	}

	return stat(pathname, statbuf, result);
}
