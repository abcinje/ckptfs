#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <tuple>
#include <unordered_map>

#include <fcntl.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "config.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;
extern config *shm_cfg;
extern message_queue *mq;

static std::shared_mutex fmap_mutex;
static std::unordered_map<int, std::tuple<int, off_t, off_t, message_queue *>> fmap; // fmap: bb_fd -> (pfs_fd, offset, len, fq)



/*******************
 * => Syscalls
 *******************/

int ckpt::read(int fd, void *buf, size_t count, ssize_t *result)
{
	void *shm_synced;
	shm_handle synced_handle;
	pid_t pid;
	int pfs_fd;
	off_t *offset;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			offset = &std::get<1>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
	new (shm_synced) bi::interprocess_semaphore(0);
	synced_handle = segment->get_handle_from_address(shm_synced);

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_read, pid, fd, 0, 0, synced_handle));
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

	segment->deallocate(shm_synced);

	if ((*result = syscall_no_intercept(SYS_read, pfs_fd, buf, count)) == -1)
		error("read() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;

	return 0;
}

int ckpt::write(int fd, const void *buf, size_t count, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *offset, *len;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			offset = &std::get<1>(it->second);
			len = &std::get<2>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	if ((*result = syscall_no_intercept(SYS_write, fd, buf, count)) == -1)
		error("write() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_write, pid, fd, *offset, *result));

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
	void *shm_pathname, *shm_fq;
	shm_handle pathname_handle, fq_handle;
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
	pathname_handle = segment->get_handle_from_address(shm_pathname);

	shm_fq = segment->allocate(sizeof(message_queue));
	new (shm_fq) message_queue();
	fq_handle = segment->get_handle_from_address(shm_fq);

	pid = syscall_no_intercept(SYS_getpid);
	mq->issue(message(SYS_open, pid, bb_fd, 0, 0, pathname_handle, fq_handle));

	if (syscall_no_intercept(SYS_fstat, pfs_fd, &statbuf) == -1)
		error("fstat() failed (" + std::string(strerror(errno)) + ")");
	len = statbuf.st_size;

	{
		std::scoped_lock lock(fmap_mutex);
		if (!fmap.insert({bb_fd, {pfs_fd, 0, len, static_cast<message_queue *>(shm_fq)}}).second)
			error("ckpt::open() failed (the same key already exists)");
	}

	*result = bb_fd;
	return 0;
}

int ckpt::close(int fd, int *result)
{
	pid_t pid;
	message_queue *fq;

	{
		std::scoped_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			fq = std::get<3>(it->second);
			fmap.erase(it);
		} else {
			return 1;
		}
	}

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_close, pid, fd, 0, 0));

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

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
		} else {
			return 1;
		}
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

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			file_offset = &std::get<1>(it->second);
		} else {
			return 1;
		}
	}

	if ((*result = syscall_no_intercept(SYS_lseek, fd, offset, whence)) == -1)
		error("lseek() failed (" + std::string(strerror(errno)) + ")");

	*file_offset = *result;

	return 0;
}

int ckpt::pread(int fd, void *buf, size_t count, off_t offset, ssize_t *result)
{
	void *shm_synced;
	shm_handle synced_handle;
	pid_t pid;
	int pfs_fd;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
	new (shm_synced) bi::interprocess_semaphore(0);
	synced_handle = segment->get_handle_from_address(shm_synced);

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_pread64, pid, fd, 0, 0, synced_handle));
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

	segment->deallocate(shm_synced);

	if ((*result = syscall_no_intercept(SYS_pread64, pfs_fd, buf, count, offset)) == -1)
		error("pread() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::pwrite(int fd, const void *buf, size_t count, off_t offset, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *len;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			len = &std::get<2>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	if ((*result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset)) == -1)
		error("pwrite() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_pwrite64, pid, fd, offset, *result));

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
	void *shm_synced;
	shm_handle synced_handle;
	pid_t pid;
	int pfs_fd;
	off_t *offset;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			offset = &std::get<1>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
	new (shm_synced) bi::interprocess_semaphore(0);
	synced_handle = segment->get_handle_from_address(shm_synced);

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_readv, pid, fd, 0, 0, synced_handle));
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

	segment->deallocate(shm_synced);

	if ((*result = syscall_no_intercept(SYS_readv, pfs_fd, iov, iovcnt)) == -1)
		error("readv() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;

	return 0;
}

int ckpt::writev(int fd, const struct iovec *iov, int iovcnt, ssize_t *result)
{
	pid_t pid;
	int pfs_fd;
	off_t *offset, *len;
	message_queue *fq;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(fd);
		if (it != fmap.end()) {
			pfs_fd = std::get<0>(it->second);
			offset = &std::get<1>(it->second);
			len = &std::get<2>(it->second);
			fq = std::get<3>(it->second);
		} else {
			return 1;
		}
	}

	if ((*result = syscall_no_intercept(SYS_writev, fd, iov, iovcnt)) == -1)
		error("writev() failed (" + std::string(strerror(errno)) + ")");

	pid = syscall_no_intercept(SYS_getpid);
	fq->issue(message(SYS_writev, pid, fd, *offset, *result));

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
	shm_handle synced_handle;
	pid_t pid;
	message_queue *fq;

	if (!shm_cfg->lazy_fsync_enabled) {
		{
			std::shared_lock lock(fmap_mutex);
			auto it = fmap.find(fd);
			if (it != fmap.end()) {
				fq = std::get<3>(it->second);
			} else {
				return 1;
			}
		}

		shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
		new (shm_synced) bi::interprocess_semaphore(0);
		synced_handle = segment->get_handle_from_address(shm_synced);

		pid = syscall_no_intercept(SYS_getpid);
		fq->issue(message(SYS_fsync, pid, fd, 0, 0, synced_handle));
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

		segment->deallocate(shm_synced);
	}

	*result = 0;
	return 0;
}

int ckpt::fdatasync(int fd, int *result)
{
	void *shm_synced;
	shm_handle synced_handle;
	pid_t pid;
	message_queue *fq;

	if (!shm_cfg->lazy_fsync_enabled) {
		{
			std::shared_lock lock(fmap_mutex);
			auto it = fmap.find(fd);
			if (it != fmap.end()) {
				fq = std::get<3>(it->second);
			} else {
				return 1;
			}
		}

		shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
		new (shm_synced) bi::interprocess_semaphore(0);
		synced_handle = segment->get_handle_from_address(shm_synced);

		pid = syscall_no_intercept(SYS_getpid);
		fq->issue(message(SYS_fdatasync, pid, fd, 0, 0, synced_handle));
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

		segment->deallocate(shm_synced);
	}

	*result = 0;
	return 0;
}

int ckpt::openat(int dirfd, const char *pathname, int flags, mode_t mode, int *result)
{
	std::string file;

	if (dirfd != AT_FDCWD && pathname[0] != '/') {
		char dirpath[PATH_MAX];
		ssize_t dirpath_len;
		
		std::string symlink("/proc/self/fd/" + std::to_string(dirfd));
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

		std::string symlink("/proc/self/fd/" + std::to_string(dirfd));
		if ((dirpath_len = syscall_no_intercept(SYS_readlink, symlink.c_str(), dirpath, PATH_MAX - 1)) == -1)
			error("readlink() failed (" + std::string(strerror(errno)) + ")");
		dirpath[dirpath_len] != '\0';

		file = resolve_abspath(std::string(dirpath) + '/' + std::string(pathname));
		pathname = file.c_str();
	}

	return stat(pathname, statbuf, result);
}

int hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long *result)
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
