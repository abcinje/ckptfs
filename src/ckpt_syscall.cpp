#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

#define MAX_NUM_FDS	(1024)

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;

/* config */
extern int fsync_lazy_level;
extern long batch_size;

extern bi::managed_shared_memory *segment;
extern message_queue *mq;

void print(std::string msg);
void error(std::string msg);

class finfo {
public:
	off_t offset;
	off_t len;
	off_t boffset;
	size_t bcount;
	bool fsynced;
	bool fdatasynced;
	message_queue *fq;

	finfo(off_t offset, off_t len, off_t boffset, size_t bcount, bool fsynced, bool fdatasynced, message_queue *fq)
			: offset(offset), len(len), boffset(boffset), bcount(bcount), fsynced(fsynced), fdatasynced(fdatasynced), fq(fq)
	{
	}
};

static finfo *fmap[MAX_NUM_FDS]; // fmap: fd -> (offset, len, boffset, bcount, fq)



/*******************
 * => Syscalls
 *******************/

int ckpt::read(int fd, void *buf, size_t count, ssize_t *result)
{
	finfo *fi;
	off_t *offset;

	fi = fmap[fd];
	if (fi) {
		offset = &fi->offset;
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_read, fd, buf, count)) == -1)
		error("read() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;

	return 0;
}

int ckpt::write(int fd, const void *buf, size_t count, ssize_t *result)
{
	finfo *fi;
	off_t *offset, *len;
	off_t *boffset;
	size_t *bcount;
	message_queue *fq;

	fi = fmap[fd];
	if (fi) {
		offset = &fi->offset;
		len = &fi->len;
		boffset = &fi->boffset;
		bcount = &fi->bcount;
		fq = fi->fq;
	} else {
		return 1;
	}

	if (*boffset + *bcount != *offset) {
		if (*bcount) {
			fq->issue(message(SYS_write, *boffset, *bcount));
			*bcount = 0;
		}
		*boffset = *offset;
	}

	if ((*result = syscall_no_intercept(SYS_write, fd, buf, count)) == -1)
		error("write() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;
	if (*len < *offset)
		*len = *offset;

	*bcount += *result;
	if (*bcount >= batch_size) {
		fq->issue(message(SYS_write, *boffset, *bcount));
		*bcount = 0;
	}

	return 0;
}

int ckpt::open(const char *pathname, int flags, mode_t mode, int *result)
{
	void *shm_pathname, *shm_fq, *shm_synced;
	shm_handle pathname_handle, fq_handle, synced_handle;
	int fd;
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

	if ((fd = syscall_no_intercept(SYS_open, bb_file.c_str(), flags, mode)) == -1)
		error("open() failed (" + std::string(strerror(errno)) + ")");

	shm_pathname = segment->allocate(ckpt_file.size() + 1);
	std::memcpy(shm_pathname, ckpt_file.data(), ckpt_file.size() + 1);
	pathname_handle = segment->get_handle_from_address(shm_pathname);

	shm_fq = segment->allocate(sizeof(message_queue));
	new (shm_fq) message_queue();
	fq_handle = segment->get_handle_from_address(shm_fq);

	shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
	new (shm_synced) bi::interprocess_semaphore(0);
	synced_handle = segment->get_handle_from_address(shm_synced);

	message::shm_handles handles = {
		.fq_handle = fq_handle,
		.pathname_handle = pathname_handle,
		.synced_handle = synced_handle,
	};
	mq->issue(message(SYS_open, 0, 0, handles, flags, mode));
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

	segment->deallocate(shm_synced);

	if (syscall_no_intercept(SYS_fstat, fd, &statbuf) == -1)
		error("fstat() failed (" + std::string(strerror(errno)) + ")");
	len = statbuf.st_size;

	if (fd >= MAX_NUM_FDS)
		error("ckpt::open() failed (fd is greater than or equal to MAX_NUM_FDS)");
	if (fmap[fd])
		error("ckpt::open() failed (the same key already exists)");
	fmap[fd] = new finfo(0, len, 0, 0, false, false, static_cast<message_queue *>(shm_fq));

	*result = fd;
	return 0;
}

int ckpt::close(int fd, int *result)
{
	void *shm_synced;
	shm_handle synced_handle;

	finfo *fi;
	off_t boffset;
	size_t bcount;
	bool fsynced;
	bool fdatasynced;
	message_queue *fq;

	fi = fmap[fd];
	if (fi) {
		boffset = fi->boffset;
		bcount = fi->bcount;
		fsynced = fi->fsynced;
		fdatasynced = fi->fdatasynced;
		fq = fi->fq;

		fmap[fd] = nullptr;
		delete fi;
	} else {
		return 1;
	}

	if (bcount)
		fq->issue(message(SYS_write, boffset, bcount));

	if (fsynced || fdatasynced) {
		int flags = fsynced ? 0 : CKPT_S_DATAONLY;

		if (fsync_lazy_level == 1) {
			flags |= CKPT_S_CLOSEWAIT;

			shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
			new (shm_synced) bi::interprocess_semaphore(0);
			synced_handle = segment->get_handle_from_address(shm_synced);

			message::shm_handles handles = {
				.synced_handle = synced_handle,
			};
			fq->issue(message(SYS_close, 0, 0, handles, flags));
			(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

			segment->deallocate(shm_synced);
		} else if (fsync_lazy_level == 2) {
			flags |= CKPT_S_CLOSENOWAIT;

			fq->issue(message(SYS_close, 0, 0, {}, flags));
		}
	}

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
	std::string bb_file(*bb_dir + file);

	if ((*result = syscall_no_intercept(SYS_stat, bb_file.c_str(), statbuf)) == -1)
		error("stat() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::fstat(int fd, struct stat *statbuf, int *result)
{
	finfo *fi;

	fi = fmap[fd];
	if (!fi)
		return 1;

	if ((*result = syscall_no_intercept(SYS_fstat, fd, statbuf)) == -1)
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
	std::string bb_file(*bb_dir + file);

	if ((*result = syscall_no_intercept(SYS_lstat, bb_file.c_str(), statbuf)) == -1)
		error("lstat() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::lseek(int fd, off_t offset, int whence, off_t *result)
{
	finfo *fi;
	off_t *file_offset;

	fi = fmap[fd];
	if (fi) {
		file_offset = &fi->offset;
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
	finfo *fi;

	fi = fmap[fd];
	if (!fi)
		return 1;

	if ((*result = syscall_no_intercept(SYS_pread64, fd, buf, count, offset)) == -1)
		error("pread() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}

int ckpt::pwrite(int fd, const void *buf, size_t count, off_t offset, ssize_t *result)
{
	finfo *fi;
	off_t *len;
	off_t *boffset;
	size_t *bcount;
	message_queue *fq;

	fi = fmap[fd];
	if (fi) {
		len = &fi->len;
		boffset = &fi->boffset;
		bcount = &fi->bcount;
		fq = fi->fq;
	} else {
		return 1;
	}

	if (*boffset + *bcount != offset) {
		if (*bcount) {
			fq->issue(message(SYS_write, *boffset, *bcount));
			*bcount = 0;
		}
		*boffset = offset;
	}

	if ((*result = syscall_no_intercept(SYS_pwrite64, fd, buf, count, offset)) == -1)
		error("pwrite() failed (" + std::string(strerror(errno)) + ")");

	offset += *result;
	if (*len < offset)
		*len = offset;

	*bcount += *result;
	if (*bcount >= batch_size) {
		fq->issue(message(SYS_write, *boffset, *bcount));
		*bcount = 0;
	}

	return 0;
}

int ckpt::readv(int fd, const struct iovec *iov, int iovcnt, ssize_t *result)
{
	finfo *fi;
	off_t *offset;

	fi = fmap[fd];
	if (fi) {
		offset = &fi->offset;
	} else {
		return 1;
	}

	if ((*result = syscall_no_intercept(SYS_readv, fd, iov, iovcnt)) == -1)
		error("readv() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;

	return 0;
}

int ckpt::writev(int fd, const struct iovec *iov, int iovcnt, ssize_t *result)
{
	finfo *fi;
	off_t *offset, *len;
	off_t *boffset;
	size_t *bcount;
	message_queue *fq;

	fi = fmap[fd];
	if (fi) {
		offset = &fi->offset;
		len = &fi->len;
		boffset = &fi->boffset;
		bcount = &fi->bcount;
		fq = fi->fq;
	} else {
		return 1;
	}

	if (*boffset + *bcount != *offset) {
		if (*bcount) {
			fq->issue(message(SYS_write, *boffset, *bcount));
			*bcount = 0;
		}
		*boffset = *offset;
	}

	if ((*result = syscall_no_intercept(SYS_writev, fd, iov, iovcnt)) == -1)
		error("writev() failed (" + std::string(strerror(errno)) + ")");

	*offset += *result;
	if (*len < *offset)
		*len = *offset;

	*bcount += *result;
	if (*bcount >= batch_size) {
		fq->issue(message(SYS_write, *boffset, *bcount));
		*bcount = 0;
	}

	return 0;
}

int ckpt::fsync(int fd, int *result)
{
	void *shm_synced;
	shm_handle synced_handle;

	finfo *fi;
	off_t boffset;
	size_t *bcount;
	message_queue *fq;

	fi = fmap[fd];
	if (!fi)
		return 1;

	if (fsync_lazy_level == 0) {
		boffset = fi->boffset;
		bcount = &fi->bcount;
		fq = fi->fq;

		if (*bcount) {
			fq->issue(message(SYS_write, boffset, *bcount));
			*bcount = 0;
		}

		shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
		new (shm_synced) bi::interprocess_semaphore(0);
		synced_handle = segment->get_handle_from_address(shm_synced);

		message::shm_handles handles = {
			.synced_handle = synced_handle,
		};
		fq->issue(message(SYS_fsync, 0, 0, handles));
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

		segment->deallocate(shm_synced);
	} else if (fsync_lazy_level < 3) {
		fi->fsynced = true;
	}

	*result = 0;
	return 0;
}

int ckpt::fdatasync(int fd, int *result)
{
	void *shm_synced;
	shm_handle synced_handle;

	finfo *fi;
	off_t boffset;
	size_t *bcount;
	message_queue *fq;

	fi = fmap[fd];
	if (!fi)
		return 1;

	if (fsync_lazy_level == 0) {
		boffset = fi->boffset;
		bcount = &fi->bcount;
		fq = fi->fq;

		if (*bcount) {
			fq->issue(message(SYS_write, boffset, *bcount));
			*bcount = 0;
		}

		shm_synced = segment->allocate(sizeof(bi::interprocess_semaphore));
		new (shm_synced) bi::interprocess_semaphore(0);
		synced_handle = segment->get_handle_from_address(shm_synced);

		message::shm_handles handles = {
			.synced_handle = synced_handle,
		};
		fq->issue(message(SYS_fdatasync, 0, 0, handles));
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->wait();

		segment->deallocate(shm_synced);
	} else if (fsync_lazy_level < 3) {
		fi->fdatasynced = true;
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
		dirpath[dirpath_len] = '\0';

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
		dirpath[dirpath_len] = '\0';

		file = resolve_abspath(std::string(dirpath) + '/' + std::string(pathname));
		pathname = file.c_str();
	}

	return stat(pathname, statbuf, result);
}
