#include <cerrno>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

#include "drainer_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "random.hpp"
#include "util.hpp"

using message_queue = queue<message>;

#define BUF_SIZE (1 << 20)

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;

thread_local struct finfo {
	int bb_fd;
	int pfs_fd;
	void *shm_fq;
	char *buf;
	std::string tmp_file;
	std::string pfs_file;
} fi;



/*******************
 * => Syscalls
 *******************/

void drainer::write(const message &msg)
{
	ssize_t len, spliced;

	if ((len = msg.len) < 0)
		throw std::overflow_error("drainer::write() failed (integer overflow)");

	do {
		spliced = (len < BUF_SIZE) ? len : BUF_SIZE;

		if (::pread(fi.bb_fd, fi.buf, spliced, msg.offset) == -1)
			throw std::runtime_error("pread() failed (" + std::string(strerror(errno)) + ")");

		if (::pwrite(fi.pfs_fd, fi.buf, spliced, msg.offset) == -1)
			throw std::runtime_error("pwrite() failed (" + std::string(strerror(errno)) + ")");

		len -= spliced;
	} while (len > 0);
}

void drainer::open(const message &msg)
{
	void *shm_pathname, *shm_fq;
	int bb_fd, pfs_fd;
	uint64_t ofid;

	shm_pathname = segment->get_address_from_handle(msg.handles.pathname_handle);
	std::string ckpt_file(static_cast<char *>(shm_pathname));
	segment->deallocate(shm_pathname);
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		throw std::runtime_error("drainer::open() failed (invalid pathname)");

	shm_fq = segment->get_address_from_handle(msg.handles.fq_handle);

	ofid = rand64();

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string bb_file(*bb_dir + file);
	std::string pfs_file(*pfs_dir + file);
	std::string tmp_file(*pfs_dir + "/.tmp" + to_hex(ofid));

	if ((bb_fd = ::open(bb_file.c_str(), O_RDONLY)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	if ((pfs_fd = ::open(tmp_file.c_str(), msg.flags, msg.mode)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	fi = {bb_fd, pfs_fd, shm_fq, new char[BUF_SIZE], std::move(tmp_file), std::move(pfs_file)};
}

void drainer::close(const message &msg)
{
	void *shm_synced;

	std::string tmp_file(std::move(fi.tmp_file));
	std::string pfs_file(std::move(fi.pfs_file));

	if (msg.flags & CKPT_SYNCLOSE_WAIT) {
		int (*synchronize)(int) = (msg.flags & CKPT_SYNCLOSE_DATA) ? (::fdatasync) : (::fsync);
		if (synchronize(fi.pfs_fd) == -1)
			throw std::runtime_error("fsync() or fdatasync() failed (" + std::string(strerror(errno)) + ")");
		shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();
	} else if (msg.flags & CKPT_SYNCLOSE_NOWAIT) {
		int (*synchronize)(int) = (msg.flags & CKPT_SYNCLOSE_DATA) ? (::fdatasync) : (::fsync);
		if (synchronize(fi.pfs_fd) == -1)
			throw std::runtime_error("fsync() or fdatasync() failed (" + std::string(strerror(errno)) + ")");
	}

	if (::rename(tmp_file.c_str(), pfs_file.c_str()) == -1)
		throw std::runtime_error("rename() failed (" + std::string(strerror(errno)) + ")");

	delete[] fi.buf;
	segment->deallocate(fi.shm_fq);

	if (::close(fi.bb_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	if (::close(fi.pfs_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");
}

void drainer::fsync(const message &msg)
{
	void *shm_synced;

	if (::fsync(fi.pfs_fd) == -1)
		throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");

	shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();
}

void drainer::fdatasync(const message &msg)
{
	void *shm_synced;

	if (::fdatasync(fi.pfs_fd) == -1)
		throw std::runtime_error("fdatasync() failed (" + std::string(strerror(errno)) + ")");

	shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();
}
