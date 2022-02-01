#include <cerrno>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
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

using message_queue = queue<message>;

#define PIPE_CAPACITY (1 << 20)

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;

static std::shared_mutex fmap_mutex;
static std::unordered_map<uint64_t, std::tuple<int, int, void *, int *>> fmap; // fmap: ofid -> (bb_fd, pfs_fd, fq, pipe)

static void do_write(const message &msg)
{
	int bb_fd, pfs_fd, *pipefd;
	off_t offset0, offset1;
	ssize_t len, spliced;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(msg.ofid);
		if (it != fmap.end()) {
			bb_fd = std::get<0>(it->second);
			pfs_fd = std::get<1>(it->second);
			pipefd = std::get<3>(it->second);
		} else {
			throw std::logic_error("no such key");
		}
	}

	offset0 = offset1 = msg.offset;
	if ((len = msg.len) < 0)
		throw std::overflow_error("do_write() failed (integer overflow)");

	do {
		spliced = (len < PIPE_CAPACITY) ? len : PIPE_CAPACITY;

		if (::splice(bb_fd, &offset1, pipefd[1], nullptr, spliced, SPLICE_F_MOVE) == -1)
			throw std::runtime_error("splice() failed (" + std::string(strerror(errno)) + ")");

		if (::splice(pipefd[0], nullptr, pfs_fd, &offset0, spliced, SPLICE_F_MOVE) == -1)
			throw std::runtime_error("splice() failed (" + std::string(strerror(errno)) + ")");

		len -= spliced;
	} while (len > 0);
}

static void do_fsync(const message &msg, bool data_only)
{
	void *shm_synced;
	int pfs_fd;

	{
		std::shared_lock lock(fmap_mutex);
		auto it = fmap.find(msg.ofid);
		if (it != fmap.end()) {
			pfs_fd = std::get<1>(it->second);
		} else {
			throw std::logic_error("no such key");
		}
	}

	if (data_only) {
		if (::fdatasync(pfs_fd) == -1)
			throw std::runtime_error("fdatasync() failed (" + std::string(strerror(errno)) + ")");
	} else {
		if (::fsync(pfs_fd) == -1)
			throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");
	}

	shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
	(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();
}



/*******************
 * => Syscalls
 *******************/

void drainer::read(const message &msg)
{
	try {
		do_fsync(msg, true);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::read() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::write(const message &msg)
{
	try {
		do_write(msg);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::write() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::open(const message &msg)
{
	void *shm_pathname, *shm_fq;
	int bb_fd, pfs_fd, *pipefd;

	shm_pathname = segment->get_address_from_handle(msg.handles.pathname_handle);
	std::string ckpt_file(static_cast<char *>(shm_pathname));
	segment->deallocate(shm_pathname);
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		throw std::runtime_error("drainer::open() failed (invalid pathname)");

	shm_fq = segment->get_address_from_handle(msg.handles.fq_handle);

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string bb_file(*bb_dir + file);
	std::string pfs_file(*pfs_dir + file);

	if ((bb_fd = ::open(bb_file.c_str(), O_RDONLY)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	if ((pfs_fd = ::open(pfs_file.c_str(), O_WRONLY)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	pipefd = new int[2];
	if (::pipe(pipefd) == -1)
		throw std::runtime_error("pipe() failed (" + std::string(strerror(errno)) + ")");

	if (::fcntl(pipefd[0], F_SETPIPE_SZ, PIPE_CAPACITY) == -1)
		throw std::runtime_error("fcntl() failed (" + std::string(strerror(errno)) + ")");

	{
		std::scoped_lock lock(fmap_mutex);
		if (!fmap.insert({msg.ofid, {bb_fd, pfs_fd, shm_fq, pipefd}}).second)
			throw std::logic_error("drainer::open() failed (the same key already exists)");
	}
}

void drainer::close(const message &msg)
{
	void *shm_fq, *shm_synced;
	int bb_fd, pfs_fd, *pipefd;

	{
		std::scoped_lock lock(fmap_mutex);
		auto it = fmap.find(msg.ofid);
		if (it != fmap.end()) {
			bb_fd = std::get<0>(it->second);
			pfs_fd = std::get<1>(it->second);
			shm_fq = std::get<2>(it->second);
			pipefd = std::get<3>(it->second);
			fmap.erase(it);
		} else {
			throw std::logic_error("drainer::close() failed (no such key)");
		}
	}

	if (msg.flags & FSYNC_CLOSE_WAIT) {
		if (::fsync(pfs_fd) == -1)
			throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");
		shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();
	} else if (msg.flags & FSYNC_CLOSE_NOWAIT) {
		if (::fsync(pfs_fd) == -1)
			throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");
	}

	delete[] pipefd;
	segment->deallocate(shm_fq);

	if (::close(bb_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	if (::close(pfs_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");
}

void drainer::pread(const message &msg)
{
	try {
		do_fsync(msg, true);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::pread() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::pwrite(const message &msg)
{
	try {
		do_write(msg);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::pwrite() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::readv(const message &msg)
{
	try {
		do_fsync(msg, true);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::readv() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::writev(const message &msg)
{
	try {
		do_write(msg);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::writev() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::fsync(const message &msg)
{
	if (!(msg.flags & FSYNC_NORMAL))
		throw std::logic_error("drainer::fsync() failed (the function shouldn't be called with the current configuration)");

	try {
		do_fsync(msg, false);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::fsync() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::fdatasync(const message &msg)
{
	if (!(msg.flags & FSYNC_NORMAL))
		throw std::logic_error("drainer::fdatasync() failed (the function shouldn't be called with the current configuration)");

	try {
		do_fsync(msg, true);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::fdatasync() failed (" + std::string(e.what()) + ")");
	}
}
