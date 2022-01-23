#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

#include "config.hpp"
#include "drainer_syscall.hpp"

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;
extern config *shm_cfg;
extern int pipefd[2];

namespace std
{
	template <>
	struct hash<std::pair<pid_t, int>> {
		size_t operator ()(const std::pair<pid_t, int> &pair) const
		{
			return hash<pid_t>()(pair.first) ^ hash<int>()(pair.second);
		}
	};
}

static std::unordered_map<std::pair<pid_t, int>, std::pair<int, int>> fmap; // fmap: (pid, fd) -> (bb_fd, pfs_fd)

static void do_write(const message &msg)
{
	int bb_fd, pfs_fd;
	off_t offset;

	auto it = fmap.find({msg.pid, msg.fd});
	if (it != fmap.end()) {
		bb_fd = it->second.first;
		pfs_fd = it->second.second;
	} else {
		throw std::logic_error("no such key");
	}

	offset = msg.offset;
	if (::splice(bb_fd, &offset, pipefd[1], nullptr, msg.len, SPLICE_F_MOVE) == -1)
		throw std::runtime_error("splice() failed (" + std::string(strerror(errno)) + ")");

	offset = msg.offset;
	if (::splice(pipefd[0], nullptr, pfs_fd, &offset, msg.len, SPLICE_F_MOVE) == -1)
		throw std::runtime_error("splice() failed (" + std::string(strerror(errno)) + ")");
}

static void do_fsync(const message &msg, bool data_only)
{
	void *shm_synced;
	int pfs_fd;

	auto it = fmap.find({msg.pid, msg.fd});
	if (it != fmap.end()) {
		pfs_fd = it->second.second;
	} else {
		throw std::logic_error("no such key");
	}

	if (data_only) {
		if (::fdatasync(pfs_fd) == -1)
			throw std::runtime_error("fdatasync() failed (" + std::string(strerror(errno)) + ")");
	} else {
		if (::fsync(pfs_fd) == -1)
			throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");
	}

	shm_synced = segment->get_address_from_handle(msg.handle);
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
	void *shm_pathname;
	int bb_fd, pfs_fd;

	shm_pathname = segment->get_address_from_handle(msg.handle);
	std::string ckpt_file(static_cast<char *>(shm_pathname));
	segment->deallocate(shm_pathname);
	if (ckpt_file.rfind(*ckpt_dir, 0) == std::string::npos)
		throw std::runtime_error("drainer::open() failed (invalid pathname)");

	std::string file(ckpt_file.substr(ckpt_dir->size()));
	std::string bb_file(*bb_dir + file);
	std::string pfs_file(*pfs_dir + file);

	if ((bb_fd = ::open(bb_file.c_str(), O_RDONLY)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	if ((pfs_fd = ::open(pfs_file.c_str(), O_WRONLY)) == -1)
		throw std::runtime_error("open() failed (" + std::string(strerror(errno)) + ")");

	if (!fmap.insert({{msg.pid, msg.fd}, {bb_fd, pfs_fd}}).second)
		throw std::logic_error("drainer::open() failed (the same key already exists)");
}

void drainer::close(const message &msg)
{
	int bb_fd, pfs_fd;

	auto it = fmap.find({msg.pid, msg.fd});
	if (it != fmap.end()) {
		bb_fd = it->second.first;
		pfs_fd = it->second.second;
	} else {
		throw std::logic_error("drainer::close() failed (no such key)");
	}

	if (shm_cfg->lazy_fsync_enabled)
		if (::fsync(pfs_fd) == -1)
			throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");

	fmap.erase(it);

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
	if (shm_cfg->lazy_fsync_enabled)
		throw std::logic_error("drainer::fsync() failed (the function shouldn't be called with the current configuration)");

	try {
		do_fsync(msg, false);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::fsync() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::fdatasync(const message &msg)
{
	if (shm_cfg->lazy_fsync_enabled)
		throw std::logic_error("drainer::fdatasync() failed (the function shouldn't be called with the current configuration)");

	try {
		do_fsync(msg, true);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::fdatasync() failed (" + std::string(e.what()) + ")");
	}
}
