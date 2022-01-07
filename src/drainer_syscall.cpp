#include <cerrno>
#include <csignal>
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

#include "drainer_syscall.hpp"

extern std::string *ckpt_dir, *bb_dir, *pfs_dir;
extern bi::managed_shared_memory *segment;
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

	if ((pfs_fd = ::open(pfs_file.c_str(), O_WRONLY | O_CREAT, 0664)) == -1)
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

	fmap.erase(it);

	if (::close(bb_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	if (::close(pfs_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");
}

void drainer::pwrite(const message &msg)
{
	try {
		do_write(msg);
	} catch (std::logic_error &e) {
		throw std::logic_error("drainer::pwrite() failed (" + std::string(e.what()) + ")");
	}
}

void drainer::fsync(const message &msg)
{
	int pfs_fd;

	auto it = fmap.find({msg.pid, msg.fd});
	if (it != fmap.end()) {
		pfs_fd = it->second.second;
	} else {
		throw std::logic_error("drainer::fsync() failed (no such key)");
	}

	if (::fsync(pfs_fd) == -1)
		throw std::runtime_error("fsync() failed (" + std::string(strerror(errno)) + ")");

	if (::kill(msg.pid, SIGUSR1) == -1)
		throw std::runtime_error("kill() failed (" + std::string(strerror(errno)) + ")");
}
