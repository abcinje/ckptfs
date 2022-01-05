#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <climits>

#include <sys/types.h>

class message {
public:
	long syscall;
	char path[PATH_MAX];
	pid_t pid;
	int fd;
	off_t offset;
	size_t len;

	message(long syscall, const char *path, pid_t pid, int fd, off_t offset, size_t len);
	message(const message &copy);
};

#endif //CKPTFS_MESSAGE_HPP
