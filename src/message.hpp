#ifndef CKPTFS_MESSAGE_HPP
#define CKPTFS_MESSAGE_HPP

#include <sys/types.h>

class message {
public:
	long syscall;
	pid_t pid;
	int fd;
	off_t offset;
	size_t len;

	message(long syscall, pid_t pid, int fd, off_t offset, size_t len);
};

#endif //CKPTFS_MESSAGE_HPP
