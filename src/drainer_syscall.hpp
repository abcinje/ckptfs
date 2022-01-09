#ifndef CKPTFS_DRAINER_SYSCALL_HPP
#define CKPTFS_DRAINER_SYSCALL_HPP

#include "message.hpp"

namespace drainer
{
	void write(const message &msg);
	void open(const message &msg);
	void close(const message &msg);
	void pwrite(const message &msg);
	void writev(const message &msg);
	void fsync(const message &msg);
}

#endif //CKPTFS_DRAINER_SYSCALL_HPP
