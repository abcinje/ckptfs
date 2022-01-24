#ifndef CKPTFS_DRAINER_SYSCALL_HPP
#define CKPTFS_DRAINER_SYSCALL_HPP

#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

namespace drainer
{
	void read(const message &msg);
	void write(const message &msg);
	void open(const message &msg);
	void close(const message &msg);
	void pread(const message &msg);
	void pwrite(const message &msg);
	void readv(const message &msg);
	void writev(const message &msg);
	void fsync(const message &msg);
	void fdatasync(const message &msg);
}

void drain(message_queue *q, bool main);

#endif //CKPTFS_DRAINER_SYSCALL_HPP
