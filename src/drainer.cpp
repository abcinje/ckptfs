#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

#include <syscall.h>

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

#include "drainer_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

std::string *ckpt_dir, *bb_dir, *pfs_dir;
bi::managed_shared_memory *segment;

static void drain(message_queue *fq)
{
	while (true) {
		message msg(fq->dispatch());

		switch (msg.syscall) {
			case SYS_write:
				drainer::write(msg);
				break;
			case SYS_open:	// start
				drainer::open(msg);
				break;
			case SYS_close:	// stop
				drainer::close(msg);
				return;
			case SYS_fsync:
				drainer::fsync(msg);
				break;
			case SYS_fdatasync:
				drainer::fdatasync(msg);
				break;
			default:
				throw std::logic_error("drain() failed (invalid operation type)");
		}
	}
}

static void init_path(void)
{
	char *ckpt, *bb, *pfs;

	if (!(ckpt = getenv("CKPT")) || !(bb = getenv("BB")) || !(pfs = getenv("PFS")))
		throw std::runtime_error("Environment variables named 'CKPT', 'BB', and 'PFS' must be specified.");

	if (!(ckpt = realpath(ckpt, nullptr)) || !(bb = realpath(bb, nullptr)) || !(pfs = realpath(pfs, nullptr)))
		throw std::runtime_error("realpath() failed (" + std::string(strerror(errno)) + ")");

	ckpt_dir = new std::string(ckpt);
	bb_dir = new std::string(bb);
	pfs_dir = new std::string(pfs);

	free(ckpt);
	free(bb);
	free(pfs);
}

int main(int argc, char *argv[])
{
	init_path();

	segment = new bi::managed_shared_memory(bi::create_only, "ckptfs", 1 << 30);
	message_queue *mq = segment->construct<message_queue>("q")();

	while (true) {
		message msg(mq->dispatch());
		if (msg.syscall != SYS_open)
			throw std::logic_error("main() failed (invalid operation type)");

		void *shm_fq = segment->get_address_from_handle(msg.handles.fq_handle);
		message_queue *fq = static_cast<message_queue *>(shm_fq);
		fq->issue(msg);

		void *shm_synced = segment->get_address_from_handle(msg.handles.synced_handle);
		(static_cast<bi::interprocess_semaphore *>(shm_synced))->post();

		std::thread worker(drain, fq);
		worker.detach();
	}

	throw std::logic_error("main() failed (control should not reach here)");
}
