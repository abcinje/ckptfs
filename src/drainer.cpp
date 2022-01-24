#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <syscall.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;

#include "config.hpp"
#include "drainer_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

std::string *ckpt_dir, *bb_dir, *pfs_dir;
bi::managed_shared_memory *segment;
config *shm_cfg;
int pipefd[2];

static message_queue *mq;

static void do_drain(void)
{
	while (true) {
		message msg(mq->dispatch());

		switch (msg.syscall) {
			case SYS_open:
				drainer::open(msg);
				break;
			default:
				throw std::logic_error("do_drain() failed (invalid operation type)");
		}
	}
}

static void init_path(void)
{
	char *ckpt, *bb, *pfs;

	if (!(ckpt = getenv("CKPT")) || !(bb = getenv("BB")) || !(pfs = getenv("PFS")))
		throw std::runtime_error("Environment variables named 'CKPT', 'BB', and 'PFS' must be specified.");

	if (!(ckpt = realpath(ckpt, NULL)) || !(bb = realpath(bb, NULL)) || !(pfs = realpath(pfs, NULL)))
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
	config cfg;
	init_config(argc, argv, &cfg);

	init_path();

	segment = new bi::managed_shared_memory(bi::create_only, "ckptfs", 1 << 20);
	shm_cfg = segment->construct<config>("cfg")(cfg);
	mq = segment->construct<message_queue>("q")();

	if (pipe(pipefd) == -1)
		throw std::runtime_error("pipe() failed (" + std::string(strerror(errno)) + ")");

	do_drain();

	/* Should not reach here */
}
