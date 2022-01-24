#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;

#include <libsyscall_intercept_hook_point.h>

#include "ckpt_syscall.hpp"
#include "config.hpp"
#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

std::string *ckpt_dir, *bb_dir, *pfs_dir;
bi::managed_shared_memory *segment;
config *shm_cfg;
message_queue *mq;

static void init_path(void)
{
	char *ckpt, *bb, *pfs;

	if (!(ckpt = getenv("CKPT")) || !(bb = getenv("BB")) || !(pfs = getenv("PFS")))
		error("Environment variables named 'CKPT', 'BB', and 'PFS' must be specified.");

	if (!(ckpt = realpath(ckpt, NULL)) || !(bb = realpath(bb, NULL)) || !(pfs = realpath(pfs, NULL)))
		error("realpath() failed (" + std::string(strerror(errno)) + ")");

	ckpt_dir = new std::string(ckpt);
	bb_dir = new std::string(bb);
	pfs_dir = new std::string(pfs);

	free(ckpt);
	free(bb);
	free(pfs);
}

static void exit_path(void)
{
	delete ckpt_dir;
	delete bb_dir;
	delete pfs_dir;
}

static __attribute__((constructor)) void init(void)
{
	init_path();

	segment = new bi::managed_shared_memory(bi::open_only, "ckptfs");
	shm_cfg = segment->find<config>("cfg").first;
	mq = segment->find<message_queue>("q").first;

	intercept_hook_point = hook;
}

static __attribute__((destructor)) void exit(void)
{
	delete segment;

	exit_path();
}
