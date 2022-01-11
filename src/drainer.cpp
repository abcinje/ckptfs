#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <syscall.h>

#include <boost/interprocess/managed_shared_memory.hpp>

namespace bi = boost::interprocess;

#include "drainer_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

std::string *ckpt_dir, *bb_dir, *pfs_dir;
bi::managed_shared_memory *segment;
int pipefd[2];

static message_queue *mq;

static void do_drain(void)
{
	sigset_t sigmask, prev_sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);

	while (true) {
		message msg(mq->dispatch());

		sigprocmask(SIG_BLOCK, &sigmask, &prev_sigmask);

		switch (msg.syscall) {
			case SYS_read:
				drainer::read(msg);
				break;
			case SYS_write:
				drainer::write(msg);
				break;
			case SYS_open:
				drainer::open(msg);
				break;
			case SYS_close:
				drainer::close(msg);
				break;
			case SYS_pread64:
				drainer::pread(msg);
				break;
			case SYS_pwrite64:
				drainer::pwrite(msg);
				break;
			case SYS_readv:
				drainer::readv(msg);
				break;
			case SYS_writev:
				drainer::writev(msg);
				break;
			case SYS_fsync:
				drainer::fsync(msg);
				break;
			case SYS_fdatasync:
				drainer::fdatasync(msg);
				break;
			default:
				throw std::logic_error("do_drain() failed (invalid operation type)");
		}

		sigprocmask(SIG_SETMASK, &prev_sigmask, nullptr);
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

static void exit_path(void)
{
	delete ckpt_dir;
	delete bb_dir;
	delete pfs_dir;
}

static void install_sigint_handler(void)
{
	struct sigaction action;

	auto sigint_handler = [](int signum) {
		std::cout << "Terminating." << std::endl;

		segment->destroy<message_queue>("q");
		delete segment;
		bi::shared_memory_object::remove("ckptfs");

		exit_path();

		exit(EXIT_SUCCESS);
	};

	action.sa_handler = sigint_handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGINT, &action, nullptr) == -1)
		throw std::runtime_error("sigaction() failed (" + std::string(strerror(errno)) + ")");
}

int main(void)
{
	init_path();

	segment = new bi::managed_shared_memory(bi::create_only, "ckptfs", 1 << 20);
	mq = segment->construct<message_queue>("q")();

	install_sigint_handler();

	if (pipe(pipefd) == -1)
		throw std::runtime_error("pipe() failed (" + std::string(strerror(errno)) + ")");

	do_drain();
}
