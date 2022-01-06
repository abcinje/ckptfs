#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "drainer_syscall.hpp"
#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

#define SHM_NAME "ckptfs"
#define SHM_SIZE sizeof(message_queue)

std::string *ckpt_dir, *bb_dir, *pfs_dir;
int pipefd[2];

static sigset_t sigmask, prev_sigmask;
static message_queue *mq;

static void do_drain(void)
{
	while (true) {
		message msg(mq->dispatch());

		sigprocmask(SIG_BLOCK, &sigmask, &prev_sigmask);

		switch (msg.syscall) {
			case SYS_write:
				drainer::write(msg);
				break;
			case SYS_open:
				drainer::open(msg);
				break;
			case SYS_close:
				drainer::close(msg);
				break;
			case SYS_pwrite64:
				drainer::pwrite(msg);
				break;
			case SYS_fsync:
				drainer::fsync(msg);
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

		if (shm_unlink(SHM_NAME) == -1)
			throw std::runtime_error("shm_unlink() failed (" + std::string(strerror(errno)) + ")");

		if (munmap(static_cast<void *>(mq), SHM_SIZE) == -1)
			throw std::runtime_error("munmap() failed (" + std::string(strerror(errno)) + ")");

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
	int shm_fd;

	init_path();

	install_sigint_handler();

	if ((shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0664)) == -1)
		throw std::runtime_error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	if (ftruncate(shm_fd, SHM_SIZE) == -1)
		throw std::runtime_error("ftruncate() failed (" + std::string(strerror(errno)) + ")");

	if ((mq = static_cast<message_queue *>(mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0))) == MAP_FAILED)
		throw std::runtime_error("mmap() failed (" + std::string(strerror(errno)) + ")");

	new (mq) message_queue();

	if (close(shm_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);

	if (pipe(pipefd) == -1)
		throw std::runtime_error("pipe() failed (" + std::string(strerror(errno)) + ")");

	do_drain();
}
