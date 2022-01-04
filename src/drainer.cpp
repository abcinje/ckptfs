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

#include "message.hpp"
#include "queue.hpp"

using message_queue = queue<message>;

#define SHM_NAME "ckptfs"
#define SHM_SIZE sizeof(message_queue)

static bool stopped;
static message_queue *mq;

static void sigint_handler(int signum)
{
	std::cout << "Terminating." << std::endl;
	stopped = true;
}

static void do_drain(void)
{
}

int main(void)
{
	int shm_fd;

	if (signal(SIGINT, sigint_handler) == SIG_ERR)
		throw std::runtime_error("signal() failed (" + std::string(strerror(errno)) + ")");

	if ((shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0664)) == -1)
		throw std::runtime_error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	if (ftruncate(shm_fd, SHM_SIZE) == -1)
		throw std::runtime_error("ftruncate() failed (" + std::string(strerror(errno)) + ")");

	if ((mq = static_cast<message_queue *>(mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0))) == MAP_FAILED)
		throw std::runtime_error("mmap() failed (" + std::string(strerror(errno)) + ")");

	if (close(shm_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	while (!stopped)
		do_drain();

	if (shm_unlink(SHM_NAME) == -1)
		throw std::runtime_error("shm_unlink() failed (" + std::string(strerror(errno)) + ")");

	if (munmap(static_cast<void *>(mq), SHM_SIZE) == -1)
		throw std::runtime_error("munmap() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}
