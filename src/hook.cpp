#include <cerrno>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "message.hpp"
#include "queue.hpp"
#include "util.hpp"

using message_queue = queue<message>;

#define SHM_NAME "ckptfs"
#define SHM_SIZE sizeof(message_queue)

message_queue *mq;

static void init_shm(void)
{
	int shm_fd;

	shm_fd = shm_open(SHM_NAME, O_RDWR, 0664);
	if (shm_fd == -1)
		error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	mq = static_cast<message_queue *>(mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0));
	if (mq == MAP_FAILED)
		error("mmap() failed (" + std::string(strerror(errno)) + ")");

	if (close(shm_fd) == -1)
		error("close() failed (" + std::string(strerror(errno)) + ")");
}

static void exit_shm(void)
{
	if (munmap(static_cast<void *>(mq), SHM_SIZE) == -1)
		error("munmap() failed (" + std::string(strerror(errno)) + ")");
}

static __attribute__((constructor)) void init(void)
{
	init_shm();
}

static __attribute__((destructor)) void exit(void)
{
	exit_shm();
}
