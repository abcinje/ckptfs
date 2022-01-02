#include <cerrno>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util.hpp"

#define SHM_NAME "ckptfs"
#define SHM_SIZE 4096

void *shm;

static void init_shm(void)
{
	int shm_fd;

	shm_fd = shm_open(SHM_NAME, O_RDWR, 0664);
	if (shm_fd == -1)
		error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	shm = mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (shm == MAP_FAILED)
		error("mmap() failed (" + std::string(strerror(errno)) + ")");

	if (close(shm_fd) == -1)
		error("close() failed (" + std::string(strerror(errno)) + ")");
}

static void exit_shm(void)
{
	if (munmap(shm, SHM_SIZE) == -1)
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
