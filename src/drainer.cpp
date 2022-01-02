#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define SHM_NAME "ckptfs"
#define SHM_SIZE 4096

int main(void)
{
	void *shm;
	int shm_fd;

	if ((shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0664)) == -1)
		throw std::runtime_error("shm_open() failed (" + std::string(strerror(errno)) + ")");

	if (ftruncate(shm_fd, SHM_SIZE) == -1)
		throw std::runtime_error("ftruncate() failed (" + std::string(strerror(errno)) + ")");

	if ((shm = mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0)) == MAP_FAILED)
		throw std::runtime_error("mmap() failed (" + std::string(strerror(errno)) + ")");

	/* TODO: drain */

	if (shm_unlink(SHM_NAME) == -1)
		throw std::runtime_error("shm_unlink() failed (" + std::string(strerror(errno)) + ")");

	if (munmap(shm, SHM_SIZE) == -1)
		throw std::runtime_error("munmap() failed (" + std::string(strerror(errno)) + ")");

	if (close(shm_fd) == -1)
		throw std::runtime_error("close() failed (" + std::string(strerror(errno)) + ")");

	return 0;
}
