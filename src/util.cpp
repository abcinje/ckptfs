#include <cstdlib>

#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#include <unistd.h>

#include "util.hpp"

void print(std::string msg)
{
	msg += '\n';
	syscall_no_intercept(SYS_write, STDOUT_FILENO, msg.data(), msg.size());
}

void error(std::string msg)
{
	msg += '\n';
	syscall_no_intercept(SYS_write, STDERR_FILENO, msg.data(), msg.size());

	exit(EXIT_FAILURE);
}
