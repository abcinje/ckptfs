#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <syscall.h>
#include <unistd.h>

#include <libsyscall_intercept_hook_point.h>

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

std::string resolve_abspath(std::string path)
{
	std::string resolved_path;

	std::vector<std::string> components, resolved;
	std::stringstream ss(path);
	std::string tmp;

	if (path.at(0) != '/')
		throw std::invalid_argument("resolve_absolute() failed (the path is not absolute)");

	while (getline(ss, tmp, '/'))
		if (!tmp.empty())
			components.push_back(tmp);

	for (auto it = components.cbegin(); it != components.cend(); it++) {
		if (*it == ".") {
			continue;
		} else if (*it == "..") {
			if (resolved.size() > 0)
				resolved.pop_back();
		} else {
			resolved.push_back(*it);
		}
	}

	for (auto it = resolved.cbegin(); it != resolved.cend(); it++)
		resolved_path += '/' + *it;

	return resolved_path;
}
