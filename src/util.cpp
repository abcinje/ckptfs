#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "util.hpp"

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

std::string to_hex(uint64_t i)
{
	std::stringstream stream;
	stream << std::setfill('0') << std::setw(16) << std::hex << i;
	return stream.str();
}
