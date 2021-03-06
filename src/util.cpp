#include <climits>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include "util.hpp"

std::string resolve_abspath(std::string path)
{
	std::string resolved_path;
	resolved_path.reserve(PATH_MAX);

	std::vector<std::string> resolved;
	std::stringstream ss(path);
	std::string tmp;

	if (path.at(0) != '/')
		throw std::invalid_argument("resolve_absolute() failed (the path is not absolute)");

	while (getline(ss, tmp, '/')) {
		if (tmp == ".") {
			continue;
		} else if (tmp == "..") {
			if (!resolved.empty())
				resolved.pop_back();
		} else if (!tmp.empty()) {
			resolved.push_back(std::move(tmp));
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
