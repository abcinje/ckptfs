#ifndef CKPTFS_UTIL_HPP
#define CKPTFS_UTIL_HPP

#include <string>

void print(std::string msg);
void error(std::string msg);

std::string resolve_abspath(std::string path);

#endif //CKPTFS_UTIL_HPP
