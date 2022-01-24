#include <random>

#include "random.hpp"

static std::random_device rd;
static std::mt19937_64 gen(rd());

uint64_t rand64(void)
{
	std::uniform_int_distribution<uint64_t> dist;
	return dist(gen);
}
