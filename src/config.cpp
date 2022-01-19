#include <cstdlib>

#include <unistd.h>

#include "config.hpp"

config::config(void) : fsync_enabled(false)
{
}

void init_config(int argc, char *argv[], config *cfg)
{
	int c;

	while ((c = getopt(argc, argv, "s")) != -1) {
		switch (c) {
			case 's':
				cfg->fsync_enabled = true;
				break;
			case '?':
				exit(EXIT_FAILURE);
		}
	}
}
