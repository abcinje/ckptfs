#include <cstdlib>

#include <unistd.h>

#include "config.hpp"

config::config(void) : lazy_fsync_enabled(false)
{
}

void init_config(int argc, char *argv[], config *cfg)
{
	int c;

	while ((c = getopt(argc, argv, "l")) != -1) {
		switch (c) {
			case 'l':
				cfg->lazy_fsync_enabled = true;
				break;
			case '?':
				exit(EXIT_FAILURE);
		}
	}
}
