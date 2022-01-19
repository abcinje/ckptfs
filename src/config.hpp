#ifndef CKPTFS_CONFIG_HPP
#define CKPTFS_CONFIG_HPP

struct config {
	bool fsync_enabled;

	config(void);
};

void init_config(int argc, char *argv[], config *cfg);

#endif //CKPTFS_CONFIG_HPP
