#ifndef CKPTFS_RWLOCK_HPP
#define CKPTFS_RWLOCK_HPP

#include <semaphore.h>

/* This is a solution of the "first" readers-writers problem. */
/* Readers have a higher priority than writers. */
class rwlock {
private:
	sem_t mutex, resource;
	unsigned long readcount;

public:
	rwlock(void);
	~rwlock(void);

	void read_lock(void);
	void read_unlock(void);
	void write_lock(void);
	void write_unlock(void);
};

#endif //CKPTFS_RWLOCK_HPP
