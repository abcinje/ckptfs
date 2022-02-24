#include "rwlock.hpp"

rwlock::rwlock(void) : readcount(0)
{
	sem_init(&mutex, 1, 1);
	sem_init(&resource, 1, 1);
}

rwlock::~rwlock(void)
{
	sem_destroy(&mutex);
	sem_destroy(&resource);
}

void rwlock::read_lock(void)
{
	sem_wait(&mutex);
	readcount++;
	if (readcount == 1)
		sem_wait(&resource);
	sem_post(&mutex);
}

void rwlock::read_unlock(void)
{
	sem_wait(&mutex);
	readcount--;
	if (readcount == 0)
		sem_post(&resource);
	sem_post(&mutex);
}

void rwlock::write_lock(void)
{
	sem_wait(&resource);
}

void rwlock::write_unlock(void)
{
	sem_post(&resource);
}
