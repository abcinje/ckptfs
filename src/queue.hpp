#ifndef CKPTFS_QUEUE_HPP
#define CKPTFS_QUEUE_HPP

#include <semaphore.h>

template <typename T, size_t capacity = 16>
class queue {
private:
	T buffer[capacity];
	int front, rear;
	sem_t mutex, slots, items;

public:
	queue(void) : front(0), rear(0)
	{
		sem_init(&mutex, 1, 1);
		sem_init(&slots, 1, capacity);
		sem_init(&items, 1, 0);
	}

	~queue(void)
	{
		sem_destroy(&mutex);
		sem_destroy(&slots);
		sem_destroy(&items);
	}

	void issue(T value) // N producers
	{
		sem_wait(&slots);
		sem_wait(&mutex);

		rear = (rear + 1) % capacity;
		buffer[rear] = value;

		sem_post(&mutex);
		sem_post(&items);
	}

	T dispatch(void) // 1 consumer
	{
		T value;

		sem_wait(&items);

		front = (front + 1) % capacity;
		value = buffer[front];

		sem_post(&slots);

		return value;
	}
};

#endif //CKPTFS_QUEUE_HPP
