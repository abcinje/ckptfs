#ifndef CKPTFS_QUEUE_HPP
#define CKPTFS_QUEUE_HPP

#include <boost/interprocess/sync/interprocess_semaphore.hpp>

namespace bi = boost::interprocess;

template <typename T, size_t capacity = 16>
class queue {
private:
	T buffer[capacity];
	int front, rear;
	bi::interprocess_semaphore mutex, slots, items;

public:
	queue(void) : front(0), rear(0), mutex(1), slots(capacity), items(0)
	{
	}

	void issue(T value) // N producers
	{
		slots.wait();
		mutex.wait();

		rear = (rear + 1) % capacity;
		buffer[rear] = value;

		mutex.post();
		items.post();
	}

	T dispatch(void) // 1 consumer
	{
		T value;

		items.wait();

		front = (front + 1) % capacity;
		value = buffer[front];

		slots.post();

		return value;
	}
};

#endif //CKPTFS_QUEUE_HPP
