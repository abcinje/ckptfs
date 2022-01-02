#ifndef CKPTFS_MQUEUE_HPP
#define CKPTFS_MQUEUE_HPP

#include <mutex>
#include <semaphore>

#define QUEUE_CAPACITY 256

template <typename T>
class mqueue {
private:
	T buffer[QUEUE_CAPACITY];
	int front, rear;
	std::mutex mutex;
	std::counting_semaphore<QUEUE_CAPACITY> slots, items;

public:
	mqueue(void) : front(0), rear(0), slots(QUEUE_CAPACITY), items(0)
	{
	}

	void issue(T value)
	{
		slots.acquire();
		{
			std::scoped_lock lock(mutex);
			rear = (rear + 1) % QUEUE_CAPACITY;
			buffer[rear] = value;
		}
		items.release();
	}

	T dispatch(void)
	{
		T value;
		items.acquire();
		{
			std::scoped_lock lock(mutex);
			front = (front + 1) % QUEUE_CAPACITY;
			value = buffer[front];
		}
		slots.release();
		return value;
	}
};

#endif //CKPTFS_MQUEUE_HPP
