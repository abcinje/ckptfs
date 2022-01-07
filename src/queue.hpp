#ifndef CKPTFS_QUEUE_HPP
#define CKPTFS_QUEUE_HPP

#include <mutex>
#include <semaphore>

template <typename T, size_t capacity = 1024>
class queue {
private:
	T buffer[capacity];
	int front, rear;
	std::mutex mutex;
	std::counting_semaphore<capacity> slots, items;

public:
	queue(void) : front(0), rear(0), slots(capacity), items(0)
	{
	}

	void issue(T value)
	{
		slots.acquire();
		{
			std::scoped_lock lock(mutex);
			rear = (rear + 1) % capacity;
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
			front = (front + 1) % capacity;
			value = buffer[front];
		}
		slots.release();
		return value;
	}
};

#endif //CKPTFS_QUEUE_HPP
