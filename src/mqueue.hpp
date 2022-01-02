#ifndef CKPTFS_MQUEUE_HPP
#define CKPTFS_MQUEUE_HPP

#include <mutex>
#include <semaphore>

template <typename T, size_t capacity = 256>
class mqueue {
private:
	T buffer[capacity];
	int front, rear;
	std::mutex mutex;
	std::counting_semaphore<capacity> slots, items;

public:
	mqueue(void) : front(0), rear(0), slots(capacity), items(0)
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

#endif //CKPTFS_MQUEUE_HPP
