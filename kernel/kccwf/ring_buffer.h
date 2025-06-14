// ring_buffer.h
#ifndef _RING_BUFFER_H
#define _RING_BUFFER_H

#include <linux/spinlock.h>
#include <linux/atomic.h>

#define RING_BUFFER_SIZE 1024
#define ENOSPC_ON_RB (-1) // 缓冲区满错误码

typedef struct ring_buffer {
	void *buffer;
	int size;
	atomic_long_t head; // 生产位置
	atomic_long_t tail; // 消费位置
	spinlock_t consume_lock; // 仅保护加锁消费操作
    unsigned long consume_lock_flags;
} ring_buffer_t;
void ring_buffer_init(struct ring_buffer *rb, int size);

unsigned long ring_buffer_produce(struct ring_buffer *rb);

// locked consume
void *ring_buffer_consume_locked(struct ring_buffer *rb, unsigned long *pos);
void ring_buffer_commit_consume_locked(struct ring_buffer *rb,
				       unsigned long pos);

// unlocked consume
void *ring_buffer_consume_unlocked(struct ring_buffer *rb, unsigned long *pos);
void ring_buffer_commit_consume_unlocked(struct ring_buffer *rb,
					 unsigned long pos);

// specific operations
void ring_buffer_set_tail_unlocked(struct ring_buffer *rb, unsigned long *pos);
#endif