// ring_buffer.c
#include "ring_buffer.h"
#include "linux/printk.h"

void ring_buffer_init(struct ring_buffer *rb, int size)
{
	if (size <= 0) {
		pr_err("Invalid ring buffer size: %d\n", size);
		return;
	}
	if (!rb->buffer) {
		pr_err("Failed to allocate ring buffer memory\n");
		return;
	}
	rb->size = size;
	pr_info("Ring buffer initialized with size: %d\n", rb->size);
	atomic_long_set(&rb->head, 0);
	atomic_long_set(&rb->tail, 0);
	spin_lock_init(&rb->consume_lock);
}

/*
* Produce in ring buffer
 * @return:
    return pos normally , negative if error
 */
	unsigned long
	ring_buffer_produce(struct ring_buffer *rb)
{
	unsigned long head, tail;

	head = atomic_long_fetch_inc(&rb->head);
	tail = atomic_long_read(&rb->tail);

	// Treat ring buffer full as fatal error
	if (head - tail >= rb->size) {
		pr_warn_ratelimited("Ring buffer full, dropping read access\n");
		return ENOSPC_ON_RB;
	}

	return head % (rb->size);
}