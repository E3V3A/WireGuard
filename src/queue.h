/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "device.h"
#include "peer.h"

enum {
	CTX_NEW,
	CTX_ENCRYPTED,
	CTX_DECRYPTED,
	CTX_FREEING,
};

struct crypt_ctx {
	struct list_head peer_list;
	struct list_head shared_list;
	union {
		struct sk_buff_head queue;
		struct sk_buff *skb;
	};
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	atomic_t state;
};

/**
 * list_dequeue_atomic - Atomically remove the first item in a queue.
 *
 * @return The address of the dequeued item, or NULL if the queue is empty.
 *
 * This function is safe to execute concurrently with any number of
 * list_enqueue_atomic() calls, but *not* with another list_dequeue_atomic()
 * call operating on the same queue.
 */
static inline struct list_head *list_dequeue_atomic(struct list_head *queue)
{
	struct list_head *first, *second;

	first = READ_ONCE(queue->next);
	if (first == queue)
		return NULL;
	do {
		second = READ_ONCE(first->next);
		WRITE_ONCE(queue->next, second);
	} while (cmpxchg(&second->prev, first, queue) != first);

	return first;
}

#define list_dequeue_entry_atomic(ptr, type, member) ({ \
	struct list_head *__head = list_dequeue_atomic(ptr); \
	__head ? list_entry(__head, type, member) : NULL; \
})

/**
 * list_enqueue_atomic - Atomically append an item to the tail of a queue.
 *
 * This function is safe to execute concurrently with any number of other
 * list_enqueue_atomic() calls, as well as with one list_dequeue_atomic() call
 * operating on the same queue.
 */
static inline void list_enqueue_atomic(struct list_head *queue,
				       struct list_head *item)
{
	struct list_head *last;

	WRITE_ONCE(item->next, queue);
	do {
		last = READ_ONCE(queue->prev);
		WRITE_ONCE(item->prev, last);
	} while (cmpxchg(&queue->prev, last, item) != last);
	WRITE_ONCE(last->next, item);
}

#endif /* WGQUEUE_H */
