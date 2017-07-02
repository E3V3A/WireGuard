/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "device.h"
#include "peer.h"

enum {
	CTX_ANY,
	CTX_NEW,
	CTX_INITIALIZING,
	CTX_INITIALIZED,
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
 * crypt_dequeue_ctx - Dequeue a ctx from a device-shared encryption/decryption
 * queue.
 *
 * This function is safe to execute concurrently with any number of
 * crypt_enqueue_ctx() calls, but *not* with another crypt_dequeue_ctx() call
 * operating on the same queue.
 */
static inline struct crypt_ctx *crypt_dequeue_ctx(struct crypt_queue *queue)
{
	struct crypt_ctx *ctx;
	struct list_head *first, *second;

	first = READ_ONCE(queue->list.next);
	if (first == &queue->list)
		return NULL;
	do {
		second = READ_ONCE(first->next);
		WRITE_ONCE(queue->list.next, second);
	} while (cmpxchg(&second->prev, first, &queue->list) != first);
	ctx = list_entry(first, struct crypt_ctx, shared_list);
	INIT_LIST_HEAD(&ctx->shared_list);

	return ctx;
}

/**
 * crypt_enqueue_ctx - Enqueue a ctx for encryption/decryption.
 *
 * This function is safe to execute concurrently with any number of other
 * crypt_enqueue_ctx() calls, as well as with one crypt_dequeue_ctx() call
 * operating on the same queue.
 */
static inline void crypt_enqueue_ctx(struct crypt_queue *queue,
				     struct crypt_ctx *ctx)
{
	struct list_head *last;

	ctx->shared_list.next = &queue->list;
	do {
		last = READ_ONCE(queue->list.prev);
		ctx->shared_list.prev = last;
	} while (cmpxchg(&queue->list.prev, last, &ctx->shared_list) != last);
	WRITE_ONCE(last->next, &ctx->shared_list);
}

/**
 * peer_claim_ctx - Claim a ctx for a specific processing step.
 *
 * @return the address of a succesfully-claimed context, or NULL if no context
 * with a matching state was found.
 *
 * This function should be called first with pos set to NULL to search from the
 * beginning of the queue.
 */
static inline struct crypt_ctx *peer_claim_ctx(struct peer_queue *queue,
					       struct crypt_ctx *pos,
					       int state,
					       int new_state)
{
	struct crypt_ctx *ctx;

	/* The starting point is either the previously-returned ctx or the head
	 * of the list. The list_entry() is undone by l_f_e_entry_continue(). */
	ctx = pos ? pos : list_entry(&queue->list, struct crypt_ctx, peer_list);
	/* The lifetimes of list entries before the first claimed one are
	 * unknown, so if pos is NULL, we have to lock the list to prevent them
	 * from being dequeued or freed during traversal. */
	if (!pos)
		spin_lock(&queue->lock);
	list_for_each_entry_continue(ctx, &queue->list, peer_list)
		if (atomic_cmpxchg(&ctx->state, state, new_state) == state)
			goto found;
	ctx = NULL;
found:
	if (!pos)
		spin_unlock(&queue->lock);

	return ctx;
}

/**
 * peer_dequeue_ctx - Dequeue a ctx for final transmission or consumption.
 *
 * @return the address of the dequeued context, or NULL if the first context in
 * the queue does not have the required state (or the queue is empty).
 *
 * The locking in this function is to synchronize with peer_claim_ctx(), not
 * peer_enqueue_ctx(), so the cmpxchg loop is still necessary. This function is
 * safe to execute concurrently with any number of peer_enqueue_ctx() calls,
 * but *not* with another peer_dequeue_ctx() call operating on the same queue.
 */
static inline struct crypt_ctx *peer_dequeue_ctx(struct peer_queue *queue,
						 int state)
{
	struct crypt_ctx *ctx;
	struct list_head *first, *second;

	ctx = list_first_entry_or_null(&queue->list, struct crypt_ctx, peer_list);
	if (!ctx || (state != CTX_ANY && atomic_read(&ctx->state) != state))
		return NULL;
	first = &ctx->peer_list;
	spin_lock(&queue->lock);
	do {
		second = READ_ONCE(first->next);
		WRITE_ONCE(queue->list.next, second);
	} while (cmpxchg(&second->prev, first, &queue->list) != first);
	spin_unlock(&queue->lock);

	return ctx;
}

/**
 * peer_enqueue_ctx - Enqueue a ctx for processing (transmission/consumption).
 *
 * This function is safe to execute concurrently with any number of other
 * peer_enqueue_ctx() calls, as well as with one peer_dequeue_ctx() call
 * operating on the same queue.
 */
static inline void peer_enqueue_ctx(struct peer_queue *queue,
				    struct crypt_ctx *ctx)
{
	struct list_head *last;

	ctx->peer_list.next = &queue->list;
	do {
		last = READ_ONCE(queue->list.prev);
		ctx->peer_list.prev = last;
	} while (cmpxchg(&queue->list.prev, last, &ctx->peer_list) != last);
	WRITE_ONCE(last->next, &ctx->peer_list);
}

static inline bool peer_has_uninitialized_packets(struct wireguard_peer *peer)
{
	struct crypt_ctx *ctx;

	spin_lock(&peer->send_queue.lock);
	list_for_each_entry(ctx, &peer->send_queue.list, peer_list) {
		if (atomic_read(&ctx->state) == CTX_NEW) {
			spin_unlock(&peer->send_queue.lock);
			return true;
		}
	}
	spin_unlock(&peer->send_queue.lock);

	return false;
}

#endif /* WGQUEUE_H */
