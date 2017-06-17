/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/kernel.h>

#include "device.h"

/**
 * The helper functions in this file rely on these states being in increasing
 * order of the way packets are processed, and they must alternate between in-
 * progress and completed states. The exception is CTX_FREEING, because it does
 * not use these helpers.
 */
enum {
	CTX_NEW = 0,
	CTX_INITIALIZING,
	CTX_INITIALIZED,
	CTX_ENCRYPTING,
	CTX_ENCRYPTED,
	CTX_FREEING,
};

struct crypt_ctx {
	struct list_head list;
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct sk_buff_head queue;
	struct rcu_head rcu;
	atomic_t state;
};

/**
 * Use this helper to ensure safe traversal of the queue looking for a context
 * to process. It returns the address of a succesfully-claimed context, or
 * NULL if no context with the appropriate peer and state was found. The
 * first time around, pos should be set to NULL. Set peer to NULL to get
 * packets of the appropriate state for any peer.
 */
static inline struct crypt_ctx *claim_next_ctx(struct list_head *queue,
					       struct crypt_ctx *pos,
					       struct wireguard_peer *peer,
					       int state)
{
	struct crypt_ctx *ctx;

	/* Due to the lack of list_for_each_entry_from_rcu(), play dirty tricks
	 * with container_of() to get the list head as a "crypt_ctx". */
	ctx = pos ? pos : container_of(queue, struct crypt_ctx, list);
	rcu_read_lock_bh();
	list_for_each_entry_continue_rcu(ctx, queue, list) {
		/* Ignore contexts for other peers if given a specific peer. */
		if (peer && ctx->peer != peer)
			continue;
		/* Marking the context "in progress" guarantees its lifetime. */
		if (atomic_cmpxchg(&ctx->state, state, state + 1) == state) {
			rcu_read_unlock_bh();
			return ctx;
		}
	}
	rcu_read_unlock_bh();

	return NULL;
}

/**
 * Must be called with RCU read lock held.
 */
static inline void del_ctx(struct crypt_ctx *ctx)
{
	struct list_head *next, *prev;

	do {
		prev = ctx->list.prev;
		next = list_next_rcu(&ctx->list);
		rcu_assign_pointer(list_next_rcu(prev), next);
	} while (cmpxchg(&next->prev, &ctx->list, prev) != &ctx->list);
}

static inline struct crypt_ctx *dequeue_ctx(struct list_head *queue,
					    struct wireguard_peer *peer,
					    int state)
{
	struct crypt_ctx *ctx;

	/* We need to ensure the lifetimes here and in del_ctx(). */
	rcu_read_lock_bh();
	ctx = list_first_or_null_rcu(queue, struct crypt_ctx, list);
	while (ctx && ctx->peer != peer)
		ctx = list_next_or_null_rcu(queue, &ctx->list,
					    struct crypt_ctx, list);
	/* Don't traverse past ctx's for this peer with other states. This helps
	 * avoid out-of-order delivery. */
	if (!ctx || atomic_read(&ctx->state) != state) {
		rcu_read_unlock_bh();
		return NULL;
	}
	del_ctx(ctx);
	rcu_read_unlock_bh();

	return ctx;
}

/**
 * ctx->state must be set correctly before calling this helper.
 */
static inline void enqueue_ctx(struct list_head *queue, struct crypt_ctx *ctx)
{
	struct list_head *prev;

	/* The enqueued context will always be last, so this needs no lock. */
	list_next_rcu(&ctx->list) = queue;
	/* We need to ensure the lifetime of prev (for all iterations). */
	rcu_read_lock_bh();
	do {
		prev = queue->prev;
		ctx->list.prev = prev;
	} while (cmpxchg(&queue->prev, prev, &ctx->list) != prev);
	/* If this is racing with a dequeue_ctx on the adjacent ctx, the cmpxchg
	 * in dequeue_ctx will fail until the rcu_assign_pointer completes, so
	 * there's no worry about assigning to a dead object. */
	rcu_assign_pointer(list_next_rcu(prev), &ctx->list);
	rcu_read_unlock_bh();
}

/**
 * Use this helper to test if there are any contexts in the queue owned by this
 * peer. This implicitly means that work is pending for the peer.
 */
static inline bool peer_has_queued_ctx(struct list_head *queue,
				       struct wireguard_peer *peer)
{
	struct crypt_ctx *ctx;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(ctx, queue, list) {
		if (ctx->peer == peer) {
			rcu_read_unlock_bh();
			return true;
		}
	}
	rcu_read_unlock_bh();

	return false;
}

#endif /* WGQUEUE_H */
