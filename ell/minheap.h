/*
 * Embedded Linux library
 * Copyright (C) 2023  Cruise LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_MINHEAP_H
#define __ELL_MINHEAP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GCC seems to only inline the less and swap operations when the ops struct
 * is declared static const and passed in to the individual operations
 * directly.  Using a const member inside l_minheap doesn't have the same
 * effect.
 */
struct l_minheap_ops {
	size_t elem_size;
	bool (*less)(const void *lhs, const void *rhs);
	void (*swap)(void *lhs, void *rhs);
};

struct l_minheap {
	void *data;
	uint32_t used;
	uint32_t capacity;
};

static inline __attribute__((always_inline))
void __minheap_sift_down(void *data, uint32_t used, uint32_t pos,
					const struct l_minheap_ops *ops)
{
	uint32_t left;
	uint32_t right;
	uint32_t smallest;

	while ((left = pos * 2 + 1) < used) {
		smallest = ops->less(data + left * ops->elem_size,
				data + pos * ops->elem_size) ? left : pos;

		if ((right = pos * 2 + 2) < used) {
			if (ops->less(data + right * ops->elem_size,
					data + smallest * ops->elem_size))
				smallest = right;
		}

		if (smallest == pos)
			break;

		ops->swap(data + pos * ops->elem_size,
				data + smallest * ops->elem_size);
		pos = smallest;
	}
}

static inline __attribute__((always_inline))
void __minheap_sift_up(void *data, uint32_t pos,
					const struct l_minheap_ops *ops)
{
	uint32_t parent;

	while (pos) {
		parent = (pos - 1) / 2;

		if (ops->less(data + parent * ops->elem_size,
					data + pos * ops->elem_size))
			break;

		ops->swap(data + parent * ops->elem_size,
				data + pos * ops->elem_size);
		pos = parent;
	}
}

static inline __attribute__((always_inline))
void __minheap_sift_updown(void *data, uint32_t used, uint32_t pos,
					const struct l_minheap_ops *ops)
{
	uint32_t parent = (pos - 1) / 2;

	if (ops->less(data + pos * ops->elem_size,
				data + parent * ops->elem_size)) {
		ops->swap(data + parent * ops->elem_size,
				data + pos * ops->elem_size);
		__minheap_sift_up(data, parent, ops);
		return;
	}

	__minheap_sift_down(data, used, pos, ops);
}

static inline __attribute__((always_inline))
void l_minheap_init(struct l_minheap *minheap, void *data,
				uint32_t used, uint32_t capacity,
				const struct l_minheap_ops *ops)
{
	int i;

	for (i = used >> 1; i >= 0; i--)
		__minheap_sift_down(data, used, i, ops);

	minheap->data = data;
	minheap->used = used;
	minheap->capacity = capacity;
}

static inline __attribute__((always_inline))
bool l_minheap_pop(struct l_minheap *minheap,
			const struct l_minheap_ops *ops, void *out)
{
	if (!minheap)
		return false;

	if (!minheap->used)
		return false;

	if (out)
		memcpy(out, minheap->data, ops->elem_size);

	minheap->used -= 1;
	memcpy(minheap->data,
		minheap->data + minheap->used * ops->elem_size,
		ops->elem_size);
	__minheap_sift_down(minheap->data, minheap->used, 0, ops);

	return true;
}

static inline __attribute__((always_inline))
bool l_minheap_pop_push(struct l_minheap *minheap,
			const struct l_minheap_ops *ops, void *inout)
{
	if (!minheap)
		return false;

	if (!minheap->used)
		return false;

	ops->swap(inout, minheap->data);
	__minheap_sift_down(minheap->data, minheap->used, 0, ops);
	return true;
}

static inline __attribute__((always_inline))
bool l_minheap_push(struct l_minheap *minheap,
			const struct l_minheap_ops *ops, const void *in)
{
	if (!minheap)
		return false;

	if (minheap->used >= minheap->capacity)
		return false;

	memcpy(minheap->data + minheap->used * ops->elem_size,
			in, ops->elem_size);
	__minheap_sift_up(minheap->data, minheap->used, ops);
	minheap->used += 1;

	return true;
}

static inline __attribute__((always_inline))
bool l_minheap_delete(struct l_minheap *minheap, uint32_t pos,
			const struct l_minheap_ops *ops)
{
	if (!minheap)
		return false;

	if (!minheap->used || pos >= minheap->used)
		return false;

	minheap->used -= 1;
	if (minheap->used == pos)
		return true;

	memcpy(minheap->data + pos * ops->elem_size,
			minheap->data + minheap->used * ops->elem_size,
			ops->elem_size);
	__minheap_sift_down(minheap->data, minheap->used, pos, ops);

	return true;
}

#ifdef __cplusplus
}
#endif

#endif /* __ELL_MINHEAP_H */
