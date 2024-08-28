/*
 * Embedded Linux library
 * Copyright (C) 2023  Cruise LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>

#include <ell/ell.h>
#include "ell/useful.h"

static inline void swap_int(void *l, void *r)
{
	int *li = l;
	int *ri = r;

	SWAP(*li, *ri);
}

static inline bool less(const void *l, const void *r)
{
	const int *li = l;
	const int *ri = r;

	return *li < *ri;
}

static const struct l_minheap_ops ops = {
	.less = less,
	.swap = swap_int,
	.elem_size = sizeof(int),
};

static const int test_values[] = {
	3, 1, 2, 4, INT_MAX, INT_MIN, -4, -2, -1, -3, 0, INT_MIN, INT_MAX
};

static void verify_pop(struct l_minheap *minheap)
{
	size_t size = minheap->used;
	int *values = minheap->data;
	int last;

	last = values[0];
	while (size) {
		assert(last <= values[0]);
		last = values[0];
		assert(l_minheap_pop(minheap, &ops, NULL));
		size -= 1;
	}
}

static void test_minheap_init(const void *data)
{
	struct l_minheap minheap;
	int *values = alloca(sizeof(test_values));

	memcpy(values, test_values, sizeof(test_values));

	l_minheap_init(&minheap, values, L_ARRAY_SIZE(test_values),
			L_ARRAY_SIZE(test_values), &ops);

	verify_pop(&minheap);
}

static void test_minheap_push(const void *data)
{
	struct l_minheap minheap;
	int *values = l_newa(int, L_ARRAY_SIZE(test_values));
	unsigned int i;

	l_minheap_init(&minheap, values, 0, L_ARRAY_SIZE(test_values), &ops);

	for (i = 0; i < L_ARRAY_SIZE(test_values); i++)
		assert(l_minheap_push(&minheap, &ops, &test_values[i]));

	verify_pop(&minheap);
}

static void test_minheap_push_random(const void *data)
{
	struct l_minheap minheap;
	unsigned int n_items = 1024 * 1024;
	int *values = l_malloc(sizeof(int) * n_items);
	unsigned int i;

	l_minheap_init(&minheap, values, 0, n_items, &ops);

	for (i = 0; i < n_items; i++) {
		unsigned int r = random();

		assert(l_minheap_push(&minheap, &ops, &r));
	}

	verify_pop(&minheap);
	l_free(values);
}

static void test_minheap_pop_push(const void *data)
{
	struct l_minheap minheap;
	int *values = alloca(sizeof(test_values));
	unsigned int i;
	int tmp;

	for (i = 0; i < L_ARRAY_SIZE(test_values); i++)
		values[i] = INT_MIN;

	l_minheap_init(&minheap, values, L_ARRAY_SIZE(test_values),
			L_ARRAY_SIZE(test_values), &ops);

	for (i = 0; i < L_ARRAY_SIZE(test_values); i++) {
		tmp = test_values[i];

		assert(l_minheap_pop_push(&minheap, &ops, &tmp));
		assert(tmp == INT_MIN);
	}

	verify_pop(&minheap);
}

static void test_minheap_delete(const void *data)
{
	struct l_minheap minheap;
	int *values = l_newa(int, L_ARRAY_SIZE(test_values));
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(test_values); i++) {
		l_minheap_init(&minheap, values, L_ARRAY_SIZE(test_values),
				L_ARRAY_SIZE(test_values), &ops);
		assert(l_minheap_delete(&minheap, i, &ops));
		verify_pop(&minheap);
	}
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("minheap/init", test_minheap_init, NULL);
	l_test_add("minheap/push", test_minheap_push, NULL);
	l_test_add("minheap/push_random", test_minheap_push_random, NULL);
	l_test_add("minheap/pop_push", test_minheap_pop_push, NULL);
	l_test_add("minheap/delete", test_minheap_delete, NULL);

	return l_test_run();
}
