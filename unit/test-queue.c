/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>

#include <ell/ell.h>

static void test_push_pop(const void *data)
{
	struct l_queue *queue;
	unsigned int n, i;

	queue = l_queue_new();
	assert(queue);

	for (n = 0; n < 1024; n++) {
		for (i = 1; i < n + 2; i++) {
			l_queue_push_tail(queue, L_UINT_TO_PTR(i));
		}

		if (l_queue_length(queue) != n + 1) {
			printf("[%u] length mismatch: %u\n", n,
						l_queue_length(queue));
		}

		for (i = 1; i < n + 2; i++) {
			void *ptr = l_queue_pop_head(queue);

			if (!ptr) {
				printf("[%u] entry empty: %u\n", n, i);
				continue;
			}

			if (i != L_PTR_TO_UINT(ptr)) {
				printf("[%u] entry misatch: %u != %u\n",
						n, i, L_PTR_TO_UINT(ptr));
			}
		}

		if (!l_queue_isempty(queue)) {
			printf("[%u] not empty: %u\n", n,
						l_queue_length(queue));
		}
	}

	l_queue_destroy(queue, NULL);
}

static int queue_compare(const void *a, const void *b, void *user)
{
	int ai = L_PTR_TO_INT(a);
	int bi = L_PTR_TO_INT(b);

	return ai - bi;
}

static void test_insert(const void *data)
{
	int unsorted[] = { 0, 50, 10, 20, 30, 5, 30 };
	int sorted[] = { 0, 5, 10, 20, 30, 30, 50 };
	struct l_queue *queue;
	const struct l_queue_entry *entry;
	unsigned int i;
	int n;

	queue = l_queue_new();
	assert(queue);

	for (i = 0; i < L_ARRAY_SIZE(unsorted); i++)
		l_queue_insert(queue, L_INT_TO_PTR(unsorted[i]),
						queue_compare, NULL);

	for (i = 0, entry = l_queue_get_entries(queue); entry;
					entry = entry->next, i++) {
		n = L_PTR_TO_INT(entry->data);
		assert(n == sorted[i]);
	}

	l_queue_destroy(queue, NULL);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("queue push & pop", test_push_pop, NULL);
	l_test_add("queue insert", test_insert, NULL);

	return l_test_run();
}
