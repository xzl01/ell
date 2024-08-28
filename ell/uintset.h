/*
 * Embedded Linux library
 * Copyright (C) 2015-2019  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_UINTSET_H
#define __ELL_UINTSET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ell/cleanup.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*l_uintset_foreach_func_t) (uint32_t number, void *user_data);

struct l_uintset;

struct l_uintset *l_uintset_new_from_range(uint32_t min, uint32_t max);
struct l_uintset *l_uintset_new(unsigned int size);
void l_uintset_free(struct l_uintset *set);
DEFINE_CLEANUP_FUNC(l_uintset_free);

bool l_uintset_contains(struct l_uintset *set, uint32_t number);
bool l_uintset_take(struct l_uintset *set, uint32_t number);
bool l_uintset_put(struct l_uintset *set, uint32_t number);

uint32_t l_uintset_get_min(struct l_uintset *set);
uint32_t l_uintset_get_max(struct l_uintset *set);

uint32_t l_uintset_find_max(struct l_uintset *set);
uint32_t l_uintset_find_min(struct l_uintset *set);

uint32_t l_uintset_find_unused_min(struct l_uintset *set);
uint32_t l_uintset_find_unused(struct l_uintset *set, uint32_t start);

void l_uintset_foreach(const struct l_uintset *set,
			l_uintset_foreach_func_t function, void *user_data);

struct l_uintset *l_uintset_clone(const struct l_uintset *original);
struct l_uintset *l_uintset_intersect(const struct l_uintset *set_a,
						const struct l_uintset *set_b);
struct l_uintset *l_uintset_subtract(const struct l_uintset *set_a,
						const struct l_uintset *set_b);

bool l_uintset_isempty(const struct l_uintset *set);
uint32_t l_uintset_size(const struct l_uintset *set);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_UINTSET_H */
