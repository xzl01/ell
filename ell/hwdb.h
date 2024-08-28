/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_HWDB_H
#define __ELL_HWDB_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_hwdb;

struct l_hwdb *l_hwdb_new(const char *pathname);
struct l_hwdb *l_hwdb_new_default(void);

struct l_hwdb *l_hwdb_ref(struct l_hwdb *hwdb);
void l_hwdb_unref(struct l_hwdb *hwdb);

struct l_hwdb_entry {
	const char *key;
	const char *value;
	struct l_hwdb_entry *next;
};

struct l_hwdb_entry *l_hwdb_lookup(struct l_hwdb *hwdb, const char *format, ...)
					__attribute__((format(printf, 2, 3)));
struct l_hwdb_entry *l_hwdb_lookup_valist(struct l_hwdb *hwdb,
					const char *format, va_list args)
					__attribute__((format(printf, 2, 0)));
void l_hwdb_lookup_free(struct l_hwdb_entry *entries);

typedef void (*l_hwdb_foreach_func_t)(const char *modalias,
					struct l_hwdb_entry *entries,
							void *user_data);

bool l_hwdb_foreach(struct l_hwdb *hwdb, l_hwdb_foreach_func_t func,
							void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_HWDB_H */
