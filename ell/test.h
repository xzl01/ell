/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_TEST_H
#define __ELL_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*l_test_func_t) (const void *test_data);

void l_test_init(int *argc, char ***argv);
int l_test_run(void);

void l_test_add(const char *name, l_test_func_t function,
					const void *test_data);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TEST_H */
