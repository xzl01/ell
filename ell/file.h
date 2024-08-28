/*
 * Embedded Linux library
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_FILE_H
#define __ELL_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

void *l_file_get_contents(const char *filename, size_t *out_len);
int l_file_set_contents(const char *filename, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_FILE_H */
