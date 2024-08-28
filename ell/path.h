/*
 * Embedded Linux library
 * Copyright (C) 2019  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_PATH_H
#define __ELL_PATH_H

#ifdef __cplusplus
extern "C" {
#endif

const char *l_path_next(const char *path_str, char **ret);
char *l_path_find(const char *basename, const char *path_str, int mode);
uint64_t l_path_get_mtime(const char *path);
int l_path_touch(const char *path);

const char *l_basename(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_PATH_H */
