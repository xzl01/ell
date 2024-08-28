/*
 * Embedded Linux library
 * Copyright (C) 2012  Intel Corporation
 * Copyright (C) 2023  Cruise LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_SYSCTL_H
#define __ELL_SYSCTL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int l_sysctl_get_u32(uint32_t *out_v, const char *format, ...)
			__attribute__((format(printf, 2, 3)));
int l_sysctl_set_u32(uint32_t v, const char *format, ...)
			__attribute__((format(printf, 2, 3)));

int l_sysctl_get_char(char *out_c, const char *format, ...)
			__attribute__((format(printf, 2, 3)));
int l_sysctl_set_char(char c, const char *format, ...)
			__attribute__((format(printf, 2, 3)));

#ifdef __cplusplus
}
#endif

#endif /* __ELL_SYSCTL_H */
