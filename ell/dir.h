/*
 * Embedded Linux library
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_DIR_H
#define __ELL_DIR_H

#ifdef __cplusplus
extern "C" {
#endif

struct l_dir_watch;

enum l_dir_watch_event {
        L_DIR_WATCH_EVENT_CREATED,
	L_DIR_WATCH_EVENT_REMOVED,
	L_DIR_WATCH_EVENT_MODIFIED,
	L_DIR_WATCH_EVENT_ACCESSED,
	L_DIR_WATCH_EVENT_ATTRIB,
};

typedef void (*l_dir_watch_event_func_t) (const char *filename,
						enum l_dir_watch_event event,
						void *user_data);
typedef void (*l_dir_watch_destroy_func_t) (void *user_data);

struct l_dir_watch *l_dir_watch_new(const char *pathname,
					l_dir_watch_event_func_t function,
					void *user_data,
					l_dir_watch_destroy_func_t destroy);
void l_dir_watch_destroy(struct l_dir_watch *watch);

int l_dir_create(const char *abspath);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_DIR_H */
