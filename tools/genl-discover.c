/*
 * Embedded Linux library
 * Copyright (C) 2019  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void family_discovered(const struct l_genl_family_info *info,
							void *user_data)
{
	char **groups;
	char *groupstr;

	l_info("Family: %s(%u) Version: %u",
			l_genl_family_info_get_name(info),
			l_genl_family_info_get_id(info),
			l_genl_family_info_get_version(info));

	groups = l_genl_family_info_get_groups(info);
	groupstr = l_strjoinv(groups, ',');
	l_strfreev(groups);

	l_info("\tMulticast Groups: %s", groupstr);
	l_free(groupstr);
}

static void discovery_done(void *user_data)
{
	l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_genl *genl;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	genl = l_genl_new();

	if (getenv("GENL_DEBUG"))
		l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	if (!l_genl_discover_families(genl, family_discovered, NULL,
						discovery_done)) {
		l_info("Unable to start family discovery");
		goto done;
	}

	l_main_run();

done:
	l_genl_unref(genl);
	l_main_exit();

	return 0;
}
