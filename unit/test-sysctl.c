/*
 * Embedded Linux library
 * Copyright (C) 2023  Cruise LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

static void test_sysctl_get_set(const void *data)
{
	FILE *f;
	uint32_t n;
	uint32_t expected;
	int r;

	/* Grab the setting via sysctl */
	f = popen("sysctl -n net.core.somaxconn", "r");
	assert(f);

	assert(fscanf(f, "%u", &expected) == 1);
	pclose(f);

	/* Now check against what we get */
	assert(l_sysctl_get_u32(&n, "/proc/sys/%s/%s/%s",
					"net", "core", "somaxconn") == 0);
	assert(n == expected);

	/*
	 * Attempt to change the setting, if we get an -EPERM, then we're
	 * most likely not running as root, so succeed silently.  Any other
	 * error is treated as a unit test failure
	 */

	r = l_sysctl_set_u32(5000, "/proc/sys/net/core/%s", "somaxconn");
	if (r == -EACCES)
		return;

	assert(!r);
	assert(!l_sysctl_get_u32(&n, "/proc/sys/net/core/somaxconn"));
	assert(n == 5000);

	/* Set it back to original */
	assert(!l_sysctl_set_u32(expected, "/proc/sys/net/core/somaxconn"));
}

int main(int argc, char *argv[])
{
	int ret;
	l_test_init(&argc, &argv);

	/*
	* test is failing if /proc/sys/net/core/somaxconn does not exist
	* this can happen when either net is not compiled, or running in
	* a namespace where sysfs is not mounted
	*/
	ret = access("/proc/sys/net/core/somaxconn", F_OK);
	if (!ret)
		l_test_add("sysctl/get_set", test_sysctl_get_set, NULL);


	return l_test_run();
}
