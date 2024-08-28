/*
 * Embedded Linux library
 * Copyright (C) 2015  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <ell/ell.h>

static void test_random(const void *data)
{
	uint8_t buf1[128];
	uint8_t buf2[128];
	char *str;

	assert(l_getrandom(buf1, 128));
	str = l_util_hexstring(buf1, 128);
	printf("buf1: %s\n", str);
	l_free(str);

	assert(l_getrandom(buf2, 128));
	str = l_util_hexstring(buf2, 128);
	printf("buf2: %s\n", str);
	l_free(str);

	assert(memcmp(buf1, buf2, 128));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_getrandom_is_supported()) {
		printf("getrandom syscall missing, skipping...");
		goto done;
	}

	l_test_add("l_getrandom sanity check", test_random, NULL);

done:
	return l_test_run();
}
