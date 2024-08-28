/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

static void example_1(const void *data)
{
}

static void example_2(const void *data)
{
}

static void example_3(const void *data)
{
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("example-1", example_1, NULL);
	l_test_add("example-2", example_2, NULL);
	l_test_add("example-3", example_3, NULL);

	return l_test_run();
}
