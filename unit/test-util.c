/*
 * Embedded Linux library
 * Copyright (C) 2011-2015  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include <ell/ell.h>

static void test_hexstring(const void *test_data)
{
	unsigned char test[] = { 0x74, 0x65, 0x73, 0x74, 0x00 };
	char *hex;

	hex = l_util_hexstring(test, 5);
	assert(hex);
	assert(!strcmp(hex, "7465737400"));
	l_free(hex);
}

static void test_hexstringv(const void *test_data)
{
	unsigned char test1[] = { 0x74, 0x65, 0x73, 0x74, 0x00 };
	unsigned char test2[] = { 0x74, 0x65, 0x73 };
	struct iovec iov[2];
	char *hex;

	iov[0].iov_base = test1;
	iov[0].iov_len = 5;
	iov[1].iov_base = test2;
	iov[1].iov_len = 3;

	hex = l_util_hexstringv(iov, 2);
	assert(hex);
	assert(!strcmp(hex, "7465737400746573"));
	l_free(hex);
}

static void test_hexstring_upper(const void *test_data)
{
	unsigned char test[] = { 0x0a, 0x0b, 0x0c, 0xde, 0xf2 };
	char *hex;

	hex = l_util_hexstring_upper(test, sizeof(test));
	assert(hex);
	assert(!strcmp(hex, "0A0B0CDEF2"));
	l_free(hex);
}

static void test_from_hexstring(const void *test_data)
{
	const char *test = "7465737400";
	unsigned char expected[] = { 0x74, 0x65, 0x73, 0x74, 0x00 };
	const char *invalid1 = "74757";
	const char *invalid2 = "746573740";

	unsigned char *bytes;
	size_t len;

	bytes = l_util_from_hexstring(test, &len);
	assert(bytes);
	assert(len == 5);
	assert(!memcmp(bytes, expected, len));
	l_free(bytes);

	bytes = l_util_from_hexstring(invalid1, &len);
	assert(!bytes);

	bytes = l_util_from_hexstring(invalid2, &len);
	assert(!bytes);
}

static void test_has_suffix(const void *test_data)
{
	const char *str = "string";
	const char *suffix = "ing";

	assert(l_str_has_suffix(str, suffix));
	assert(l_str_has_suffix(str, str));
	assert(!l_str_has_suffix(NULL, suffix));
	assert(!l_str_has_suffix(str, NULL));
	assert(!l_str_has_suffix(suffix, str));
}

static void do_strlcpy(size_t dst_bytes, size_t src_bytes)
{
	/* A valid address is needed for the destination buffer
	 * even if l_strlcpy is told to not copy anything there
	 */
	char *dst = l_malloc(dst_bytes ?: 1);
	char *src = l_malloc(src_bytes);
	size_t src_strlen = src_bytes - 1;

	memset(dst, ' ', dst_bytes ?: 1);
	memset(src, '@', src_strlen);
	src[src_strlen] = '\0';

	assert(l_strlcpy(dst, src, dst_bytes) == src_strlen);

	if (!dst_bytes) {
		assert(*dst == ' ');
	} else if (src_strlen >= dst_bytes) {
		/* Copy was truncated */
		assert(strlen(dst) == dst_bytes - 1);
		assert(l_str_has_prefix(src, dst));
	} else
		assert(!strcmp(src, dst));

	l_free(dst);
	l_free(src);
}

static void test_strlcpy(const void *test_data)
{
	do_strlcpy(0, 1);
	do_strlcpy(0, 10);
	do_strlcpy(10, 8);
	do_strlcpy(10, 9);
	do_strlcpy(10, 10);
	do_strlcpy(10, 11);
	do_strlcpy(10, 12);
}

static void test_in_set(const void *test_data)
{
	char *a1 = "a";
	const char *a2 = a1;

	assert(L_IN_SET(1, 1, 2, 3));
	assert(L_IN_SET(2U, 1, 2, 3));
	assert(L_IN_SET(3LL, 1, 2, 3));
	assert(!L_IN_SET(4, 1, 2, 3));
	assert(!L_IN_SET(4));

	assert(L_IN_STRSET(a1, a2, "b"));
	assert(L_IN_STRSET(a2, a1, "b"));
	assert(L_IN_STRSET("b", "a", "b"));
	assert(!L_IN_STRSET("c", "a", "b"));
	assert(L_IN_STRSET(NULL, "a", NULL));
	assert(!L_IN_STRSET(NULL, "a", "b"));
	assert(!L_IN_STRSET("a", NULL, NULL));
	assert(!L_IN_STRSET("a"));
}

static void test_safe_atoux(const void *test_data)
{
	uint32_t r;
	uint16_t h;
	uint8_t c;
	char s[64];

	assert(!l_safe_atou32("234233", &r) && r == 234233);
	assert(!l_safe_atou32("0", &r) && r == 0);

	assert(!l_safe_atox32("a34", &r) && r == 0xa34);
	assert(!l_safe_atox32("0xa34", &r) && r == 0xa34);
	assert(l_safe_atou32("a34", NULL) == -EINVAL);

	sprintf(s, "%u", UINT_MAX);
	assert(!l_safe_atou32(s, &r) && r == UINT_MAX);

	sprintf(s, "%x", UINT_MAX);
	assert(!l_safe_atox32(s, &r) && r == UINT_MAX);

	assert(l_safe_atou32("", NULL) == -EINVAL);
	assert(l_safe_atox32("", NULL) == -EINVAL);

	sprintf(s, "%llu", ULLONG_MAX);
	assert(l_safe_atou32(s, NULL) == -ERANGE);

	sprintf(s, "%llx", ULLONG_MAX);
	assert(l_safe_atox32(s, NULL) == -ERANGE);

	assert(l_safe_atou32("    3", NULL) == -EINVAL);
	assert(l_safe_atou32("+3434", NULL) == -EINVAL);
	assert(l_safe_atou32("-3434", NULL) == -EINVAL);
	assert(l_safe_atou32("00000", &r) == -EINVAL);
	assert(!l_safe_atox32("0002", &r) && r == 0x2);
	assert(!l_safe_atox32("0x02", &r) && r == 0x2);

	assert(l_safe_atox32("+0x3434", NULL) == -EINVAL);
	assert(l_safe_atox32("-0x3434", NULL) == -EINVAL);

	assert(!l_safe_atox16("0xffff", &h) && h == 0xffff);
	assert(!l_safe_atox8("0xff", &c) && c == 0xff);
	assert(l_safe_atox8("0xffff", &c) == -ERANGE);
}

static void test_set_bit(const void *test_data)
{
	uint32_t bitmap[2] = { };
	int one = 0;

	L_BIT_SET(&bitmap[0], 0);
	L_BIT_SET(bitmap, 1);
	L_BIT_SET(bitmap, 2);
	L_BIT_SET(bitmap, 3);

	assert(bitmap[0] == 0x0f);
	assert(bitmap[1] == 0);

	L_BIT_SET(bitmap, 63);
	L_BIT_SET(bitmap, 62);
	L_BIT_SET(bitmap, 61);
	L_BIT_SET(bitmap, 60);

	assert(bitmap[0] == 0x0fU);
	assert(bitmap[1] == 0xf0000000U);

	L_BIT_SET(&one, 0);
	assert(one == 1);
}

static void test_clear_bit(const void *test_data)
{
	uint32_t bitmap[2] = { 0xfU, 0xf0000000U };

	L_BIT_CLEAR(&bitmap[0], 3);
	L_BIT_CLEAR(bitmap, 63);

	assert(bitmap[0] == 0x07U);
	assert(bitmap[1] == 0x70000000U);
}

static void test_is_bit_set(const void *test_data)
{
	uint32_t bitmap[2] = { 0xfU, 0xf0000000U };
	uint8_t one = 1;

	assert(L_BIT_TEST(&bitmap[0], 0) == true);
	assert(L_BIT_TEST(bitmap, 1) == true);
	assert(L_BIT_TEST(bitmap, 2) == true);
	assert(L_BIT_TEST(bitmap, 3) == true);
	assert(L_BIT_TEST(bitmap, 4) == false);

	assert(L_BIT_TEST(bitmap, 63) == true);
	assert(L_BIT_TEST(bitmap, 55) == false);

	assert(L_BIT_TEST(&one, 0) == true);
	assert(L_BIT_TEST(&one, 1) == false);
}

static void test_set_bits(const void *test_data)
{
	uint16_t bitmap[4] = {};

	L_BITS_SET(bitmap, 0, 1, 16, 32, 48);

	assert(bitmap[0] == 0x3);
	assert(bitmap[1] == 0x1);
	assert(bitmap[2] == 0x1);
	assert(bitmap[3] == 0x1);
}

static void test_clear_bits(const void *test_data)
{
	uint16_t bitmap[4] = { 0x3, 0x1, 0x1, 0x1 };

	L_BITS_CLEAR(bitmap, 0, 1, 16, 32, 48);

	assert(l_memeqzero(bitmap, sizeof(bitmap)));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("l_util_hexstring", test_hexstring, NULL);
	l_test_add("l_util_hexstring_upper", test_hexstring_upper, NULL);
	l_test_add("l_util_hexstringv", test_hexstringv, NULL);
	l_test_add("l_util_from_hexstring", test_from_hexstring, NULL);

	l_test_add("l_util_has_suffix", test_has_suffix, NULL);

	l_test_add("l_strlcpy", test_strlcpy, NULL);

	l_test_add("L_IN_SET", test_in_set, NULL);

	l_test_add("l_safe_atoux", test_safe_atoux, NULL);

	l_test_add("L_BIT_SET", test_set_bit, NULL);
	l_test_add("L_BIT_CLEAR", test_clear_bit, NULL);
	l_test_add("L_BIT_TEST", test_is_bit_set, NULL);
	l_test_add("L_BITS_SET", test_set_bits, NULL);
	l_test_add("L_BITS_CLEAR", test_clear_bits, NULL);

	return l_test_run();
}
