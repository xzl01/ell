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

#include <ell/ell.h>

struct base64_decode_test {
	const char *input;
	size_t input_size;
	const uint8_t *output;
	size_t output_size;
};

static const uint8_t decode_output_1[] = {
	'p', 'l', 'e', 'a', 's', 'u', 'r', 'e', '.'
};

static const struct base64_decode_test decode_1 = {
	.input = "cGxlYXN1cmUu",
	.output = decode_output_1,
	.output_size = 9,
};

static const struct base64_decode_test decode_2 = {
	.input = "bGVhc3VyZS4=",
	.output = decode_output_1 + 1,
	.output_size = 8,
};

static const struct base64_decode_test decode_3 = {
	.input = "ZWFzdXJlLg==",
	.output = decode_output_1 + 2,
	.output_size = 7,
};

static const uint8_t decode_output_2[] = {
	'S', 'o', '?', '<', 'p', '>',
};

static const struct base64_decode_test decode_4 = {
	.input = "U28/PHA+",
	.output = decode_output_2,
	.output_size = 6,
};

static void test_base64_decode(const void *data)
{
	const struct base64_decode_test *test = data;
	uint8_t *decoded;
	size_t decoded_size;

	decoded = l_base64_decode(test->input, strlen(test->input),
								&decoded_size);
	assert(decoded);
	assert(decoded_size == test->output_size);
	assert(!memcmp(decoded, test->output, decoded_size));

	l_free(decoded);
}

/* Length != string length */
static const struct base64_decode_test error_1 = {
	.input = "cGxlYXN1cmUu",
	.input_size = 11
};

/* Length doesn't include pad */
static const struct base64_decode_test error_2 = {
	.input = "bGVhc3VyZS4=",
	.input_size = 11,
};

/* Length doesn't include pad */
static const struct base64_decode_test error_3 = {
	.input = "ZWFzdXJlLg==",
	.input_size = 10
};

/* Length correct, but data after padding */
static const struct base64_decode_test error_4 = {
	.input = "ZWFzdXJlLg==bG",
	.input_size = 14
};

/* Only pad */
static const struct base64_decode_test error_5 = {
	.input = "==",
	.input_size = 2
};

static void test_base64_error(const void *data)
{
	const struct base64_decode_test *test = data;
	uint8_t *decoded;
	size_t decoded_size;

	decoded = l_base64_decode(test->input, test->input_size, &decoded_size);
	assert(!decoded);
}

struct base64_encode_test {
	const char *input;
	const char *output;
	int columns;
};

static const struct base64_encode_test encode_1 = {
	.input = "So?<p>",
	.columns = 4,
	.output = "U28/\nPHA+",
};

static const struct base64_encode_test encode_2 = {
	.input = "pleasure.",
	.columns = 0,
	.output = "cGxlYXN1cmUu",
};

static const struct base64_encode_test encode_3 = {
	.input = "leasure.",
	.columns = 0,
	.output = "bGVhc3VyZS4=",
};

static const struct base64_encode_test encode_4 = {
	.input = "easure.",
	.columns = 0,
	.output = "ZWFzdXJlLg==",
};

static void test_base64_encode(const void *data)
{
	const struct base64_encode_test *test = data;
	char *encoded;

	encoded = l_base64_encode((uint8_t *)test->input, strlen(test->input),
					test->columns);
	assert(encoded);
	assert(strlen(encoded) == strlen(test->output));
	assert(!memcmp(encoded, test->output, strlen(encoded)));

	l_free(encoded);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("base64/decode/test1", test_base64_decode, &decode_1);
	l_test_add("base64/decode/test2", test_base64_decode, &decode_2);
	l_test_add("base64/decode/test3", test_base64_decode, &decode_3);
	l_test_add("base64/decode/test4", test_base64_decode, &decode_4);
	l_test_add("base64/decode/test5", test_base64_error, &error_1);
	l_test_add("base64/decode/test6", test_base64_error, &error_2);
	l_test_add("base64/decode/test7", test_base64_error, &error_3);
	l_test_add("base64/decode/test8", test_base64_error, &error_4);
	l_test_add("base64/decode/test9", test_base64_error, &error_5);

	l_test_add("base64/encode/test1", test_base64_encode, &encode_1);
	l_test_add("base64/encode/test2", test_base64_encode, &encode_2);
	l_test_add("base64/encode/test3", test_base64_encode, &encode_3);
	l_test_add("base64/encode/test4", test_base64_encode, &encode_4);

	return l_test_run();
}
