/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>

#include <ell/ell.h>
#include "ell/ecc.h"
#include "ell/ecc-private.h"

#define HEX2BUF(s, buf) { \
	unsigned char *tmp = l_util_from_hexstring(s, NULL); \
	memcpy(buf, tmp, curve->ndigits * 8); \
	l_free(tmp); \
}

#define CURVE_P_32_STR "ffffffffffffffffffffffff00000000"\
			"000000000000000001000000ffffffff"

enum ecc_test_type {
	TEST_ADD = 0,
	TEST_SUB,
	TEST_MULT,
	TEST_INV,
	TEST_EXP,
	TEST_POINT_ADD,
	TEST_SCALAR_MULT,
	TEST_LEGENDRE,
};

struct ecc_test_data {
	enum ecc_test_type type;
	/* basic math arguments/result */
	char *a;
	char *b;
	char *qr;
	char *qnr;
	char *r;
	bool is_residue;
	char *mod;
	char *result;
	int lres;
	/* point operations */
	char *scalar;
	char *ax, *ay;
	char *bx, *by;
	char *rx, *ry;
};

/* (a + b) mod c */
struct ecc_test_data add_test = {
	.type = TEST_ADD,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "5e82004ae05a7bcaa7bcd545bf6e7f25"
			"1372fe6222dc029dbccc4b0d6d67f10a"
};

/* (a - b) mod c */
struct ecc_test_data sub_test = {
	.type = TEST_SUB,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "3741aa79a62eb4b6403e5570263b5834"
			"c80e0a6d038bc6e01a32ddfecfd6e847"
};

/* (a * b) mod c */
struct ecc_test_data mult_test = {
	.type = TEST_MULT,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "a31ff5c7d65d8bd806b0407f27d1f1bc"
			"2c072e28c19720f6a654a75efc2faab5"

};

/* (a^-1) mod c */
struct ecc_test_data inv_test = {
	.type = TEST_INV,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.mod = CURVE_P_32_STR,
	.result = "48faaac115571047ead565911fc334fd"
			"633c986755e87ab10fd79a4453a60bc5"

};

/* (a^-1) mod c */
struct ecc_test_data inv_test2 = {
	.type = TEST_INV,
	.a = "698e5c10b63a9c79a9720b3f7f4d2f5c9fbb31daf93ac0f8fa8ca5cde8234418",
	.mod = CURVE_P_32_STR,
	.result = "5fd113c3b6053c38e54e5917826c8520"
			"c5a0708a8a47345edbb7fc1d67d9b42b"

};

/* (a ^ b) mod c */
struct ecc_test_data exp_test = {
	.type = TEST_EXP,
	.a = "cae1d5624344984073fd955a72d4ebacedc084679333e4beebff94869e9f6ca8",
	.b = "93a02ae89d15e38a33bf3fea4c99937825b279fa8fa81dded1ccb687cec88461",
	.mod = CURVE_P_32_STR,
	.result = "e7488e3a4d56938bbddc2a615c768d48"
			"9e5634aced9ceee37249fae1caa36fec"

};

struct ecc_test_data legendre_test1 = {
	.type = TEST_LEGENDRE,
	.a = "b59c0c366aa89ba229f857190497261d5a0a7a0a774caa72aef041ff00092447",
	.mod = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data legendre_test2 = {
	.type = TEST_LEGENDRE,
	.a = "1214f9607d348c998b3fba332d884d65945561fd007ff56d8bf603148d74d2e4",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test3 = {
	.type = TEST_LEGENDRE,
	.a = "282d751c898bfc593b1d21b6812df48e3ec811f40349b30b7294575c47b871d8",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test4 = {
	.type = TEST_LEGENDRE,
	.a = "0694ccde1db3d02faa26856678bd9358ecc0d82791405eb3892a8b4f07f1e5d6",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data legendre_test5 = {
	.type = TEST_LEGENDRE,
	.a = "92247f96df65a6d04af0c57318e999fd493c42864d156f7e5bba75c964f3c6b0",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = 1
};

struct ecc_test_data legendre_test6 = {
	.type = TEST_LEGENDRE,
	.a = "084f7eb6ed8021d095787fd401b0f19b13937dc23f7c84dfe69bb9a204bb3768",
	.mod = "ffffffff000000010000000000000000"
			"00000000ffffffffffffffffffffffff",
	.lres = -1
};

struct ecc_test_data point_add_test = {
	.type = TEST_POINT_ADD,
	.ax = "d36b6768a3279fbe23a5bf5cc19b13354"
		"fa2c6d6fd9de467d62db007c39452df",
	.ay = "4d601e7be3efd7f357452de7584274c54"
		"c18ddb0ef2f0f4cf43375152a9780c4",
	.bx = "c833c5d3ab916ed37f16597ace5dcf41f"
		"080891c0c41b6ce561705bd736a29e0",
	.by = "9d266e5ba8ba3e8d9679238f44a376b05"
		"133df0510a7b8e6e7dd3a654d40a04a",
	.rx = "24c4ede340dbdd144ccaaea67e5b1fca"
		"87b3aa26dc11114fcd12186318533101",
	.ry = "1d96391fb2942bf286e9251c257b960e"
		"7d23d4caff4b6fc898aff87e1f6f5514"

};

struct ecc_test_data point_mult_test = {
	.type = TEST_SCALAR_MULT,
	.ax = "768bc2f17fbf4e49282fbd4068994562b"
		"fc7145306762c26a90be1e9c346ac67",
	.ay = "93a02ae89d15e38a33bf3fea4c9993782"
		"5b279fa8fa81dded1ccb687cec88461",
	.scalar = "7521d940aa073c1675114ed27b866561"
		"9c826cac8eaa341f70d61b43ad32058b",
	.rx = "d4c80de349966df5542c984e80885d36"
		"a965ceb74ffe6a0fdc8343184dedfe66",
	.ry = "6d3a1ac3d1d392413286a0e00e94b01e"
		"ae8423c7f53b9d39cc7fc9c3a5880f3b"

};

static void run_test_p256(const void *arg)
{
	const struct ecc_test_data *data = arg;
	uint64_t a[L_ECC_MAX_DIGITS], b[L_ECC_MAX_DIGITS], mod[L_ECC_MAX_DIGITS],
			scalar[L_ECC_MAX_DIGITS], result[L_ECC_MAX_DIGITS],
			check[L_ECC_MAX_DIGITS];
	struct l_ecc_point point1, point2, point_ret;
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(19);

	point_ret.curve = curve;

	memset(result, 0, sizeof(result));

	if (data->a) {
		HEX2BUF(data->a, a);
		_ecc_be2native(a, a, curve->ndigits);
	}

	if (data->b) {
		HEX2BUF(data->b, b);
		_ecc_be2native(b, b, curve->ndigits);
	}

	if (data->mod) {
		HEX2BUF(data->mod, mod);
		_ecc_be2native(mod, mod, curve->ndigits);
	}

	if (data->ax) {
		HEX2BUF(data->ax, point1.x);
		_ecc_be2native(point1.x, point1.x, curve->ndigits);
		point1.curve = curve;
	}

	if (data->ay) {
		HEX2BUF(data->ay, point1.y);
		_ecc_be2native(point1.y, point1.y, curve->ndigits);
	}

	if (data->bx) {
		HEX2BUF(data->bx, point2.x);
		_ecc_be2native(point2.x, point2.x, curve->ndigits);
		point2.curve = curve;
	}

	if (data->by) {
		HEX2BUF(data->by, point2.y);
		_ecc_be2native(point2.y, point2.y, curve->ndigits);
	}

	if (data->scalar) {
		HEX2BUF(data->scalar, scalar);
		_ecc_be2native(scalar, scalar, curve->ndigits);
	}

	switch (data->type) {
	case TEST_ADD:
		_vli_mod_add(result, a, b, mod, curve->ndigits);
		break;
	case TEST_SUB:
		_vli_mod_sub(result, a, b, mod, curve->ndigits);
		break;
	case TEST_MULT:
		_vli_mod_mult_fast(result, a, b, mod, curve->ndigits);
		break;
	case TEST_INV:
		_vli_mod_inv(result, a, mod, curve->ndigits);
		break;
	case TEST_EXP:
		_vli_mod_exp(result, a, b, mod, curve->ndigits);
		break;
	case TEST_LEGENDRE:
	{
		int lres = _vli_legendre(a, mod, curve->ndigits);
		assert(data->lres == lres);
		break;
	}
	case TEST_POINT_ADD:
		_ecc_point_add(&point_ret, &point1, &point2, curve->p);

		break;
	case TEST_SCALAR_MULT:
		_ecc_point_mult(&point_ret, &point1, scalar, NULL, curve->p);

		break;
	}

	if (data->type <= TEST_EXP) {
		HEX2BUF(data->result, check);
		_ecc_native2be(check, check, curve->ndigits);

		assert(memcmp(result, check, 32) == 0);
	} else if (data->type <= TEST_SCALAR_MULT) {
		uint64_t checkx[L_ECC_MAX_DIGITS];
		uint64_t checky[L_ECC_MAX_DIGITS];

		HEX2BUF(data->rx, checkx);
		_ecc_native2be(checkx, checkx, curve->ndigits);
		HEX2BUF(data->ry, checky);
		_ecc_native2be(checky, checky, curve->ndigits);

		assert(memcmp(checkx, point_ret.x, 32) == 0);
		assert(memcmp(checky, point_ret.y, 32) == 0);
	}
}

static void run_test_reduce(const void *arg)
{
	static const uint8_t p_reduced[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x43, 0x19, 0x05, 0x53, 0x58, 0xe8, 0x61, 0x7b,
		0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xb0,
	};

	const struct l_ecc_curve *p256 = l_ecc_curve_from_ike_group(19);
	struct l_ecc_scalar *tmp;
	struct l_ecc_scalar *reduced;
	char buf[32];

	tmp = l_ecc_curve_get_prime(p256);
	assert(tmp);
	assert(l_ecc_scalar_get_data(tmp, buf, sizeof(buf)) > 0);
	l_ecc_scalar_free(tmp);

	reduced = l_ecc_scalar_new_reduced_1_to_n(p256, buf, sizeof(buf));
	assert(reduced);
	assert(l_ecc_scalar_get_data(reduced, buf, sizeof(buf)) > 0);
	assert(!memcmp(buf, p_reduced, sizeof(p_reduced)));
	l_ecc_scalar_free(reduced);

	tmp = l_ecc_curve_get_order(p256);
	assert(tmp);
	assert(l_ecc_scalar_get_data(tmp, buf, sizeof(buf)) > 0);
	l_ecc_scalar_free(tmp);

	reduced = l_ecc_scalar_new_reduced_1_to_n(p256, buf, sizeof(buf));
	assert(reduced);
	assert(l_ecc_scalar_get_data(reduced, buf, sizeof(buf)) > 0);
	assert(l_memeqzero(buf, 31));
	assert(buf[31] == 0x02);
	l_ecc_scalar_free(reduced);
}

static void run_test_zero_or_one(const void *arg)
{
	uint64_t zero[L_ECC_MAX_DIGITS] = { };
	uint64_t _1[L_ECC_MAX_DIGITS] = { 1ull };
	uint64_t _2[L_ECC_MAX_DIGITS] = { 2ull };

	assert(_vli_is_zero_or_one(zero, L_ECC_MAX_DIGITS));
	assert(_vli_is_zero_or_one(_1, L_ECC_MAX_DIGITS));
	assert(!_vli_is_zero_or_one(_2, L_ECC_MAX_DIGITS));
}

struct compressed_point_data {
	char *x;
	char *exp_y;
	enum l_ecc_point_type type;
};

static struct compressed_point_data compressed_tests[] = {
	{
		/* BIT0, computed Y is odd, subtraction performed */
		.x = "19b3fec1c000a888ee9c44272e4d7317e6e36577fc9d53e1edfb4e296b0b7ce1",
		.exp_y = "a8f9efd0ab526cd930870779621f4e9a53d4e78887ac9f4ed45ff75ded32b158",
		.type = L_ECC_POINT_TYPE_COMPRESSED_BIT0,
	},
	{
		/* BIT0, computed Y is even, no subtraction */
		.x = "958df5997362a9695ad73938c86be34a4730da877eccaaf8b189e73ff20e67c3",
		.exp_y = "1042f37262ded34d8424c1728a1ed23a726645b71db30a38f2932001a2027f46",
		.type = L_ECC_POINT_TYPE_COMPRESSED_BIT0,
	},
	{
		/* BIT1, computed Y is even, subtraction performed */
		.x = "069bd56634454ca76e7ba434244137509141cbbf532586c6b36e9b5be8a2cc34",
		.exp_y = "f4f34d46e4bdc1473fec4b4c8724f349375a8a602f5e83c260d6724e64ec7e99",
		.type = L_ECC_POINT_TYPE_COMPRESSED_BIT1,
	},
	{
		/* BIT1, computed Y is odd, no subtraction */
		.x = "8cade296a68e0c40bcf45a049f1993263bdc8524825e2be44b14ce114e475df0",
		.exp_y = "94ed7d09b2a0e95d8df993eaf81eb64d5ff734d01da57e53b2e0277199bc5897",
		.type = L_ECC_POINT_TYPE_COMPRESSED_BIT1,
	},
};

static void run_test_compressed_points(const void *arg)
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(compressed_tests); i++) {
		const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(19);
		struct compressed_point_data *data = &compressed_tests[i];
		uint64_t x[L_ECC_MAX_DIGITS];
		uint64_t y[L_ECC_MAX_DIGITS];
		uint64_t exp_y[L_ECC_MAX_DIGITS];
		size_t bytes = l_ecc_curve_get_scalar_bytes(curve);
		struct l_ecc_point *p;

		HEX2BUF(data->x, x);
		HEX2BUF(data->exp_y, exp_y);

		p = l_ecc_point_from_data(curve, data->type, x, bytes);
		assert(p);

		l_ecc_point_get_y(p, y, bytes);

		assert(!memcmp(exp_y, y, bytes));

		l_ecc_point_free(p);
	}
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("ECC add test", run_test_p256, &add_test);
	l_test_add("ECC sub test", run_test_p256, &sub_test);
	l_test_add("ECC mult test", run_test_p256, &mult_test);
	l_test_add("ECC inv test", run_test_p256, &inv_test);
	l_test_add("ECC inv test", run_test_p256, &inv_test2);
	l_test_add("ECC exp test", run_test_p256, &exp_test);
	l_test_add("ECC point add test", run_test_p256, &point_add_test);
	l_test_add("ECC point mult test", run_test_p256, &point_mult_test);
	l_test_add("ECC legendre", run_test_p256, &legendre_test1);
	l_test_add("ECC legendre", run_test_p256, &legendre_test2);
	l_test_add("ECC legendre", run_test_p256, &legendre_test3);
	l_test_add("ECC legendre", run_test_p256, &legendre_test4);
	l_test_add("ECC legendre", run_test_p256, &legendre_test5);
	l_test_add("ECC legendre", run_test_p256, &legendre_test6);

	l_test_add("ECC reduce test", run_test_reduce, NULL);
	l_test_add("ECC zero or one test", run_test_zero_or_one, NULL);
	l_test_add("ECC compressed points", run_test_compressed_points, NULL);

	return l_test_run();
}
