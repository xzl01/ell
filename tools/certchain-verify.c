/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include <ell/ell.h>

static void usage(const char *bin)
{
	printf("%s - Certificate chain verification utility\n\n", bin);

	printf("Usage: %s [options] <ca_cert file> <certchain container>\n"
		"  <ca_cert file> - local CA Certificates to validate against\n"
		"  <certchain container> - certificate chain to verify\n"
		"  --help\n\n", bin);
}

int main(int argc, char *argv[])
{
	int status = EXIT_FAILURE;
	struct l_certchain *certchain;
	struct l_queue *ca_certs;
	const char *error_str;

	if (argc != 3) {
		usage(argv[0]);
		return -1;
	}

	l_log_set_stderr();

	if (!l_cert_load_container_file(argv[2], NULL, &certchain, NULL, NULL))
		goto done;

	if (!certchain) {
		status = EXIT_SUCCESS;
		fprintf(stdout, "Certchain is empty, nothing to do\n");
		goto done;
	}

	ca_certs = l_pem_load_certificate_list(argv[1]);
	if (!ca_certs) {
		fprintf(stderr, "Unable to load CA certifiates\n");
		goto free_certchain;
	}

	if (!l_certchain_verify(certchain, ca_certs, &error_str)) {
		fprintf(stderr, "Verification failed: %s\n", error_str);
		goto free_cacert;
	}

	fprintf(stdout, "Verification succeeded\n");
	status = EXIT_SUCCESS;

free_cacert:
	l_queue_destroy(ca_certs, (l_queue_destroy_func_t) l_cert_free);
free_certchain:
	l_certchain_free(certchain);
done:
	return status;
}
