/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ell/ell.h>
#include <ell/useful.h>

static struct l_io *io;
static struct l_tls *tls;
static const char *hostname;
static bool ready;
static struct l_settings *session_cache;
static char *session_cache_path;

static void https_io_disconnect(struct l_io *io, void *user_data)
{
	if (!ready)
		printf("socket disconnected\n");
	l_main_quit();
}

static bool https_io_read(struct l_io *io, void *user_data)
{
	uint8_t buf[2048];
	int l;

	l = read(l_io_get_fd(io), buf, sizeof(buf));
	if (l == 0) {
		if (!ready)
			printf("socket EOF\n");
		l_main_quit();
	} else if (l > 0)
		l_tls_handle_rx(tls, buf, l);

	return true;
}

static void https_tls_disconnected(enum l_tls_alert_desc reason, bool remote,
					void *user_data)
{
	if (reason)
		fprintf(stderr, "TLS error: %s\n", l_tls_alert_to_str(reason));
	l_main_quit();
}

static void https_new_data(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = write(1, data, len);
		if (r < 0) {
			printf("socket EOF\n");
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_write(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = send(l_io_get_fd(io), data, len, MSG_NOSIGNAL);
		if (r < 0) {
			printf("socket send: %s\n", strerror(errno));
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_ready(const char *peer_identity, void *user_data)
{
	uint8_t buf[2048];
	int l;

	ready = true;

	if (peer_identity)
		printf("Server authenticated as %s\n", peer_identity);
	else
		printf("Server not authenticated\n");

	l = snprintf((char *) buf, sizeof(buf),
			"HEAD / HTTP/1.1\r\n"
			"Connection: close\r\n"
			"Host: %s\r\n\r\n", hostname);
	l_tls_write(tls, buf, l);
}

static void https_tls_debug_cb(const char *str, void *user_data)
{
	printf("%s\n", str);
}

static void https_tls_session_cache_update_cb(void *user_data)
{
	size_t len;
	char *data = l_settings_to_data(session_cache, &len);
	_auto_(close) int fd = L_TFR(creat(session_cache_path, 0600));

	if (!data) {
		fprintf(stderr, "l_settings_to_data() failed\n");
		return;
	}

	if (fd < 0) {
		fprintf(stderr, "can't open %s: %s\n",
			session_cache_path, strerror(errno));
		return;
	}

	if (L_TFR(write(fd, data, len)) < (ssize_t) len)
		fprintf(stderr, "short write to %s\n", session_cache_path);
}

int main(int argc, char *argv[])
{
	struct hostent *he;
	struct in_addr **addr_list;
	struct sockaddr_in addr;
	int fd;
	bool auth_ok;
	struct l_certchain *cert = NULL;
	struct l_key *priv_key = NULL;
	struct l_queue *ca_cert = NULL;
	bool encrypted;

	if (argc != 2 && argc != 3 && argc != 6) {
		printf("Usage: %s <https-host-name> [<ca-cert-path> "
				"[<client-cert-path> <client-key-path> "
				"<client-key-passphrase>]]\n"
				"Note: The passphrase will be ignored if the "
				"key is not encrypted.\n",
				argv[0]);
		return -1;
	}

	l_log_set_stderr();

	hostname = argv[1];
	he = gethostbyname(hostname);
	if (!he) {
		fprintf(stderr, "gethostbyname: %s\n", strerror(errno));
		return -1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	if (!addr_list) {
		fprintf(stderr, "No host addresses found\n");
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	memcpy(&addr.sin_addr, addr_list[0], sizeof(addr.sin_addr));
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "connect: %s\n", strerror(errno));
		return -1;
	}

	if (!l_main_init())
		return -1;

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);
	l_io_set_read_handler(io, https_io_read, tls, NULL);
	l_io_set_disconnect_handler(io, https_io_disconnect, tls, NULL);

	tls = l_tls_new(false, https_new_data, https_tls_write,
			https_tls_ready, https_tls_disconnected, NULL);

	if (getenv("TLS_DEBUG")) {
		char *str;

		l_tls_set_debug(tls, https_tls_debug_cb, NULL, NULL);

		str = l_strdup_printf("/tmp/ell-certchain-%s.pem", hostname);
		l_tls_set_cert_dump_path(tls, str);
		l_free(str);
	}

	if (getenv("TLS_CACHE")) {
		const char *homedir = getenv("HOME");

		if (!homedir)
			homedir = "/tmp";

		session_cache_path =
			l_strdup_printf("%s/.ell-https-client-test", homedir);
		session_cache = l_settings_new();
		l_settings_load_from_file(session_cache, session_cache_path);

		l_tls_set_session_cache(tls, session_cache, hostname,
					24 * 3600 * L_USEC_PER_SEC, 0,
					https_tls_session_cache_update_cb,
					NULL);
	}

	if (argc >= 3) {
		ca_cert = l_pem_load_certificate_list(argv[2]);
		if (!ca_cert) {
			fprintf(stderr, "Couldn't load the CA certificates\n");
			return -1;
		}
	}

	if (argc >= 4) {
		cert = l_pem_load_certificate_chain(argv[3]);
		if (!cert) {
			fprintf(stderr,
				"Couldn't load the server certificate\n");
			return -1;
		}
	}

	if (argc >= 6) {
		priv_key = l_pem_load_private_key(argv[4], argv[5], &encrypted);
		if (!priv_key) {
			fprintf(stderr,
				"Couldn't load the client private key%s\n",
				encrypted ? " (encrypted)" : "");
			return -1;
		}
	}

	auth_ok = (argc <= 2 || l_tls_set_cacert(tls, ca_cert)) &&
		(argc <= 5 ||
		 l_tls_set_auth_data(tls, cert, priv_key)) &&
		l_tls_start(tls);

	if (tls && auth_ok)
		l_main_run();
	else {
		fprintf(stderr, "TLS setup failed\n");
		l_queue_destroy(ca_cert, (l_queue_destroy_func_t) l_cert_free);
		l_certchain_free(cert);
		l_key_free(priv_key);
	}

	l_io_destroy(io);
	l_tls_free(tls);

	if (session_cache) {
		l_settings_free(session_cache);
		l_free(session_cache_path);
	}

	l_main_exit();

	return 0;
}
