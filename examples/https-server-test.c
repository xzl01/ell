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
bool served;
static struct l_settings *session_cache;
static char *session_cache_path;

static void https_io_disconnect(struct l_io *io, void *user_data)
{
	if (!served)
		fprintf(stderr, "Disconnected before serving a page\n");
	l_main_quit();
}

static bool https_io_read(struct l_io *io, void *user_data)
{
	uint8_t buf[2048];
	int l;

	l = read(l_io_get_fd(io), buf, sizeof(buf));
	if (l == 0) {
		if (!served)
			fprintf(stderr, "EOF before serving a page\n");
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
	char *reply = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n"
		"\r\n"
		"Hello, world!\n";

	if (len >= 4 && !memcmp(data + len - 4, "\r\n\r\n", 4)) {
		l_tls_write(tls, (void *) reply, strlen(reply));
		served = true;
		printf("Hello world page served\n");
		l_tls_close(tls);
	}
}

static void https_tls_write(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = send(l_io_get_fd(io), data, len, MSG_NOSIGNAL);
		if (r < 0) {
			fprintf(stderr, "send: %s\n", strerror(errno));
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_ready(const char *peer_identity, void *user_data)
{
	if (peer_identity)
		printf("Client authenticated as %s\n", peer_identity);
	else
		printf("Client not authenticated\n");
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
	struct sockaddr_in addr = {};
	struct sockaddr_in client_addr = {};
	socklen_t client_addr_len = sizeof(client_addr);
	int fd, listenfd;
	bool auth_ok;
	struct l_certchain *cert;
	struct l_key *priv_key;
	struct l_queue *ca_cert = NULL;
	bool encrypted;

	if (argc != 4 && argc != 5) {
		printf("Usage: %s <server-cert-path> <server-key-path> "
				"<server-key-passphrase> [<ca-cert-path>]\n"
				"Note: The passphrase will be ignored if the "
				"key is not encrypted.\n",
				argv[0]);

		return -1;
	}

	l_log_set_stderr();

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 },
			sizeof(int));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(1234);

	if (bind(listenfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		return -1;
	}
	if (listen(listenfd, 1) == -1) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		return -1;
	}

	printf("Try https://localhost:1234/ now\n");

	fd = accept(listenfd, (struct sockaddr *) &client_addr,
			&client_addr_len);
	close(listenfd);
	if (fd == -1) {
		fprintf(stderr, "accept: %s\n", strerror(errno));
		return -1;
	}

	if (!l_main_init())
		return -1;

	cert = l_pem_load_certificate_chain(argv[1]);
	if (!cert) {
		fprintf(stderr, "Couldn't load the server certificate\n");
		return -1;
	}

	priv_key = l_pem_load_private_key(argv[2], argv[3], &encrypted);
	if (!priv_key) {
		fprintf(stderr, "Couldn't load the server private key%s\n",
			encrypted ? " (encrypted)" : "");
		return -1;
	}

	if (argc >= 5) {
		ca_cert = l_pem_load_certificate_list(argv[4]);
		if (!ca_cert) {
			fprintf(stderr, "Couldn't load the CA certificates\n");
			return -1;
		}
	}

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);
	l_io_set_read_handler(io, https_io_read, tls, NULL);
	l_io_set_disconnect_handler(io, https_io_disconnect, tls, NULL);

	tls = l_tls_new(true, https_new_data, https_tls_write,
			https_tls_ready, https_tls_disconnected, NULL);

	if (getenv("TLS_DEBUG")) {
		char buf[INET_ADDRSTRLEN];
		char *str;

		l_tls_set_debug(tls, https_tls_debug_cb, NULL, NULL);

		inet_ntop(AF_INET,&client_addr.sin_addr, buf, INET_ADDRSTRLEN);
		str = l_strdup_printf("/tmp/ell-certchain-%s.pem", buf);
		l_tls_set_cert_dump_path(tls, str);
		l_free(str);
	}

	if (getenv("TLS_CACHE")) {
		const char *homedir = getenv("HOME");

		if (!homedir)
			homedir = "/tmp";

		session_cache_path =
			l_strdup_printf("%s/.ell-https-server-test", homedir);
		session_cache = l_settings_new();
		l_settings_load_from_file(session_cache, session_cache_path);

		l_tls_set_session_cache(tls, session_cache, "tls-session",
					24 * 3600 * L_USEC_PER_SEC, 10,
					https_tls_session_cache_update_cb,
					NULL);
	}

	auth_ok = l_tls_set_auth_data(tls, cert, priv_key) &&
		(argc <= 4 || l_tls_set_cacert(tls, ca_cert)) &&
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

	l_main_exit();

	return 0;
}
