/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <ell/ell.h>

#ifndef WAIT_ANY
#define WAIT_ANY (-1) /* Any process */
#endif

#define TEST_BUS_ADDRESS_UNIX "unix:path=/tmp/ell-test-bus"
#define TEST_BUS_ADDRESS_TCP "tcp:host=127.0.0.1,port=14046"

static pid_t dbus_daemon_pid = -1;

static int tests_completed = 0;
static bool bus_became_ready = false;
static bool match_cb_called = false;
static bool req_name_cb_called = false;

static bool start_dbus_daemon(void)
{
	char *prg_argv[5];
	char *prg_envp[1];
	pid_t pid;

	prg_argv[0] = "dbus-daemon";
	prg_argv[1] = "--nopidfile";
	prg_argv[2] = "--nofork";
	prg_argv[3] = "--config-file=" UNITDIR "dbus.conf";
	prg_argv[4] = NULL;

	prg_envp[0] = NULL;

	l_info("launching dbus-daemon");

	pid = fork();
	if (pid < 0) {
		l_error("failed to fork new process");
		return false;
	}

	if (pid == 0) {
		execvpe(prg_argv[0], prg_argv, prg_envp);
		exit(EXIT_SUCCESS);
	}

	l_info("dbus-daemon process %d created", pid);

	dbus_daemon_pid = pid;

	return true;
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void sigchld_handler(void *user_data)
{
	while (1) {
		pid_t pid;
		int status;

		pid = waitpid(WAIT_ANY, &status, WNOHANG);
		if (pid < 0 || pid == 0)
			break;

		l_info("process %d terminated with status=%d\n", pid, status);

		if (pid == dbus_daemon_pid) {
			dbus_daemon_pid = -1;
			l_main_quit();
		}
	}
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

#define test_assert(cond)	\
	do {	\
		if (!(cond)) {	\
			l_info("TEST FAILED in %s at %s:%i: %s",	\
				__func__, __FILE__, __LINE__,	\
				L_STRINGIFY(cond));	\
			l_main_quit();	\
			return;	\
		}	\
	} while (0)

static void signal_message(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member, *destination, *sender;

	path = l_dbus_message_get_path(message);
	destination = l_dbus_message_get_destination(message);

	l_info("path=%s destination=%s", path, destination);

	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);

	l_info("interface=%s member=%s", interface, member);

	sender = l_dbus_message_get_sender(message);

	l_info("sender=%s", sender);

	if (!strcmp(member, "NameOwnerChanged")) {
		const char *name, *old_owner, *new_owner;

		if (!l_dbus_message_get_arguments(message, "sss",
					&name, &old_owner, &new_owner))
			return;

		l_info("name=%s old=%s new=%s", name, old_owner, new_owner);
	}
}

static void request_name_setup(struct l_dbus_message *message, void *user_data)
{
	const char *name = "org.test";

	l_dbus_message_set_arguments(message, "su", name, 0);
}

static void request_name_callback(struct l_dbus_message *message,
							void *user_data)
{
	const char *error, *text;
	uint32_t result;

	req_name_cb_called = true;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		test_assert(false);
	}

	test_assert(l_dbus_message_get_arguments(message, "u", &result));

	l_info("request name result=%d", result);

	l_main_quit();
}

static const char *match_rule = "type=signal,sender=org.freedesktop.DBus";

static void add_match_setup(struct l_dbus_message *message, void *user_data)
{
	l_dbus_message_set_arguments(message, "s", match_rule);
}

static void add_match_callback(struct l_dbus_message *message, void *user_data)
{
	const char *error, *text;

	match_cb_called = true;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		test_assert(false);
		return;
	}

	test_assert(l_dbus_message_get_arguments(message, ""));

	l_info("add match");
}

static void ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;
	int rc;

	l_info("ready");
	bus_became_ready = true;

	rc = l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "AddMatch",
				add_match_setup,
				add_match_callback, NULL, NULL);
	test_assert(rc > 0);

	rc = l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);
	test_assert(rc > 0);
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void test_dbus(const void *data)
{
	const char *address = data;
	struct l_dbus *dbus;
	int i;

	bus_became_ready = false;
	match_cb_called = false;
	req_name_cb_called = false;

	test_assert(l_main_init());

	l_log_set_stderr();

	for (i = 0; i < 10; i++) {
		usleep(200 * 1000);

		dbus = l_dbus_new(address);
		if (dbus)
			break;
	}

	test_assert(dbus);

	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_register(dbus, signal_message, NULL, NULL);

	l_main_run_with_signal(signal_handler, NULL);

	test_assert(bus_became_ready);
	test_assert(match_cb_called);
	test_assert(req_name_cb_called);

	l_dbus_destroy(dbus);
	l_main_exit();
	tests_completed++;
}

int main(int argc, char *argv[])
{
	struct l_signal *sigchld;

	l_test_init(&argc, &argv);

	l_test_add("Using a unix socket", test_dbus, TEST_BUS_ADDRESS_UNIX);
	l_test_add("Using a tcp socket", test_dbus, TEST_BUS_ADDRESS_TCP);

	sigchld = l_signal_create(SIGCHLD, sigchld_handler, NULL, NULL);

	if (!start_dbus_daemon())
		return -1;

	l_test_run();

	if (dbus_daemon_pid > 0)
		kill(dbus_daemon_pid, SIGKILL);

	l_signal_remove(sigchld);

	if (tests_completed == 2)
		return 0;

	return -1;
}
