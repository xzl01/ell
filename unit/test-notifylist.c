/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <ell/ell.h>

enum notify_state_flags {
	CALLED = 0x1,
	DESTROYED = 0x02,
};

static uint32_t notify1_flags;
static uint32_t notify2_flags;
static uint32_t notify3_flags;
static uint32_t notify1_id;
static uint32_t notify2_id;
static uint32_t notify3_id;
static struct l_notifylist *list;

struct simple_watch_entry {
	struct l_notifylist_entry super;
	void (*callback)(int, uint32_t *);
};

static void set_called(int arg1, uint32_t *flags)
{
	assert(arg1 == 42);
	*flags |= CALLED;
}

static void destroy(void *user)
{
	uint32_t *flags = user;
	*flags |= DESTROYED;
}

static void simple_notify(const struct l_notifylist_entry *e,
						int type, va_list args)
{
	const struct simple_watch_entry *swe =
		l_container_of(e, struct simple_watch_entry, super);
	uint32_t *flags = swe->super.notify_data;
	int arg1;

	assert(type == 0);
	arg1 = va_arg(args, int);

	if (swe->callback)
		swe->callback(arg1, flags);
}

static void simple_free_entry(struct l_notifylist_entry *e)
{
	struct simple_watch_entry *swe =
		l_container_of(e, struct simple_watch_entry, super);

	l_free(swe);
}

static struct l_notifylist_ops simple_ops = {
	.free_entry = simple_free_entry,
	.notify = simple_notify,
};

static bool id_matches(const struct l_notifylist_entry *e, const void *user)
{
	return e->id == L_PTR_TO_UINT(user);
}

static void make_notifylist(void (*cb)(int, uint32_t *))
{
	struct simple_watch_entry *swe;

	list = l_notifylist_new(&simple_ops);

	swe = l_new(struct simple_watch_entry, 1);
	swe->super.notify_data = &notify1_flags;
	swe->super.destroy = destroy;
	swe->callback = cb;
	notify1_id = l_notifylist_add(list, &swe->super);

	swe = l_new(struct simple_watch_entry, 1);
	swe->super.notify_data = &notify2_flags;
	swe->super.destroy = destroy;
	swe->callback = cb;
	notify2_id = l_notifylist_add(list, &swe->super);

	swe = l_new(struct simple_watch_entry, 1);
	swe->super.notify_data = &notify3_flags;
	swe->super.destroy = destroy;
	swe->callback = cb;
	notify3_id = l_notifylist_add(list, &swe->super);

	notify1_flags = 0;
	notify2_flags = 0;
	notify3_flags = 0;
}

static void test_notify(const void *test_data)
{
	make_notifylist(set_called);

	l_notifylist_notify(list, 0, 42);
	assert(notify1_flags == CALLED);
	assert(notify2_flags == CALLED);
	assert(notify3_flags == CALLED);

	l_notifylist_free(list);
	assert(notify1_flags & DESTROYED);
	assert(notify2_flags & DESTROYED);
	assert(notify3_flags & DESTROYED);
}

static void test_notify_matches(const void *test_data)
{
	make_notifylist(set_called);

	l_notifylist_notify_matches(list, id_matches, L_UINT_TO_PTR(notify2_id),
					0, 42);
	assert(!notify1_flags);
	assert(notify2_flags == CALLED);
	assert(!notify3_flags);

	l_notifylist_free(list);
	assert(notify1_flags & DESTROYED);
	assert(notify2_flags & DESTROYED);
	assert(notify3_flags & DESTROYED);
}

static void remove_second(int arg1, uint32_t *flags)
{
	*flags |= CALLED;

	if (flags == &notify2_flags)
		l_notifylist_remove(list, notify2_id);
}

static void test_notify_and_remove(const void *test_data)
{
	make_notifylist(remove_second);

	l_notifylist_notify(list, 0, 42);
	assert(notify1_flags == CALLED);
	assert(notify2_flags == (CALLED | DESTROYED));
	assert(notify3_flags == CALLED);

	l_notifylist_free(list);
}

static void remove_third(int arg1, uint32_t *flags)
{
	*flags |= CALLED;

	if (flags == &notify2_flags)
		l_notifylist_remove(list, notify3_id);
}

static void test_notify_and_remove_other(const void *test_data)
{
	make_notifylist(remove_third);

	l_notifylist_notify(list, 0, 42);
	assert(notify1_flags == CALLED);
	assert(notify2_flags == CALLED);
	assert(notify3_flags == DESTROYED);

	l_notifylist_free(list);
}

static void free_list(int arg1, uint32_t *flags)
{
	*flags |= CALLED;
	l_notifylist_free(list);
}

static void test_notify_and_free(const void *test_data)
{
	make_notifylist(free_list);
	l_notifylist_notify(list, 0, 42);

	assert(notify1_flags == (CALLED | DESTROYED));
	assert(notify2_flags == DESTROYED);
	assert(notify3_flags == DESTROYED);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("notifylist/notify", test_notify, NULL);
	l_test_add("notifylist/notify_matches", test_notify_matches, NULL);
	l_test_add("notifylist/notify_and_remove", test_notify_and_remove, NULL);
	l_test_add("notifylist/notify_and_remove_other",
			test_notify_and_remove_other, NULL);
	l_test_add("notifylist/notify_and_free", test_notify_and_free, NULL);

	return l_test_run();
}
