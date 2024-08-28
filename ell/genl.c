/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include "useful.h"
#include "log.h"
#include "queue.h"
#include "io.h"
#include "private.h"
#include "netlink-private.h"
#include "notifylist.h"
#include "genl.h"

#define MAX_NESTING_LEVEL 4
#define GENL_DEBUG(fmt, args...)	\
	l_util_debug(genl->debug_callback, genl->debug_data, "%s:%i " fmt, \
			__func__, __LINE__, ## args)

struct nest_info {
	uint16_t type;
	uint16_t offset;
};

struct unicast_watch {
	struct l_notifylist_entry super;
	char name[GENL_NAMSIZ];
	l_genl_msg_func_t handler;
};

struct family_watch {
	uint32_t id;
	char *name;
	l_genl_discover_func_t appeared_func;
	l_genl_vanished_func_t vanished_func;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct genl_discovery {
	l_genl_discover_func_t cb;
	l_genl_destroy_func_t destroy;
	void *user_data;
	uint32_t cmd_id;
};

struct l_genl {
	int ref_count;
	int fd;
	uint32_t pid;
	uint32_t next_seq;
	struct l_io *io;
	struct l_queue *request_queue;
	struct l_queue *pending_list;
	struct l_queue *notify_list;
	unsigned int next_request_id;
	unsigned int next_notify_id;
	struct genl_discovery *discovery;
	uint32_t next_watch_id;
	struct l_notifylist *unicast_watches;
	struct l_queue *family_watches;
	struct l_queue *family_infos;
	struct l_genl_family *nlctrl;
	uint32_t next_handle_id;
	l_genl_debug_func_t debug_callback;
	l_genl_destroy_func_t debug_destroy;
	void *debug_data;

	bool in_family_watch_notify : 1;
	bool in_unicast_watch_notify : 1;
	bool in_mcast_notify : 1;
	bool writer_active : 1;
};

struct l_genl_msg {
	int ref_count;
	int error;
	char *error_msg;
	uint8_t cmd;
	uint8_t version;
	void *data;
	uint32_t size;
	uint32_t len;
	struct nest_info nests[MAX_NESTING_LEVEL];
	uint8_t nesting_level;
};

struct genl_request {
	unsigned int id;
	uint32_t handle_id;
	uint16_t type;
	uint16_t flags;
	uint32_t seq;
	struct l_genl_msg *msg;
	l_genl_msg_func_t callback;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct mcast_notify {
	unsigned int id;
	uint32_t handle_id;
	uint16_t type;
	uint32_t group;
	l_genl_msg_func_t callback;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct genl_op {
	uint32_t id;
	uint32_t flags;
};

struct genl_mcast {
	char name[GENL_NAMSIZ];
	uint32_t id;
	unsigned int users;
};

struct l_genl_family_info {
	char name[GENL_NAMSIZ];
	uint16_t id;
	uint32_t version;
	uint32_t hdrsize;
	uint32_t maxattr;
	struct l_queue *op_list;
	struct l_queue *mcast_list;
};

struct l_genl_family {
	uint16_t id;
	uint32_t handle_id;
	struct l_genl *genl;
};

static inline uint32_t get_next_id(uint32_t *id)
{
	*id += 1;
	if (!*id)
		*id = 1;

	return *id;
}

static bool family_info_match(const void *a, const void *b)
{
	const struct l_genl_family_info *ia = a;
	uint16_t id = L_PTR_TO_UINT(b);

	return ia->id == id;
}

static struct l_genl_family_info *family_info_new(const char *name)
{
	struct l_genl_family_info *info = l_new(struct l_genl_family_info, 1);

	l_strlcpy(info->name, name, GENL_NAMSIZ);
	info->op_list = l_queue_new();
	info->mcast_list = l_queue_new();
	return info;
}

static void family_info_free(void *user_data)
{
	struct l_genl_family_info *info = user_data;

	l_queue_destroy(info->op_list, l_free);
	info->op_list = NULL;
	l_queue_destroy(info->mcast_list, l_free);
	info->mcast_list = NULL;
	l_free(info);
}

static void family_info_add_op(struct l_genl_family_info *info,
				uint32_t id, uint32_t flags)
{
	struct genl_op *op;

	op = l_new(struct genl_op, 1);

	op->id = id;
	op->flags = flags;

	l_queue_push_tail(info->op_list, op);
}

static bool match_mcast_name(const void *a, const void *b)
{
	const struct genl_mcast *mcast = a;
	const char *name = b;

	return !strncmp(mcast->name, name, GENL_NAMSIZ);
}

static bool match_mcast_id(const void *a, const void *b)
{
	const struct genl_mcast *mcast = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return mcast->id == id;
}

static void family_info_add_mcast(struct l_genl_family_info *info,
					const char *name, uint32_t id)
{
	struct genl_mcast *mcast;

	mcast = l_queue_find(info->mcast_list, match_mcast_name, name);
	if (mcast)
		return;

	mcast = l_new(struct genl_mcast, 1);
	l_strlcpy(mcast->name, name, GENL_NAMSIZ);
	mcast->id = id;
	mcast->users = 0;

	l_queue_push_tail(info->mcast_list, mcast);
}

static void family_ops(struct l_genl_family_info *info,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		struct l_genl_attr attr_op;
		uint32_t id = 0, flags = 0;

		if (!l_genl_attr_recurse(attr, &attr_op))
			continue;

		while (l_genl_attr_next(&attr_op, &type, &len, &data)) {
			switch (type) {
			case CTRL_ATTR_OP_ID:
				id = *((uint32_t *) data);
				break;
			case CTRL_ATTR_OP_FLAGS:
				flags = *((uint32_t *) data);
				break;
			}
		}

		if (id > 0)
			family_info_add_op(info, id, flags);
	}
}

static void family_mcast_groups(struct l_genl_family_info *info,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		struct l_genl_attr attr_grp;
		const char *name = NULL;
		uint32_t id = 0;

		if (!l_genl_attr_recurse(attr, &attr_grp))
			continue;

		while (l_genl_attr_next(&attr_grp, &type, &len, &data)) {
			switch (type) {
			case CTRL_ATTR_MCAST_GRP_NAME:
				name = data;
				break;
			case CTRL_ATTR_MCAST_GRP_ID:
				id = *((uint32_t *) data);
				break;
			}
		}

		if (name && id > 0)
			family_info_add_mcast(info, name, id);
	}
}

static int parse_cmd_newfamily(struct l_genl_family_info *info,
					struct l_genl_msg *msg)
{
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	int error;

	error = l_genl_msg_get_error(msg);
	if (error < 0)
		return error;

	if (!l_genl_attr_init(&attr, msg))
		return -EINVAL;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case CTRL_ATTR_FAMILY_ID:
			info->id = *((uint16_t *) data);
			break;
		case CTRL_ATTR_FAMILY_NAME:
			l_strlcpy(info->name, data, GENL_NAMSIZ);
			break;
		case CTRL_ATTR_VERSION:
			info->version = l_get_u32(data);
			break;
		case CTRL_ATTR_HDRSIZE:
			info->hdrsize = l_get_u32(data);
			break;
		case CTRL_ATTR_MAXATTR:
			info->maxattr = l_get_u32(data);
			break;
		case CTRL_ATTR_OPS:
			if (l_genl_attr_recurse(&attr, &nested))
				family_ops(info, &nested);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			if (l_genl_attr_recurse(&attr, &nested))
				family_mcast_groups(info, &nested);
			break;
		}
	}

	return 0;
}

LIB_EXPORT bool l_genl_family_info_has_group(
				const struct l_genl_family_info *info,
				const char *group)
{
	struct genl_mcast *mcast;

	if (unlikely(!info))
		return false;

	mcast = l_queue_find(info->mcast_list, match_mcast_name,
							(char *) group);
	if (!mcast)
		return false;

	return true;
}

static bool match_op_id(const void *a, const void *b)
{
	const struct genl_op *op = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return op->id == id;
}

LIB_EXPORT bool l_genl_family_info_can_send(
					const struct l_genl_family_info *info,
					uint8_t cmd)
{
	struct genl_op *op;

	if (unlikely(!info))
		return false;

	op = l_queue_find(info->op_list, match_op_id, L_UINT_TO_PTR(cmd));
	if (!op)
		return false;

	if (op->flags & GENL_CMD_CAP_DO)
		return true;

	return false;
}

LIB_EXPORT bool l_genl_family_info_can_dump(
					const struct l_genl_family_info *info,
					uint8_t cmd)
{
	struct genl_op *op;

	if (!info)
		return false;

	op = l_queue_find(info->op_list, match_op_id, L_UINT_TO_PTR(cmd));
	if (!op)
		return false;

	if (op->flags & GENL_CMD_CAP_DUMP)
		return true;

	return false;
}

LIB_EXPORT char **l_genl_family_info_get_groups(
					const struct l_genl_family_info *info)
{
	char **groups;
	size_t n_groups;
	const struct l_queue_entry *entry;
	int i;

	if (unlikely(!info))
		return NULL;

	n_groups = l_queue_length(info->mcast_list);
	groups = l_new(char *, n_groups + 1);

	for (entry = l_queue_get_entries(info->mcast_list), i = 0;
						entry; entry = entry->next) {
		struct genl_mcast *mcast = entry->data;

		groups[i++] = l_strdup(mcast->name);
	}

	return groups;
}

LIB_EXPORT uint32_t l_genl_family_info_get_id(
					const struct l_genl_family_info *info)
{
	if (unlikely(!info))
		return 0;

	return info->id;
}

LIB_EXPORT const char *l_genl_family_info_get_name(
					const struct l_genl_family_info *info)
{
	if (unlikely(!info))
		return NULL;

	return info->name;
}

LIB_EXPORT uint32_t l_genl_family_info_get_version(
					const struct l_genl_family_info *info)
{
	if (unlikely(!info))
		return 0;

	return info->version;
}

static void unicast_watch_free(struct l_notifylist_entry *e)
{
	struct unicast_watch *watch =
			l_container_of(e, struct unicast_watch, super);
	l_free(watch);
}

static void unicast_watch_notify(const struct l_notifylist_entry *e,
						int type, va_list args)
{
	const struct unicast_watch *watch =
			l_container_of(e, struct unicast_watch, super);

	if (!watch->handler)
		return;

	watch->handler(va_arg(args, struct l_genl_msg *),
			watch->super.notify_data);
}

static struct l_notifylist_ops unicast_watch_ops = {
	.free_entry = unicast_watch_free,
	.notify = unicast_watch_notify,
};

static bool unicast_watch_match_name(const struct l_notifylist_entry *e,
					const void *user)
{
	struct unicast_watch *watch =
			l_container_of(e, struct unicast_watch, super);

	return !strncmp(watch->name, user, GENL_NAMSIZ);
}

static void family_watch_free(void *data)
{
	struct family_watch *watch = data;

	if (watch->destroy)
		watch->destroy(watch->user_data);

	l_free(watch->name);
	l_free(watch);
}

static bool family_watch_match(const void *a, const void *b)
{
	const struct family_watch *watch = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return watch->id == id;
}

static struct l_genl_family_info *family_info_update(struct l_genl *genl,
					struct l_genl_family_info *info)
{
	struct l_genl_family_info *old =
		l_queue_find(genl->family_infos, family_info_match,
						L_UINT_TO_PTR(info->id));
	if (old) {
		GENL_DEBUG("Keeping old family info: %s", old->name);
		family_info_free(info);
		return old;
	}

	GENL_DEBUG("Added new family info: %s", info->name);
	l_queue_push_head(genl->family_infos, info);
	return info;
}

static void family_watch_prune(struct l_genl *genl)
{
	struct family_watch *watch;

	while ((watch = l_queue_remove_if(genl->family_watches,
						family_watch_match,
						L_UINT_TO_PTR(0))))
		family_watch_free(watch);
}

static void nlctrl_newfamily(struct l_genl_msg *msg, struct l_genl *genl)
{
	struct l_genl_family_info *info = family_info_new(NULL);
	const struct l_queue_entry *entry;

	if (parse_cmd_newfamily(info, msg) < 0) {
		family_info_free(info);
		return;
	}

	info = family_info_update(genl, info);

	genl->in_family_watch_notify = true;

	for (entry = l_queue_get_entries(genl->family_watches);
						entry; entry = entry->next) {
		struct family_watch *watch = entry->data;

		if (!watch->id)
			continue;

		if (!watch->appeared_func)
			continue;

		if (watch->name && strcmp(watch->name, info->name))
			continue;

		watch->appeared_func(info, watch->user_data);
	}

	genl->in_family_watch_notify = false;
	family_watch_prune(genl);
}

static void nlctrl_delfamily(struct l_genl_msg *msg, struct l_genl *genl)
{
	const struct l_queue_entry *entry;
	struct l_genl_attr attr;
	uint16_t type, len;
	const void *data;
	uint16_t id = 0;
	const char *name = NULL;
	struct l_genl_family_info *old;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case CTRL_ATTR_FAMILY_ID:
			id = l_get_u16(data);
			break;
		case CTRL_ATTR_FAMILY_NAME:
			name = data;
			break;
		}
	}

	if (!id || !name)
		return;

	genl->in_family_watch_notify = true;

	for (entry = l_queue_get_entries(genl->family_watches);
						entry; entry = entry->next) {
		struct family_watch *watch = entry->data;

		if (!watch->id)
			continue;

		if (!watch->vanished_func)
			continue;

		if (watch->name && strcmp(watch->name, name))
			continue;

		watch->vanished_func(name, watch->user_data);
	}

	genl->in_family_watch_notify = false;
	family_watch_prune(genl);

	old = l_queue_remove_if(genl->family_infos, family_info_match,
					L_UINT_TO_PTR(id));
	if (old) {
		GENL_DEBUG("Removing old family info: %s", old->name);
		family_info_free(old);
	}
}

static void nlctrl_notify(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl *genl = user_data;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	switch (cmd) {
	case CTRL_CMD_NEWFAMILY:
		nlctrl_newfamily(msg, genl);
		break;
	case CTRL_CMD_DELFAMILY:
		nlctrl_delfamily(msg, genl);
		break;
	case CTRL_CMD_NEWOPS:
		GENL_DEBUG("CMD_NEWOPS");
		break;
	case CTRL_CMD_DELOPS:
		GENL_DEBUG("CMD_DELOPS");
		break;
	case CTRL_CMD_NEWMCAST_GRP:
		GENL_DEBUG("CMD_NEWMCAST_GRP");
		break;
	case CTRL_CMD_DELMCAST_GRP:
		GENL_DEBUG("CMD_DELMCAST_GRP");
		break;
	}
}

static struct l_genl_family *family_alloc(struct l_genl *genl, uint16_t id)
{
	struct l_genl_family *family;

	family = l_new(struct l_genl_family, 1);
	family->genl = genl;
	family->id = id;
	family->handle_id = get_next_id(&genl->next_handle_id);
	return family;
}

static void destroy_request(void *data)
{
	struct genl_request *request = data;

	if (request->destroy)
		request->destroy(request->user_data);

	l_genl_msg_unref(request->msg);

	l_free(request);
}

static void mcast_notify_free(void *data)
{
	struct mcast_notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	l_free(notify);
}

static bool mcast_notify_match(const void *a, const void *b)
{
	const struct mcast_notify *notify = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return notify->id == id;
}

static void mcast_notify_prune(struct l_genl *genl)
{
	struct mcast_notify *notify;

	while ((notify = l_queue_remove_if(genl->notify_list,
						mcast_notify_match,
						L_UINT_TO_PTR(0))))
		mcast_notify_free(notify);
}

static bool match_request_id(const void *a, const void *b)
{
	const struct genl_request *request = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return request->id == id;
}

static bool match_request_hid(const void *a, const void *b)
{
	const struct genl_request *request = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return request->handle_id == id;
}

static struct l_genl_msg *msg_alloc(uint8_t cmd, uint8_t version, uint32_t size)
{
	struct l_genl_msg *msg;

	msg = l_new(struct l_genl_msg, 1);

	msg->cmd = cmd;
	msg->version = version;

	msg->len = NLMSG_HDRLEN + GENL_HDRLEN;
	msg->size = msg->len + NLMSG_ALIGN(size);

	msg->data = l_realloc(NULL, msg->size);
	memset(msg->data, 0, msg->size);
	msg->nesting_level = 0;

	return l_genl_msg_ref(msg);
}

static bool msg_grow(struct l_genl_msg *msg, uint32_t needed)
{
	uint32_t grow_by;

	if (msg->size >= msg->len + needed)
		return true;

	grow_by = msg->len + needed - msg->size;

	if (grow_by < 32)
		grow_by = 128;

	msg->data = l_realloc(msg->data, msg->size + grow_by);
	memset(msg->data + msg->size, 0, grow_by);
	msg->size += grow_by;

	return true;
}

static struct l_genl_msg *msg_create(const struct nlmsghdr *nlmsg)
{
	struct l_genl_msg *msg;

	msg = l_new(struct l_genl_msg, 1);

	if (nlmsg->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlmsg);
		const char *error_msg = NULL;

		msg->error = err->error;

		if (netlink_parse_ext_ack_error(nlmsg, &error_msg, NULL) &&
						error_msg)
			msg->error_msg = l_strdup(error_msg);

		goto done;
	}

	msg->data = l_memdup(nlmsg, nlmsg->nlmsg_len);

	msg->len = nlmsg->nlmsg_len;
	msg->size = nlmsg->nlmsg_len;

	if (msg->len >= GENL_HDRLEN) {
		struct genlmsghdr *genlmsg = msg->data + NLMSG_HDRLEN;

		msg->cmd = genlmsg->cmd;
		msg->version = genlmsg->version;
	}

done:
	return l_genl_msg_ref(msg);
}

static const void *msg_as_bytes(struct l_genl_msg *msg, uint16_t type,
				uint16_t flags, uint32_t seq, uint32_t pid,
				size_t *out_size)
{
	struct nlmsghdr *nlmsg;
	struct genlmsghdr *genlmsg;

	nlmsg = msg->data;

	nlmsg->nlmsg_len = msg->len;
	nlmsg->nlmsg_type = type;
	nlmsg->nlmsg_flags = flags;
	nlmsg->nlmsg_seq = seq;
	nlmsg->nlmsg_pid = pid;

	genlmsg = msg->data + NLMSG_HDRLEN;

	genlmsg->cmd = msg->cmd;
	genlmsg->version = msg->version;

	if (out_size)
		*out_size = msg->len;

	return msg->data;
}

static void write_watch_destroy(void *user_data)
{
	struct l_genl *genl = user_data;

	genl->writer_active = false;
}

static bool can_write_data(struct l_io *io, void *user_data)
{
	struct l_genl *genl = user_data;
	struct genl_request *request;
	const void *data;
	size_t size;
	ssize_t bytes_written;

	request = l_queue_pop_head(genl->request_queue);
	if (!request)
		return false;

	request->seq = get_next_id(&genl->next_seq);
	data = msg_as_bytes(request->msg, request->type, request->flags,
				request->seq, genl->pid, &size);

	bytes_written = send(genl->fd, data, size, 0);
	if (bytes_written < 0) {
		l_queue_push_head(genl->request_queue, request);
		return false;
	}

	l_util_hexdump(false, request->msg->data, bytes_written,
				genl->debug_callback, genl->debug_data);

	l_queue_push_tail(genl->pending_list, request);

	return false;
}

static void wakeup_writer(struct l_genl *genl)
{
	if (genl->writer_active)
		return;

	if (l_queue_isempty(genl->request_queue))
		return;

	if (!l_queue_isempty(genl->pending_list))
		return;

	l_io_set_write_handler(genl->io, can_write_data, genl,
						write_watch_destroy);

	genl->writer_active = true;
}

static bool match_request_seq(const void *a, const void *b)
{
	const struct genl_request *request = a;
	uint32_t seq = L_PTR_TO_UINT(b);

	return request->seq == seq;
}

static void process_unicast(struct l_genl *genl, const struct nlmsghdr *nlmsg)
{
	struct l_genl_msg *msg;
	struct genl_request *request;

	if (nlmsg->nlmsg_type == NLMSG_NOOP ||
					nlmsg->nlmsg_type == NLMSG_OVERRUN)
		return;

	msg = msg_create(nlmsg);
	if (!nlmsg->nlmsg_seq) {
		struct l_genl_family_info *info =
			l_queue_find(genl->family_infos, family_info_match,
					L_UINT_TO_PTR(nlmsg->nlmsg_type));

		if (info && msg)
			l_notifylist_notify_matches(genl->unicast_watches,
						unicast_watch_match_name,
						info->name, 0, msg);

		goto done;
	}

	request = l_queue_remove_if(genl->pending_list, match_request_seq,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
	if (!request)
		goto done;

	if (!msg)
		goto free_request;

	if (request->callback && nlmsg->nlmsg_type != NLMSG_DONE)
		request->callback(msg, request->user_data);

	if ((nlmsg->nlmsg_flags & NLM_F_MULTI) &&
					nlmsg->nlmsg_type != NLMSG_DONE) {
		l_queue_push_head(genl->pending_list, request);
		goto done;
	}

free_request:
	destroy_request(request);
	wakeup_writer(genl);
done:
	l_genl_msg_unref(msg);
}

static void process_multicast(struct l_genl *genl, uint32_t group,
						const struct nlmsghdr *nlmsg)
{
	const struct l_queue_entry *entry;
	struct l_genl_msg *msg = msg_create(nlmsg);

	if (!msg)
		return;

	genl->in_mcast_notify = true;

	for (entry = l_queue_get_entries(genl->notify_list);
						entry; entry = entry->next) {
		struct mcast_notify *notify = entry->data;

		/* Skip those that might have been removed due this mcast */
		if (!notify->id)
			continue;

		if (notify->type != nlmsg->nlmsg_type)
			continue;

		if (notify->group != group)
			continue;

		if (!notify->callback)
			continue;

		notify->callback(msg, notify->user_data);
	}

	genl->in_mcast_notify = false;
	mcast_notify_prune(genl);

	l_genl_msg_unref(msg);
}

static void read_watch_destroy(void *user_data)
{
}

static bool received_data(struct l_io *io, void *user_data)
{
	struct l_genl *genl = user_data;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	unsigned char buf[8192];
	unsigned char control[32];
	ssize_t bytes_read;
	struct nlmsghdr *nlmsg;
	size_t nlmsg_len;
	uint32_t group = 0;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	bytes_read = recvmsg(genl->fd, &msg, 0);
	if (bytes_read < 0) {
		if (errno != EAGAIN && errno != EINTR)
			return false;

		return true;
	}

	nlmsg_len = bytes_read;

	l_util_hexdump(true, buf, nlmsg_len,
				genl->debug_callback, genl->debug_data);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct nl_pktinfo pktinfo;

		if (cmsg->cmsg_level != SOL_NETLINK)
			continue;

		if (cmsg->cmsg_type != NETLINK_PKTINFO)
			continue;

		memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

		group = pktinfo.group;
	}

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, nlmsg_len);
				nlmsg = NLMSG_NEXT(nlmsg, nlmsg_len)) {
		if (group > 0)
			process_multicast(genl, group, nlmsg);
		else
			process_unicast(genl, nlmsg);
	}

	return true;
}

static struct l_genl_family_info *build_nlctrl_info()
{
	struct l_genl_family_info *r = family_info_new("nlctrl");

	r->id = GENL_ID_CTRL;
	family_info_add_mcast(r, "notify", GENL_ID_CTRL);
	family_info_add_op(r, CTRL_CMD_GETFAMILY, GENL_CMD_CAP_DUMP);

	return r;
}

LIB_EXPORT struct l_genl *l_genl_new(void)
{
	struct l_genl *genl;
	struct l_io *io;
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int fd;
	int pktinfo = 1;
	int ext_ack = 1;

	fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							NETLINK_GENERIC);
	if (fd < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto err;

	if (getsockname(fd, (struct sockaddr *) &addr, &addrlen) < 0)
		goto err;

	if (setsockopt(fd, SOL_NETLINK, NETLINK_PKTINFO,
					&pktinfo, sizeof(pktinfo)) < 0)
		goto err;

	/* Try setting EXT_ACK, but ignore the error if it isn't set */
	setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK,
					&ext_ack, sizeof(ext_ack));

	io = l_io_new(fd);
	if (!io)
		goto err;

	genl = l_new(struct l_genl, 1);
	genl->pid = addr.nl_pid;
	genl->ref_count = 1;
	genl->fd = fd;
	genl->io = io;
	l_io_set_read_handler(genl->io, received_data, genl,
						read_watch_destroy);

	genl->request_queue = l_queue_new();
	genl->pending_list = l_queue_new();
	genl->notify_list = l_queue_new();
	genl->family_watches = l_queue_new();
	genl->family_infos = l_queue_new();
	genl->unicast_watches = l_notifylist_new(&unicast_watch_ops);

	l_queue_push_head(genl->family_infos, build_nlctrl_info());

	genl->nlctrl = family_alloc(genl, GENL_ID_CTRL);
	l_genl_family_register(genl->nlctrl, "notify",
						nlctrl_notify, genl, NULL);

	return genl;

err:
	close(fd);
	return NULL;
}

LIB_EXPORT struct l_genl *l_genl_ref(struct l_genl *genl)
{
	if (unlikely(!genl))
		return NULL;

	__atomic_fetch_add(&genl->ref_count, 1, __ATOMIC_SEQ_CST);

	return genl;
}

LIB_EXPORT void l_genl_unref(struct l_genl *genl)
{
	if (unlikely(!genl))
		return;

	if (__atomic_sub_fetch(&genl->ref_count, 1, __ATOMIC_SEQ_CST))
		return;

	if (genl->discovery) {
		if (genl->discovery->destroy)
			genl->discovery->destroy(genl->discovery->user_data);

		l_free(genl->discovery);
		genl->discovery = NULL;
	}

	l_genl_family_free(genl->nlctrl);

	l_notifylist_free(genl->unicast_watches);
	l_queue_destroy(genl->family_watches, family_watch_free);
	l_queue_destroy(genl->family_infos, family_info_free);
	l_queue_destroy(genl->notify_list, mcast_notify_free);
	l_queue_destroy(genl->pending_list, destroy_request);
	l_queue_destroy(genl->request_queue, destroy_request);

	l_io_set_write_handler(genl->io, NULL, NULL, NULL);
	l_io_set_read_handler(genl->io, NULL, NULL, NULL);

	l_io_destroy(genl->io);
	genl->io = NULL;
	close(genl->fd);

	if (genl->debug_destroy)
		genl->debug_destroy(genl->debug_data);

	l_free(genl);
}

LIB_EXPORT bool l_genl_set_debug(struct l_genl *genl,
					l_genl_debug_func_t callback,
					void *user_data,
					l_genl_destroy_func_t destroy)
{
	if (unlikely(!genl))
		return false;

	if (genl->debug_destroy)
		genl->debug_destroy(genl->debug_data);

	genl->debug_callback = callback;
	genl->debug_destroy = destroy;
	genl->debug_data = user_data;

	return true;
}

static void dump_family_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl *genl = user_data;
	struct genl_discovery *discovery = genl->discovery;
	struct l_genl_family_info *info = family_info_new(NULL);

	discovery->cmd_id = 0;

	if (parse_cmd_newfamily(info, msg) < 0) {
		family_info_free(info);
		return;
	}

	info = family_info_update(genl, info);

	if (discovery->cb)
		discovery->cb(info, discovery->user_data);
}

static void dump_family_done(void *user_data)
{
	struct l_genl *genl = user_data;
	struct genl_discovery *discovery = genl->discovery;

	if (discovery->destroy)
		discovery->destroy(discovery->user_data);

	l_free(discovery);
	genl->discovery = NULL;
}

LIB_EXPORT bool l_genl_discover_families(struct l_genl *genl,
						l_genl_discover_func_t cb,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	struct l_genl_msg *msg;
	struct genl_discovery *discovery;

	if (unlikely(!genl))
		return false;

	if (genl->discovery)
		return false;

	discovery = l_new(struct genl_discovery, 1);
	discovery->cb = cb;
	discovery->user_data = user_data;
	discovery->destroy = destroy;

	msg = l_genl_msg_new_sized(CTRL_CMD_GETFAMILY, NLA_HDRLEN);
	discovery->cmd_id = l_genl_family_dump(genl->nlctrl, msg,
						dump_family_callback,
						genl, dump_family_done);

	if (!discovery->cmd_id) {
		l_free(discovery);
		return false;
	}

	genl->discovery = discovery;
	return true;
}

/**
 * l_genl_add_unicast_watch:
 * @genl: GENL connection
 * @name: Name of the family for which a unicast watch will be registered
 * @handler: Callback to call when a matching unicast is received
 * @user_data: user data for the callback
 * @destroy: Destroy callback for user data
 *
 * Adds a watch for unicast messages for a given family specified by @family.
 * The watch can be registered even if the family has not been discovered yet
 * or doesn't exist.
 *
 * Returns: a non-zero watch identifier that can be passed to
 *          l_genl_remove_unicast_watch to remove this watch, or zero if the
 *          watch could not be created successfully.
 **/
LIB_EXPORT unsigned int l_genl_add_unicast_watch(struct l_genl *genl,
						const char *family,
						l_genl_msg_func_t handler,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	struct unicast_watch *watch;

	if (unlikely(!genl || !family))
		return 0;

	if (strlen(family) >= GENL_NAMSIZ)
		return 0;

	watch = l_new(struct unicast_watch, 1);
	l_strlcpy(watch->name, family, GENL_NAMSIZ);
	watch->handler = handler;
	watch->super.destroy = destroy;
	watch->super.notify_data = user_data;

	return l_notifylist_add(genl->unicast_watches, &watch->super);
}

/**
 * l_genl_remove_unicast_watch:
 * @genl: GENL connection
 * @id: unique identifier of the unicast watch to remove
 *
 * Removes the unicast watch.  If a destroy callback was provided, then it is
 * called in order to free any associated user data.
 *
 * Returns: #true if the watch was removed successfully and #false otherwise.
 **/
LIB_EXPORT bool l_genl_remove_unicast_watch(struct l_genl *genl,
							unsigned int id)
{
	if (unlikely(!genl))
		return false;

	return l_notifylist_remove(genl->unicast_watches, id);
}

/**
 * l_genl_add_family_watch:
 * @genl: GENL connection
 * @name: Name of the family to watch for.  Use NULL to match any family.
 * @appeared_func: Callback to call when the matching family appears
 * @vanished_func: Callback to call when the matching family disappears
 * @user_data: user data for the callback
 * @destroy: Destroy callback for user data
 *
 * Returns: a non-zero watch identifier that can be passed to
 *          l_genl_remove_family_watch to remove this watch, or zero if the
 *          watch could not be created successfully.
 **/
LIB_EXPORT unsigned int l_genl_add_family_watch(struct l_genl *genl,
					const char *name,
					l_genl_discover_func_t appeared_func,
					l_genl_vanished_func_t vanished_func,
					void *user_data,
					l_genl_destroy_func_t destroy)
{
	struct family_watch *watch;
	size_t len = 0;

	if (unlikely(!genl))
		return 0;

	if (name) {
		len = strlen(name);
		if (len >= GENL_NAMSIZ)
			return 0;
	}

	watch = l_new(struct family_watch, 1);
	watch->name = l_strdup(name);
	watch->appeared_func = appeared_func;
	watch->vanished_func = vanished_func;
	watch->user_data = user_data;
	watch->destroy = destroy;
	watch->id = get_next_id(&genl->next_watch_id);
	l_queue_push_tail(genl->family_watches, watch);

	return watch->id;
}

/**
 * l_genl_remove_family_watch:
 * @genl: GENL connection
 * @id: unique identifier of the family watch to remove
 *
 * Removes the family watch.  If a destroy callback was provided, then it is
 * called in order to free any associated user data.
 *
 * Returns: #true if the watch was removed successfully and #false otherwise.
 **/
LIB_EXPORT bool l_genl_remove_family_watch(struct l_genl *genl,
							unsigned int id)
{
	struct family_watch *watch;

	if (unlikely(!genl))
		return false;

	if (genl->in_family_watch_notify) {
		watch = l_queue_find(genl->family_watches, family_watch_match,
							L_UINT_TO_PTR(id));
		if (!watch)
			return false;

		watch->id = 0;
		return true;
	}

	watch = l_queue_remove_if(genl->family_watches, family_watch_match,
							L_UINT_TO_PTR(id));
	if (!watch)
		return false;

	family_watch_free(watch);

	return true;
}

struct family_request {
	void *user_data;
	l_genl_discover_func_t appeared_func;
	l_genl_destroy_func_t destroy;
	struct l_genl *genl;
};

static void request_family_callback(struct l_genl_msg *msg, void *user_data)
{
	struct family_request *req = user_data;
	struct l_genl_family_info *info = family_info_new(NULL);

	if (parse_cmd_newfamily(info, msg) < 0) {
		family_info_free(info);

		if (req->appeared_func)
			req->appeared_func(NULL, req->user_data);

		return;
	}

	info = family_info_update(req->genl, info);

	/*
	 * watch events should trigger as a result of new_family event.
	 * Do not trigger these here as the family might have already been
	 * discovered
	 */

	if (req->appeared_func)
		req->appeared_func(info, req->user_data);
}

static void family_request_free(void *user_data)
{
	struct family_request *req = user_data;

	if (req->destroy)
		req->destroy(req->user_data);

	l_free(req);
}

/**
 * l_genl_request_family:
 * @genl: GENL connection
 * @name: Name of the family to request
 * @appeared_func: Callback to call
 * @user_data: User data
 * @destroy: Destroy callback for user_data
 *
 * Attempts to request a family given by @name. If the family is not currently
 * available, then the kernel will attempt to auto-load the module for that
 * family and if successful, the family will appear.  If the family is already
 * loaded, the kernel will not perform auto-loading.  In both cases the callback
 * is called with the family information.  If auto-loading failed, a NULL
 * will be given as a parameter to @appeared_func.
 *
 * Returns: #true if the request could be started successfully,
 * false otherwise.
 **/
LIB_EXPORT bool l_genl_request_family(struct l_genl *genl, const char *name,
					l_genl_discover_func_t appeared_func,
					void *user_data,
					l_genl_destroy_func_t destroy)
{
	size_t len;
	struct l_genl_msg *msg;
	struct family_request *req;

	if (unlikely(!genl) || unlikely(!name))
		return false;

	len = strlen(name);
	if (unlikely(strlen(name) >= GENL_NAMSIZ))
		return false;

	req = l_new(struct family_request, 1);
	req->appeared_func = appeared_func;
	req->user_data = user_data;
	req->destroy = destroy;
	req->genl = genl;

	msg = l_genl_msg_new_sized(CTRL_CMD_GETFAMILY,
						NLA_HDRLEN + GENL_NAMSIZ);
	l_genl_msg_append_attr(msg, CTRL_ATTR_FAMILY_NAME, len + 1, name);

	if (l_genl_family_send(genl->nlctrl, msg, request_family_callback,
				req, family_request_free) > 0)
		return true;

	return false;
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_new(uint8_t cmd)
{
	return l_genl_msg_new_sized(cmd, 0);
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_new_sized(uint8_t cmd, uint32_t size)
{
	return msg_alloc(cmd, 0x00, size);
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_new_from_data(const void *data,
							size_t size)
{
	const struct nlmsghdr *nlmsg = (const void *) data;

	if (size < sizeof(struct nlmsghdr))
		return NULL;

	if (size < nlmsg->nlmsg_len)
		return NULL;

	return msg_create(nlmsg);
}

LIB_EXPORT const void *l_genl_msg_to_data(struct l_genl_msg *msg, uint16_t type,
						uint16_t flags, uint32_t seq,
						uint32_t pid,
						size_t *out_size)
{
	return msg_as_bytes(msg, type, flags, seq, pid, out_size);
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_ref(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return NULL;

	__atomic_fetch_add(&msg->ref_count, 1, __ATOMIC_SEQ_CST);

	return msg;
}

LIB_EXPORT void l_genl_msg_unref(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return;

	if (__atomic_sub_fetch(&msg->ref_count, 1, __ATOMIC_SEQ_CST))
		return;

	l_free(msg->error_msg);
	l_free(msg->data);
	l_free(msg);
}

LIB_EXPORT uint8_t l_genl_msg_get_command(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return 0;

	return msg->cmd;
}

LIB_EXPORT uint8_t l_genl_msg_get_version(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return 0;

	return msg->version;
}

LIB_EXPORT int l_genl_msg_get_error(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return -ENOMSG;

	return msg->error;
}

LIB_EXPORT const char *l_genl_msg_get_extended_error(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return NULL;

	return msg->error_msg;
}

LIB_EXPORT bool l_genl_msg_append_attr(struct l_genl_msg *msg, uint16_t type,
						uint16_t len, const void *data)
{
	struct nlattr *nla;

	if (unlikely(!msg))
		return false;

	if (!msg_grow(msg, NLA_HDRLEN + NLA_ALIGN(len)))
		return false;

	nla = msg->data + msg->len;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;

	if (len)
		memcpy(msg->data + msg->len + NLA_HDRLEN, data, len);

	msg->len += NLA_HDRLEN + NLA_ALIGN(len);

	return true;
}

LIB_EXPORT bool l_genl_msg_append_attrv(struct l_genl_msg *msg, uint16_t type,
					const struct iovec *iov,
					size_t iov_len)
{
	struct nlattr *nla;
	size_t len = 0;
	unsigned int i;

	if (unlikely(!msg))
		return false;

	for (i = 0; i < iov_len; i++)
		len += iov[i].iov_len;

	if (!msg_grow(msg, NLA_HDRLEN + NLA_ALIGN(len)))
		return false;

	nla = msg->data + msg->len;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;

	msg->len += NLA_HDRLEN;

	for (i = 0; i < iov_len; i++, iov++) {
		memcpy(msg->data + msg->len, iov->iov_base, iov->iov_len);
		msg->len += iov->iov_len;
	}

	msg->len += NLA_ALIGN(len) - len;

	return true;
}

LIB_EXPORT bool l_genl_msg_enter_nested(struct l_genl_msg *msg, uint16_t type)
{
	if (unlikely(!msg))
		return false;

	if (unlikely(msg->nesting_level == MAX_NESTING_LEVEL))
		return false;

	if (!msg_grow(msg, NLA_HDRLEN))
		return false;

	msg->nests[msg->nesting_level].type = type | NLA_F_NESTED;
	msg->nests[msg->nesting_level].offset = msg->len;
	msg->nesting_level += 1;

	msg->len += NLA_HDRLEN;

	return true;
}

LIB_EXPORT bool l_genl_msg_leave_nested(struct l_genl_msg *msg)
{
	struct nlattr *nla;

	if (unlikely(!msg))
		return false;

	if (unlikely(msg->nesting_level == 0))
		return false;

	nla = msg->data + msg->nests[msg->nesting_level - 1].offset;
	nla->nla_type = msg->nests[msg->nesting_level - 1].type;
	nla->nla_len = msg->len - msg->nests[msg->nesting_level - 1].offset;

	msg->nesting_level -= 1;

	return true;
}

LIB_EXPORT bool l_genl_attr_init(struct l_genl_attr *attr,
						struct l_genl_msg *msg)
{
	const struct nlattr *nla;
	uint32_t len;

	if (unlikely(!attr) || unlikely(!msg))
		return false;

	if (!msg->data || msg->len < NLMSG_HDRLEN + GENL_HDRLEN)
		return false;

	nla = msg->data + NLMSG_HDRLEN + GENL_HDRLEN;
	len = msg->len - NLMSG_HDRLEN - GENL_HDRLEN;

	if (!NLA_OK(nla, len))
		return false;

	attr->data = NULL;
	attr->len = 0;
	attr->next_data = nla;
	attr->next_len = len;

	return true;
}

LIB_EXPORT bool l_genl_attr_next(struct l_genl_attr *attr,
						uint16_t *type,
						uint16_t *len,
						const void **data)
{
	const struct nlattr *nla;

	if (unlikely(!attr))
		return false;

	nla = attr->next_data;

	if (!NLA_OK(nla, attr->next_len))
		return false;

	if (type)
		*type = nla->nla_type & NLA_TYPE_MASK;

	if (len)
		*len = NLA_PAYLOAD(nla);

	if (data)
		*data = NLA_DATA(nla);

	attr->data = attr->next_data;
	attr->len = attr->next_len;

	attr->next_data = NLA_NEXT(nla, attr->next_len);

	return true;
}

LIB_EXPORT bool l_genl_attr_recurse(const struct l_genl_attr *attr,
						struct l_genl_attr *nested)
{
	const struct nlattr *nla;

	if (unlikely(!attr) || unlikely(!nested))
		return false;

	nla = attr->data;
	if (!nla)
		return false;

	nested->data = NULL;
	nested->len = 0;
	nested->next_data = NLA_DATA(nla);
	nested->next_len = NLA_PAYLOAD(nla);

	return true;
}

/**
 * l_genl_family_new:
 * @genl: GENL connection
 * @name: Name of the family for which a handle will be created
 *
 * Attempts to create a handle over which applications can send requests and
 * listen to events from a given family.  The family must have been discovered
 * previously via @l_genl_discover_families or @l_genl_add_family_watch; or
 * autoloaded using @l_genl_family_request.
 *
 * The destruction of the handle using @l_genl_family_free will clean up all
 * requests started via this handle as well as unregister from any
 * notifications.  Notifications & Requests started by other handles will be
 * unaffected.
 *
 * Returns: #NULL if the family handle could not be created and a valid
 * handle on success.
 **/
LIB_EXPORT struct l_genl_family *l_genl_family_new(struct l_genl *genl,
							const char *name)
{
	struct l_genl_family *family;
	struct l_genl_family_info *info;
	const struct l_queue_entry *entry;

	if (unlikely(!genl) || unlikely(!name))
		return NULL;

	for (entry = l_queue_get_entries(genl->family_infos);
						entry; entry = entry->next) {
		info = entry->data;

		if (!strncmp(name, info->name, GENL_NAMSIZ))
			break;
	}

	if (!entry)
		return NULL;

	family = family_alloc(l_genl_ref(genl), info->id);

	return family;
}

LIB_EXPORT const struct l_genl_family_info *l_genl_family_get_info(
						struct l_genl_family *family)
{
	if (unlikely(!family))
		return NULL;

	return l_queue_find(family->genl->family_infos, family_info_match,
					L_UINT_TO_PTR(family->id));
}

LIB_EXPORT struct l_genl *l_genl_family_get_genl(struct l_genl_family *family)
{
	if (unlikely(!family))
		return 0;

	return family->genl;
}

static unsigned int send_common(struct l_genl_family *family, uint16_t flags,
				struct l_genl_msg *msg, l_genl_msg_func_t callback,
				void *user_data, l_genl_destroy_func_t destroy)
{
	struct l_genl *genl;
	struct genl_request *request;

	if (!family || !msg)
		return 0;

	genl = family->genl;
	if (!genl)
		return 0;

	request = l_new(struct genl_request, 1);
	request->type = family->id;
	request->flags = NLM_F_REQUEST | flags;
	request->msg = msg;
	request->callback = callback;
	request->destroy = destroy;
	request->user_data = user_data;
	request->id = get_next_id(&genl->next_request_id);
	request->handle_id = family->handle_id;
	l_queue_push_tail(genl->request_queue, request);

	wakeup_writer(genl);

	return request->id;
}

LIB_EXPORT unsigned int l_genl_family_send(struct l_genl_family *family,
						struct l_genl_msg *msg,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	return send_common(family, NLM_F_ACK, msg, callback,
						user_data, destroy);
}

LIB_EXPORT unsigned int l_genl_family_dump(struct l_genl_family *family,
						struct l_genl_msg *msg,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	return send_common(family, NLM_F_ACK | NLM_F_DUMP, msg, callback,
							user_data, destroy);
}

LIB_EXPORT bool l_genl_family_cancel(struct l_genl_family *family,
							unsigned int id)
{
	struct l_genl *genl;
	struct genl_request *request;

	if (unlikely(!family) || unlikely(!id))
		return false;

	genl = family->genl;
	if (!genl)
		return false;

	request = l_queue_remove_if(genl->request_queue, match_request_id,
							L_UINT_TO_PTR(id));
	if (request)
		goto done;

	request = l_queue_find(genl->pending_list, match_request_id,
							L_UINT_TO_PTR(id));
	if (!request)
		return false;

	/*
	 * A message in-flight still needs to wait for NLMSG_DONE so clean up
	 * for the caller but keep the request queued until its done.
	 */
	if (request->destroy)
		request->destroy(request->user_data);

	request->callback = NULL;
	request->destroy = NULL;

	return true;

done:
	destroy_request(request);

	return true;
}

LIB_EXPORT bool l_genl_family_request_sent(struct l_genl_family *family,
						unsigned int id)
{
	struct l_genl *genl;

	if (unlikely(!family) || unlikely(!id))
		return false;

	genl = family->genl;
	if (!genl)
		return false;

	return l_queue_find(genl->pending_list, match_request_id,
				L_UINT_TO_PTR(id)) != NULL;
}

static void add_membership(struct l_genl *genl, struct genl_mcast *mcast)
{
	int group = mcast->id;

	if (mcast->users > 0)
		goto done;

	if (setsockopt(genl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
						&group, sizeof(group)) < 0)
		return;

done:
	mcast->users++;
}

static void drop_membership(struct l_genl *genl, struct genl_mcast *mcast)
{
	int group;

	if (--mcast->users)
		return;

	group = mcast->id;

	setsockopt(genl->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
							&group, sizeof(group));
}

LIB_EXPORT unsigned int l_genl_family_register(struct l_genl_family *family,
						const char *group,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	struct l_genl *genl;
	struct l_genl_family_info *info;
	struct mcast_notify *notify;
	struct genl_mcast *mcast;

	if (unlikely(!family) || unlikely(!group))
		return 0;

	genl = family->genl;
	if (!genl)
		return 0;

	info = l_queue_find(genl->family_infos, family_info_match,
					L_UINT_TO_PTR(family->id));
	if (!info)
		return 0;

	mcast = l_queue_find(info->mcast_list, match_mcast_name, group);
	if (!mcast)
		return 0;

	notify = l_new(struct mcast_notify, 1);
	notify->type = info->id;
	notify->group = mcast->id;
	notify->callback = callback;
	notify->destroy = destroy;
	notify->user_data = user_data;
	notify->id = get_next_id(&genl->next_notify_id);
	notify->handle_id = family->handle_id;
	l_queue_push_tail(genl->notify_list, notify);

	add_membership(genl, mcast);

	return notify->id;
}

LIB_EXPORT bool l_genl_family_unregister(struct l_genl_family *family,
							unsigned int id)
{
	struct l_genl *genl;
	struct mcast_notify *notify;
	struct l_genl_family_info *info;
	struct genl_mcast *mcast;

	if (unlikely(!family) || unlikely(!id))
		return false;

	genl = family->genl;
	if (!genl)
		return false;

	if (genl->in_mcast_notify) {
		notify = l_queue_find(genl->notify_list, mcast_notify_match,
							L_UINT_TO_PTR(id));
		if (!notify)
			return false;

		notify->id = 0;
	} else {
		notify = l_queue_remove_if(genl->notify_list,
							mcast_notify_match,
							L_UINT_TO_PTR(id));
		if (!notify)
			return false;
	}

	info = l_queue_find(genl->family_infos, family_info_match,
					L_UINT_TO_PTR(family->id));
	if (!info)
		goto done;

	mcast = l_queue_find(info->mcast_list, match_mcast_id,
						L_UINT_TO_PTR(notify->group));
	if (!mcast)
		goto done;

	drop_membership(genl, mcast);

done:
	if (notify->id)
		mcast_notify_free(notify);

	return true;
}

LIB_EXPORT void l_genl_family_free(struct l_genl_family *family)
{
	struct l_genl *genl;
	struct genl_request *req;
	struct l_genl_family_info *info;
	const struct l_queue_entry *entry;

	if (!family)
		return;

	genl = family->genl;
	info = l_queue_find(genl->family_infos, family_info_match,
					L_UINT_TO_PTR(family->id));
	L_WARN_ON(!info);

	while ((req = l_queue_remove_if(genl->pending_list,
					match_request_hid,
					L_UINT_TO_PTR(family->handle_id))))
		destroy_request(req);

	while ((req = l_queue_remove_if(genl->request_queue,
					match_request_hid,
					L_UINT_TO_PTR(family->handle_id))))
		destroy_request(req);

	for (entry = l_queue_get_entries(genl->notify_list);
						entry; entry = entry->next) {
		struct mcast_notify *notify = entry->data;

		if (notify->handle_id != family->handle_id)
			continue;

		notify->id = 0;

		if (info) {
			struct genl_mcast *mcast =
				l_queue_find(info->mcast_list, match_mcast_id,
						L_UINT_TO_PTR(notify->group));

			if (mcast)
				drop_membership(genl, mcast);
		}
	}

	if (!genl->in_mcast_notify)
		mcast_notify_prune(genl);

	l_free(family);
	l_genl_unref(genl);
}
