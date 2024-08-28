/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/types.h>
#include <net/if_arp.h>
#include <errno.h>
#include <arpa/inet.h>

#include "private.h"
#include "useful.h"
#include "random.h"
#include "time.h"
#include "time-private.h"
#include "net.h"
#include "timeout.h"
#include "dhcp.h"
#include "dhcp-private.h"
#include "netlink.h"
#include "rtnl.h"
#include "acd.h"
#include "log.h"

#define CLIENT_LOG(priority, fmt, args...)				\
	if (priority <= client->debug_level)				\
		l_util_debug(client->debug_handler, client->debug_data,	\
				"%s:%i " fmt, __func__, __LINE__, ## args)
#define CLIENT_DEBUG(fmt, args...)					\
	CLIENT_LOG(L_LOG_DEBUG, fmt, ## args)
#define CLIENT_INFO(fmt, args...)					\
	CLIENT_LOG(L_LOG_INFO, fmt, ## args)
#define CLIENT_WARN(fmt, args...)					\
	CLIENT_LOG(L_LOG_WARNING, fmt, ## args)
#define CLIENT_ENTER_STATE(s)						\
	CLIENT_INFO("Entering state: " #s);				\
	client->state = (s)

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define CLIENT_MAX_ATTEMPT_LIMIT 30
#define CLIENT_MIN_ATTEMPT_LIMIT 3

enum dhcp_state {
	DHCP_STATE_INIT,
	DHCP_STATE_SELECTING,
	DHCP_STATE_INIT_REBOOT,
	DHCP_STATE_REBOOTING,
	DHCP_STATE_REQUESTING,
	DHCP_STATE_BOUND,
	DHCP_STATE_RENEWING,
	DHCP_STATE_REBINDING,
};

const char *_dhcp_message_type_to_string(uint8_t type)
{
	switch(type) {
	case DHCP_MESSAGE_TYPE_DISCOVER:
		return "DHCPDISCOVER";
	case DHCP_MESSAGE_TYPE_OFFER:
		return "DHCPOFFER";
	case DHCP_MESSAGE_TYPE_REQUEST:
		return "DHCPREQUEST";
	case DHCP_MESSAGE_TYPE_DECLINE:
		return "DHCPDECLINE";
	case DHCP_MESSAGE_TYPE_ACK:
		return "DHCPACK";
	case DHCP_MESSAGE_TYPE_NAK:
		return "DHCPNAK";
	case DHCP_MESSAGE_TYPE_RELEASE:
		return "DHCPRELEASE";
	default:
		return "unknown";
	}
}

const char *_dhcp_option_to_string(uint8_t option)
{
	switch (option) {
	case DHCP_OPTION_PAD:
		return "Pad";
	case L_DHCP_OPTION_SUBNET_MASK:
		return "Subnet Mask";
	case L_DHCP_OPTION_ROUTER:
		return "Router";
	case L_DHCP_OPTION_DOMAIN_NAME_SERVER:
		return "Domain Name Server";
	case L_DHCP_OPTION_HOST_NAME:
		return "Host Name";
	case L_DHCP_OPTION_DOMAIN_NAME:
		return "Domain Name";
	case L_DHCP_OPTION_BROADCAST_ADDRESS:
		return "Broadcast Address";
	case L_DHCP_OPTION_NTP_SERVERS:
		return "NTP Servers";
	case L_DHCP_OPTION_REQUESTED_IP_ADDRESS:
		return "IP Address";
	case L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
		return "IP Address Lease Time";
	case DHCP_OPTION_OVERLOAD:
		return "Overload";
	case DHCP_OPTION_MESSAGE_TYPE:
		return "DHCP Message Type";
	case L_DHCP_OPTION_SERVER_IDENTIFIER:
		return "Server Identifier";
	case DHCP_OPTION_PARAMETER_REQUEST_LIST:
		return "Parameter Request List";
	case DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:
		return "Maximum Message Size";
	case L_DHCP_OPTION_RENEWAL_T1_TIME:
		return "Renewal Time";
	case L_DHCP_OPTION_REBINDING_T2_TIME:
		return "Rebinding Time";
	case DHCP_OPTION_CLIENT_IDENTIFIER:
		return "Client Identifier";
	case DHCP_OPTION_END:
		return "End";
	default:
		return "unknown";
	}
}

static void dhcp_message_set_address_type(struct dhcp_message *message,
						uint8_t addr_type,
						uint8_t addr_len)
{
	message->htype = addr_type;

	switch (addr_type) {
	case ARPHRD_ETHER:
		message->hlen = addr_len;
		break;
	default:
		message->hlen = 0;
	}
}

struct l_dhcp_client {
	enum dhcp_state state;
	unsigned long request_options[256 / BITS_PER_LONG];
	uint32_t ifindex;
	char *ifname;
	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;
	char *hostname;
	uint32_t xid;
	struct dhcp_transport *transport;
	uint64_t start_t;
	struct l_timeout *timeout_resend;
	struct l_timeout *timeout_lease;
	struct l_dhcp_lease *lease;
	struct l_netlink *rtnl;
	uint32_t rtnl_add_cmdid;
	struct l_rtnl_address *rtnl_configured_address;
	uint8_t attempt;
	uint8_t max_attempts;
	l_dhcp_client_event_cb_t event_handler;
	void *event_data;
	l_dhcp_destroy_cb_t event_destroy;
	l_dhcp_debug_cb_t debug_handler;
	l_dhcp_destroy_cb_t debug_destroy;
	int debug_level;
	struct l_acd *acd;
	void *debug_data;
	bool have_addr : 1;
	bool override_xid : 1;
};

static inline void dhcp_enable_option(struct l_dhcp_client *client,
								uint8_t option)
{
	client->request_options[option / BITS_PER_LONG] |=
						1UL << (option % BITS_PER_LONG);
}

static uint16_t dhcp_attempt_secs(uint64_t start)
{
	uint64_t now = l_time_now();
	uint64_t elapsed = l_time_to_secs(now - start);

	if (elapsed == 0)
		return 1;

	if (elapsed > UINT16_MAX)
		return UINT16_MAX;

	return elapsed;
}

/*
 * Takes a time in seconds and produces a fuzzed value that can be directly
 * used by l_timeout_modify_ms
 */
static uint64_t dhcp_fuzz_secs(uint32_t secs)
{
	/*
	 * RFC2132, Section 4.1:
	 * DHCP clients are responsible for all message retransmission.  The
	 * client MUST adopt a retransmission strategy that incorporates a
	 * randomized exponential backoff algorithm to determine the delay
	 * between retransmissions.
	 *
	 * and later in the same paragraph:
	 * For example, in a 10Mb/sec Ethernet internetwork, the delay before
	 * the first retransmission SHOULD be 4 seconds randomized by the
	 * value of a uniform random number chosen from the range -1 to +1.
	 * Clients with clocks that provide resolution granularity of less than
	 * one second may choose a non-integer randomization value.
	 */
	return _time_fuzz_secs(secs, 1);
}

/*
 * Takes a time in milliseconds and produces a fuzzed value that can be directly
 * used by l_timeout_modify_ms. The fluctuation of the random noise added is
 * from -63 to 63 milliseconds.
 */
static uint64_t dhcp_fuzz_msecs(uint64_t ms)
{
	uint32_t r = l_getrandom_uint32();

	if (r & 0x80000000)
		ms += r & 0x3f;
	else
		ms -= r & 0x3f;

	return ms;
}

static uint32_t dhcp_rebind_renew_retry_time(uint64_t start_t, uint32_t expiry)
{
	uint64_t now = l_time_now();
	uint32_t relative_now;
	uint32_t retry_time;

	/*
	 * RFC 2131, Section 4.4.5:
	 * "   In both RENEWING and REBINDING states, if the client receives no
	 * response to its DHCPREQUEST message, the client SHOULD wait one-half
	 * of the remaining time until T2 (in RENEWING state) and one-half of
	 * the remaining lease time (in REBINDING state), down to a minimum of
	 * 60 seconds, before retransmitting the DHCPREQUEST message.
	 */
	relative_now = l_time_to_secs(now - start_t);
	retry_time = (expiry - relative_now) / 2;

	if (retry_time < 60)
		retry_time = 60;

	return retry_time;
}

static int client_message_init(struct l_dhcp_client *client,
					struct dhcp_message *message,
					struct dhcp_message_builder *builder)
{
	uint16_t max_size;

	message->op = DHCP_OP_CODE_BOOTREQUEST;
	message->xid = L_CPU_TO_BE32(client->xid);
	message->magic = L_CPU_TO_BE32(DHCP_MAGIC);

	dhcp_message_set_address_type(message, client->addr_type,
							client->addr_len);
	/*
	 * RFC2132 section 4.1.1:
	 * The client MUST include its hardware address in the ’chaddr’ field,
	 * if necessary for delivery of DHCP reply messages.  Non-Ethernet
	 * interfaces will leave 'chaddr' empty and use the client identifier
	 * instead
	 */
	if (client->addr_type == ARPHRD_ETHER)
		memcpy(message->chaddr, &client->addr, client->addr_len);

	/*
	 * Althrough RFC 2131 says that secs should be initialized to 0,
	 * some servers refuse to give us a lease unless we set this to a
	 * non-zero value
	 */
	message->secs = L_CPU_TO_BE16(dhcp_attempt_secs(client->start_t));

	if (!_dhcp_message_builder_append_prl(builder,
						client->request_options))
		return -EINVAL;

	/*
	 * Set the maximum DHCP message size to the minimum legal value.  This
	 * helps some buggy DHCP servers to not send bigger packets
	 */
	max_size = L_CPU_TO_BE16(576);
	if (!_dhcp_message_builder_append(builder,
					DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
					2, &max_size))
		return -EINVAL;

	return 0;
}

static void dhcp_client_event_notify(struct l_dhcp_client *client,
						enum l_dhcp_client_event event)
{
	if (client->event_handler)
		client->event_handler(client, event, client->event_data);
}

static int dhcp_client_send_discover(struct l_dhcp_client *client)
{
	struct dhcp_message_builder builder;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, discover);
	int err;

	CLIENT_DEBUG("");

	discover = (struct dhcp_message *) l_new(uint8_t, len);

	_dhcp_message_builder_init(&builder, discover, len,
					DHCP_MESSAGE_TYPE_DISCOVER);

	err = client_message_init(client, discover, &builder);
	if (err < 0)
		return err;

	if (client->hostname)
		if (!_dhcp_message_builder_append(&builder,
						L_DHCP_OPTION_HOST_NAME,
						strlen(client->hostname),
						client->hostname))
			return -EINVAL;

	_dhcp_message_builder_append(&builder, DHCP_OPTION_RAPID_COMMIT,
					0, "");
	_dhcp_message_builder_finalize(&builder, &len);

	return client->transport->l2_send(client->transport,
					INADDR_ANY, DHCP_PORT_CLIENT,
					INADDR_BROADCAST, DHCP_PORT_SERVER,
					NULL,
					discover, len);
}

static int dhcp_client_send_unicast(struct l_dhcp_client *client,
					struct dhcp_message *request,
					unsigned int len)
{
	struct sockaddr_in si;
	int r;

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = L_CPU_TO_BE16(DHCP_PORT_SERVER);
	si.sin_addr.s_addr = client->lease->server_address;

	/*
	 * sendto() might fail with an EPERM error, which most likely means
	 * that the unicast was prevented by netfilter.  Ignore this case
	 * and assume that once the REBINDING timeout is hit, a broadcast
	 * will go through which will have a chance of renewing the lease
	 */
	r = client->transport->send(client->transport, &si, request, len);
	if (r == -EPERM) {
		CLIENT_DEBUG("transport->send() failed with EPERM -> ignore");
		CLIENT_DEBUG("Is a firewall denying unicast DHCP packets?");
		return 0;
	}

	return r;
}

static int dhcp_client_send_request(struct l_dhcp_client *client)
{
	struct dhcp_message_builder builder;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, request);
	int err;

	CLIENT_DEBUG("");

	request = (struct dhcp_message *) l_new(uint8_t, len);

	_dhcp_message_builder_init(&builder, request, len,
					DHCP_MESSAGE_TYPE_REQUEST);


	err = client_message_init(client, request, &builder);
	if (err < 0)
		return err;

	switch (client->state) {
	case DHCP_STATE_REQUESTING:
		/*
		 * RFC 2131, Section 4.3.2:
		 * "If the DHCPREQUEST message contains a 'server identifier'
		 * option, the message is in response to a DHCPOFFER message."
		 *
		 * and
		 *
		 * "DHCPREQUEST generated during SELECTING state:
		 * Client inserts the address of the selected server in
		 * 'server identifier', 'ciaddr' MUST be zero, 'requested IP
		 * address' MUST be filled in with the yiaddr value from the
		 * chosen DHCPOFFER."
		 *
		 * NOTE: 'SELECTING' is meant to be 'REQUESTING' in the RFC
		 */
		if (!_dhcp_message_builder_append(&builder,
					L_DHCP_OPTION_SERVER_IDENTIFIER,
					4, &client->lease->server_address)) {
			CLIENT_WARN("Failed to append server ID");
			return -EINVAL;
		}

		if (!_dhcp_message_builder_append(&builder,
					L_DHCP_OPTION_REQUESTED_IP_ADDRESS,
					4, &client->lease->address)) {
			CLIENT_WARN("Failed to append requested IP");
			return -EINVAL;
		}

		break;
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		request->ciaddr = client->lease->address;
		break;

	case DHCP_STATE_INIT:
	case DHCP_STATE_SELECTING:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		return -EINVAL;
	}

	if (client->hostname) {
		if (!_dhcp_message_builder_append(&builder,
						L_DHCP_OPTION_HOST_NAME,
						strlen(client->hostname),
						client->hostname)) {
			CLIENT_WARN("Failed to append host name");
			return -EINVAL;
		}
	}

	_dhcp_message_builder_finalize(&builder, &len);

	/*
	 * RFC2131, Section 4.1:
	 * "DHCP clients MUST use the IP address provided in the
	 * 'server identifier' option for any unicast requests to the DHCP
	 * server.
	 */
	if (client->state == DHCP_STATE_RENEWING)
		return dhcp_client_send_unicast(client, request, len);

	return client->transport->l2_send(client->transport,
					INADDR_ANY, DHCP_PORT_CLIENT,
					INADDR_BROADCAST, DHCP_PORT_SERVER,
					NULL, request, len);
}

static void dhcp_client_send_release(struct l_dhcp_client *client)
{
	struct dhcp_message_builder builder;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, request);
	int err;
	struct sockaddr_in si;

	CLIENT_DEBUG("");

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = L_CPU_TO_BE16(DHCP_PORT_SERVER);
	si.sin_addr.s_addr = client->lease->server_address;

	request = (struct dhcp_message *) l_new(uint8_t, len);

	_dhcp_message_builder_init(&builder, request, len,
					DHCP_MESSAGE_TYPE_RELEASE);

	err = client_message_init(client, request, &builder);
	if (err < 0)
		return;

	request->ciaddr = client->lease->address;

	if (!_dhcp_message_builder_append(&builder,
					L_DHCP_OPTION_SERVER_IDENTIFIER,
					4, &client->lease->server_address)) {
		CLIENT_WARN("Failed to append server ID");
		return;
	}

	_dhcp_message_builder_finalize(&builder, &len);

	dhcp_client_send_unicast(client, request, len);
}

static void dhcp_client_timeout_resend(struct l_timeout *timeout,
								void *user_data)
{
	struct l_dhcp_client *client = user_data;
	struct l_dhcp_lease *lease = client->lease;
	unsigned int next_timeout = 0;
	int r;

	CLIENT_DEBUG("");

	switch (client->state) {
	case DHCP_STATE_SELECTING:
		r = dhcp_client_send_discover(client);
		if (r < 0) {
			CLIENT_WARN("Sending discover failed: %s",
								strerror(-r));
			goto error;
		}

		break;
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_REBINDING:
		r = dhcp_client_send_request(client);
		if (r < 0) {
			CLIENT_WARN("Sending Request failed: %s",
								strerror(-r));
			goto error;
		}

		break;
	case DHCP_STATE_INIT:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	}

	switch (client->state) {
	case DHCP_STATE_RENEWING:
		next_timeout = dhcp_rebind_renew_retry_time(lease->bound_time,
								lease->t2);
		break;
	case DHCP_STATE_REBINDING:
		next_timeout = dhcp_rebind_renew_retry_time(lease->bound_time,
							lease->lifetime);
		break;
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_SELECTING:
		/*
		 * RFC 2131 Section 4.1:
		 * "The retransmission delay SHOULD be doubled with subsequent
		 * retransmissions up to a maximum of 64 seconds.
		 */
		if (client->attempt < client->max_attempts) {
			next_timeout = minsize(2 << client->attempt++, 64);
			break;
		}

		CLIENT_DEBUG("Max request/discover attempts reached");

		dhcp_client_event_notify(client,
				L_DHCP_CLIENT_EVENT_MAX_ATTEMPTS_REACHED);
		return;
	case DHCP_STATE_INIT:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	}

	if (next_timeout)
		l_timeout_modify_ms(timeout, dhcp_fuzz_secs(next_timeout));

	return;

error:
	l_dhcp_client_stop(client);
}

static void dhcp_client_lease_expired(struct l_timeout *timeout,
							void *user_data)
{
	struct l_dhcp_client *client = user_data;

	CLIENT_DEBUG("");

	l_dhcp_client_stop(client);
	dhcp_client_event_notify(client, L_DHCP_CLIENT_EVENT_LEASE_EXPIRED);
}

static void dhcp_client_t2_expired(struct l_timeout *timeout, void *user_data)
{
	struct l_dhcp_client *client = user_data;
	uint32_t next_timeout = client->lease->lifetime - client->lease->t2;

	CLIENT_DEBUG("");

	/*
	 * If we got here, then resend_timeout is active, with a timeout
	 * set originally for ~60 seconds.  So we simply set the new state
	 * and wait for the timer to fire
	 */
	CLIENT_ENTER_STATE(DHCP_STATE_REBINDING);

	l_timeout_modify_ms(client->timeout_lease,
				dhcp_fuzz_secs(next_timeout));
	l_timeout_set_callback(client->timeout_lease,
				dhcp_client_lease_expired, client, NULL);
}

static void dhcp_client_t1_expired(struct l_timeout *timeout, void *user_data)
{
	struct l_dhcp_client *client = user_data;
	uint32_t next_timeout;
	int r;

	CLIENT_DEBUG("");

	CLIENT_ENTER_STATE(DHCP_STATE_RENEWING);
	client->attempt = 1;

	r = dhcp_client_send_request(client);
	if  (r < 0) {
		CLIENT_WARN("Sending request failed: %s", strerror(-r));
		goto error;
	}

	next_timeout = client->lease->t2 - client->lease->t1;
	l_timeout_modify_ms(client->timeout_lease,
						dhcp_fuzz_secs(next_timeout));
	l_timeout_set_callback(client->timeout_lease, dhcp_client_t2_expired,
				client, NULL);

	next_timeout = dhcp_rebind_renew_retry_time(client->lease->bound_time,
							client->lease->t2);
	client->timeout_resend =
		l_timeout_create_ms(dhcp_fuzz_secs(next_timeout),
					dhcp_client_timeout_resend,
					client, NULL);
	return;

error:
	l_dhcp_client_stop(client);
}

static void dhcp_client_address_add_cb(int error, uint16_t type,
						const void *data, uint32_t len,
						void *user_data)
{
	struct l_dhcp_client *client = user_data;

	client->rtnl_add_cmdid = 0;

	if (error < 0 && error != -EEXIST) {
		l_rtnl_address_free(client->rtnl_configured_address);
		client->rtnl_configured_address = NULL;
		CLIENT_WARN("Unable to set address on ifindex: %u: %d(%s)",
				client->ifindex, error,
				strerror(-error));
		return;
	}
}

static int dhcp_client_receive_ack(struct l_dhcp_client *client,
					const uint8_t *saddr,
					const struct dhcp_message *ack,
					size_t len, uint64_t timestamp)
{
	struct dhcp_message_iter iter;
	struct l_dhcp_lease *lease;
	int r;

	CLIENT_DEBUG("");

	if (ack->yiaddr == 0)
		return -ENOMSG;

	if (!_dhcp_message_iter_init(&iter, ack, len))
		return -EINVAL;

	lease = _dhcp_lease_parse_options(&iter);
	if (!lease) {
		CLIENT_WARN("Failed to parse DHCP options.");

		return -ENOMSG;
	}

	lease->address = ack->yiaddr;

	if (saddr)
		memcpy(lease->server_mac, saddr, ETH_ALEN);

	r = L_DHCP_CLIENT_EVENT_LEASE_RENEWED;

	if (client->lease) {
		if (client->lease->subnet_mask != lease->subnet_mask ||
				client->lease->address != lease->address ||
				client->lease->router != lease->router)
			r = L_DHCP_CLIENT_EVENT_IP_CHANGED;

		_dhcp_lease_free(client->lease);
	}

	client->lease = lease;

	/* In case this is an initial request, override to LEASE_OBTAINED */
	if (client->state == DHCP_STATE_REQUESTING ||
			client->state == DHCP_STATE_REBOOTING)
		r = L_DHCP_CLIENT_EVENT_LEASE_OBTAINED;

	if (client->rtnl) {
		struct l_rtnl_address *a;
		L_AUTO_FREE_VAR(char *, ip) =
			l_dhcp_lease_get_address(client->lease);
		uint8_t prefix_len;
		uint32_t l = l_dhcp_lease_get_lifetime(client->lease);
		L_AUTO_FREE_VAR(char *, broadcast) =
				l_dhcp_lease_get_broadcast(client->lease);
		uint64_t et = timestamp + l * L_USEC_PER_SEC;

		prefix_len = l_dhcp_lease_get_prefix_length(client->lease);
		if (!prefix_len)
			prefix_len = 24;

		a = l_rtnl_address_new(ip, prefix_len);
		l_rtnl_address_set_noprefixroute(a, true);
		l_rtnl_address_set_lifetimes(a, l, l);
		l_rtnl_address_set_expiry(a, et, et);
		l_rtnl_address_set_broadcast(a, broadcast);

		client->rtnl_add_cmdid =
			l_rtnl_ifaddr_add(client->rtnl, client->ifindex, a,
						dhcp_client_address_add_cb,
						client, NULL);
		if (client->rtnl_add_cmdid)
			client->rtnl_configured_address = a;
		else {
			CLIENT_WARN("Configuring address via RTNL failed");
			l_rtnl_address_free(a);
		}
	}

	return r;
}

static int dhcp_client_receive_offer(struct l_dhcp_client *client,
					const struct dhcp_message *offer,
					size_t len)
{
	struct dhcp_message_iter iter;
	struct l_dhcp_lease *lease;

	CLIENT_DEBUG("");

	if (offer->yiaddr == 0)
		return -ENOMSG;

	if (!_dhcp_message_iter_init(&iter, offer, len))
		return -EINVAL;

	lease = _dhcp_lease_parse_options(&iter);
	if (!lease)
		return -ENOMSG;

	/*
	 * Received another offer. In the case of multiple DHCP servers we want
	 * to ignore it and continue using the first offer. If this is from the
	 * same server its likely a buggy DHCP implementation and we should
	 * use the last offer it sends.
	 */
	if (client->lease) {
		if (client->lease->server_address != lease->server_address) {
			_dhcp_lease_free(lease);
			return -ENOMSG;
		}

		CLIENT_INFO("Server sent another offer, using it instead");

		_dhcp_lease_free(client->lease);
	}

	client->lease = lease;

	client->lease->address = offer->yiaddr;

	return 0;
}

static bool dhcp_client_handle_offer(struct l_dhcp_client *client,
					const struct dhcp_message *message,
					size_t len)
{
	if (dhcp_client_receive_offer(client, message, len) < 0)
		return false;

	CLIENT_ENTER_STATE(DHCP_STATE_REQUESTING);
	client->attempt = 1;

	if (dhcp_client_send_request(client) < 0) {
		l_dhcp_client_stop(client);

		return false;
	}

	l_timeout_modify_ms(client->timeout_resend, dhcp_fuzz_secs(4));

	return true;
}

static void dhcp_client_rx_message(const void *data, size_t len, void *userdata,
					const uint8_t *saddr,
					uint64_t timestamp)
{
	struct l_dhcp_client *client = userdata;
	const struct dhcp_message *message = data;
	struct dhcp_message_iter iter;
	char buf[INET_ADDRSTRLEN];
	uint8_t msg_type = 0;
	uint8_t t, l;
	const void *v;
	int r, e;
	struct in_addr ia;
	enum l_dhcp_client_event event = L_DHCP_CLIENT_EVENT_LEASE_EXPIRED;

	CLIENT_DEBUG("");

	if (len < sizeof(struct dhcp_message))
		return;

	if (message->op != DHCP_OP_CODE_BOOTREPLY)
		return;

	if (L_BE32_TO_CPU(message->xid) != client->xid)
		return;

	if (memcmp(message->chaddr, client->addr, client->addr_len))
		return;

	if (!_dhcp_message_iter_init(&iter, message, len))
		return;

	while (_dhcp_message_iter_next(&iter, &t, &l, &v) && !msg_type) {
		switch (t) {
		case DHCP_OPTION_MESSAGE_TYPE:
			if (l == 1)
				msg_type = l_get_u8(v);
			break;
		}
	}

	switch (client->state) {
	case DHCP_STATE_INIT:
		return;
	case DHCP_STATE_SELECTING:
		if (msg_type == DHCP_MESSAGE_TYPE_ACK) {
			_dhcp_message_iter_init(&iter, message, len);

			while (_dhcp_message_iter_next(&iter, &t, &l, &v))
				if (t == DHCP_OPTION_RAPID_COMMIT) {
					CLIENT_ENTER_STATE(
							DHCP_STATE_REQUESTING);
					goto receive_rapid_commit;
				}
		}

		if (msg_type != DHCP_MESSAGE_TYPE_OFFER)
			return;

		if (!dhcp_client_handle_offer(client, message, len))
			return;

		break;
	case DHCP_STATE_REQUESTING:
		if (msg_type == DHCP_MESSAGE_TYPE_OFFER) {
			dhcp_client_handle_offer(client, message, len);
			return;
		}

		event = L_DHCP_CLIENT_EVENT_NO_LEASE;
		/* Fall through */
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
	receive_rapid_commit:
		if (msg_type == DHCP_MESSAGE_TYPE_NAK) {
			CLIENT_INFO("Received NAK, Stopping...");
			l_dhcp_client_stop(client);

			dhcp_client_event_notify(client, event);
			return;
		}

		if (msg_type != DHCP_MESSAGE_TYPE_ACK)
			return;

		r = dhcp_client_receive_ack(client, saddr, message, len,
						timestamp);
		if (r < 0)
			return;

		CLIENT_ENTER_STATE(DHCP_STATE_BOUND);
		l_timeout_remove(client->timeout_resend);
		client->timeout_resend = NULL;
		client->lease->bound_time = timestamp;

		if (client->transport->bind) {
			e = client->transport->bind(client->transport,
						client->lease->address);
			if (e < 0) {
				CLIENT_WARN("Failed to bind dhcp socket. "
					"Error %d: %s", e, strerror(-e));
			}
		}

		dhcp_client_event_notify(client, r);

		/*
		 * Start T1, once it expires we will start the T2 timer.  If
		 * we renew the lease, we will end up back here.
		 *
		 * RFC2131, Section 4.4.5 states:
		 * "Times T1 and T2 SHOULD be chosen with some random "fuzz"
		 * around a fixed value, to avoid synchronization of client
		 * reacquisition."
		 */
		l_timeout_remove(client->timeout_lease);
		client->timeout_lease = NULL;

		/* Infinite lease, no need to start t1 */
		if (client->lease->lifetime != 0xffffffffu) {
			uint32_t next_timeout =
					dhcp_fuzz_secs(client->lease->t1);

			CLIENT_INFO("T1 expiring in %u ms", next_timeout);
			client->timeout_lease =
				l_timeout_create_ms(next_timeout,
							dhcp_client_t1_expired,
							client, NULL);
		}

		/* ACD is already running, no need to re-announce */
		if (client->acd)
			break;

		client->acd = l_acd_new(client->ifindex);

		if (client->debug_handler && client->debug_level == L_LOG_DEBUG)
			l_acd_set_debug(client->acd, client->debug_handler,
					client->debug_data,
					client->debug_destroy);

		/*
		 * TODO: There is no mechanism yet to deal with IPs leased by
		 * the DHCP server which conflict with other devices. For now
		 * the ACD object is being initialized to defend infinitely
		 * which is effectively no different than the non-ACD behavior
		 * (ignore conflicts and continue using address). The only
		 * change is that announcements will be sent if conflicts are
		 * found.
		 */
		l_acd_set_defend_policy(client->acd,
						L_ACD_DEFEND_POLICY_INFINITE);
		l_acd_set_skip_probes(client->acd, true);

		ia.s_addr = client->lease->address;
		inet_ntop(AF_INET, &ia, buf, INET_ADDRSTRLEN);

		/* For unit testing we don't want this to be a fatal error */
		if (!l_acd_start(client->acd, buf)) {
			CLIENT_WARN("Failed to start ACD on %s, continuing",
						buf);
			l_acd_destroy(client->acd);
			client->acd = NULL;
		}

		break;
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	}
}

LIB_EXPORT struct l_dhcp_client *l_dhcp_client_new(uint32_t ifindex)
{
	struct l_dhcp_client *client;

	client = l_new(struct l_dhcp_client, 1);

	client->state = DHCP_STATE_INIT;
	client->ifindex = ifindex;
	client->max_attempts = CLIENT_MAX_ATTEMPT_LIMIT;

	/* Enable these options by default */
	dhcp_enable_option(client, L_DHCP_OPTION_SUBNET_MASK);
	dhcp_enable_option(client, L_DHCP_OPTION_ROUTER);
	dhcp_enable_option(client, L_DHCP_OPTION_HOST_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME_SERVER);
	dhcp_enable_option(client, L_DHCP_OPTION_NTP_SERVERS);

	return client;
}

LIB_EXPORT void l_dhcp_client_destroy(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return;

	if (client->state != DHCP_STATE_INIT)
		l_dhcp_client_stop(client);

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	_dhcp_transport_free(client->transport);
	l_free(client->ifname);
	l_free(client->hostname);

	l_free(client);
}

LIB_EXPORT bool l_dhcp_client_add_request_option(struct l_dhcp_client *client,
								uint8_t option)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	switch (option) {
	case DHCP_OPTION_PAD:
	case DHCP_OPTION_END:
	case DHCP_OPTION_OVERLOAD:
	case DHCP_OPTION_MESSAGE_TYPE:
	case DHCP_OPTION_PARAMETER_REQUEST_LIST:
		return false;
	}

	dhcp_enable_option(client, option);

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_address(struct l_dhcp_client *client,
						uint8_t type,
						const uint8_t *addr,
						size_t addr_len)
{
	if (unlikely(!client))
		return false;

	switch (type) {
	case ARPHRD_ETHER:
		if (addr_len != ETH_ALEN)
			return false;
		break;
	default:
		return false;
	}

	client->addr_len = addr_len;
	memcpy(client->addr, addr, addr_len);
	client->addr_type = type;

	client->have_addr = true;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_interface_name(struct l_dhcp_client *client,
							const char *ifname)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	l_free(client->ifname);
	client->ifname = l_strdup(ifname);

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_hostname(struct l_dhcp_client *client,
						const char *hostname)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (!hostname)
		goto done;

	if (client->hostname && !strcmp(client->hostname, hostname))
		return true;

done:
	l_free(client->hostname);
	client->hostname = l_strdup(hostname);

	return true;
}

bool _dhcp_client_set_transport(struct l_dhcp_client *client,
					struct dhcp_transport *transport)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (client->transport)
		_dhcp_transport_free(client->transport);

	client->transport = transport;
	return true;
}

struct dhcp_transport *_dhcp_client_get_transport(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return NULL;

	return client->transport;
}


void _dhcp_client_override_xid(struct l_dhcp_client *client, uint32_t xid)
{
	client->override_xid = true;
	client->xid = xid;
}

LIB_EXPORT const struct l_dhcp_lease *l_dhcp_client_get_lease(
					const struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return NULL;

	return client->lease;
}

LIB_EXPORT bool l_dhcp_client_start(struct l_dhcp_client *client)
{
	int err;

	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (!client->have_addr) {
		uint8_t mac[6];

		if (!l_net_get_mac_address(client->ifindex, mac))
			return false;

		l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6);
	}

	if (!client->ifname) {
		client->ifname = l_net_get_name(client->ifindex);

		if (!client->ifname)
			return false;
	}

	if (!client->transport) {
		client->transport =
			_dhcp_default_transport_new(client->ifindex,
							client->ifname,
							DHCP_PORT_CLIENT);

		if (!client->transport)
			return false;
	}

	if (!client->override_xid)
		l_getrandom(&client->xid, sizeof(client->xid));

	if (client->transport->open)
		if (client->transport->open(client->transport,
							client->xid) < 0)
			return false;

	_dhcp_transport_set_rx_callback(client->transport,
						dhcp_client_rx_message,
						client);

	client->start_t = l_time_now();

	err = dhcp_client_send_discover(client);
	if (err < 0)
		return false;

	client->timeout_resend = l_timeout_create_ms(dhcp_fuzz_msecs(600),
						dhcp_client_timeout_resend,
						client, NULL);
	CLIENT_ENTER_STATE(DHCP_STATE_SELECTING);
	client->attempt = 1;

	return true;
}

LIB_EXPORT bool l_dhcp_client_stop(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return false;

	/*
	 * RFC 2131 Section 4.4.6
	 * "If the client no longer requires use of its assigned network address
	 * (e.g., the client is gracefully shut down), the client sends a
	 * DHCPRELEASE message to the server.""
	 */
	if (client->state == DHCP_STATE_BOUND ||
			client->state == DHCP_STATE_RENEWING ||
			client->state == DHCP_STATE_REBINDING)
		dhcp_client_send_release(client);

	if (client->rtnl_add_cmdid) {
		l_netlink_cancel(client->rtnl, client->rtnl_add_cmdid);
		client->rtnl_add_cmdid = 0;
	}

	if (client->rtnl_configured_address) {
		l_rtnl_ifaddr_delete(client->rtnl, client->ifindex,
					client->rtnl_configured_address,
					NULL, NULL, NULL);
		l_rtnl_address_free(client->rtnl_configured_address);
		client->rtnl_configured_address = NULL;
	}

	l_timeout_remove(client->timeout_resend);
	client->timeout_resend = NULL;

	l_timeout_remove(client->timeout_lease);
	client->timeout_lease = NULL;

	if (client->transport && client->transport->close)
		client->transport->close(client->transport);

	client->start_t = 0;
	CLIENT_ENTER_STATE(DHCP_STATE_INIT);

	_dhcp_lease_free(client->lease);
	client->lease = NULL;

	if (client->acd) {
		l_acd_destroy(client->acd);
		client->acd = NULL;
	}

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_event_handler(struct l_dhcp_client *client,
					l_dhcp_client_event_cb_t handler,
					void *userdata,
					l_dhcp_destroy_cb_t destroy)
{
	if (unlikely(!client))
		return false;

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	client->event_handler = handler;
	client->event_data = userdata;
	client->event_destroy = destroy;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_debug(struct l_dhcp_client *client,
						l_dhcp_debug_cb_t function,
						void *user_data,
						l_dhcp_destroy_cb_t destroy,
						int priority)
{
	if (unlikely(!client))
		return false;

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	client->debug_handler = function;
	client->debug_destroy = destroy;
	client->debug_data = user_data;
	client->debug_level = priority;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_rtnl(struct l_dhcp_client *client,
					struct l_netlink *rtnl)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	client->rtnl = rtnl;
	return true;
}

LIB_EXPORT bool l_dhcp_client_set_max_attempts(struct l_dhcp_client *client,
						uint8_t attempts)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (attempts < CLIENT_MIN_ATTEMPT_LIMIT ||
				attempts > CLIENT_MAX_ATTEMPT_LIMIT)
		return false;

	client->max_attempts = attempts;

	return true;
}
