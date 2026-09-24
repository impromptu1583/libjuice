/**
 * Copyright (c) 2026 Jesse
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "qwave.h"
#include "log.h"
#include "thread.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(NO_QWAVE)

#include <qos2.h>

// Windows intentionally broke IP_TOS in favor of qWave: without administrator rights, DSCP
// can only be marked by adding sockets to policy-based flows, one flow per socket. Each
// traffic type selects a system-provisioned policy. See docs/qwave-diffserv.md for the
// researched behavior of the QOS2 API.

#define ENTRIES_INITIAL_SIZE 16
#define SYNTHETIC_DEST_PORT 9 // discard

typedef struct flow_entry {
	socket_t sock;
	QOS_FLOWID flow;
	QOS_TRAFFIC_TYPE type;
} flow_entry_t;

static HANDLE handle = NULL;
static mutex_t mutex = MUTEX_INITIALIZER;
static flow_entry_t *entries = NULL;
static int entries_size = 0;
static int entries_count = 0;

static QOS_TRAFFIC_TYPE traffic_type_from_ds(int ds) {
	if (ds < 0 || ds > 0xFF)
		return QOSTrafficTypeBestEffort;

	ds &= 0xFC; // ignore ECN bits
	if (ds == 0xB8) // EF
		return QOSTrafficTypeVoice;
	if (ds == 0x00) // CS0
		return QOSTrafficTypeBestEffort;
	if (ds <= 0x30) // CS1, AF1x
		return QOSTrafficTypeBackground;
	if (ds <= 0x78) // CS2, AF2x, CS3, AF3x
		return QOSTrafficTypeExcellentEffort;
	if (ds <= 0xA0) // CS4, AF4x, CS5
		return QOSTrafficTypeAudioVideo;
	return QOSTrafficTypeControl; // CS6, CS7
}

static flow_entry_t *find_entry(socket_t sock) {
	for (int i = 0; i < entries_count; ++i)
		if (entries[i].sock == sock)
			return entries + i;
	return NULL;
}

static int add_entry(socket_t sock, QOS_FLOWID flow, QOS_TRAFFIC_TYPE type) {
	if (entries_count == entries_size) {
		int new_size = entries_size > 0 ? entries_size * 2 : ENTRIES_INITIAL_SIZE;
		flow_entry_t *new_entries = realloc(entries, (size_t)new_size * sizeof(flow_entry_t));
		if (!new_entries) {
			JLOG_ERROR("Memory allocation failed for qWave flows array");
			return -1;
		}
		entries = new_entries;
		entries_size = new_size;
	}

	flow_entry_t *entry = entries + entries_count++;
	entry->sock = sock;
	entry->flow = flow;
	entry->type = type;
	return 0;
}

static void remove_entry(flow_entry_t *entry) {
	*entry = entries[--entries_count];
}

static int create_handle(void) { // mutex must be locked
	QOS_VERSION version;
	version.MajorVersion = 1;
	version.MinorVersion = 0;
	if (!QOSCreateHandle(&version, &handle)) {
		handle = NULL;
		JLOG_INFO("qWave is not available, errno=%d", (int)GetLastError());
		return -1;
	}
	return 0;
}

static void destroy_handle(void) { // mutex must be locked
	if (handle) {
		QOSCloseHandle(handle); // aborts all flows of the handle
		handle = NULL;
	}
	entries_count = 0; // the flows died with the handle
}

static int build_flow_dest(socket_t sock, const addr_record_t *dst, struct sockaddr_storage *dest,
                           socklen_t *len) {
	addr_record_t record = *dst;
	addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr, &record.len);

	addr_record_t name;
	name.len = sizeof(name.addr);
	name.socktype = SOCK_DGRAM;
	if (getsockname(sock, (struct sockaddr *)&name.addr, &name.len) < 0) {
		JLOG_WARN("getsockname failed, errno=%d", sockerrno);
		return -1;
	}

	if (record.addr.ss_family == name.addr.ss_family) {
		*dest = record.addr;
		*len = record.len;
		return 0;
	}

	// qWave rejects destinations whose family differs from the socket family. The
	// destination is ignored for tagging on UDP sockets, so for an IPv4 destination on a
	// dual-stack socket, use a synthetic IPv6 link-local address, which resolves on any
	// machine with IPv6 enabled.
	if (name.addr.ss_family == AF_INET6 && record.addr.ss_family == AF_INET) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dest;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(SYNTHETIC_DEST_PORT);
		sin6->sin6_addr.s6_addr[0] = 0xFE;
		sin6->sin6_addr.s6_addr[1] = 0x80;
		sin6->sin6_addr.s6_addr[15] = 0x01; // fe80::1
		*len = sizeof(*sin6);
		return 0;
	}

	return -1;
}

static int apply_diffserv(socket_t sock, const addr_record_t *dst, QOS_TRAFFIC_TYPE type,
                          DWORD *error) { // mutex must be locked
	flow_entry_t *entry = find_entry(sock);
	if (entry) {
		if (entry->type == type)
			return 0;

		if (QOSSetFlow(handle, entry->flow, QOSSetTrafficType, sizeof(type), &type, 0, NULL)) {
			entry->type = type;
			return 0;
		}
		*error = GetLastError();
		JLOG_DEBUG("QOSSetFlow failed, errno=%d, recreating the flow", (int)*error);
		QOSRemoveSocketFromFlow(handle, sock, entry->flow, 0);
		remove_entry(entry);
	} else if (type == QOSTrafficTypeBestEffort) {
		return 0; // no flow, no marking
	}

	struct sockaddr_storage dest;
	socklen_t dest_len;
	if (build_flow_dest(sock, dst, &dest, &dest_len) < 0)
		return -1;

	QOS_FLOWID flow = 0; // must be 0 on input
	if (!QOSAddSocketToFlow(handle, sock, (struct sockaddr *)&dest, type, QOS_NON_ADAPTIVE_FLOW,
	                        &flow)) {
		*error = GetLastError();
		JLOG_INFO("QOSAddSocketToFlow failed, errno=%d", (int)*error);
		return -1;
	}

	if (add_entry(sock, flow, type) < 0) {
		QOSRemoveSocketFromFlow(handle, sock, flow, 0);
		return -1;
	}
	return 0;
}

int qwave_set_diffserv(socket_t sock, const addr_record_t *dst, int ds) {
	QOS_TRAFFIC_TYPE type = traffic_type_from_ds(ds);
	DWORD error = 0;

	mutex_lock(&mutex);

	if (!handle && create_handle() < 0) {
		mutex_unlock(&mutex);
		return -1;
	}

	int ret = apply_diffserv(sock, dst, type, &error);
	if (ret < 0 &&
	    (error == ERROR_INVALID_HANDLE || error == ERROR_DEVICE_REINITIALIZATION_NEEDED)) {
		// The handle and its flows were invalidated, e.g., after standby. Retry once.
		JLOG_DEBUG("Recreating the qWave handle, errno=%d", (int)error);
		destroy_handle();
		if (create_handle() == 0)
			ret = apply_diffserv(sock, dst, type, &error);
	}

	mutex_unlock(&mutex);
	return ret;
}

void qwave_remove_socket(socket_t sock) {
	mutex_lock(&mutex);

	flow_entry_t *entry = find_entry(sock);
	if (entry) {
		QOS_FLOWID flow = entry->flow;
		remove_entry(entry);
		if (handle && !QOSRemoveSocketFromFlow(handle, sock, flow, 0)) {
			// Flows are not shared between sockets, so destroy the flow entirely
			QOSRemoveSocketFromFlow(handle, (SOCKET)0, flow, 0);
		}
	}

	mutex_unlock(&mutex);
}

#else // !_WIN32 || NO_QWAVE

int qwave_set_diffserv(socket_t sock, const addr_record_t *dst, int ds) {
	(void)sock;
	(void)dst;
	(void)ds;
	JLOG_INFO("IP Differentiated Services are not supported on this system");
	return -1;
}

void qwave_remove_socket(socket_t sock) {
	(void)sock;
}

#endif