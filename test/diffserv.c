/**
 * Copyright (c) 2026 Jesse
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

#define BUFFER_SIZE 4096

#define MESSAGES_COUNT 5
static const char *messages[MESSAGES_COUNT] = {"cs0", "cs1", "af41", "ef", "cs7"};
static const int ds_values[MESSAGES_COUNT] = {0x00, 0x20, 0x88, 0xB8, 0xE0};

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static bool received1[MESSAGES_COUNT];
static bool received2[MESSAGES_COUNT];

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

static void mark_received(const char *data, size_t size, bool *received) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received: %s\n", buffer);
	for (int i = 0; i < MESSAGES_COUNT; ++i) {
		if (strcmp(buffer, messages[i]) == 0)
			received[i] = true;
	}
}

int test_diffserv() {
	juice_set_log_level(JUICE_LOG_LEVEL_INFO);

	// Agent 1: Create agent
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	// Agent 2: Create agent
	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);

	// Agent 1: Generate local description
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);

	// Agent 2: Receive description from agent 1
	juice_set_remote_description(agent2, sdp1);

	// Agent 2: Generate local description
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);

	// Agent 1: Receive description from agent 2
	juice_set_remote_description(agent1, sdp2);

	// Agent 1: Gather candidates (and send them to agent 2)
	juice_gather_candidates(agent1);
	sleep(2);

	// Agent 2: Gather candidates (and send them to agent 1)
	juice_gather_candidates(agent2);
	sleep(2);

	// -- Connection should be finished --

	bool success = juice_get_state(agent1) == JUICE_STATE_COMPLETED &&
	               juice_get_state(agent2) == JUICE_STATE_COMPLETED;

	if (success) {
		// Send datagrams with Diffserv values across the traffic classes, in both
		// directions. Sends must succeed whatever the platform support for marking is.
		for (int i = 0; i < MESSAGES_COUNT; ++i) {
			if (juice_send_diffserv(agent1, messages[i], strlen(messages[i]), ds_values[i]) < 0 ||
			    juice_send_diffserv(agent2, messages[i], strlen(messages[i]), ds_values[i]) < 0) {
				printf("Send failed with ds=0x%02X\n", ds_values[i]);
				success = false;
				break;
			}
		}
		sleep(1);

		for (int i = 0; i < MESSAGES_COUNT; ++i) {
			if (!received1[i] || !received2[i]) {
				printf("Datagram with ds=0x%02X was not received\n", ds_values[i]);
				success = false;
			}
		}
	}

	// Agent 1: destroy
	juice_destroy(agent1);

	// Agent 2: destroy
	juice_destroy(agent2);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

// Agent 1: on state changed
static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 1: %s\n", juice_state_to_string(state));
}

// Agent 2: on state changed
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 2: %s\n", juice_state_to_string(state));
}

// Agent 1: on local candidate gathered
static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	// Agent 2: Receive it from agent 1
	juice_add_remote_candidate(agent2, sdp);
}

// Agent 2: on local candidate gathered
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	// Agent 1: Receive it from agent 2
	juice_add_remote_candidate(agent1, sdp);
}

// Agent 1: on local candidates gathering done
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	juice_set_remote_gathering_done(agent2); // optional
}

// Agent 2: on local candidates gathering done
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	juice_set_remote_gathering_done(agent1); // optional
}

// Agent 1: on message received
static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	mark_received(data, size, received1);
}

// Agent 2: on message received
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	mark_received(data, size, received2);
}