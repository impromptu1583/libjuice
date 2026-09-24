/**
 * Copyright (c) 2026 Jesse
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_QWAVE_H
#define JUICE_QWAVE_H

#include "addr.h"
#include "socket.h"

// Windows qWave (QOS2) Diffserv support. Compiled to no-ops on other platforms and when
// NO_QWAVE is defined.

int qwave_set_diffserv(socket_t sock, const addr_record_t *dst, int ds);
void qwave_remove_socket(socket_t sock); // release Diffserv state before closing the socket

#endif // JUICE_QWAVE_H