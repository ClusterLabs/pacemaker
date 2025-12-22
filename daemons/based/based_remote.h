/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_REMOTE__H
#define BASED_REMOTE__H

#include <stdbool.h>

extern int remote_fd;
extern int remote_tls_fd;

int based_init_remote_listener(int port, bool encrypted);

#endif // BASED_REMOTE__H
