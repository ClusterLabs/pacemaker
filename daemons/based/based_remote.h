/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_REMOTE__H
#define BASED_REMOTE__H

extern int remote_fd;
extern int remote_tls_fd;

void based_remote_init(void);
void based_drop_remote_clients(void);

#endif // BASED_REMOTE__H
