/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_COROSYNC__H
#define BASED_COROSYNC__H

int based_cluster_connect(void);
void based_cluster_disconnect(void);
const char *based_cluster_node_name(void);

#endif // BASED_COROSYNC__H
