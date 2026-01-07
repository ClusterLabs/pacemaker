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

#include <crm/cluster.h>            // pcmk_cluster_t

extern pcmk_cluster_t *based_cluster;

int based_cluster_connect(void);

#endif // BASED_COROSYNC__H
