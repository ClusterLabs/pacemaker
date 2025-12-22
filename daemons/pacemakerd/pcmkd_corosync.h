/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

gboolean cluster_connect_cfg(void);
void cluster_disconnect_cfg(void);
gboolean pacemakerd_read_config(void);
bool pcmkd_corosync_connected(void);
void pcmkd_shutdown_corosync(void);
