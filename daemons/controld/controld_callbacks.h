/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_CALLBACKS__H
#  define CONTROLD_CALLBACKS__H

#include <crm/cluster.h>

void crmd_ha_msg_filter(xmlNode *msg);

void crmd_cib_connection_destroy(gpointer user_data);

gboolean crm_fsa_trigger(gpointer user_data);

void peer_update_callback(enum crm_status_type type, crm_node_t *node, const void *data);

#if SUPPORT_COROSYNC
gboolean crmd_connect_corosync(crm_cluster_t *cluster);
#endif

#endif
