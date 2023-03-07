/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_CALLBACKS__H
#  define CONTROLD_CALLBACKS__H

#include <crm/cluster.h>

extern void crmd_ha_msg_filter(xmlNode * msg);

extern gboolean crm_fsa_trigger(gpointer user_data);

extern void peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data);

#endif
