/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_CALLBACKS__H
#  define CONTROLD_CALLBACKS__H

#include <crm/cluster/internal.h>

extern void crmd_ha_msg_filter(xmlNode * msg);

gboolean crm_fsa_trigger(void *user_data);

void peer_update_callback(enum pcmk__node_update type,
                          pcmk__node_status_t *node, const void *data);

#endif
