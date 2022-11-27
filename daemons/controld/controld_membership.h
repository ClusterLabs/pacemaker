/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef MEMBERSHIP__H
#  define MEMBERSHIP__H

#ifdef __cplusplus
extern "C" {
#endif

#include <crm/cluster/internal.h>

void post_cache_update(int instance);

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

void controld_destroy_failed_sync_table(void);
void controld_remove_failed_sync_node(const char *node_name);

#ifdef __cplusplus
}
#endif

#endif
