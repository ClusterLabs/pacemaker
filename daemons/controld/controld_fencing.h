/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_FENCING__H
#  define CONTROLD_FENCING__H

#include <stdbool.h>                // bool
#include <crm/transition.h>         // crm_graph_t, crm_action_t

extern crm_trigger_t *stonith_reconnect;
extern char *te_client_id;
extern stonith_t *stonith_api;

// stonith fail counts
void st_fail_count_reset(const char * target);
void update_stonith_max_attempts(const char* value);

// stonith API client
gboolean te_connect_stonith(gpointer user_data);
gboolean te_fence_node(crm_graph_t *graph, crm_action_t *action);

// stonith cleanup list
void add_stonith_cleanup(const char *target);
void remove_stonith_cleanup(const char *target);
void purge_stonith_cleanup(void);
void execute_stonith_cleanup(void);

// stonith history synchronization
void te_trigger_stonith_history_sync(void);

#endif
