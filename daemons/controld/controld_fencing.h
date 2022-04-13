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
#include <pacemaker-internal.h>     // crm_graph_t, pcmk__graph_action_t

// reaction to notification of local node being fenced
void set_fence_reaction(const char *reaction_s);

// stonith fail counts
void st_fail_count_reset(const char * target);
void update_stonith_max_attempts(const char* value);

// stonith API client
void controld_trigger_fencer_connect(void);
void controld_disconnect_fencer(bool destroy);
gboolean te_fence_node(crm_graph_t *graph, pcmk__graph_action_t *action);
bool controld_verify_stonith_watchdog_timeout(const char *value);

// stonith cleanup list
void add_stonith_cleanup(const char *target);
void remove_stonith_cleanup(const char *target);
void purge_stonith_cleanup(void);
void execute_stonith_cleanup(void);

// stonith history synchronization
void te_trigger_stonith_history_sync(bool long_timeout);
void te_cleanup_stonith_history_sync(stonith_t *st, bool free_timers);

#endif
