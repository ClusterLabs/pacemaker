/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_FENCING__H
#  define CONTROLD_FENCING__H

#include <stdbool.h>                // bool
#include <pacemaker-internal.h>     // pcmk__graph_t, pcmk__graph_action_t

void controld_configure_fencing(GHashTable *options);

// stonith fail counts
void st_fail_count_reset(const char * target);

// stonith API client
gboolean controld_timer_fencer_connect(gpointer user_data);
void controld_disconnect_fencer(bool destroy);
int controld_execute_fence_action(pcmk__graph_t *graph,
                                  pcmk__graph_action_t *action);
void controld_validate_fencing_watchdog_timeout(const char *value);

// Fencing cleanup list
void controld_remove_fencing_cleanup(const char *target);
void controld_purge_fencing_cleanup(void);
void controld_execute_fencing_cleanup(void);

// Fencing history synchronization
void controld_trigger_fencing_history_sync(bool long_timeout);
void controld_cleanup_fencing_history_sync(stonith_t *st, bool free_timers);

#endif
