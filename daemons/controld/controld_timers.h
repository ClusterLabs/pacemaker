/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_TIMERS__H
#  define CONTROLD_TIMERS__H

#  include <stdbool.h>              // bool
#  include <glib.h>                 // gboolean, gpointer, guint
#  include <controld_fsa.h>         // crmd_fsa_input

bool controld_init_fsa_timers(void);
void controld_free_fsa_timers(void);
void controld_configure_fsa_timers(GHashTable *options);

bool controld_stop_recheck_timer(void);
bool controld_stop_transition_timer(void);

void controld_start_recheck_timer(void);
void controld_start_transition_timer(void);
void controld_start_wait_timer(void);

bool controld_is_started_transition_timer(void);

guint controld_get_period_transition_timer(void);

void controld_reset_counter_election_timer(void);

void controld_shutdown_start_countdown(guint default_period_ms);

#endif
