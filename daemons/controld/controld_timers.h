/*
 * Copyright 2004-2019 the Pacemaker project contributors
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

typedef struct fsa_timer_s {
    guint source_id;            /* timer source id */
    int period_ms;              /* timer period */
    enum crmd_fsa_input fsa_input;
    gboolean (*callback) (gpointer data);
    bool log_error;
    int counter;
} fsa_timer_t;

extern fsa_timer_t *election_trigger;
extern fsa_timer_t *shutdown_escalation_timer;
extern fsa_timer_t *transition_timer;
extern fsa_timer_t *integration_timer;
extern fsa_timer_t *finalization_timer;
extern fsa_timer_t *wait_timer;
extern fsa_timer_t *recheck_timer;

gboolean crm_timer_stop(fsa_timer_t *timer);
gboolean crm_timer_start(fsa_timer_t *timer);
gboolean crm_timer_popped(gpointer data);
gboolean is_timer_started(fsa_timer_t *timer);

const char *get_timer_desc(fsa_timer_t * timer);

#endif
