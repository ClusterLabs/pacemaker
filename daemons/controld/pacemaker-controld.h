/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD__H
#  define CRMD__H

#include <controld_alerts.h>
#include <controld_callbacks.h>
#include <controld_cib.h>
#include <controld_fencing.h>
#include <controld_fsa.h>
#include <controld_globals.h>
#include <controld_timers.h>
#include <controld_lrm.h>
#include <controld_membership.h>
#include <controld_messages.h>
#include <controld_metadata.h>
#include <controld_throttle.h>
#include <controld_transition.h>
#include <controld_utils.h>

#  define controld_trigger_config()  \
    controld_trigger_config_as(__func__, __LINE__)

void crmd_metadata(void);
void controld_trigger_config_as(const char *fn, int line);
void controld_election_init(const char *uname);
void controld_configure_election(GHashTable *options);
void controld_remove_voter(const char *uname);
void controld_election_fini(void);
void controld_stop_current_election_timeout(void);

void set_join_state(const char *start_state, const char *node_name,
                    const char *node_uuid, bool remote);

#endif
