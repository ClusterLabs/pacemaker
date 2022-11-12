/*
 * Copyright 2004-2019 the Pacemaker project contributors
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
#include <controld_fencing.h>
#include <controld_fsa.h>
#include <controld_timers.h>
#include <controld_lrm.h>
#include <controld_membership.h>
#include <controld_messages.h>
#include <controld_metadata.h>
#include <controld_throttle.h>
#include <controld_transition.h>
#include <controld_utils.h>

extern GMainLoop *crmd_mainloop;
extern bool no_quorum_suicide_escalation;

void do_cib_updated(const char *event, xmlNode * msg);
void do_cib_replaced(const char *event, xmlNode * msg);
void crmd_metadata(void);
void controld_election_init(const char *uname);
void controld_remove_voter(const char *uname);
void controld_election_fini(void);
void controld_set_election_period(const char *value);
void controld_stop_current_election_timeout(void);
void controld_disconnect_cib_manager(void);

#endif
