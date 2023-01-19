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

void do_cib_updated(const char *event, xmlNode * msg);
void do_cib_replaced(const char *event, xmlNode * msg);

void controld_add_resource_history_xml_as(const char *func, xmlNode *parent,
                                          const lrmd_rsc_info_t *rsc,
                                          lrmd_event_data_t *op,
                                          const char *node_name);

#define controld_add_resource_history_xml(parent, rsc, op, node_name)   \
    controld_add_resource_history_xml_as(__func__, (parent), (rsc),     \
                                         (op), (node_name))

bool controld_record_pending_op(const char *node_name,
                                const lrmd_rsc_info_t *rsc,
                                lrmd_event_data_t *op);

void controld_update_resource_history(const char *node_name,
                                      const lrmd_rsc_info_t *rsc,
                                      lrmd_event_data_t *op, time_t lock_time);

void controld_delete_action_history(const lrmd_event_data_t *op);

void crmd_metadata(void);
void controld_trigger_config_as(const char *fn, int line);
void controld_election_init(const char *uname);
void controld_configure_election(GHashTable *options);
void controld_remove_voter(const char *uname);
void controld_election_fini(void);
void controld_stop_current_election_timeout(void);
void controld_disconnect_cib_manager(void);

#endif
