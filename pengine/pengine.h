/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PENGINE__H
#  define PENGINE__H

typedef struct rsc_to_node_s rsc_to_node_t;
typedef struct rsc_colocation_s rsc_colocation_t;
typedef struct rsc_ticket_s rsc_ticket_t;
typedef struct lrm_agent_s lrm_agent_t;
typedef struct order_constraint_s order_constraint_t;

#  include <glib.h>
#  include <crm/crm.h>
#  include <crm/common/iso8601.h>
#  include <crm/pengine/rules.h>
#  include <crm/pengine/common.h>
#  include <crm/pengine/status.h>

#  include <crm/pengine/complex.h>

enum pe_stop_fail {
    pesf_block,
    pesf_stonith,
    pesf_ignore
};

enum pe_weights {
    pe_weights_none = 0x0,
    pe_weights_init = 0x1,
    pe_weights_forward = 0x4,
    pe_weights_positive = 0x8,
    pe_weights_rollback = 0x10,
};

struct rsc_colocation_s {
    const char *id;
    const char *node_attribute;
    resource_t *rsc_lh;
    resource_t *rsc_rh;

    int role_lh;
    int role_rh;

    int score;
};

enum loss_ticket_policy_e {
    loss_ticket_stop,
    loss_ticket_demote,
    loss_ticket_fence,
    loss_ticket_freeze
};

struct rsc_ticket_s {
    const char *id;
    resource_t *rsc_lh;
    ticket_t *ticket;
    enum loss_ticket_policy_e loss_policy;

    int role_lh;
};

struct rsc_to_node_s {
    const char *id;
    resource_t *rsc_lh;

    enum rsc_role_e role_filter;
    GListPtr node_list_rh;      /* node_t* */
};

struct order_constraint_s {
    int id;
    enum pe_ordering type;

    void *lh_opaque;
    resource_t *lh_rsc;
    action_t *lh_action;
    char *lh_action_task;

    void *rh_opaque;
    resource_t *rh_rsc;
    action_t *rh_action;
    char *rh_action_task;

    /* (soon to be) variant specific */
/* 		int   lh_rsc_incarnation; */
/* 		int   rh_rsc_incarnation; */
};

extern gboolean stage0(pe_working_set_t * data_set);
extern gboolean probe_resources(pe_working_set_t * data_set);
extern gboolean stage2(pe_working_set_t * data_set);
extern gboolean stage3(pe_working_set_t * data_set);
extern gboolean stage4(pe_working_set_t * data_set);
extern gboolean stage5(pe_working_set_t * data_set);
extern gboolean stage6(pe_working_set_t * data_set);
extern gboolean stage7(pe_working_set_t * data_set);
extern gboolean stage8(pe_working_set_t * data_set);

extern gboolean summary(GListPtr resources);

extern gboolean unpack_constraints(xmlNode * xml_constraints, pe_working_set_t * data_set);

extern gboolean update_action_states(GListPtr actions);

extern gboolean shutdown_constraints(node_t * node, action_t * shutdown_op,
                                     pe_working_set_t * data_set);

extern gboolean stonith_constraints(node_t * node, action_t * stonith_op,
                                    pe_working_set_t * data_set);

extern int custom_action_order(resource_t * lh_rsc, char *lh_task, action_t * lh_action,
                               resource_t * rh_rsc, char *rh_task, action_t * rh_action,
                               enum pe_ordering type, pe_working_set_t * data_set);

extern int new_rsc_order(resource_t * lh_rsc, const char *lh_task,
                         resource_t * rh_rsc, const char *rh_task,
                         enum pe_ordering type, pe_working_set_t * data_set);

#  define order_start_start(rsc1,rsc2, type)				\
    new_rsc_order(rsc1, CRMD_ACTION_START, rsc2, CRMD_ACTION_START, type, data_set)
#  define order_stop_stop(rsc1, rsc2, type)				\
    new_rsc_order(rsc1, CRMD_ACTION_STOP, rsc2, CRMD_ACTION_STOP, type, data_set)

extern void graph_element_from_action(action_t * action, pe_working_set_t * data_set);

extern gboolean show_scores;
extern int scores_log_level;
extern gboolean show_utilization;
extern int utilization_log_level;
extern const char *transition_idle_timeout;

#endif
