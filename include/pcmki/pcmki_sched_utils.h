/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_AUTILS__H
#  define PENGINE_AUTILS__H

#include <stdbool.h>                    // bool
#include <glib.h>                       // GList, GHashTable, gboolean, guint
#include <crm/lrmd.h>                   // lrmd_event_data_t
#include <crm/cib.h>                    // cib_t
#include <crm/pengine/pe_types.h>
#include <crm/pengine/internal.h>
#include <pcmki/pcmki_scheduler.h>

/* Constraint helper functions */
pcmk__colocation_t *invert_constraint(pcmk__colocation_t *constraint);

pe__location_t *copy_constraint(pe__location_t *constraint);

pe__location_t *rsc2node_new(const char *id, pe_resource_t *rsc, int weight,
                             const char *discovery_mode, pe_node_t *node,
                             pe_working_set_t *data_set);

void pcmk__new_colocation(const char *id, const char *node_attr, int score,
                          pe_resource_t *rsc_lh, pe_resource_t *rsc_rh,
                          const char *state_lh, const char *state_rh,
                          bool influence, pe_working_set_t *data_set);

GHashTable *pcmk__copy_node_table(GHashTable *nodes);
GList *pcmk__copy_node_list(const GList *list, bool reset);
GList *sort_nodes_by_weight(GList *nodes, pe_node_t *active_node,
                            pe_working_set_t *data_set);

extern gboolean can_run_resources(const pe_node_t * node);
extern gboolean native_assign_node(pe_resource_t *rsc, pe_node_t *chosen,
                                   gboolean force);
void native_deallocate(pe_resource_t * rsc);

extern void log_action(unsigned int log_level, const char *pre_text,
                       pe_action_t * action, gboolean details);

gboolean can_run_any(GHashTable * nodes);
pe_resource_t *find_compatible_child(pe_resource_t *local_child,
                                     pe_resource_t *rsc, enum rsc_role_e filter,
                                     gboolean current,
                                     pe_working_set_t *data_set);
pe_resource_t *find_compatible_child_by_node(pe_resource_t * local_child, pe_node_t * local_node, pe_resource_t * rsc,
                                             enum rsc_role_e filter, gboolean current);
gboolean is_child_compatible(pe_resource_t *child_rsc, pe_node_t * local_node, enum rsc_role_e filter, gboolean current);
bool assign_node(pe_resource_t * rsc, pe_node_t * node, gboolean force);
enum pe_action_flags summary_action_flags(pe_action_t * action, GList *children, pe_node_t * node);
enum action_tasks clone_child_action(pe_action_t * action);
int copies_per_node(pe_resource_t * rsc);

enum filter_colocation_res {
    influence_nothing = 0,
    influence_rsc_location,
    influence_rsc_priority,
};

extern enum filter_colocation_res
filter_colocation_constraint(pe_resource_t * rsc_lh, pe_resource_t * rsc_rh,
                             pcmk__colocation_t *constraint, gboolean preview);

extern int compare_capacity(const pe_node_t * node1, const pe_node_t * node2);
extern void calculate_utilization(GHashTable * current_utilization,
                                  GHashTable * utilization, gboolean plus);

extern void process_utilization(pe_resource_t * rsc, pe_node_t ** prefer, pe_working_set_t * data_set);
pe_action_t *create_pseudo_resource_op(pe_resource_t * rsc, const char *task, bool optional, bool runnable, pe_working_set_t *data_set);
pe_action_t *pe_cancel_op(pe_resource_t *rsc, const char *name,
                          guint interval_ms, pe_node_t *node,
                          pe_working_set_t *data_set);
pe_action_t *sched_shutdown_op(pe_node_t *node, pe_working_set_t *data_set);

xmlNode *pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *event,
                                 const char *caller_version, int target_rc,
                                 const char *node, const char *origin,
                                 int level);

#  define LOAD_STOPPED "load_stopped"

void modify_configuration(
    pe_working_set_t * data_set, cib_t *cib,
    const char *quorum, const char *watchdog, GList *node_up, GList *node_down, GList *node_fail,
    GList *op_inject, GList *ticket_grant, GList *ticket_revoke,
    GList *ticket_standby, GList *ticket_activate);

int run_simulation(pe_working_set_t * data_set, cib_t *cib, GList *op_fail_list);

pcmk__output_t *pcmk__new_logger(void);

bool pcmk__threshold_reached(pe_resource_t *rsc, pe_node_t *node,
                             pe_working_set_t *data_set,
                             pe_resource_t **failed);

#endif
