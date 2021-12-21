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
#include <pcmki/pcmki_transition.h>
#include <pacemaker.h>

/* Constraint helper functions */
pcmk__colocation_t *invert_constraint(pcmk__colocation_t *constraint);

pe__location_t *copy_constraint(pe__location_t *constraint);

GHashTable *pcmk__copy_node_table(GHashTable *nodes);
GList *pcmk__copy_node_list(const GList *list, bool reset);
GList *pcmk__sort_nodes(GList *nodes, pe_node_t *active_node,
                        pe_working_set_t *data_set);

bool pcmk__node_available(const pe_node_t *node);
bool pcmk__any_node_available(GHashTable *nodes);

pe_resource_t *find_compatible_child(pe_resource_t *local_child,
                                     pe_resource_t *rsc, enum rsc_role_e filter,
                                     gboolean current,
                                     pe_working_set_t *data_set);
pe_resource_t *find_compatible_child_by_node(pe_resource_t * local_child, pe_node_t * local_node, pe_resource_t * rsc,
                                             enum rsc_role_e filter, gboolean current);
gboolean is_child_compatible(pe_resource_t *child_rsc, pe_node_t * local_node, enum rsc_role_e filter, gboolean current);
enum pe_action_flags summary_action_flags(pe_action_t * action, GList *children, pe_node_t * node);
enum action_tasks clone_child_action(pe_action_t * action);
int copies_per_node(pe_resource_t * rsc);

xmlNode *pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *event,
                                 const char *caller_version, int target_rc,
                                 const char *node, const char *origin,
                                 int level);

#  define LOAD_STOPPED "load_stopped"

#endif
