/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H
#  define PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/common/xml_internal.h>
#  include <crm/pengine/internal.h>
#  include <crm/common/xml.h>
#  include <pcmki/pcmki_scheduler.h>

void pcmk__native_merge_weights(pe_resource_t *rsc, const char *rhs,
                                GHashTable **nodes, const char *attr,
                                float factor, uint32_t flags);

void pcmk__group_merge_weights(pe_resource_t *rsc, const char *rhs,
                               GHashTable **nodes, const char *attr,
                               float factor, uint32_t flags);

pe_node_t *pcmk__native_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                 pe_working_set_t *data_set);
extern void native_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void native_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
extern enum pe_action_flags native_action_flags(pe_action_t * action, pe_node_t * node);

void native_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern void native_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern gboolean native_create_probe(pe_resource_t * rsc, pe_node_t * node, pe_action_t * complete,
                                    gboolean force, pe_working_set_t * data_set);
extern void native_append_meta(pe_resource_t * rsc, xmlNode * xml);
void pcmk__primitive_add_utilization(pe_resource_t *rsc,
                                     pe_resource_t *orig_rsc, GList *all_rscs,
                                     GHashTable *utilization);
void pcmk__primitive_shutdown_lock(pe_resource_t *rsc);

pe_node_t *pcmk__group_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                pe_working_set_t *data_set);
extern void group_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void group_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
extern enum pe_action_flags group_action_flags(pe_action_t * action, pe_node_t * node);
void group_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern void group_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void group_append_meta(pe_resource_t * rsc, xmlNode * xml);
void pcmk__group_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                                 GList *all_rscs, GHashTable *utilization);
void pcmk__group_shutdown_lock(pe_resource_t *rsc);

pe_node_t *pcmk__bundle_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                 pe_working_set_t *data_set);
void pcmk__bundle_create_actions(pe_resource_t *rsc,
                                 pe_working_set_t *data_set);
gboolean pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node,
                                   pe_action_t *complete, gboolean force,
                                   pe_working_set_t *data_set);
void pcmk__bundle_internal_constraints(pe_resource_t *rsc,
                                       pe_working_set_t *data_set);
void pcmk__bundle_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
enum pe_action_flags pcmk__bundle_action_flags(pe_action_t *action,
                                               pe_node_t *node);
void pcmk__bundle_expand(pe_resource_t *rsc, pe_working_set_t *data_set);
void pcmk__bundle_append_meta(pe_resource_t *rsc, xmlNode *xml);
void pcmk__bundle_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                                  GList *all_rscs, GHashTable *utilization);
void pcmk__bundle_shutdown_lock(pe_resource_t *rsc);

pe_node_t *pcmk__clone_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                pe_working_set_t *data_set);
extern void clone_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void clone_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
void clone_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern enum pe_action_flags clone_action_flags(pe_action_t * action, pe_node_t * node);
extern void clone_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern gboolean clone_create_probe(pe_resource_t * rsc, pe_node_t * node, pe_action_t * complete,
                                   gboolean force, pe_working_set_t * data_set);
extern void clone_append_meta(pe_resource_t * rsc, xmlNode * xml);
void pcmk__clone_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                                 GList *all_rscs, GHashTable *utilization);
void pcmk__clone_shutdown_lock(pe_resource_t *rsc);

void pcmk__add_promotion_scores(pe_resource_t *rsc);

enum pe_graph_flags native_update_actions(pe_action_t *first, pe_action_t *then,
                                          pe_node_t *node,
                                          enum pe_action_flags flags,
                                          enum pe_action_flags filter,
                                          enum pe_ordering type,
                                          pe_working_set_t *data_set);
enum pe_graph_flags group_update_actions(pe_action_t *first, pe_action_t *then,
                                         pe_node_t *node,
                                         enum pe_action_flags flags,
                                         enum pe_action_flags filter,
                                         enum pe_ordering type,
                                         pe_working_set_t *data_set);
enum pe_graph_flags pcmk__multi_update_actions(pe_action_t *first,
                                               pe_action_t *then,
                                               pe_node_t *node,
                                               enum pe_action_flags flags,
                                               enum pe_action_flags filter,
                                               enum pe_ordering type,
                                               pe_working_set_t *data_set);

void pcmk__log_transition_summary(const char *filename);
void clone_create_pseudo_actions(
    pe_resource_t * rsc, GList *children, notify_data_t **start_notify, notify_data_t **stop_notify,  pe_working_set_t * data_set);
#endif
