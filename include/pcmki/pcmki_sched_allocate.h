/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef SCHED_ALLOCATE__H
#  define SCHED_ALLOCATE__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/pengine/internal.h>
#  include <pcmki/pcmki_scheduler.h>

struct resource_alloc_functions_s {
    GHashTable *(*merge_weights) (pe_resource_t *, const char *, GHashTable *, const char *, float,
                                  enum pe_weights);
    pe_node_t *(*allocate) (pe_resource_t *, pe_node_t *, pe_working_set_t *);
    void (*create_actions) (pe_resource_t *, pe_working_set_t *);
     gboolean(*create_probe) (pe_resource_t *, pe_node_t *, pe_action_t *, gboolean, pe_working_set_t *);
    void (*internal_constraints) (pe_resource_t *, pe_working_set_t *);

    void (*rsc_colocation_lh) (pe_resource_t *, pe_resource_t *,
                               pcmk__colocation_t *, pe_working_set_t *);
    void (*rsc_colocation_rh) (pe_resource_t *, pe_resource_t *,
                               pcmk__colocation_t *, pe_working_set_t *);

    void (*rsc_location) (pe_resource_t *, pe__location_t *);

    enum pe_action_flags (*action_flags) (pe_action_t *, pe_node_t *);
    enum pe_graph_flags (*update_actions) (pe_action_t *, pe_action_t *,
                                           pe_node_t *, enum pe_action_flags,
                                           enum pe_action_flags,
                                           enum pe_ordering,
                                           pe_working_set_t *data_set);

    void (*expand) (pe_resource_t *, pe_working_set_t *);
    void (*append_meta) (pe_resource_t * rsc, xmlNode * xml);
};

GHashTable *pcmk__native_merge_weights(pe_resource_t *rsc, const char *rhs,
                                       GHashTable *nodes, const char *attr,
                                       float factor, uint32_t flags);

GHashTable *pcmk__group_merge_weights(pe_resource_t *rsc, const char *rhs,
                                      GHashTable *nodes, const char *attr,
                                      float factor, uint32_t flags);

pe_node_t *pcmk__native_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                 pe_working_set_t *data_set);
extern void native_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void native_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
void native_rsc_colocation_lh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                              pcmk__colocation_t *constraint,
                              pe_working_set_t *data_set);
void native_rsc_colocation_rh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                              pcmk__colocation_t *constraint,
                              pe_working_set_t *data_set);
extern void rsc_ticket_constraint(pe_resource_t * lh_rsc, rsc_ticket_t * rsc_ticket,
                                  pe_working_set_t * data_set);
extern enum pe_action_flags native_action_flags(pe_action_t * action, pe_node_t * node);

void native_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern void native_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern gboolean native_create_probe(pe_resource_t * rsc, pe_node_t * node, pe_action_t * complete,
                                    gboolean force, pe_working_set_t * data_set);
extern void native_append_meta(pe_resource_t * rsc, xmlNode * xml);

pe_node_t *pcmk__group_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                pe_working_set_t *data_set);
extern void group_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void group_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
void group_rsc_colocation_lh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                             pcmk__colocation_t *constraint,
                             pe_working_set_t *data_set);
void group_rsc_colocation_rh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                             pcmk__colocation_t *constraint,
                             pe_working_set_t *data_set);
extern enum pe_action_flags group_action_flags(pe_action_t * action, pe_node_t * node);
void group_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern void group_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void group_append_meta(pe_resource_t * rsc, xmlNode * xml);

pe_node_t *pcmk__bundle_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                 pe_working_set_t *data_set);
void pcmk__bundle_create_actions(pe_resource_t *rsc,
                                 pe_working_set_t *data_set);
gboolean pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node,
                                   pe_action_t *complete, gboolean force,
                                   pe_working_set_t *data_set);
void pcmk__bundle_internal_constraints(pe_resource_t *rsc,
                                       pe_working_set_t *data_set);
void pcmk__bundle_rsc_colocation_lh(pe_resource_t *lh_rsc,
                                    pe_resource_t *rh_rsc,
                                    pcmk__colocation_t *constraint,
                                    pe_working_set_t *data_set);
void pcmk__bundle_rsc_colocation_rh(pe_resource_t *lh_rsc,
                                    pe_resource_t *rh_rsc,
                                    pcmk__colocation_t *constraint,
                                    pe_working_set_t *data_set);
void pcmk__bundle_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
enum pe_action_flags pcmk__bundle_action_flags(pe_action_t *action,
                                               pe_node_t *node);
void pcmk__bundle_expand(pe_resource_t *rsc, pe_working_set_t *data_set);
void pcmk__bundle_append_meta(pe_resource_t *rsc, xmlNode *xml);

pe_node_t *pcmk__clone_allocate(pe_resource_t *rsc, pe_node_t *preferred,
                                pe_working_set_t *data_set);
extern void clone_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set);
extern void clone_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set);
void clone_rsc_colocation_lh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                             pcmk__colocation_t *constraint,
                             pe_working_set_t *data_set);
void clone_rsc_colocation_rh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                             pcmk__colocation_t *constraint,
                             pe_working_set_t *data_set);
void clone_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
extern enum pe_action_flags clone_action_flags(pe_action_t * action, pe_node_t * node);
extern void clone_expand(pe_resource_t * rsc, pe_working_set_t * data_set);
extern gboolean clone_create_probe(pe_resource_t * rsc, pe_node_t * node, pe_action_t * complete,
                                   gboolean force, pe_working_set_t * data_set);
extern void clone_append_meta(pe_resource_t * rsc, xmlNode * xml);

void pcmk__add_promotion_scores(pe_resource_t *rsc);
pe_node_t *pcmk__set_instance_roles(pe_resource_t *rsc,
                                    pe_working_set_t *data_set);
void create_promotable_actions(pe_resource_t *rsc, pe_working_set_t *data_set);
void promote_demote_constraints(pe_resource_t *rsc, pe_working_set_t *data_set);
void promotable_constraints(pe_resource_t *rsc, pe_working_set_t *data_set);
void promotable_colocation_rh(pe_resource_t *lh_rsc, pe_resource_t *rh_rsc,
                              pcmk__colocation_t *constraint,
                              pe_working_set_t *data_set);

/* extern resource_object_functions_t resource_variants[]; */
extern resource_alloc_functions_t resource_class_alloc_functions[];

void LogNodeActions(pe_working_set_t * data_set);
void LogActions(pe_resource_t * rsc, pe_working_set_t * data_set);
void pcmk__bundle_log_actions(pe_resource_t *rsc, pe_working_set_t *data_set);

extern void rsc_stonith_ordering(pe_resource_t * rsc, pe_action_t * stonith_op,
                                 pe_working_set_t * data_set);

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

gboolean update_action(pe_action_t *action, pe_working_set_t *data_set);
void complex_set_cmds(pe_resource_t * rsc);
void pcmk__log_transition_summary(const char *filename);
void clone_create_pseudo_actions(
    pe_resource_t * rsc, GList *children, notify_data_t **start_notify, notify_data_t **stop_notify,  pe_working_set_t * data_set);
#endif
