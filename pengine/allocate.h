/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_PENGINE_COMPLEX_ALLOC__H
#  define CRM_PENGINE_COMPLEX_ALLOC__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/pengine/internal.h>
#  include <pengine.h>

struct resource_alloc_functions_s {
    GHashTable *(*merge_weights) (resource_t *, const char *, GHashTable *, const char *, float,
                                  enum pe_weights);
    node_t *(*allocate) (resource_t *, node_t *, pe_working_set_t *);
    void (*create_actions) (resource_t *, pe_working_set_t *);
     gboolean(*create_probe) (resource_t *, node_t *, action_t *, gboolean, pe_working_set_t *);
    void (*internal_constraints) (resource_t *, pe_working_set_t *);

    void (*rsc_colocation_lh) (resource_t *, resource_t *, rsc_colocation_t *);
    void (*rsc_colocation_rh) (resource_t *, resource_t *, rsc_colocation_t *);

    void (*rsc_location) (resource_t *, rsc_to_node_t *);

    enum pe_action_flags (*action_flags) (action_t *, node_t *);
    enum pe_graph_flags (*update_actions) (action_t *, action_t *, node_t *, enum pe_action_flags,
                                           enum pe_action_flags, enum pe_ordering);

    void (*expand) (resource_t *, pe_working_set_t *);
    void (*append_meta) (resource_t * rsc, xmlNode * xml);
};

extern GHashTable *rsc_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                     const char *attr, float factor, enum pe_weights flags);

extern GHashTable *clone_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                       const char *attr, float factor, enum pe_weights flags);

extern GHashTable *container_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                       const char *attr, float factor, enum pe_weights flags);

extern GHashTable *native_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                        const char *attr, float factor, enum pe_weights flags);

extern GHashTable *group_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                       const char *attr, float factor, enum pe_weights flags);

extern node_t *native_color(resource_t * rsc, node_t * preferred, pe_working_set_t * data_set);
extern void native_create_actions(resource_t * rsc, pe_working_set_t * data_set);
extern void native_internal_constraints(resource_t * rsc, pe_working_set_t * data_set);
extern void native_rsc_colocation_lh(resource_t * lh_rsc, resource_t * rh_rsc,
                                     rsc_colocation_t * constraint);
extern void native_rsc_colocation_rh(resource_t * lh_rsc, resource_t * rh_rsc,
                                     rsc_colocation_t * constraint);
extern void rsc_ticket_constraint(resource_t * lh_rsc, rsc_ticket_t * rsc_ticket,
                                  pe_working_set_t * data_set);
extern enum pe_action_flags native_action_flags(action_t * action, node_t * node);

extern void native_rsc_location(resource_t * rsc, rsc_to_node_t * constraint);
extern void native_expand(resource_t * rsc, pe_working_set_t * data_set);
extern gboolean native_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                                    gboolean force, pe_working_set_t * data_set);
extern void native_append_meta(resource_t * rsc, xmlNode * xml);

extern node_t *group_color(resource_t * rsc, node_t * preferred, pe_working_set_t * data_set);
extern void group_create_actions(resource_t * rsc, pe_working_set_t * data_set);
extern void group_internal_constraints(resource_t * rsc, pe_working_set_t * data_set);
extern void group_rsc_colocation_lh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern void group_rsc_colocation_rh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern enum pe_action_flags group_action_flags(action_t * action, node_t * node);
extern void group_rsc_location(resource_t * rsc, rsc_to_node_t * constraint);
extern void group_expand(resource_t * rsc, pe_working_set_t * data_set);
extern void group_append_meta(resource_t * rsc, xmlNode * xml);

extern node_t *container_color(resource_t * rsc, node_t * preferred, pe_working_set_t * data_set);
extern void container_create_actions(resource_t * rsc, pe_working_set_t * data_set);
extern void container_internal_constraints(resource_t * rsc, pe_working_set_t * data_set);
extern void container_rsc_colocation_lh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern void container_rsc_colocation_rh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern void container_rsc_location(resource_t * rsc, rsc_to_node_t * constraint);
extern enum pe_action_flags container_action_flags(action_t * action, node_t * node);
extern void container_expand(resource_t * rsc, pe_working_set_t * data_set);
extern gboolean container_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                                   gboolean force, pe_working_set_t * data_set);
extern void container_append_meta(resource_t * rsc, xmlNode * xml);

extern node_t *clone_color(resource_t * rsc, node_t * preferred, pe_working_set_t * data_set);
extern void clone_create_actions(resource_t * rsc, pe_working_set_t * data_set);
extern void clone_internal_constraints(resource_t * rsc, pe_working_set_t * data_set);
extern void clone_rsc_colocation_lh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern void clone_rsc_colocation_rh(resource_t * lh_rsc, resource_t * rh_rsc,
                                    rsc_colocation_t * constraint);
extern void clone_rsc_location(resource_t * rsc, rsc_to_node_t * constraint);
extern enum pe_action_flags clone_action_flags(action_t * action, node_t * node);
extern void clone_expand(resource_t * rsc, pe_working_set_t * data_set);
extern gboolean clone_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                                   gboolean force, pe_working_set_t * data_set);
extern void clone_append_meta(resource_t * rsc, xmlNode * xml);

void apply_master_prefs(resource_t *rsc);
node_t *color_promotable(resource_t *rsc, pe_working_set_t *data_set);
void create_promotable_actions(resource_t *rsc, pe_working_set_t *data_set);
void promote_demote_constraints(resource_t *rsc, pe_working_set_t *data_set);
void promotable_constraints(resource_t *rsc, pe_working_set_t *data_set);
void promotable_colocation_rh(resource_t *lh_rsc, resource_t *rh_rsc,
                              rsc_colocation_t *constraint);

/* extern resource_object_functions_t resource_variants[]; */
extern resource_alloc_functions_t resource_class_alloc_functions[];
extern gboolean is_active(rsc_to_node_t * cons);

extern gboolean unpack_rsc_order(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_colocation(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_location(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_ticket(xmlNode * xml_obj, pe_working_set_t * data_set);

void LogNodeActions(pe_working_set_t * data_set, gboolean terminal);
void LogActions(resource_t * rsc, pe_working_set_t * data_set, gboolean terminal);
void container_LogActions(resource_t * rsc, pe_working_set_t * data_set, gboolean terminal);

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

extern void rsc_stonith_ordering(resource_t * rsc, action_t * stonith_op,
                                 pe_working_set_t * data_set);

extern enum pe_graph_flags native_update_actions(action_t * first, action_t * then, node_t * node,
                                                 enum pe_action_flags flags,
                                                 enum pe_action_flags filter,
                                                 enum pe_ordering type);
extern enum pe_graph_flags group_update_actions(action_t * first, action_t * then, node_t * node,
                                                enum pe_action_flags flags,
                                                enum pe_action_flags filter, enum pe_ordering type);
extern enum pe_graph_flags container_update_actions(action_t * first, action_t * then, node_t * node,
                                                    enum pe_action_flags flags,
                                                    enum pe_action_flags filter, enum pe_ordering type);

gboolean update_action_flags(action_t * action, enum pe_action_flags flags, const char *source, int line);
gboolean update_action(action_t * action);
void complex_set_cmds(resource_t * rsc);

void clone_create_pseudo_actions(
    resource_t * rsc, GListPtr children, notify_data_t **start_notify, notify_data_t **stop_notify,  pe_working_set_t * data_set);

#endif
