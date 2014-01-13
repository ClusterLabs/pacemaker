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
#ifndef CRM_PENGINE_COMPLEX_ALLOC__H
#  define CRM_PENGINE_COMPLEX_ALLOC__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/pengine/internal.h>
#  include <pengine.h>

typedef struct notify_entry_s {
    resource_t *rsc;
    node_t *node;
} notify_entry_t;

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

action_t *pe_fence_op(node_t * node, const char *op, pe_working_set_t * data_set);

extern GHashTable *rsc_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                     const char *attr, float factor, enum pe_weights flags);

extern GHashTable *clone_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
                                       const char *attr, float factor, enum pe_weights flags);

extern GHashTable *master_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes,
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
extern void native_dump(resource_t * rsc, const char *pre_text, gboolean details);
extern void create_notify_element(resource_t * rsc, action_t * op,
                                  notify_data_t * n_data, pe_working_set_t * data_set);
extern gboolean native_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                                    gboolean force, pe_working_set_t * data_set);
extern void native_append_meta(resource_t * rsc, xmlNode * xml);

extern int group_num_allowed_nodes(resource_t * rsc);
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

extern int clone_num_allowed_nodes(resource_t * rsc);
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

extern gboolean master_unpack(resource_t * rsc, pe_working_set_t * data_set);
extern node_t *master_color(resource_t * rsc, node_t * preferred, pe_working_set_t * data_set);
extern void master_create_actions(resource_t * rsc, pe_working_set_t * data_set);
extern void master_internal_constraints(resource_t * rsc, pe_working_set_t * data_set);
extern void master_rsc_colocation_rh(resource_t * lh_rsc, resource_t * rh_rsc,
                                     rsc_colocation_t * constraint);
extern void master_append_meta(resource_t * rsc, xmlNode * xml);

/* extern resource_object_functions_t resource_variants[]; */
extern resource_alloc_functions_t resource_class_alloc_functions[];
extern gboolean is_active(rsc_to_node_t * cons);

extern gboolean native_constraint_violated(resource_t * rsc_lh, resource_t * rsc_rh,
                                           rsc_colocation_t * constraint);

extern gboolean unpack_rsc_to_attr(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_to_node(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_order(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_colocation(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_location(xmlNode * xml_obj, pe_working_set_t * data_set);

extern gboolean unpack_rsc_ticket(xmlNode * xml_obj, pe_working_set_t * data_set);

extern void LogActions(resource_t * rsc, pe_working_set_t * data_set, gboolean terminal);

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

extern notify_data_t *create_notification_boundaries(resource_t * rsc, const char *action,
                                                     action_t * start, action_t * end,
                                                     pe_working_set_t * data_set);

extern void collect_notification_data(resource_t * rsc, gboolean state, gboolean activity,
                                      notify_data_t * n_data);
extern gboolean expand_notification_data(notify_data_t * n_data);
extern void create_notifications(resource_t * rsc, notify_data_t * n_data,
                                 pe_working_set_t * data_set);
extern void free_notification_data(notify_data_t * n_data);
extern void rsc_reload(resource_t * rsc, pe_working_set_t * data_set);
extern void rsc_stonith_ordering(resource_t * rsc, action_t * stonith_op,
                                 pe_working_set_t * data_set);

extern enum pe_graph_flags native_update_actions(action_t * first, action_t * then, node_t * node,
                                                 enum pe_action_flags flags,
                                                 enum pe_action_flags filter,
                                                 enum pe_ordering type);
extern enum pe_graph_flags group_update_actions(action_t * first, action_t * then, node_t * node,
                                                enum pe_action_flags flags,
                                                enum pe_action_flags filter, enum pe_ordering type);
extern enum pe_graph_flags clone_update_actions(action_t * first, action_t * then, node_t * node,
                                                enum pe_action_flags flags,
                                                enum pe_action_flags filter, enum pe_ordering type);

static inline gboolean
update_action_flags(action_t * action, enum pe_action_flags flags)
{
    gboolean changed = FALSE;
    gboolean clear = is_set(flags, pe_action_clear);
    enum pe_action_flags last = action->flags;

    if (clear) {
        pe_clear_action_bit(action, flags);
    } else {
        pe_set_action_bit(action, flags);
    }

    if (last != action->flags) {
        changed = TRUE;
        clear_bit(flags, pe_action_clear);
        crm_trace("%s on %s: %sset flags 0x%.6x (was 0x%.6x, now 0x%.6x)",
                  action->uuid, action->node ? action->node->details->uname : "[none]",
                  clear ? "un-" : "", flags, last, action->flags);
    }

    return changed;
}

#endif
