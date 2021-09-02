/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__LIBPACEMAKER_PRIVATE__H
#  define PCMK__LIBPACEMAKER_PRIVATE__H

/* This header is for the sole use of libpacemaker, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <crm/pengine/pe_types.h> // pe_action_t, pe_node_t, pe_working_set_t

G_GNUC_INTERNAL
void pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__order_vs_unfence(pe_resource_t *rsc, pe_node_t *node,
                            pe_action_t *action, enum pe_ordering order,
                            pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__fence_guest(pe_node_t *node, pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__node_unfenced(pe_node_t *node);

G_GNUC_INTERNAL
bool pcmk__is_unfence_device(const pe_resource_t *rsc,
                             const pe_working_set_t *data_set);

G_GNUC_INTERNAL
pe_resource_t *pcmk__find_constraint_resource(GList *rsc_list, const char *id);

G_GNUC_INTERNAL
xmlNode *pcmk__expand_tags_in_sets(xmlNode *xml_obj,
                                   pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean pcmk__valid_resource_or_tag(pe_working_set_t *data_set, const char *id,
                                     pe_resource_t **rsc, pe_tag_t **tag);

G_GNUC_INTERNAL
gboolean pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                          gboolean convert_rsc, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__unpack_location(xmlNode *xml_obj, pe_working_set_t *data_set);

G_GNUC_INTERNAL
pe__location_t *pcmk__new_location(const char *id, pe_resource_t *rsc,
                                   int node_weight, const char *discover_mode,
                                   pe_node_t *foo_node,
                                   pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__unpack_colocation(xmlNode *xml_obj, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__new_colocation(const char *id, const char *node_attr, int score,
                          pe_resource_t *rsc_lh, pe_resource_t *rsc_rh,
                          const char *state_lh, const char *state_rh,
                          bool influence, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__block_colocated_starts(pe_action_t *action,
                                  pe_working_set_t *data_set);

/*!
 * \internal
 * \brief Create a new ordering between two resource actions
 *
 * \param[in] lh_rsc    Resource for 'first' action
 * \param[in] rh_rsc    Resource for 'then' action
 * \param[in] lh_task   Action key for 'first' action
 * \param[in] rh_task   Action key for 'then' action
 * \param[in] flags     Bitmask of enum pe_ordering flags
 * \param[in] data_set  Cluster working set to add ordering to
 */
#define pcmk__order_resource_actions(lh_rsc, lh_task, rh_rsc, rh_task,      \
                                     flags, data_set)                       \
    custom_action_order((lh_rsc), pcmk__op_key((lh_rsc)->id, (lh_task), 0), \
                       NULL,                                                \
                       (rh_rsc), pcmk__op_key((rh_rsc)->id, (rh_task), 0),  \
                       NULL, (flags), (data_set))

G_GNUC_INTERNAL
void pcmk__unpack_rsc_ticket(xmlNode *xml_obj, pe_working_set_t *data_set);

#endif // PCMK__LIBPACEMAKER_PRIVATE__H
