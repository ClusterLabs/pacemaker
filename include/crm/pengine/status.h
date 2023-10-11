/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_STATUS__H
#  define PCMK__CRM_PENGINE_STATUS__H

#  include <glib.h>                 // gboolean
#  include <stdbool.h>              // bool
#  include <crm/common/util.h>      // pcmk_is_set()
#  include <crm/common/iso8601.h>
#  include <crm/pengine/common.h>
#  include <crm/pengine/pe_types.h> // pcmk_node_t, pcmk_resource_t, etc.
#  include <crm/pengine/complex.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Cluster status and scheduling
 * \ingroup pengine
 */

const char *rsc_printable_id(const pcmk_resource_t *rsc);
gboolean cluster_status(pcmk_scheduler_t *data_set);
pcmk_scheduler_t *pe_new_working_set(void);
void pe_free_working_set(pcmk_scheduler_t *data_set);
void set_working_set_defaults(pcmk_scheduler_t *data_set);
void cleanup_calculations(pcmk_scheduler_t *data_set);
void pe_reset_working_set(pcmk_scheduler_t *data_set);
pcmk_resource_t *pe_find_resource(GList *rsc_list, const char *id_rh);
pcmk_resource_t *pe_find_resource_with_flags(GList *rsc_list, const char *id,
                                             enum pe_find flags);
pcmk_node_t *pe_find_node(const GList *node_list, const char *node_name);
pcmk_node_t *pe_find_node_id(const GList *node_list, const char *id);
pcmk_node_t *pe_find_node_any(const GList *node_list, const char *id,
                            const char *node_name);
GList *find_operations(const char *rsc, const char *node, gboolean active_filter,
                         pcmk_scheduler_t *data_set);
void calculate_active_ops(const GList *sorted_op_list, int *start_index,
                          int *stop_index);
int pe_bundle_replicas(const pcmk_resource_t *rsc);

/*!
 * \brief Check whether a resource is any clone type
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource is clone, false otherwise
 */
static inline bool
pe_rsc_is_clone(const pcmk_resource_t *rsc)
{
    return (rsc != NULL) && (rsc->variant == pcmk_rsc_variant_clone);
}

/*!
 * \brief Check whether a resource is a globally unique clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource is unique clone, false otherwise
 */
static inline bool
pe_rsc_is_unique_clone(const pcmk_resource_t *rsc)
{
    return pe_rsc_is_clone(rsc) && pcmk_is_set(rsc->flags, pcmk_rsc_unique);
}

/*!
 * \brief Check whether a resource is an anonymous clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource is anonymous clone, false otherwise
 */
static inline bool
pe_rsc_is_anon_clone(const pcmk_resource_t *rsc)
{
    return pe_rsc_is_clone(rsc) && !pcmk_is_set(rsc->flags, pcmk_rsc_unique);
}

/*!
 * \brief Check whether a resource is part of a bundle
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource is part of a bundle, false otherwise
 */
static inline bool
pe_rsc_is_bundled(const pcmk_resource_t *rsc)
{
    if (rsc == NULL) {
        return false;
    }
    while (rsc->parent != NULL) {
        rsc = rsc->parent;
    }
    return rsc->variant == pcmk_rsc_variant_bundle;
}

#ifdef __cplusplus
}
#endif

#endif
