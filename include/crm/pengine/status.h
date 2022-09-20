/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
#  include <crm/pengine/pe_types.h> // pe_node_t, pe_resource_t, etc.
#  include <crm/pengine/complex.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Cluster status and scheduling
 * \ingroup pengine
 */

const char *rsc_printable_id(pe_resource_t *rsc);
gboolean cluster_status(pe_working_set_t * data_set);
pe_working_set_t *pe_new_working_set(void);
void pe_free_working_set(pe_working_set_t *data_set);
void set_working_set_defaults(pe_working_set_t * data_set);
void cleanup_calculations(pe_working_set_t * data_set);
void pe_reset_working_set(pe_working_set_t *data_set);
pe_resource_t *pe_find_resource(GList *rsc_list, const char *id_rh);
pe_resource_t *pe_find_resource_with_flags(GList *rsc_list, const char *id, enum pe_find flags);
pe_node_t *pe_find_node(GList *node_list, const char *uname);
pe_node_t *pe_find_node_id(GList *node_list, const char *id);
pe_node_t *pe_find_node_any(GList *node_list, const char *id, const char *uname);
GList *find_operations(const char *rsc, const char *node, gboolean active_filter,
                         pe_working_set_t * data_set);
int pe_bundle_replicas(const pe_resource_t *rsc);
#if ENABLE_VERSIONED_ATTRS
pe_rsc_action_details_t *pe_rsc_action_details(pe_action_t *action);
#endif

/*!
 * \brief Check whether a resource is any clone type
 *
 * \param[in] rsc  Resource to check
 *
 * \return TRUE if resource is clone, FALSE otherwise
 */
static inline bool
pe_rsc_is_clone(const pe_resource_t *rsc)
{
    return rsc && (rsc->variant == pe_clone);
}

/*!
 * \brief Check whether a resource is a globally unique clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource is unique clone, false otherwise
 */
static inline bool
pe_rsc_is_unique_clone(const pe_resource_t *rsc)
{
    return pe_rsc_is_clone(rsc) && pcmk_is_set(rsc->flags, pe_rsc_unique);
}

/*!
 * \brief Check whether a resource is an anonymous clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return TRUE if resource is anonymous clone, FALSE otherwise
 */
static inline bool
pe_rsc_is_anon_clone(pe_resource_t *rsc)
{
    return pe_rsc_is_clone(rsc) && !pcmk_is_set(rsc->flags, pe_rsc_unique);
}

/*!
 * \brief Check whether a resource is part of a bundle
 *
 * \param[in] rsc  Resource to check
 *
 * \return TRUE if resource is part of a bundle, FALSE otherwise
 */
static inline bool
pe_rsc_is_bundled(pe_resource_t *rsc)
{
    return uber_parent(rsc)->parent != NULL;
}

#ifdef __cplusplus
}
#endif

#endif
