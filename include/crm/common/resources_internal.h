/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES_INTERNAL__H
#define PCMK__CRM_COMMON_RESOURCES_INTERNAL__H

#include <glib.h>                       // gboolean, GList
#include <crm/common/resources.h>       // enum rsc_recovery_type
#include <crm/common/roles.h>           // enum rsc_role_e
#include <crm/common/scheduler_types.h> // pcmk_node_t, pcmk_resource_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Set resource flags
 *
 * \param[in,out] resource      Resource to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk_rsc_flags to set
 */
#define pcmk__set_rsc_flags(resource, flags_to_set) do {                    \
        (resource)->flags = pcmk__set_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_set), #flags_to_set);                                 \
    } while (0)

/*!
 * \internal
 * \brief Clear resource flags
 *
 * \param[in,out] resource        Resource to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk_rsc_flags to clear
 */
#define pcmk__clear_rsc_flags(resource, flags_to_clear) do {                \
        (resource)->flags = pcmk__clear_flags_as(__func__, __LINE__,        \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_clear), #flags_to_clear);                             \
    } while (0)

//! Resource object methods
typedef struct {
    /*!
     * \internal
     * \brief Parse variant-specific resource XML from CIB into struct members
     *
     * \param[in,out] rsc        Partially unpacked resource
     * \param[in,out] scheduler  Scheduler data
     *
     * \return TRUE if resource was unpacked successfully, otherwise FALSE
     */
    gboolean (*unpack)(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);

    /*!
     * \internal
     * \brief Search for a resource ID in a resource and its children
     *
     * \param[in] rsc      Search this resource and its children
     * \param[in] id       Search for this resource ID
     * \param[in] on_node  If not NULL, limit search to resources on this node
     * \param[in] flags    Group of enum pe_find flags
     *
     * \return Resource that matches search criteria if any, otherwise NULL
     */
    pcmk_resource_t *(*find_rsc)(pcmk_resource_t *rsc, const char *search,
                                 const pcmk_node_t *node, int flags);

    /*!
     * \internal
     * \brief Get value of a resource instance attribute
     *
     * \param[in,out] rsc        Resource to check
     * \param[in]     node       Node to use to evaluate rules
     * \param[in]     create     Ignored
     * \param[in]     name       Name of instance attribute to check
     * \param[in,out] scheduler  Scheduler data
     *
     * \return Value of requested attribute if available, otherwise NULL
     * \note The caller is responsible for freeing the result using free().
     */
    char *(*parameter)(pcmk_resource_t *rsc, pcmk_node_t *node, gboolean create,
                       const char *name, pcmk_scheduler_t *scheduler);

    /*!
     * \internal
     * \brief Check whether a resource is active
     *
     * \param[in] rsc  Resource to check
     * \param[in] all  If \p rsc is collective, all instances must be active
     *
     * \return TRUE if \p rsc is active, otherwise FALSE
     */
    gboolean (*active)(pcmk_resource_t *rsc, gboolean all);

    /*!
     * \internal
     * \brief Get resource's current or assigned role
     *
     * \param[in] rsc      Resource to check
     * \param[in] current  If TRUE, check current role, otherwise assigned role
     *
     * \return Current or assigned role of \p rsc
     */
    enum rsc_role_e (*state)(const pcmk_resource_t *rsc, gboolean current);

    /*!
     * \internal
     * \brief List nodes where a resource (or any of its children) is
     *
     * \param[in]  rsc      Resource to check
     * \param[out] list     List to add result to
     * \param[in]  current  If 0, list nodes where \p rsc is assigned;
     *                      if 1, where active; if 2, where active or pending
     *
     * \return If list contains only one node, that node, otherwise NULL
     */
    pcmk_node_t *(*location)(const pcmk_resource_t *rsc, GList **list,
                             int current);

    /*!
     * \internal
     * \brief Free all memory used by a resource
     *
     * \param[in,out] rsc  Resource to free
     */
    void (*free)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Increment cluster's instance counts for a resource
     *
     * Given a resource, increment its cluster's ninstances, disabled_resources,
     * and blocked_resources counts for the resource and its descendants.
     *
     * \param[in,out] rsc  Resource to count
     */
    void (*count)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Check whether a given resource is in a list of resources
     *
     * \param[in] rsc           Resource ID to check for
     * \param[in] only_rsc      List of resource IDs to check
     * \param[in] check_parent  If TRUE, check top ancestor as well
     *
     * \return TRUE if \p rsc, its top parent if requested, or '*' is in
     *         \p only_rsc, otherwise FALSE
     */
    gboolean (*is_filtered)(const pcmk_resource_t *rsc, GList *only_rsc,
                            gboolean check_parent);

    /*!
     * \internal
     * \brief Find a node (and optionally count all) where resource is active
     *
     * \param[in]  rsc          Resource to check
     * \param[out] count_all    If not NULL, set this to count of active nodes
     * \param[out] count_clean  If not NULL, set this to count of clean nodes
     *
     * \return A node where the resource is active, preferring the source node
     *         if the resource is involved in a partial migration, or a clean,
     *         online node if the resource's \c PCMK_META_REQUIRES is
     *         \c PCMK_VALUE_QUORUM or \c PCMK_VALUE_NOTHING, otherwise \c NULL.
     */
    pcmk_node_t *(*active_node)(const pcmk_resource_t *rsc,
                                unsigned int *count_all,
                                unsigned int *count_clean);

    /*!
     * \internal
     * \brief Get maximum resource instances per node
     *
     * \param[in] rsc  Resource to check
     *
     * \return Maximum number of \p rsc instances that can be active on one node
     */
    unsigned int (*max_per_node)(const pcmk_resource_t *rsc);
} pcmk__rsc_methods_t;

// Implementation of pcmk__resource_private_t
struct pcmk__resource_private {
    const pcmk__rsc_methods_t *fns;         // Resource object methods
};

const char *pcmk__multiply_active_text(enum rsc_recovery_type recovery);

/*!
 * \internal
 * \brief Get node where resource is currently active (if any)
 *
 * \param[in] rsc  Resource to check
 *
 * \return Node that \p rsc is active on, if any, otherwise NULL
 */
static inline pcmk_node_t *
pcmk__current_node(const pcmk_resource_t *rsc)
{
    if (rsc == NULL) {
        return NULL;
    }
    return rsc->private->fns->active_node(rsc, NULL, NULL);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES_INTERNAL__H
