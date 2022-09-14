/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H
#  define PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H

#include <glib.h>            // GList
#include <crm/common/ipc.h>  // pcmk_ipc_api_t

#ifdef __cplusplus
extern "C" {
#endif

//! Possible types of attribute manager replies
enum pcmk__attrd_api_reply {
    pcmk__attrd_reply_unknown,
    pcmk__attrd_reply_query,
};

// Information passed with pcmk__attrd_reply_query
typedef struct {
    const char *node;
    const char *name;
    const char *value;
} pcmk__attrd_query_pair_t;

/*!
 * Attribute manager reply passed to event callback
 *
 * \note The pointers in the reply are only guaranteed to be meaningful for the
 *       execution of the callback; if the values are needed for later, the
 *       callback should copy them.
 */
typedef struct {
    enum pcmk__attrd_api_reply reply_type;

    union {
        // pcmk__attrd_reply_query
        GList *pairs;
    } data;
} pcmk__attrd_api_reply_t;

/*!
 * \internal
 * \brief Send a request to pacemaker-attrd to clear resource failure
 *
 * \param[in,out] api           pacemaker-attrd IPC object
 * \param[in]     node          Affect only this node (or NULL for all nodes)
 * \param[in]     resource      Name of resource to clear (or NULL for all)
 * \param[in]     operation     Name of operation to clear (or NULL for all)
 * \param[in]     interval_spec If operation is not NULL, its interval
 * \param[in]     user_name     ACL user to pass to pacemaker-attrd
 * \param[in]     options       Bitmask of pcmk__node_attr_opts
 *
 * \note If \p api is NULL, a new temporary connection will be created
 *       just for this operation and destroyed afterwards.  If \p api is
 *       not NULL but is not yet connected to pacemaker-attrd, the object
 *       will be connected for this operation and left connected afterwards.
 *       This allows for reusing an IPC connection.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_clear_failures(pcmk_ipc_api_t *api, const char *node,
                                   const char *resource, const char *operation,
                                   const char *interval_spec, const char *user_name,
                                   uint32_t options);

/*!
 * \internal
 *
 * \brief Delete a previously set attribute by setting its value to NULL
 *
 * \param[in,out] api      Connection to pacemaker-attrd (or NULL to use
 *                         a temporary new connection)
 * \param[in]     node     Delete attribute for this node (or NULL for local)
 * \param[in]     name     Attribute name
 * \param[in]     options  Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_delete(pcmk_ipc_api_t *api, const char *node, const char *name,
                           uint32_t options);

/*!
 * \internal
 * \brief Purge a node from pacemaker-attrd
 *
 * \param[in,out] api           pacemaker-attrd IPC object
 * \param[in]     node          Node to remove
 *
 * \note If \p api is NULL, a new temporary connection will be created
 *       just for this operation and destroyed afterwards.  If \p api is
 *       not NULL but is not yet connected to pacemaker-attrd, the object
 *       will be connected for this operation and left connected afterwards.
 *       This allows for reusing an IPC connection.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_purge(pcmk_ipc_api_t *api, const char *node);

/*!
 * \internal
 * \brief Get the value of an attribute from pacemaker-attrd
 *
 * \param[in,out] api           Connection to pacemaker-attrd
 * \param[in]     node          Look up the attribute for this node
 *                              (or NULL for all nodes)
 * \param[in]     name          Attribute name
 * \param[in]     options       Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_query(pcmk_ipc_api_t *api, const char *node, const char *name,
                          uint32_t options);

/*!
 * \internal
 * \brief Tell pacemaker-attrd to update the CIB with current values
 *
 * \param[in,out] api   pacemaker-attrd IPC object
 * \param[in]     node  Affect only this node (or NULL for all nodes)
 *
 * \note If \p api is NULL, a new temporary connection will be created
 *       just for this operation and destroyed afterwards.  If \p api is
 *       not NULL but is not yet connected to pacemaker-attrd, the object
 *       will be connected for this operation and left connected afterwards.
 *       This allows for reusing an IPC connection.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_refresh(pcmk_ipc_api_t *api, const char *node);

/*!
 * \internal
 * \brief Update an attribute's value, time to wait, or both
 *
 * \param[in,out] api        pacemaker-attrd IPC object
 * \param[in]     node       Affect only this node (or NULL for current node)
 * \param[in]     name       Attribute name
 * \param[in]     value      The attribute's new value, or NULL to unset
 * \param[in]     dampen     The new time to wait value, or NULL to unset
 * \param[in]     set        ID of attribute set to use (or NULL for first)
 * \param[in]     user_name  ACL user to pass to pacemaker-attrd
 * \param[in]     options    Bitmask of pcmk__node_attr_opts
 *
 * \note If \p api is NULL, a new temporary connection will be created
 *       just for this operation and destroyed afterwards.  If \p api is
 *       not NULL but is not yet connected to pacemaker-attrd, the object
 *       will be connected for this operation and left connected afterwards.
 *       This allows for reusing an IPC connection.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_update(pcmk_ipc_api_t *api, const char *node, const char *name,
                           const char *value, const char *dampen, const char *set,
                           const char *user_name, uint32_t options);

/*!
 * \internal
 * \brief Like pcmk__attrd_api_update, but for multiple attributes at once
 *
 * \param[in,out] api        pacemaker-attrd IPC object
 * \param[in,out] attrs      A list of pcmk__attr_query_pair_t structs
 * \param[in]     dampen     The new time to wait value, or NULL to unset
 * \param[in]     set        ID of attribute set to use (or NULL for first)
 * \param[in]     user_name  ACL user to pass to pacemaker-attrd
 * \param[in]     options    Bitmask of pcmk__node_attr_opts
 *
 * \note If \p api is NULL, a new temporary connection will be created
 *       just for this operation and destroyed afterwards.  If \p api is
 *       not NULL but is not yet connected to pacemaker-attrd, the object
 *       will be connected for this operation and left connected afterwards.
 *       This allows for reusing an IPC connection.
 *
 * \note Not all attrd versions support setting multiple attributes at once.
 *       For those servers that do not, this function will fall back to just
 *       sending a separate IPC request for each attribute.
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_update_list(pcmk_ipc_api_t *api, GList *attrs,
                                const char *dampen, const char *set,
                                const char *user_name, uint32_t options);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H
