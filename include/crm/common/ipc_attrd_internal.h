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
 * \param[in] api           Connection to pacemaker-attrd
 * \param[in] node          Affect only this node (or NULL for all nodes)
 * \param[in] resource      Name of resource to clear (or NULL for all)
 * \param[in] operation     Name of operation to clear (or NULL for all)
 * \param[in] interval_spec If operation is not NULL, its interval
 * \param[in] user_name     ACL user to pass to pacemaker-attrd
 * \param[in] options       Bitmask of pcmk__node_attr_opts
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
 * \param[in] api           Connection to pacemaker-attrd
 * \param[in] node          Delete attribute for this node (or NULL for current node)
 * \param[in] name          Attribute name
 * \param[in] options       Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_delete(pcmk_ipc_api_t *api, const char *node, const char *name,
                           uint32_t options);

/*!
 * \internal
 * \brief Get the value of an attribute from pacemaker-attrd
 *
 * \param[in] api           Connection to pacemaker-attrd
 * \param[in] node          Look up the attribute for this node
 *                          (or NULL for all nodes)
 * \param[in] name          Attribute name
 * \param[in] options       Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_query(pcmk_ipc_api_t *api, const char *node, const char *name,
                          uint32_t options);

/*!
 * \internal
 * \brief Tell pacemaker-attrd to update the CIB with current values
 *
 * \param[in] api           Connection to pacemaker-attrd
 * \param[in] node          Affect only this node (or NULL for all nodes)
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_refresh(pcmk_ipc_api_t *api, const char *node);

/*!
 * \internal
 * \brief Update an attribute's value, time to wait, or both
 *
 * \param[in] api           Connection to pacemaker-attrd
 * \param[in] node          Affect only this node (or NULL for current node)
 * \param[in] name          Attribute name
 * \param[in] value         The attribute's new value, or NULL to unset
 * \param[in] dampen        The new time to wait value, or NULL to unset
 * \param[in] set           ID of attribute set to use (or NULL to choose first)
 * \param[in] user_name     ACL user to pass to pacemaker-attrd
 * \param[in] options       Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int pcmk__attrd_api_update(pcmk_ipc_api_t *api, const char *node, const char *name,
                           const char *value, const char *dampen, const char *set,
                           const char *user_name, uint32_t options);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_ATTRD_INTERNAL__H
