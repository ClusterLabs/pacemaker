/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CLUSTER_INTERNAL__H
#define PCMK__CRM_CLUSTER_INTERNAL__H

#include <stdbool.h>
#include <stdint.h>         // uint32_t, uint64_t

#include <glib.h>           // gboolean

#include <crm/cluster.h>

#ifdef __cplusplus
extern "C" {
#endif

enum crm_proc_flag {
    /* @COMPAT When pcmk__node_status_t:processes is made internal, we can merge
     * this into node flags or turn it into a boolean. Until then, in theory
     * something could depend on these particular numeric values.
     */
    crm_proc_none       = 0x00000001,

    // Cluster layers
    crm_proc_cpg        = 0x04000000,
};

/*!
 * \internal
 * \enum pcmk__node_status_flags
 * \brief Boolean flags for a \c pcmk__node_status_t object
 *
 * Some flags may not be related to status specifically. However, we keep these
 * separate from <tt>enum pcmk__node_flags</tt> because they're used with
 * different object types.
 */
enum pcmk__node_status_flags {
    /*!
     * Node is a Pacemaker Remote node and should not be considered for cluster
     * membership
     */
    pcmk__node_status_remote = (UINT32_C(1) << 0),

    //! Node's cache entry is dirty
    pcmk__node_status_dirty  = (UINT32_C(1) << 1),
};

// Used with node cache search functions
enum pcmk__node_search_flags {
    //! Does not affect search
    pcmk__node_search_none              = 0,

    //! Search for cluster nodes from membership cache
    pcmk__node_search_cluster_member    = (1 << 0),

    //! Search for remote nodes
    pcmk__node_search_remote            = (1 << 1),

    //! Search for cluster member nodes and remote nodes
    pcmk__node_search_any               = pcmk__node_search_cluster_member
                                          |pcmk__node_search_remote,

    //! Search for cluster nodes from CIB (as of last cache refresh)
    pcmk__node_search_cluster_cib       = (1 << 2),
};

//! Node status data (may be a cluster node or a Pacemaker Remote node)
typedef struct pcmk__node_status {
    //! Node name as known to cluster layer, or Pacemaker Remote node name
    char *name;

    /* @COMPAT This is less than ideal since the value is not a valid XML ID
     * (for Corosync, it's the string equivalent of the node's numeric node ID,
     * but XML IDs can't start with a number) and the three elements should have
     * different IDs.
     *
     * Ideally, we would use something like node-NODEID, node_state-NODEID, and
     * transient_attributes-NODEID as the element IDs. Unfortunately changing it
     * would be impractical due to backward compatibility; older nodes in a
     * rolling upgrade will always write and expect the value in the old format.
     */

    /*!
     * Value of the PCMK_XA_ID XML attribute to use with the node's
     * PCMK_XE_NODE, PCMK_XE_NODE_STATE, and PCMK_XE_TRANSIENT_ATTRIBUTES
     * XML elements in the CIB
     */
    char *xml_id;

    char *state;                // @TODO change to enum

    //! Group of <tt>enum pcmk__node_status_flags</tt>
    uint32_t flags;

    /*!
     * Most recent cluster membership in which node was seen (0 for Pacemaker
     * Remote nodes)
     */
    uint64_t membership_id;

    uint32_t processes;         // @TODO most not needed, merge into flags

    /* @TODO When we can break public API compatibility, we can make the rest of
     * these members separate structs and use void *cluster_data and
     * void *user_data here instead, to abstract the cluster layer further.
     */

    // Only used by controller
    enum crm_join_phase join;
    char *expected;

    time_t peer_lost;
    char *conn_host;

    time_t when_member;         // Since when node has been a cluster member
    time_t when_online;         // Since when peer has been online in CPG

    /* @TODO The following are currently needed only by the Corosync stack.
     * Eventually consider moving them to a cluster-layer-specific data object.
     */
    uint32_t cluster_layer_id;  //!< Cluster-layer numeric node ID
    time_t when_lost;           //!< When CPG membership was last lost
} pcmk__node_status_t;

/*!
 * \internal
 * \brief Return the process bit corresponding to the current cluster stack
 *
 * \return Process flag if detectable, otherwise 0
 */
static inline uint32_t
crm_get_cluster_proc(void)
{
    switch (pcmk_get_cluster_layer()) {
        case pcmk_cluster_layer_corosync:
            return crm_proc_cpg;

        default:
            break;
    }
    return crm_proc_none;
}

/*!
 * \internal
 * \brief Get log-friendly string description of a Corosync return code
 *
 * \param[in] error  Corosync return code
 *
 * \return Log-friendly string description corresponding to \p error
 */
static inline const char *
pcmk__cs_err_str(int error)
{
#  if SUPPORT_COROSYNC
    switch (error) {
        case CS_OK:                         return "OK";
        case CS_ERR_LIBRARY:                return "Library error";
        case CS_ERR_VERSION:                return "Version error";
        case CS_ERR_INIT:                   return "Initialization error";
        case CS_ERR_TIMEOUT:                return "Timeout";
        case CS_ERR_TRY_AGAIN:              return "Try again";
        case CS_ERR_INVALID_PARAM:          return "Invalid parameter";
        case CS_ERR_NO_MEMORY:              return "No memory";
        case CS_ERR_BAD_HANDLE:             return "Bad handle";
        case CS_ERR_BUSY:                   return "Busy";
        case CS_ERR_ACCESS:                 return "Access error";
        case CS_ERR_NOT_EXIST:              return "Doesn't exist";
        case CS_ERR_NAME_TOO_LONG:          return "Name too long";
        case CS_ERR_EXIST:                  return "Exists";
        case CS_ERR_NO_SPACE:               return "No space";
        case CS_ERR_INTERRUPT:              return "Interrupt";
        case CS_ERR_NAME_NOT_FOUND:         return "Name not found";
        case CS_ERR_NO_RESOURCES:           return "No resources";
        case CS_ERR_NOT_SUPPORTED:          return "Not supported";
        case CS_ERR_BAD_OPERATION:          return "Bad operation";
        case CS_ERR_FAILED_OPERATION:       return "Failed operation";
        case CS_ERR_MESSAGE_ERROR:          return "Message error";
        case CS_ERR_QUEUE_FULL:             return "Queue full";
        case CS_ERR_QUEUE_NOT_AVAILABLE:    return "Queue not available";
        case CS_ERR_BAD_FLAGS:              return "Bad flags";
        case CS_ERR_TOO_BIG:                return "Too big";
        case CS_ERR_NO_SECTIONS:            return "No sections";
    }
#  endif
    return "Corosync error";
}

#  if SUPPORT_COROSYNC

#if 0
/* This is the new way to do it, but we still support all Corosync 2 versions,
 * and this isn't always available. A better alternative here would be to check
 * for support in the configure script and enable this conditionally.
 */
#define pcmk__init_cmap(handle) cmap_initialize_map((handle), CMAP_MAP_ICMAP)
#else
#define pcmk__init_cmap(handle) cmap_initialize(handle)
#endif

char *pcmk__corosync_cluster_name(void);
bool pcmk__corosync_add_nodes(xmlNode *xml_parent);

void pcmk__cpg_confchg_cb(cpg_handle_t handle,
                          const struct cpg_name *group_name,
                          const struct cpg_address *member_list,
                          size_t member_list_entries,
                          const struct cpg_address *left_list,
                          size_t left_list_entries,
                          const struct cpg_address *joined_list,
                          size_t joined_list_entries);

char *pcmk__cpg_message_data(cpg_handle_t handle, uint32_t sender_id,
                             uint32_t pid, void *content, uint32_t *kind,
                             const char **from);

#  endif

const char *pcmk__cluster_node_uuid(pcmk__node_status_t *node);
char *pcmk__cluster_node_name(uint32_t nodeid);
const char *pcmk__cluster_local_node_name(void);
const char *pcmk__node_name_from_uuid(const char *uuid);

pcmk__node_status_t *crm_update_peer_proc(const char *source,
                                          pcmk__node_status_t *peer,
                                          uint32_t flag, const char *status);
pcmk__node_status_t *pcmk__update_peer_state(const char *source,
                                             pcmk__node_status_t *node,
                                             const char *state,
                                             uint64_t membership);

void pcmk__update_peer_expected(const char *source, pcmk__node_status_t *node,
                                const char *expected);
void pcmk__reap_unseen_nodes(uint64_t ring_id);

void pcmk__corosync_quorum_connect(gboolean (*dispatch)(unsigned long long,
                                                        gboolean),
                                   void (*destroy) (gpointer));

enum crm_ais_msg_types pcmk__cluster_parse_msg_type(const char *text);
bool pcmk__cluster_send_message(const pcmk__node_status_t *node,
                                enum crm_ais_msg_types service,
                                const xmlNode *data);

// Membership

bool pcmk__cluster_has_quorum(void);

void pcmk__cluster_init_node_caches(void);
void pcmk__cluster_destroy_node_caches(void);

void pcmk__cluster_set_autoreap(bool enable);
void pcmk__cluster_set_status_callback(void (*dispatch)(enum crm_status_type,
                                                        pcmk__node_status_t *,
                                                        const void *));

bool pcmk__cluster_is_node_active(const pcmk__node_status_t *node);
unsigned int pcmk__cluster_num_active_nodes(void);
unsigned int pcmk__cluster_num_remote_nodes(void);

pcmk__node_status_t *pcmk__cluster_lookup_remote_node(const char *node_name);
void pcmk__cluster_forget_cluster_node(uint32_t id, const char *node_name);
void pcmk__cluster_forget_remote_node(const char *node_name);
pcmk__node_status_t *pcmk__search_node_caches(unsigned int id,
                                              const char *uname,
                                              uint32_t flags);
void pcmk__purge_node_from_cache(const char *node_name, uint32_t node_id);

void pcmk__refresh_node_caches_from_cib(xmlNode *cib);

pcmk__node_status_t *pcmk__get_node(unsigned int id, const char *uname,
                                    const char *uuid, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CLUSTER_INTERNAL__H
