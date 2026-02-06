/*
 * Copyright 2004-2026 the Pacemaker project contributors
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
#include <libxml/tree.h>    // xmlNode

#include <crm/common/ipc.h> // enum crm_ipc_server
#include <crm/cluster.h>

#if SUPPORT_COROSYNC
#include <corosync/cpg.h>   // cpg_name, cpg_handle_t
#endif

#ifdef __cplusplus
extern "C" {
#endif

// @TODO Replace this with a pcmk__node_status_flags value
enum crm_proc_flag {
    crm_proc_none       = 0x00000001,

    // Cluster layers
    crm_proc_cpg        = 0x04000000,
};

/*!
 * \internal
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

/*!
 * \internal
 * \brief Used with node cache search functions
 */
enum pcmk__node_search_flags {
    //! Does not affect search
    pcmk__node_search_none              = 0,

    //! Search for cluster nodes from membership cache
    pcmk__node_search_cluster_member    = (UINT32_C(1) << 0),

    //! Search for remote nodes
    pcmk__node_search_remote            = (UINT32_C(1) << 1),

    //! Search for cluster member nodes and remote nodes
    pcmk__node_search_any               = pcmk__node_search_cluster_member
                                          |pcmk__node_search_remote,

    //! Search for cluster nodes from CIB (as of last cache refresh)
    pcmk__node_search_cluster_cib       = (UINT32_C(1) << 2),
};

/*!
 * \internal
 * \brief Type of update to a \c pcmk__node_status_t object
 */
enum pcmk__node_update {
    pcmk__node_update_name,         //!< Node name updated
    pcmk__node_update_state,        //!< Node connection state updated
    pcmk__node_update_processes,    //!< Node process group membership updated
};

typedef struct pcmk__election pcmk__election_t;

//! Implementation of pcmk__cluster_private_t
struct pcmk__cluster_private {
    enum pcmk_ipc_server server;    //!< Server this connection is for (if any)
    char *node_name;                //!< Local node name at cluster layer
    char *node_xml_id;              //!< Local node XML ID in CIB
    pcmk__election_t *election;     //!< Election state (if election is needed)

    /* @TODO Corosync uses an integer node ID, but cluster layers in the
     * abstract do not necessarily need to
     */
    uint32_t node_id;               //!< Local node ID at cluster layer

#if SUPPORT_COROSYNC
    /* @TODO Make these members a separate struct and use void *cluster_data
     * here instead, to abstract the cluster layer further.
     */
    struct cpg_name group;          //!< Corosync CPG name

    cpg_handle_t cpg_handle;        //!< Corosync CPG handle
#endif  // SUPPORT_COROSYNC
};

//! Node status data (may be a cluster node or a Pacemaker Remote node)
typedef struct {
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

    //! Arbitrary data (must be freeable by \c free())
    void *user_data;

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
                             uint32_t pid, void *content, const char **from);

#  endif

const char *pcmk__cluster_get_xml_id(pcmk__node_status_t *node);
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

void pcmk__update_peer_expected_as(const char *function,
                                   pcmk__node_status_t *node,
                                   const char *expected);

#define pcmk__update_peer_expected(node, expected)  \
        pcmk__update_peer_expected_as(__func__, (node), (expected));

void pcmk__reap_unseen_nodes(uint64_t ring_id);

void pcmk__corosync_quorum_connect(gboolean (*dispatch)(unsigned long long,
                                                        gboolean),
                                   void (*destroy) (gpointer));

bool pcmk__cluster_send_message(const pcmk__node_status_t *node,
                                enum pcmk_ipc_server service,
                                const xmlNode *data);

// Membership

extern GHashTable *pcmk__peer_cache;
extern GHashTable *pcmk__remote_peer_cache;

bool pcmk__cluster_has_quorum(void);

void pcmk__cluster_init_node_caches(void);
void pcmk__cluster_destroy_node_caches(void);

void pcmk__cluster_set_autoreap(bool enable);
void pcmk__cluster_set_status_callback(void (*dispatch)(enum pcmk__node_update,
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
                                              const char *xml_id,
                                              uint32_t flags);
void pcmk__purge_node_from_cache(const char *node_name, uint32_t node_id);

void pcmk__refresh_node_caches_from_cib(xmlNode *cib);

pcmk__node_status_t *pcmk__get_node(unsigned int id, const char *uname,
                                    const char *xml_id, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CLUSTER_INTERNAL__H
