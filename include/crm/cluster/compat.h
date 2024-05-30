/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CLUSTER_COMPAT__H
#  define PCMK__CRM_CLUSTER_COMPAT__H

#include <stdint.h>         // uint32_t
#include <sys/types.h>      // size_t

#include <glib.h>           // gboolean, guint
#include <libxml/tree.h>    // xmlNode

#if SUPPORT_COROSYNC
#include <corosync/cpg.h>   // cpg_handle_t
#endif  // SUPPORT_COROSYNC

#include <crm/cluster.h>    // crm_node_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker cluster API
 * \ingroup cluster
 * \deprecated Do not include this header directly. The cluster APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
enum crm_get_peer_flags {
    CRM_GET_PEER_CLUSTER   = 0x0001,
    CRM_GET_PEER_REMOTE    = 0x0002,
    CRM_GET_PEER_ANY       = CRM_GET_PEER_CLUSTER|CRM_GET_PEER_REMOTE,
};

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_t instead
typedef pcmk_cluster_t crm_cluster_t;

//! \deprecated Do not use Pacemaker for cluster node cacheing
crm_node_t *crm_get_peer(unsigned int id, const char *uname);

//! \deprecated Do not use Pacemaker for cluster node cacheing
crm_node_t *crm_get_peer_full(unsigned int id, const char *uname, int flags);

//! \deprecated Use stonith_api_kick() from libstonithd instead
int crm_terminate_member(int nodeid, const char *uname, void *unused);

//! \deprecated Use \c stonith_api_kick() from libstonithd instead
int crm_terminate_member_no_mainloop(int nodeid, const char *uname,
                                     int *connection);

/*!
 * \deprecated Use
 *             <tt>crm_xml_add(xml, attr, pcmk__cluster_node_uuid(node))</tt>
 *             instead
 */
void set_uuid(xmlNode *xml, const char *attr, crm_node_t *node);

#if SUPPORT_COROSYNC

//! \deprecated Do not use
gboolean cluster_connect_cpg(pcmk_cluster_t *cluster);

//! \deprecated Do not use
void cluster_disconnect_cpg(pcmk_cluster_t *cluster);

//! \deprecated Do not use
uint32_t get_local_nodeid(cpg_handle_t handle);

//! \deprecated Do not use
void pcmk_cpg_membership(cpg_handle_t handle,
                         const struct cpg_name *group_name,
                         const struct cpg_address *member_list,
                         size_t member_list_entries,
                         const struct cpg_address *left_list,
                         size_t left_list_entries,
                         const struct cpg_address *joined_list,
                         size_t joined_list_entries);

//! \deprecated Do not use
gboolean crm_is_corosync_peer_active(const crm_node_t * node);

//! \deprecated Do not use
gboolean send_cluster_text(enum crm_ais_msg_class msg_class, const char *data,
                           gboolean local, const crm_node_t *node,
                           enum crm_ais_msg_types dest);

//! \deprecated Do not use
char *pcmk_message_common_cs(cpg_handle_t handle, uint32_t nodeid, uint32_t pid,
                             void *msg, uint32_t *kind, const char **from);

#endif  // SUPPORT_COROSYNC

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_connect() instead
gboolean crm_cluster_connect(pcmk_cluster_t *cluster);

//! \deprecated Use \c pcmk_cluster_disconnect() instead
void crm_cluster_disconnect(pcmk_cluster_t *cluster);

//! \deprecated Do not use
int crm_remote_peer_cache_size(void);

//! \deprecated Do not use
void crm_remote_peer_cache_refresh(xmlNode *cib);

//! \deprecated Do not use
crm_node_t *crm_remote_peer_get(const char *node_name);

//! \deprecated Do not use
void crm_remote_peer_cache_remove(const char *node_name);

//! \deprecated Do not use
gboolean crm_is_peer_active(const crm_node_t *node);

// NOTE: sbd (as of at least 1.5.2) uses this enum
//!@{
//! \deprecated Use <tt>enum pcmk_cluster_layer</tt> instead
enum cluster_type_e {
    // NOTE: sbd (as of at least 1.5.2) uses this value
    pcmk_cluster_unknown    = pcmk_cluster_layer_unknown,

    pcmk_cluster_invalid    = pcmk_cluster_layer_invalid,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    pcmk_cluster_corosync   = pcmk_cluster_layer_corosync,
};
//!@}

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_layer_text() instead
const char *name_for_cluster_type(enum cluster_type_e type);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_get_cluster_layer() instead
enum cluster_type_e get_cluster_type(void);

#ifdef __cplusplus
}
#endif

#endif // PCMK_CLUSTER_COMPAT__H
