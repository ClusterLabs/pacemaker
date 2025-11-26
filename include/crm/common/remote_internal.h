/*
 * Copyright 2008-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <remote_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_REMOTE_INTERNAL__H
#define PCMK__CRM_COMMON_REMOTE_INTERNAL__H

#include <stdio.h>          // NULL
#include <stdbool.h>        // bool
#include <libxml/tree.h>    // xmlNode

#include <crm/common/ipc_internal.h>        // pcmk__client_t
#include <crm/common/nodes_internal.h>      // pcmk__node_variant_remote, etc.
#include <crm/common/resources_internal.h>  // struct pcmk__remote_private
#include <crm/common/scheduler_types.h>     // pcmk_node_t

#ifdef __cplusplus
extern "C" {
#endif

// internal functions from remote.c

typedef struct pcmk__remote_s pcmk__remote_t;

int pcmk__remote_send_xml(pcmk__remote_t *remote, const xmlNode *msg);
int pcmk__remote_ready(const pcmk__remote_t *remote, int timeout_ms);
int pcmk__read_available_remote_data(pcmk__remote_t *remote);
int pcmk__read_remote_message(pcmk__remote_t *remote, int timeout_ms);
xmlNode *pcmk__remote_message_xml(pcmk__remote_t *remote);
int pcmk__connect_remote(const char *host, int port, int timeout_ms,
                         int *timer_id, int *sock_fd, void *userdata,
                         void (*callback) (void *userdata, int rc, int sock));
int pcmk__accept_remote_connection(int ssock, int *csock);
void pcmk__sockaddr2str(const void *sa, char *s);

/*!
 * \internal
 * \brief Check whether a node is a Pacemaker Remote node of any kind
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is a remote, guest, or bundle node, otherwise false
 */
static inline bool
pcmk__is_pacemaker_remote_node(const pcmk_node_t *node)
{
    return (node != NULL)
            && (node->priv->variant == pcmk__node_variant_remote);
}

/*!
 * \internal
 * \brief Check whether a node is a remote node
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is a remote node, otherwise false
 */
static inline bool
pcmk__is_remote_node(const pcmk_node_t *node)
{
    return pcmk__is_pacemaker_remote_node(node)
           && ((node->priv->remote == NULL)
               || (node->priv->remote->priv->launcher == NULL));
}

/*!
 * \internal
 * \brief Check whether a node is a guest or bundle node
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is a guest or bundle node, otherwise false
 */
static inline bool
pcmk__is_guest_or_bundle_node(const pcmk_node_t *node)
{
    return pcmk__is_pacemaker_remote_node(node)
           && (node->priv->remote != NULL)
           && (node->priv->remote->priv->launcher != NULL);
}

#ifdef __cplusplus
}
#endif

#endif      // PCMK__CRM_COMMON_REMOTE_INTERNAL__H
