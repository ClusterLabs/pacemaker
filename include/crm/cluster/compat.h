/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CLUSTER_COMPAT__H
#  define PCMK__CRM_CLUSTER_COMPAT__H

#include <libxml/tree.h>    // xmlNode
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

// \deprecated Use stonith_api_kick() from libstonithd instead
int crm_terminate_member(int nodeid, const char *uname, void *unused);

// \deprecated Use stonith_api_kick() from libstonithd instead
int crm_terminate_member_no_mainloop(int nodeid, const char *uname,
                                     int *connection);

// \deprecated Use crm_xml_add(xml, attr, crm_peer_uuid(node)) instead
void set_uuid(xmlNode *xml, const char *attr, crm_node_t *node);

#ifdef __cplusplus
}
#endif

#endif // PCMK_CLUSTER_COMPAT__H
