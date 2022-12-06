/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRMCLUSTER_PRIVATE__H
#  define PCMK__CRMCLUSTER_PRIVATE__H

/* This header is for the sole use of libcrmcluster, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <stdint.h>                // uint32_t, uint64_t

#include <glib.h>                  // G_GNUC_INTERNAL, gboolean
#include <libxml/tree.h>           // xmlNode

#include <crm/cluster.h>           // cluster_type_e, crm_node_t

G_GNUC_INTERNAL
enum cluster_type_e pcmk__corosync_detect(void);

G_GNUC_INTERNAL
bool pcmk__corosync_has_nodelist(void);

G_GNUC_INTERNAL
char *pcmk__corosync_uuid(const crm_node_t *peer);

G_GNUC_INTERNAL
char *pcmk__corosync_name(uint64_t /*cmap_handle_t */ cmap_handle,
                          uint32_t nodeid);

G_GNUC_INTERNAL
gboolean pcmk__corosync_connect(crm_cluster_t *cluster);

G_GNUC_INTERNAL
void pcmk__corosync_disconnect(crm_cluster_t *cluster);

G_GNUC_INTERNAL
gboolean pcmk__cpg_send_xml(xmlNode *msg, const crm_node_t *node,
                            enum crm_ais_msg_types dest);

#endif  // PCMK__CRMCLUSTER_PRIVATE__H
