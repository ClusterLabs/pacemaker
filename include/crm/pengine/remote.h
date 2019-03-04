/*
 * Copyright 2013-2019 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_REMOTE__H
#  define PE_REMOTE__H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>                   // gboolean
#include <libxml/tree.h>            // xmlNode
#include <crm/pengine/status.h>

gboolean xml_contains_remote_node(xmlNode *xml);
gboolean is_baremetal_remote_node(node_t *node);
gboolean is_container_remote_node(node_t *node);
gboolean is_remote_node(node_t *node);
gboolean is_rsc_baremetal_remote_node(resource_t *rsc, pe_working_set_t * data_set);
resource_t * rsc_contains_remote_node(pe_working_set_t * data_set, resource_t *rsc);
void pe_foreach_guest_node(const pe_working_set_t *data_set, const node_t *host,
                           void (*helper)(const node_t*, void*), void *user_data);
xmlNode *pe_create_remote_xml(xmlNode *parent, const char *uname,
                              const char *container_id, const char *migrateable,
                              const char *is_managed, const char *start_timeout,
                              const char *server, const char *port);

#ifdef __cplusplus
}
#endif

#endif
