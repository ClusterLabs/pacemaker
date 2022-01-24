/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMPLEX__H
#  define PCMK__CRM_PENGINE_COMPLEX__H

#include <glib.h>                   // gboolean, GHashTable
#include <libxml/tree.h>            // xmlNode
#include <crm/pengine/pe_types.h>   // pe_node_t, pe_resource_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

extern resource_object_functions_t resource_class_functions[];

GHashTable *pe_rsc_params(pe_resource_t *rsc, pe_node_t *node,
                          pe_working_set_t *data_set);
void get_meta_attributes(GHashTable * meta_hash, pe_resource_t *rsc,
                         pe_node_t *node, pe_working_set_t *data_set);
void get_rsc_attributes(GHashTable *meta_hash, pe_resource_t *rsc,
                        pe_node_t *node, pe_working_set_t *data_set);

#if ENABLE_VERSIONED_ATTRS
void pe_get_versioned_attributes(xmlNode *meta_hash, pe_resource_t *rsc,
                                 pe_node_t *node, pe_working_set_t *data_set);
#endif

gboolean is_parent(pe_resource_t *child, pe_resource_t *rsc);
pe_resource_t *uber_parent(pe_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#endif
