/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
#include <crm/pengine/pe_types.h>   // pcmk_node_t, pcmk_resource_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

// @COMPAT Make internal when we can break API backward compatibility
//! \deprecated Do not use
extern pcmk_rsc_methods_t resource_class_functions[];

GHashTable *pe_rsc_params(pcmk_resource_t *rsc, const pcmk_node_t *node,
                          pcmk_scheduler_t *scheduler);
void get_meta_attributes(GHashTable * meta_hash, pcmk_resource_t *rsc,
                         pcmk_node_t *node, pcmk_scheduler_t *scheduler);
void get_rsc_attributes(GHashTable *meta_hash, const pcmk_resource_t *rsc,
                        const pcmk_node_t *node, pcmk_scheduler_t *scheduler);

gboolean is_parent(pcmk_resource_t *child, pcmk_resource_t *rsc);
pcmk_resource_t *uber_parent(pcmk_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#endif
