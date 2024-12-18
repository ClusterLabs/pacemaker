/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_STATUS__H
#  define PCMK__CRM_PENGINE_STATUS__H

#  include <glib.h>                 // gboolean
#  include <stdbool.h>              // bool
#  include <crm/common/util.h>      // pcmk_is_set()
#  include <crm/common/iso8601.h>
#  include <crm/pengine/pe_types.h> // pcmk_node_t, pcmk_resource_t, etc.
#  include <crm/pengine/complex.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Cluster status and scheduling
 * \ingroup pengine
 */

const char *rsc_printable_id(const pcmk_resource_t *rsc);

int pcmk_unpack_scheduler_input(pcmk_scheduler_t *scheduler);

// NOTE: sbd (as of at least 1.5.2) uses this
pcmk_scheduler_t *pe_new_working_set(void);

// NOTE: sbd (as of at least 1.5.2) uses this
void pe_free_working_set(pcmk_scheduler_t *scheduler);

void set_working_set_defaults(pcmk_scheduler_t *scheduler);
void cleanup_calculations(pcmk_scheduler_t *scheduler);

// NOTE: sbd (as of at least 1.5.2) uses this
void pe_reset_working_set(pcmk_scheduler_t *scheduler);

pcmk_resource_t *pe_find_resource(GList *rsc_list, const char *id);
pcmk_resource_t *pe_find_resource_with_flags(GList *rsc_list, const char *id,
                                             enum pe_find flags);
pcmk_node_t *pe_find_node_id(const GList *node_list, const char *id);
pcmk_node_t *pe_find_node_any(const GList *node_list, const char *id,
                            const char *node_name);
GList *find_operations(const char *rsc, const char *node, gboolean active_filter,
                         pcmk_scheduler_t *scheduler);
void calculate_active_ops(const GList *sorted_op_list, int *start_index,
                          int *stop_index);
int pe_bundle_replicas(const pcmk_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/common.h>
#include <crm/pengine/status_compat.h>
#endif

#endif
