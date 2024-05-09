/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOCATION_INTERNAL__H
#define PCMK__CRM_COMMON_LOCATION_INTERNAL__H

#include <glib.h>                       // GList

#include <crm/common/nodes.h>           // enum pe_discover_e
#include <crm/common/resources.h>       // enum rsc_role_e
#include <crm/common/scheduler_types.h> // pcmk_resource_t

#ifdef __cplusplus
extern "C" {
#endif

//! Location constraint object
typedef struct {
    char *id;                           // XML ID of location constraint
    pcmk_resource_t *rsc;               // Resource with location preference
    enum rsc_role_e role_filter;        // Limit to instances with this role
    enum pe_discover_e discover_mode;   // How to probe resource on node
    GList *nodes;                       // Affected nodes, with preference score
} pcmk__location_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOCATION_INTERNAL__H
