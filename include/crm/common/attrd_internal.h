/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_ATTRD__H
#  define CRM_ATTRD__H

#ifdef __cplusplus
extern "C" {
#endif

#  include <crm/common/ipc.h>

/* attribute options for clients to use with these functions */
#define attrd_opt_none    0x000
#define attrd_opt_remote  0x001
#define attrd_opt_private 0x002

const char *attrd_get_target(const char *name);

int attrd_update_delegate(crm_ipc_t * ipc, char command, const char *host,
                          const char *name, const char *value, const char *section,
                          const char *set, const char *dampen, const char *user_name, int options);
int attrd_clear_delegate(crm_ipc_t *ipc, const char *host, const char *resource,
                         const char *operation, const char *interval_spec,
                         const char *user_name, int options);

#ifdef __cplusplus
}
#endif

#endif
