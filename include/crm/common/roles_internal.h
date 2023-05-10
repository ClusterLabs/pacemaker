/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ROLES_INTERNAL__H
#  define PCMK__CRM_COMMON_ROLES_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// String equivalents of enum rsc_role_e
#define PCMK__ROLE_UNKNOWN      "Unknown"
#define PCMK__ROLE_STOPPED      "Stopped"
#define PCMK__ROLE_STARTED      "Started"
#define PCMK__ROLE_UNPROMOTED   "Unpromoted"
#define PCMK__ROLE_PROMOTED     "Promoted"
#define PCMK__ROLE_UNPROMOTED_LEGACY    "Slave"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ROLES_INTERNAL__H
