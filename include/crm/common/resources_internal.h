/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES_INTERNAL__H
#define PCMK__CRM_COMMON_RESOURCES_INTERNAL__H

#include <crm/common/resources.h>   // enum rsc_recovery_type

#ifdef __cplusplus
extern "C" {
#endif

// Implementation of pcmk__resource_private_t
struct pcmk__resource_private {
};

const char *pcmk__multiply_active_text(enum rsc_recovery_type recovery);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES_INTERNAL__H
