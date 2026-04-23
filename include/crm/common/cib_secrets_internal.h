/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <cib_secrets_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_CIB_SECRETS_INTERNAL__H
#define PCMK__CRM_COMMON_CIB_SECRETS_INTERNAL__H

#include <glib.h>               // GHashTable

#ifdef __cplusplus
extern "C" {
#endif

#if PCMK__ENABLE_CIBSECRETS
int pcmk__substitute_secrets(const char *rsc_id, GHashTable *params);
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_CIB_SECRETS_INTERNAL__H
