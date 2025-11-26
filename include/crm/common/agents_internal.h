/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <agents_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_AGENTS_INTERNAL__H
#define PCMK__CRM_COMMON_AGENTS_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

#define PCMK__FENCING_STONITH_TIMEOUT "stonith-timeout"

int pcmk__effective_rc(int rc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_AGENTS_INTERNAL__H
