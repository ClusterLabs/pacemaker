/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_STONITH_NG_COMPAT__H
#define PCMK__CRM_STONITH_NG_COMPAT__H

#include <crm/stonith-ng.h>         // stonith_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated fencing API
 * \ingroup fencing
 * \deprecated Do not include this header directly. The APIs in this header, and
 *             the header itself, will be removed in a future release.
 */

//! \deprecated Use appropriate functions in libpacemaker
stonith_t *stonith_api_new(void);

//! \deprecated Use appropriate functions in libpacemaker
void stonith_api_delete(stonith_t *stonith);

//! \deprecated Do not use
void stonith_dump_pending_callbacks(stonith_t *stonith);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_STONITH_NG_COMPAT__H
