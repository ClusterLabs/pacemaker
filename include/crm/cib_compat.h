/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CIB_COMPAT__H
#define PCMK__CRM_CIB_COMPAT__H

#include <crm/cib/cib_types.h>      // cib_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated CIB utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define T_CIB_DIFF_NOTIFY "cib_diff_notify"

/*!
 * \deprecated Save CIB_shadow, unset it, call cib_new(), and restore old
 *             CIB_shadow instead
 */
cib_t *cib_new_no_shadow(void);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CIB_COMPAT__H
