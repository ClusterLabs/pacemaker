/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESULTS_COMPAT__H
#  define PCMK__CRM_COMMON_RESULTS_COMPAT__H

#include <crm/common/results.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker results API
 * \ingroup core
 * \deprecated Do not include this header directly. The result APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use pcmk_rc2exitc(pcmk_legacy2rc(rc)) instead
crm_exit_t crm_errno2exit(int rc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MAINLOOP_COMPAT__H
