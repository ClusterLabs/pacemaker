/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESULTS_COMPAT__H
#define PCMK__CRM_COMMON_RESULTS_COMPAT__H

#include <glib.h>               // TRUE, FALSE
#include <crm/common/results.h> // crm_abort()

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker results API
 * \ingroup core
 * \deprecated Do not include this header directly. The APIs in this header, and
 *             the header itself, will be removed in a future release.
 */

#define CRM_ASSERT(expr) do {                                               \
        if (!(expr)) {                                                      \
            crm_abort(__FILE__, __func__, __LINE__, #expr, TRUE, FALSE);    \
        }                                                                   \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESULTS_COMPAT__H
