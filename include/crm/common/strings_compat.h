/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_STRINGS_COMPAT__H
#define PCMK__CRM_COMMON_STRINGS_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker strings API
 * \ingroup core
 * \deprecated Do not include this header directly. The XML APIs in this header,
 *             and the header itself, will be removed in a future release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
long long crm_get_msec(const char *input);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_STRINGS_COMPAT__H
