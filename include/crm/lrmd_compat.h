/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_LRMD_COMPAT__H
#define PCMK__CRM_LRMD_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated executor utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
int lrmd_compare_versions(const char *version1, const char *version2);

#define LRMD_SUPPORTS_SCHEMA_XFER(x) (lrmd_compare_versions((x), "1.2") >= 0)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_LRMD_COMPAT__H
