/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_UTIL_COMPAT__H
#define PCMK__CRM_COMMON_UTIL_COMPAT__H

#include <glib.h>
#include <libxml/tree.h>
#include <crm/common/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define CRM_DEFAULT_OP_TIMEOUT_S "20s"

//! \deprecated Use !pcmk_is_set() or !pcmk_all_flags_set() instead
static inline gboolean
is_not_set(long long word, long long bit)
{
    return ((word & bit) == 0);
}

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_is_set() or pcmk_all_flags_set() instead
static inline gboolean
is_set(long long word, long long bit)
{
    return ((word & bit) == bit);
}

//! \deprecated Use pcmk_any_flags_set() instead
static inline gboolean
is_set_any(long long word, long long bit)
{
    return ((word & bit) != 0);
}

//! \deprecated Use strcmp() or strcasecmp() instead
gboolean crm_str_eq(const char *a, const char *b, gboolean use_case);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UTIL_COMPAT__H
