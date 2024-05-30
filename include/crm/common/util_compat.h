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

//! \deprecated Use strcmp() instead
gboolean safe_str_neq(const char *a, const char *b);

//! \deprecated Use strcasecmp() instead
#define safe_str_eq(a, b) crm_str_eq(a, b, FALSE)

//! \deprecated Use snprintf() instead
char *crm_itoa_stack(int an_int, char *buf, size_t len);

//! \deprecated Use sscanf() instead
int pcmk_scan_nvpair(const char *input, char **name, char **value);

//! \deprecated Use a standard printf()-style function instead
char *pcmk_format_nvpair(const char *name, const char *value,
                         const char *units);

//! \deprecated Use \c crm_xml_add() or \c xml_remove_prop() instead
const char *crm_xml_replace(xmlNode *node, const char *name, const char *value);

//! \deprecated Use a standard printf()-style function instead
char *pcmk_format_named_time(const char *name, time_t epoch_time);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UTIL_COMPAT__H
