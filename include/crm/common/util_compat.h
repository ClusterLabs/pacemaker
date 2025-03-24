/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_UTIL_COMPAT__H
#define PCMK__CRM_COMMON_UTIL_COMPAT__H

#include <stdbool.h>    // bool
#include <stdint.h>     // uint64_t
#include <sys/types.h>  // uid_t, gid_t

#include <glib.h>       // gboolean

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

//! \deprecated Use gnutls_global_init() instead
void crm_gnutls_global_init(void);

//! \deprecated Do not use (will be dropped in a future release)
bool crm_is_daemon_name(const char *name);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
static inline gboolean
is_set(long long word, long long bit)
{
    return ((word & bit) == bit);
}

//! \deprecated Do not use
static inline bool
pcmk_any_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) != 0;
}

//! \deprecated Do not use
static inline bool
pcmk_all_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) == flags_to_check;
}

//! \deprecated Do not use
#define pcmk_is_set(g, f)   pcmk_all_flags_set((g), (f))

//! \deprecated Do not use
char *crm_md5sum(const char *buffer);

//! \deprecated Do not use
char *crm_generate_uuid(void);

//! \deprecated Do not use
int pcmk_daemon_user(uid_t *uid, gid_t *gid);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_UTIL_COMPAT__H
