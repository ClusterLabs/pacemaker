/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_UTIL__H
#define PCMK__CRM_COMMON_UTIL__H

#include <sys/types.h>    // gid_t, mode_t, size_t, time_t, uid_t
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>       // uint32_t
#include <limits.h>
#include <signal.h>
#include <glib.h>

#include <crm/common/acl.h>
#include <crm/common/actions.h>
#include <crm/common/agents.h>
#include <crm/common/results.h>
#include <crm/common/scores.h>
#include <crm/common/strings.h>
#include <crm/common/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Utility functions
 * \ingroup core
 */

/* public node attribute functions (from attrd_client.c) */
char *pcmk_promotion_score_name(const char *rsc_id);

/* public Pacemaker Remote functions (from remote.c) */
int crm_default_remote_port(void);

int compare_version(const char *version1, const char *version2);

/*!
 * \brief Check whether any of specified flags are set in a flag group
 *
 * \param[in] flag_group        The flag group being examined
 * \param[in] flags_to_check    Which flags in flag_group should be checked
 *
 * \return true if \p flags_to_check is nonzero and any of its flags are set in
 *         \p flag_group, or false otherwise
 */
static inline bool
pcmk_any_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) != 0;
}

/*!
 * \brief Check whether all of specified flags are set in a flag group
 *
 * \param[in] flag_group        The flag group being examined
 * \param[in] flags_to_check    Which flags in flag_group should be checked
 *
 * \return true if \p flags_to_check is zero or all of its flags are set in
 *         \p flag_group, or false otherwise
 */
static inline bool
pcmk_all_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) == flags_to_check;
}

/*!
 * \brief Convenience alias for pcmk_all_flags_set(), to check single flag
 */
#define pcmk_is_set(g, f)   pcmk_all_flags_set((g), (f))

char *crm_md5sum(const char *buffer);

char *crm_generate_uuid(void);

int crm_user_lookup(const char *name, uid_t * uid, gid_t * gid);
int pcmk_daemon_user(uid_t *uid, gid_t *gid);

void crm_gnutls_global_init(void);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/util_compat.h>
#endif

#endif
