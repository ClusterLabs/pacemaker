/*
 * Copyright 2004-2025 the Pacemaker project contributors
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

/* public node attribute functions (from attrs.c) */
char *pcmk_promotion_score_name(const char *rsc_id);

/* public Pacemaker Remote functions (from remote.c) */
int crm_default_remote_port(void);

int compare_version(const char *version1, const char *version2);

void pcmk_common_cleanup(void);
int crm_user_lookup(const char *name, uid_t * uid, gid_t * gid);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/util_compat.h>
#endif

#endif
