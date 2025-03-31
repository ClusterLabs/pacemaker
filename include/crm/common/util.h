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

void pcmk_common_cleanup(void);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/util_compat.h>
#endif

#endif
