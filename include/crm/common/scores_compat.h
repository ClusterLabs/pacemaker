/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCORES_COMPAT__H
#define PCMK__CRM_COMMON_SCORES_COMPAT__H

#include <sys/types.h>  // size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker score APIs
 * \ingroup core
 * \deprecated Do not include this header directly. The APIs in this header, and
 *             the header itself, will be removed in a future release.
 */

//! \deprecated Use pcmk_readable_score() instead
char *score2char(int score);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCORES_COMPAT__H
