/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCORES__H
#define PCMK__CRM_COMMON_SCORES__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Pacemaker APIs related to scores
 * \ingroup core
 */

//! Integer score to use to represent "infinity"
#define PCMK_SCORE_INFINITY 1000000

const char *pcmk_readable_score(int score);
int char2score(const char *score);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCORES__H
