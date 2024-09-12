/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCORES_COMPAT__H
#define PCMK__CRM_COMMON_SCORES_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

//! \deprecated Use pcmk_parse_score() instead
int char2score(const char *score);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCORES_COMPAT__H
