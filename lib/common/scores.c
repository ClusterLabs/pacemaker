/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>      // snprintf(), NULL
#include <string.h>     // strcpy(), strdup()
#include <sys/types.h>  // size_t

int pcmk__score_red = 0;
int pcmk__score_green = 0;
int pcmk__score_yellow = 0;

/*!
 * \brief Get the integer value of a score string
 *
 * Given a string representation of a score, return the integer equivalent.
 * This accepts infinity strings as well as red, yellow, and green, and
 * bounds the result to +/-INFINITY.
 *
 * \param[in] score  Score as string
 *
 * \return Integer value corresponding to \p score
 */
int
char2score(const char *score)
{
    if (score == NULL) {
        return 0;

    } else if (pcmk_str_is_minus_infinity(score)) {
        return -CRM_SCORE_INFINITY;

    } else if (pcmk_str_is_infinity(score)) {
        return CRM_SCORE_INFINITY;

    } else if (pcmk__str_eq(score, PCMK__VALUE_RED, pcmk__str_casei)) {
        return pcmk__score_red;

    } else if (pcmk__str_eq(score, PCMK__VALUE_YELLOW, pcmk__str_casei)) {
        return pcmk__score_yellow;

    } else if (pcmk__str_eq(score, PCMK__VALUE_GREEN, pcmk__str_casei)) {
        return pcmk__score_green;

    } else {
        long long score_ll;

        pcmk__scan_ll(score, &score_ll, 0LL);
        if (score_ll > CRM_SCORE_INFINITY) {
            return CRM_SCORE_INFINITY;

        } else if (score_ll < -CRM_SCORE_INFINITY) {
            return -CRM_SCORE_INFINITY;

        } else {
            return (int) score_ll;
        }
    }
}

/*!
 * \brief Return a displayable static string for a score value
 *
 * Given a score value, return a pointer to a static string representation of
 * the score suitable for log messages, output, etc.
 *
 * \param[in] score  Score to display
 *
 * \return Pointer to static memory containing string representation of \p score
 * \note Subsequent calls to this function will overwrite the returned value, so
 *       it should be used only in a local context such as a printf()-style
 *       statement.
 */
const char *
pcmk_readable_score(int score)
{
    // The longest possible result is "-INFINITY"
    static char score_s[sizeof(CRM_MINUS_INFINITY_S)];

    if (score >= CRM_SCORE_INFINITY) {
        strcpy(score_s, CRM_INFINITY_S);

    } else if (score <= -CRM_SCORE_INFINITY) {
        strcpy(score_s, CRM_MINUS_INFINITY_S);

    } else {
        // Range is limited to +/-1000000, so no chance of overflow
        snprintf(score_s, sizeof(score_s), "%d", score);
    }

    return score_s;
}

/*!
 * \internal
 * \brief Add two scores, bounding to +/-INFINITY
 *
 * \param[in] score1  First score to add
 * \param[in] score2  Second score to add
 *
 * \note This function does not have context about what the scores mean, so it
 *       does not log any messages.
 */
int
pcmk__add_scores(int score1, int score2)
{
    /* As long as CRM_SCORE_INFINITY is less than half of the maximum integer,
     * we can ignore the possibility of integer overflow.
     */
    int result = score1 + score2;

    // First handle the cases where one or both is infinite
    if ((score1 <= -CRM_SCORE_INFINITY) || (score2 <= -CRM_SCORE_INFINITY)) {
        return -CRM_SCORE_INFINITY;
    }
    if ((score1 >= CRM_SCORE_INFINITY) || (score2 >= CRM_SCORE_INFINITY)) {
        return CRM_SCORE_INFINITY;
    }

    // Bound result to infinity.
    if (result >= CRM_SCORE_INFINITY) {
        return CRM_SCORE_INFINITY;
    }
    if (result <= -CRM_SCORE_INFINITY) {
        return -CRM_SCORE_INFINITY;
    }

    return result;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/util_compat.h>

char *
score2char(int score)
{
    char *result = strdup(pcmk_readable_score(score));

    CRM_ASSERT(result != NULL);
    return result;
}

char *
score2char_stack(int score, char *buf, size_t len)
{
    CRM_CHECK((buf != NULL) && (len >= sizeof(CRM_MINUS_INFINITY_S)),
              return NULL);
    strcpy(buf, pcmk_readable_score(score));
    return buf;
}

// LCOV_EXCL_STOP
// End deprecated API
