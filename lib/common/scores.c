/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // snprintf(), NULL
#include <string.h>     // strcpy(), strdup()
#include <sys/types.h>  // size_t

int pcmk__score_red = 0;
int pcmk__score_green = 0;
int pcmk__score_yellow = 0;

/*!
 * \brief Parse an integer score from a string
 *
 * Parse an integer score from a string. This accepts infinity strings as well
 * as red, yellow, and green, and bounds the result to +/-INFINITY.
 *
 * \param[in]  score_s        Score as string
 * \param[out] score          Where to store integer value corresponding to
 *                            \p score_s (may be NULL to only check validity)
 * \param[in]  default_score  Value to use if \p score_s is NULL or invalid
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_parse_score(const char *score_s, int *score, int default_score)
{
    int rc = pcmk_rc_ok;
    int local_score = 0;

    // Ensure default score is in bounds
    default_score = QB_MIN(default_score, PCMK_SCORE_INFINITY);
    default_score = QB_MAX(default_score, -PCMK_SCORE_INFINITY);
    local_score = default_score;

    if (score_s == NULL) {

    } else if (pcmk_str_is_minus_infinity(score_s)) {
        local_score = -PCMK_SCORE_INFINITY;

    } else if (pcmk_str_is_infinity(score_s)) {
        local_score = PCMK_SCORE_INFINITY;

    } else if (pcmk__str_eq(score_s, PCMK_VALUE_RED, pcmk__str_casei)) {
        local_score = pcmk__score_red;

    } else if (pcmk__str_eq(score_s, PCMK_VALUE_YELLOW, pcmk__str_casei)) {
        local_score = pcmk__score_yellow;

    } else if (pcmk__str_eq(score_s, PCMK_VALUE_GREEN, pcmk__str_casei)) {
        local_score = pcmk__score_green;

    } else {
        long long score_ll = 0LL;

        rc = pcmk__scan_ll(score_s, &score_ll, default_score);
        if (rc == ERANGE) {
            rc = pcmk_rc_ok;
        }
        if (rc != pcmk_rc_ok) {
            local_score = default_score;

        } else if (score_ll > PCMK_SCORE_INFINITY) {
            local_score = PCMK_SCORE_INFINITY;

        } else if (score_ll < -PCMK_SCORE_INFINITY) {
            local_score = -PCMK_SCORE_INFINITY;

        } else {
            local_score = (int) score_ll;
        }
    }

    if (score != NULL) {
        *score = local_score;
    }
    return rc;
}

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
    int result = 0;

    (void) pcmk_parse_score(score, &result, 0);
    return result;
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
    static char score_s[sizeof(PCMK_VALUE_MINUS_INFINITY)];

    if (score >= PCMK_SCORE_INFINITY) {
        strcpy(score_s, PCMK_VALUE_INFINITY);

    } else if (score <= -PCMK_SCORE_INFINITY) {
        strcpy(score_s, PCMK_VALUE_MINUS_INFINITY);

    } else {
        // Range is limited to +/-1000000, so no chance of overflow
        snprintf(score_s, sizeof(score_s), "%d", score);
    }

    return score_s;
}

/*!
 * \internal
 * \brief Check whether a string represents an infinite value
 *
 * \param[in] s  String to check
 *
 * \return \c true if \p s is "INFINITY" or "+INFINITY", otherwise \c false
 */
bool
pcmk_str_is_infinity(const char *s) {
    return pcmk__str_any_of(s, PCMK_VALUE_INFINITY, PCMK_VALUE_PLUS_INFINITY,
                            NULL);
}

/*!
 * \internal
 * \brief Check whether a string represents an negatively infinite value
 *
 * \param[in] s  String to check
 *
 * \return \c true if \p s is "-INFINITY", otherwise \c false
 */
bool
pcmk_str_is_minus_infinity(const char *s) {
    return pcmk__str_eq(s, PCMK_VALUE_MINUS_INFINITY, pcmk__str_none);
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
    /* As long as PCMK_SCORE_INFINITY is less than half of the maximum integer,
     * we can ignore the possibility of integer overflow.
     */
    int result = score1 + score2;

    // First handle the cases where one or both is infinite
    if ((score1 <= -PCMK_SCORE_INFINITY) || (score2 <= -PCMK_SCORE_INFINITY)) {
        return -PCMK_SCORE_INFINITY;
    }
    if ((score1 >= PCMK_SCORE_INFINITY) || (score2 >= PCMK_SCORE_INFINITY)) {
        return PCMK_SCORE_INFINITY;
    }

    // Bound result to infinity.
    if (result >= PCMK_SCORE_INFINITY) {
        return PCMK_SCORE_INFINITY;
    }
    if (result <= -PCMK_SCORE_INFINITY) {
        return -PCMK_SCORE_INFINITY;
    }

    return result;
}
