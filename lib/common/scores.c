/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

    } else if (pcmk__str_eq(score, "red", pcmk__str_casei)) {
        return pcmk__score_red;

    } else if (pcmk__str_eq(score, "yellow", pcmk__str_casei)) {
        return pcmk__score_yellow;

    } else if (pcmk__str_eq(score, "green", pcmk__str_casei)) {
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
 * \brief Convert an integer score to a string, using a provided buffer
 *
 * Store the string equivalent of a given integer score in a given string
 * buffer, using "INFINITY" and "-INFINITY" when appropriate.
 *
 * \param[in]  score  Integer score to convert
 * \param[out] buf    Where to store string representation of \p score
 * \param[in]  len    Size of \p buf (in bytes)
 *
 * \return \p buf (or NULL if \p len is too small)
 */
char *
score2char_stack(int score, char *buf, size_t len)
{
    CRM_CHECK((buf != NULL) && (len >= sizeof(CRM_MINUS_INFINITY_S)),
              return NULL);

    if (score >= CRM_SCORE_INFINITY) {
        strcpy(buf, CRM_INFINITY_S);
    } else if (score <= -CRM_SCORE_INFINITY) {
        strcpy(buf, CRM_MINUS_INFINITY_S);
    } else {
        snprintf(buf, len, "%d", score);
    }
    return buf;
}

/*!
 * \brief Return the string equivalent of an integer score
 *
 * Return the string equivalent of a given integer score, using "INFINITY" and
 * "-INFINITY" when appropriate.
 *
 * \param[in]  score  Integer score to convert
 *
 * \return Newly allocated string equivalent of \p score
 * \note The caller is responsible for freeing the return value. This function
 *       asserts on memory errors, so the return value can be assumed to be
 *       non-NULL.
 */
char *
score2char(int score)
{
    char *result = NULL;

    if (score >= CRM_SCORE_INFINITY) {
        result = strdup(CRM_INFINITY_S);
        CRM_ASSERT(result != NULL);

    } else if (score <= -CRM_SCORE_INFINITY) {
        result = strdup(CRM_MINUS_INFINITY_S);
        CRM_ASSERT(result != NULL);

    } else {
        result = pcmk__itoa(score);
    }
    return result;
}
