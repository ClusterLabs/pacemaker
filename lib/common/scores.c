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
#include <string.h>     // strncpy(), strdup()
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

char *
score2char_stack(int score, char *buf, size_t len)
{
    CRM_CHECK((buf != NULL) && (len >= sizeof(CRM_MINUS_INFINITY_S)),
              return NULL);

    if (score >= CRM_SCORE_INFINITY) {
        strncpy(buf, CRM_INFINITY_S, 9);
    } else if (score <= -CRM_SCORE_INFINITY) {
        strncpy(buf, CRM_MINUS_INFINITY_S , 10);
    } else {
        snprintf(buf, len, "%d", score);
    }
    return buf;
}

char *
score2char(int score)
{
    if (score >= CRM_SCORE_INFINITY) {
        return strdup(CRM_INFINITY_S);

    } else if (score <= -CRM_SCORE_INFINITY) {
        return strdup(CRM_MINUS_INFINITY_S);
    }
    return pcmk__itoa(score);
}
