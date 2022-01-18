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

int
char2score(const char *score)
{
    int score_f = 0;

    if (score == NULL) {

    } else if (pcmk_str_is_minus_infinity(score)) {
        score_f = -CRM_SCORE_INFINITY;

    } else if (pcmk_str_is_infinity(score)) {
        score_f = CRM_SCORE_INFINITY;

    } else if (pcmk__str_eq(score, "red", pcmk__str_casei)) {
        score_f = pcmk__score_red;

    } else if (pcmk__str_eq(score, "yellow", pcmk__str_casei)) {
        score_f = pcmk__score_yellow;

    } else if (pcmk__str_eq(score, "green", pcmk__str_casei)) {
        score_f = pcmk__score_green;

    } else {
        long long score_ll;

        pcmk__scan_ll(score, &score_ll, 0LL);
        if (score_ll > CRM_SCORE_INFINITY) {
            score_f = CRM_SCORE_INFINITY;

        } else if (score_ll < -CRM_SCORE_INFINITY) {
            score_f = -CRM_SCORE_INFINITY;

        } else {
            score_f = (int) score_ll;
        }
    }

    return score_f;
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
