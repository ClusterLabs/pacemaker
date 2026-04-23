/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>                   // struct timespec

#include <qb/qbutil.h>              // qb_util_timespec_from_epoch_get()

#include <crm/common/util.h>
#include <crm/common/internal.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ns = NULL;
    crm_time_period_t *period = NULL;

    struct timespec tv = { 0, };
    crm_time_t *now = NULL;
    char *result = NULL;

    // Ensure we have enough data.
    if (size < 10) {
        return -1; // Do not add input to testing corpus
    }
    ns = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(ns, data, size);

    period = crm_time_parse_period(ns);
    crm_time_free_period(period);

    qb_util_timespec_from_epoch_get(&tv);
    now = pcmk__copy_timet(tv.tv_sec);
    result = pcmk__time_format_hr(ns, now,
                                  (int) (tv.tv_nsec / QB_TIME_NS_IN_USEC));
    crm_time_free(now);
    free(result);

    free(ns);
    return 0;
}
