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

#include <crm/common/util.h>
#include <crm/common/internal.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ns = NULL;
    char *result = NULL;
    time_t epoch = 0;
    pcmk__time_hr_t *now = NULL;
    crm_time_period_t *period = NULL;

    // Ensure we have enough data.
    if (size < 10) {
        return -1; // Do not add input to testing corpus
    }
    ns = pcmk__assert_alloc(1, size + 1);
    memcpy(ns, data, size);

    period = crm_time_parse_period(ns);
    crm_time_free_period(period);

    now = pcmk__time_hr_now(&epoch);
    result = pcmk__time_format_hr(ns, now);
    pcmk__time_hr_free(now);
    free(result);

    free(ns);
    return 0;
}
