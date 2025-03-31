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
#include <strings.h>
#include <glib.h>

#include <crm/common/options.h>
#include <crm/common/util.h>
#include <crm/common/internal.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ns = NULL;
    guint res = 0U;
    long long msec = 0LL;

    if (size < 10) {
        return -1; // Do not add input to testing corpus
    }
    ns = pcmk__assert_alloc(1, size + 1);
    memcpy(ns, data, size);
    ns[size] = '\0';

    pcmk__numeric_strcasecmp(ns, ns);
    pcmk__trim(ns);
    pcmk_parse_interval_spec(ns, &res);
    pcmk__parse_ms(ns, &msec);

    free(ns);
    return 0;
}
