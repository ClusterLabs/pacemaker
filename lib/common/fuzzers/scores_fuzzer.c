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
    guint result = 0U;

    if (size > 0) {
        ns = pcmk__assert_alloc(size + 1, sizeof(char));
        memcpy(ns, data, size);
        ns[size] = '\0';
    }

    pcmk_str_is_infinity(ns);
    pcmk_str_is_minus_infinity(ns);

    free(ns);
    return 0;
}
