/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <crm/cib.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *filename = NULL;
    int fd = 0;
    cib_t *cib = NULL;

    // Have at least some data
    if (size < 5) {
        return -1; // Do not add input to testing corpus
    }

    filename = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(filename, data, size);
    filename[size] = '\0';

    cib = cib_file_new(filename);

    cib_delete(cib);
    free(filename);
    return 0;
}
