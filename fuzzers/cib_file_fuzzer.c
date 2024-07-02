/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <crm_internal.h>
#include <crm/cib/internal.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *filename = NULL;
    int fd = 0;

    // Have at least some data
    if (size < 5) {
        return -1; // Do not add input to testing corpus
    }

    filename = crm_strdup_printf("%s/libfuzzer.XXXXXX", pcmk__get_tmpdir());
    fd = mkstemp(filename);
    if (fd == -1) {
        free(filename);
        return 0;
    }
    if (write(fd, data, size) < 0) {
        close(fd);
        unlink(filename);
        free(filename);
        return 0;
    }
    close(fd);

    cib_file_read_and_verify(filename, NULL, NULL);

    unlink(filename);
    free(filename);

    return 0;
}
