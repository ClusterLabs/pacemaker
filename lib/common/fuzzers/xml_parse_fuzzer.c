/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <crm/common/util.h>
#include <crm/common/internal.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input = NULL;
    xmlNode *xml = NULL;

    if (size < 5) {
        return -1;
    }

    // Null-terminate the input to create a valid C string
    input = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse the XML string — this is the core function under test
    xml = pcmk__xml_parse(input);

    // If parsing succeeded, exercise some read-only operations on the result
    if (xml != NULL) {
        // Access the element name and ID (common post-parse operations)
        pcmk__xe_id(xml);

        // Iterate children — exercises XML tree traversal
        for (xmlNode *child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
             child != NULL;
             child = pcmk__xe_next(child, NULL)) {

            pcmk__xe_id(child);
        }

        pcmk__xml_free(xml);
    }

    free(input);
    return 0;
}
