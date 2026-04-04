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
#include <crm/common/acl.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input = NULL;
    xmlNode *xml = NULL;
    xmlNode *result = NULL;

    if (size < 20) {
        return -1;
    }

    // Null-terminate the fuzz input
    input = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse the fuzz input as XML
    xml = pcmk__xml_parse(input);
    if (xml == NULL) {
        free(input);
        return 0;
    }

    // Run the ACL filtered copy with a non-root user
    // pcmk_acl_required() returns false for "root" and "hacluster", so we use
    // a regular user name to ensure ACL processing is actually exercised.
    xml_acl_filtered_copy("fuzzuser", xml, xml, &result);

    if (result != NULL) {
        pcmk__xml_free(result);
    }

    pcmk__xml_free(xml);
    free(input);
    return 0;
}
