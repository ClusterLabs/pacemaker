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
#include <time.h>

#include <crm/common/util.h>
#include <crm/common/internal.h>
#include <crm/common/rules.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input = NULL;
    xmlNode *xml = NULL;
    crm_time_t *now = NULL;
    pcmk_rule_input_t rule_input = { NULL, };

    if (size < 10) {
        return -1;
    }

    // Null-terminate the fuzz input
    input = pcmk__assert_alloc(size + 1, sizeof(char));
    memcpy(input, data, size);
    input[size] = '\0';

    // Parse the fuzz input as XML — rules are always XML-based
    xml = pcmk__xml_parse(input);
    if (xml == NULL) {
        free(input);
        return 0;
    }

    // Set up a minimal rule evaluation context with a fixed "now" time
    now = pcmk__copy_timet(1700000000);  // Fixed time for determinism
    rule_input.now = now;

    // Evaluate the parsed XML as a rule
    pcmk_evaluate_rule(xml, &rule_input, NULL);

    crm_time_free(now);
    pcmk__xml_free(xml);
    free(input);
    return 0;
}
