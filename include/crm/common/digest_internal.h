/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_DIGEST_INTERNAL__H
#define PCMK__CRM_COMMON_DIGEST_INTERNAL__H

/*
 * Internal-only functions to create digest strings from XML
 */

#include <stdbool.h>

#include <libxml/tree.h>    // xmlNode

#ifdef __cplusplus
extern "C" {
#endif

// Digest comparison results
enum pcmk__digest_result {
    pcmk__digest_unknown,   // No digest available for comparison
    pcmk__digest_match,     // Digests match
    pcmk__digest_mismatch,  // Any parameter changed (potentially reloadable)
    pcmk__digest_restart,   // Parameters that require a restart changed
};

// Information needed to compare operation digests
typedef struct {
    enum pcmk__digest_result rc;    // Result of digest comparison
    xmlNode *params_all;            // All operation parameters
    xmlNode *params_secure;         // Parameters marked private
    xmlNode *params_restart;        // Parameters marked not reloadable
    char *digest_all_calc;          // Digest of params_all
    char *digest_secure_calc;       // Digest of params_secure
    char *digest_restart_calc;      // Digest of params_restart
} pcmk__op_digest_t;

char *pcmk__digest_on_disk_cib(const xmlNode *input);
char *pcmk__digest_operation(xmlNode *input);
char *pcmk__digest_xml(const xmlNode *input, bool filter);

bool pcmk__verify_digest(xmlNode *input, const char *expected);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__CRM_COMMON_DIGEST_INTERNAL__H
