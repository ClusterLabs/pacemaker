/*
 * Copyright 2023-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_TRANSACTION__H
#define BASED_TRANSACTION__H

#include <libxml/tree.h>            // xmlNode

#include <crm/common/internal.h>    // pcmk__client_t

char *based_transaction_source_str(const pcmk__client_t *client,
                                   const char *origin);

int based_commit_transaction(xmlNode *transaction, pcmk__client_t *client,
                             const char *origin, xmlNode **result_cib);

#endif // BASED_TRANSACTION__H
