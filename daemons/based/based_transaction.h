/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_TRANSACTION__H
#define BASED_TRANSACTION__H

#include <crm_internal.h>

#include <libxml/tree.h>

char *based_transaction_source_str(const pcmk__client_t *client,
                                   const char *origin);

int based_commit_transaction(xmlNodePtr transaction,
                             const pcmk__client_t *client,
                             const char *origin, xmlNodePtr *result_cib);

#endif // BASED_TRANSACTION__H
