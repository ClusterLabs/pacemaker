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

int based_init_transaction(const pcmk__client_t *client);
int based_extend_transaction(pcmk__client_t *client, xmlNodePtr request,
                             bool privileged);
void based_discard_transaction(const pcmk__client_t *client);
int based_commit_transaction(const pcmk__client_t *client,
                             xmlNodePtr *result_cib);
void based_free_transaction_table(void);

#endif // BASED_TRANSACTION__H
