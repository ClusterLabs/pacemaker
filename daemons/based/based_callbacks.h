/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_CALLBACKS__H
#define BASED_CALLBACKS__H

#include <stdbool.h>

#include <libxml/tree.h>                // xmlNode

#include <crm/common/internal.h>        // pcmk__client_t

int based_process_request(xmlNode *request, bool privileged,
                          const pcmk__client_t *client);
void based_shutdown(int nsig);
void based_terminate(int exit_status);

#endif // BASED_CALLBACKS__H
