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

#include <libxml/tree.h>                // xmlNode

#include <crm/common/internal.h>        // pcmk__client_t

void based_callbacks_init(void);
void based_callbacks_cleanup(void);

int based_handle_request(pcmk__request_t *request);

#endif // BASED_CALLBACKS__H
