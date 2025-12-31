/*
 * Copyright 2025-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_NOTIFY__H
#define BASED_NOTIFY__H

#include <libxml/tree.h>            // xmlNode

#include <crm/common/internal.h>    // pcmk__client_t

int based_update_notify_flags(const xmlNode *xml, pcmk__client_t *client);

void based_diff_notify(const char *op, int result, const char *call_id,
                       const char *client_id, const char *client_name,
                       const char *origin, xmlNode *diff);

#endif // BASED_NOTIFY__H
