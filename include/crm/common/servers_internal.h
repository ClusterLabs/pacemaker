/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <servers_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_SERVERS_INTERNAL__H
#define PCMK__CRM_COMMON_SERVERS_INTERNAL__H

#include <crm/common/ipc.h>     // enum pcmk_ipc_server

#ifdef __cplusplus
extern "C" {
#endif

// Pacemaker server names
#define PCMK__SERVER_ATTRD      "pacemaker-attrd"
#define PCMK__SERVER_BASED      "pacemaker-based"
#define PCMK__SERVER_CONTROLD   "pacemaker-controld"
#define PCMK__SERVER_EXECD      "pacemaker-execd"
#define PCMK__SERVER_FENCED     "pacemaker-fenced"
#define PCMK__SERVER_PACEMAKERD "pacemakerd"
#define PCMK__SERVER_REMOTED    "pacemaker-remoted"
#define PCMK__SERVER_SCHEDULERD "pacemaker-schedulerd"

const char *pcmk__server_name(enum pcmk_ipc_server server);
const char *pcmk__server_log_name(enum pcmk_ipc_server server);
const char *pcmk__server_ipc_name(enum pcmk_ipc_server server);
const char *pcmk__server_message_type(enum pcmk_ipc_server server);
enum pcmk_ipc_server pcmk__parse_server(const char *text);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SERVERS_INTERNAL__H
