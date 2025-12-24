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
#include <qb/qbipcs.h>                  // qb_*

#include <crm/common/internal.h>        // pcmk__client_t

extern struct qb_ipcs_service_handlers ipc_ro_callbacks;
extern struct qb_ipcs_service_handlers ipc_rw_callbacks;

extern qb_ipcs_service_t *ipcs_ro;
extern qb_ipcs_service_t *ipcs_rw;
extern qb_ipcs_service_t *ipcs_shm;

void based_peer_callback(xmlNode *msg, void *private_data);
int based_process_request(xmlNode *request, bool privileged,
                          const pcmk__client_t *client);
void based_shutdown(int nsig);
void based_terminate(int exit_status);

#endif // BASED_CALLBACKS__H
