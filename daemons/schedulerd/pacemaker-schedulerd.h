/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER_SCHEDULERD__H
#define PCMK__PACEMAKER_SCHEDULERD__H

#include <crm_internal.h>

extern pcmk__output_t *logger_out;
extern struct qb_ipcs_service_handlers ipc_callbacks;
void schedulerd_unregister_handlers(void);
void schedulerd_handle_request(pcmk__request_t *request);

#endif
