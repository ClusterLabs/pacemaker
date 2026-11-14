/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER_SCHEDULERD__H
#define PCMK__PACEMAKER_SCHEDULERD__H

#include <crm_internal.h>

#include <crm/common/internal.h>        // pcmk__daemon_t, pcmk__output_t, pcmk__request_t

extern pcmk__output_t *logger_out;
extern pcmk__daemon_t schedulerd;
extern pcmk__server_command_t schedulerd_handlers[];

void schedulerd_handle_request(pcmk__request_t *request);
void schedulerd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request);

#endif
