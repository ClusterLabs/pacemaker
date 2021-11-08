/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER_SCHEDULERD__H
#define PCMK__PACEMAKER_SCHEDULERD__H

#include <crm_internal.h>
#include <crm/pengine/pe_types.h>

extern pe_working_set_t *sched_data_set;
extern pcmk__output_t *logger_out;
extern pcmk__output_t *out;
extern struct qb_ipcs_service_handlers ipc_callbacks;

#endif
