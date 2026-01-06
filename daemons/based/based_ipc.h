/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef BASED_IPC__H
#define BASED_IPC__H

#include <qb/qbipcs.h>                  // qb_*

extern qb_ipcs_service_t *ipcs_ro;
extern qb_ipcs_service_t *ipcs_rw;
extern qb_ipcs_service_t *ipcs_shm;

void based_ipc_init(void);

#endif // BASED_IPC__H
