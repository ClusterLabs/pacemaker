/*
 * Copyright 2014-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef SCHED_TRANSITION__H
#  define SCHED_TRANSITION__H

#include <crm/cib.h>

void modify_configuration(
    pe_working_set_t * data_set, cib_t *cib,
    const char *quorum, const char *watchdog, GListPtr node_up, GListPtr node_down, GListPtr node_fail,
    GListPtr op_inject, GListPtr ticket_grant, GListPtr ticket_revoke,
    GListPtr ticket_standby, GListPtr ticket_activate);

int run_simulation(pe_working_set_t * data_set, cib_t *cib, GListPtr op_fail_list, bool quiet);

#endif
