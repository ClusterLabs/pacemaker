/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_BASED__H
#define PACEMAKER_BASED__H

#include <stdbool.h>

#include <glib.h>                   // gchar

#include <crm/common/results.h>     // crm_exit_t

#include "based_callbacks.h"
#include "based_corosync.h"
#include "based_io.h"
#include "based_ipc.h"
#include "based_messages.h"
#include "based_operation.h"
#include "based_notify.h"
#include "based_remote.h"
#include "based_transaction.h"

#define OUR_NODENAME    \
    (based_stand_alone()? "localhost" : based_cluster_node_name())

extern xmlNode *based_cib;
extern gchar *cib_root;
extern int cib_status;

bool based_get_local_node_dc(void);
void based_set_local_node_dc(bool value);

bool based_shutting_down(void);
bool based_stand_alone(void);

void based_quit_main_loop(crm_exit_t ec);

#endif // PACEMAKER_BASED__H
