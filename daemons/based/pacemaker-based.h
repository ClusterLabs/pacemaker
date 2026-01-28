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

#include <glib.h>                   // gboolean, gchar, GMainLoop

#include <crm/cluster.h>            // pcmk_cluster_t

#include "based_callbacks.h"
#include "based_io.h"
#include "based_messages.h"
#include "based_operation.h"
#include "based_notify.h"
#include "based_remote.h"
#include "based_transaction.h"

#define OUR_NODENAME (stand_alone? "localhost" : crm_cluster->priv->node_name)

extern GMainLoop *mainloop;
extern pcmk_cluster_t *crm_cluster;
extern gboolean stand_alone;
extern bool cib_shutdown_flag;
extern gchar *cib_root;
extern int cib_status;

#endif // PACEMAKER_BASED__H
