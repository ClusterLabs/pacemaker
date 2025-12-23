/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_BASED__H
#  define PACEMAKER_BASED__H

#include <stdbool.h>
#include <stdint.h>                 // uint32_t, UINT64_C

#include <glib.h>                   // GHashTable, g_hash_table_lookup
#include <libxml/tree.h>            // xmlNode
#include <qb/qbipcs.h>              // qb_ipcs_service_t

#include <crm/cluster.h>            // pcmk_cluster_t
#include <crm/common/internal.h>    // pcmk__client_t

#include "based_io.h"
#include "based_messages.h"
#include "based_operation.h"
#include "based_notify.h"
#include "based_remote.h"
#include "based_transaction.h"

#define OUR_NODENAME (stand_alone? "localhost" : crm_cluster->priv->node_name)

// CIB-specific client flags
enum cib_client_flags {
    // Notifications
    cib_notify_pre     = (UINT64_C(1) << 0),
    cib_notify_post    = (UINT64_C(1) << 1),
    cib_notify_confirm = (UINT64_C(1) << 3),
    cib_notify_diff    = (UINT64_C(1) << 4),
};

extern GHashTable *config_hash;

extern GMainLoop *mainloop;
extern pcmk_cluster_t *crm_cluster;
extern gboolean stand_alone;
extern bool cib_shutdown_flag;
extern gchar *cib_root;
extern int cib_status;

extern struct qb_ipcs_service_handlers ipc_ro_callbacks;
extern struct qb_ipcs_service_handlers ipc_rw_callbacks;
extern qb_ipcs_service_t *ipcs_ro;
extern qb_ipcs_service_t *ipcs_rw;
extern qb_ipcs_service_t *ipcs_shm;

void cib_peer_callback(xmlNode *msg, void *private_data);
void cib_common_callback_worker(uint32_t id, uint32_t flags,
                                xmlNode *op_request, pcmk__client_t *cib_client,
                                bool privileged);
int based_process_request(xmlNode *request, bool privileged,
                          const pcmk__client_t *client);
void cib_shutdown(int nsig);
void terminate_cib(int exit_status);

static inline const char *
cib_config_lookup(const char *opt)
{
    return g_hash_table_lookup(config_hash, opt);
}

#endif // PACEMAKER_BASED__H
