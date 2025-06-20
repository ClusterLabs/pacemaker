/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_BASED__H
#  define PACEMAKER_BASED__H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <errno.h>
#include <fcntl.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/mainloop.h>
#include <crm/cib/internal.h>

#include "based_transaction.h"

#include <gnutls/gnutls.h>

#define OUR_NODENAME (stand_alone? "localhost" : crm_cluster->priv->node_name)

// CIB-specific client flags
enum cib_client_flags {
    // Notifications
    cib_notify_pre     = (UINT64_C(1) << 0),
    cib_notify_post    = (UINT64_C(1) << 1),
    cib_notify_confirm = (UINT64_C(1) << 3),
    cib_notify_diff    = (UINT64_C(1) << 4),

    // Whether client is another cluster daemon
    cib_is_daemon      = (UINT64_C(1) << 12),
};

extern bool based_is_primary;
extern GHashTable *config_hash;
extern xmlNode *the_cib;
extern crm_trigger_t *cib_writer;
extern gboolean cib_writes_enabled;

extern GMainLoop *mainloop;
extern pcmk_cluster_t *crm_cluster;
extern gboolean stand_alone;
extern gboolean cib_shutdown_flag;
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
                                gboolean privileged);
int cib_process_request(xmlNode *request, gboolean privileged,
                        const pcmk__client_t *cib_client);
void cib_shutdown(int nsig);
void terminate_cib(int exit_status);

gboolean uninitializeCib(void);
xmlNode *readCibXmlFile(const char *dir, const char *file,
                        gboolean discard_status);
int activateCibXml(xmlNode *doc, gboolean to_disk, const char *op);

int cib_process_shutdown_req(const char *op, int options, const char *section,
                             xmlNode *req, xmlNode *input,
                             xmlNode *existing_cib, xmlNode **result_cib,
                             xmlNode **answer);
int cib_process_noop(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);
int cib_process_ping(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);
int cib_process_readwrite(const char *op, int options, const char *section,
                          xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                          xmlNode **result_cib, xmlNode **answer);
int cib_process_replace_svr(const char *op, int options, const char *section,
                            xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                            xmlNode **result_cib, xmlNode **answer);
int cib_server_process_diff(const char *op, int options, const char *section,
                            xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                            xmlNode **result_cib, xmlNode **answer);
int cib_process_sync(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer);
int cib_process_sync_one(const char *op, int options, const char *section,
                         xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                         xmlNode **result_cib, xmlNode **answer);
int cib_process_delete_absolute(const char *op, int options,
                                const char *section, xmlNode *req,
                                xmlNode *input, xmlNode *existing_cib,
                                xmlNode **result_cib, xmlNode **answer);
int cib_process_upgrade_server(const char *op, int options, const char *section,
                               xmlNode *req, xmlNode *input,
                               xmlNode *existing_cib, xmlNode **result_cib,
                               xmlNode **answer);
int cib_process_commit_transaction(const char *op, int options,
                                   const char *section, xmlNode *req,
                                   xmlNode *input, xmlNode *existing_cib,
                                   xmlNode **result_cib, xmlNode **answer);
int cib_process_schemas(const char *op, int options, const char *section,
                        xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                        xmlNode **result_cib, xmlNode **answer);

void send_sync_request(const char *host);
int sync_our_cib(xmlNode *request, gboolean all);

cib__op_fn_t based_get_op_function(const cib__operation_t *operation);
void cib_diff_notify(const char *op, int result, const char *call_id,
                     const char *client_id, const char *client_name,
                     const char *origin, xmlNode *update, xmlNode *diff);

static inline const char *
cib_config_lookup(const char *opt)
{
    return g_hash_table_lookup(config_hash, opt);
}

#endif // PACEMAKER_BASED__H
