/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/mainloop.h>
#include <crm/cib/internal.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  include <gnutls/gnutls.h>
#endif

// CIB-specific client flags
enum cib_client_flags {
    // Notifications
    cib_notify_pre     = (UINT64_C(1) << 0),
    cib_notify_post    = (UINT64_C(1) << 1),
    cib_notify_replace = (UINT64_C(1) << 2),
    cib_notify_confirm = (UINT64_C(1) << 3),
    cib_notify_diff    = (UINT64_C(1) << 4),

    // Whether client is another cluster daemon
    cib_is_daemon      = (UINT64_C(1) << 12),
};

typedef struct cib_operation_s {
    const char *operation;
    gboolean modifies_cib;
    gboolean needs_privileges;
    gboolean needs_quorum;
    int (*prepare) (xmlNode *, xmlNode **, const char **);
    int (*cleanup) (int, xmlNode **, xmlNode **);
    int (*fn) (const char *, int, const char *, xmlNode *,
               xmlNode *, xmlNode *, xmlNode **, xmlNode **);
} cib_operation_t;

extern bool based_is_primary;
extern GHashTable *config_hash;
extern xmlNode *the_cib;
extern crm_trigger_t *cib_writer;
extern gboolean cib_writes_enabled;

extern GMainLoop *mainloop;
extern crm_cluster_t *crm_cluster;
extern GHashTable *local_notify_queue;
extern gboolean legacy_mode;
extern gboolean stand_alone;
extern gboolean cib_shutdown_flag;
extern gchar *cib_root;
extern int cib_status;
extern pcmk__output_t *logger_out;

extern struct qb_ipcs_service_handlers ipc_ro_callbacks;
extern struct qb_ipcs_service_handlers ipc_rw_callbacks;
extern qb_ipcs_service_t *ipcs_ro;
extern qb_ipcs_service_t *ipcs_rw;
extern qb_ipcs_service_t *ipcs_shm;

void cib_peer_callback(xmlNode *msg, void *private_data);
void cib_common_callback_worker(uint32_t id, uint32_t flags,
                                xmlNode *op_request, pcmk__client_t *cib_client,
                                gboolean privileged);
void cib_shutdown(int nsig);
void terminate_cib(const char *caller, int fast);
gboolean cib_legacy_mode(void);

gboolean uninitializeCib(void);
xmlNode *readCibXmlFile(const char *dir, const char *file,
                        gboolean discard_status);
int activateCibXml(xmlNode *doc, gboolean to_disk, const char *op);

int cib_process_shutdown_req(const char *op, int options, const char *section,
                             xmlNode *req, xmlNode *input,
                             xmlNode *existing_cib, xmlNode **result_cib,
                             xmlNode **answer);
int cib_process_default(const char *op, int options, const char *section,
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
void send_sync_request(const char *host);
int sync_our_cib(xmlNode *request, gboolean all);

xmlNode *cib_msg_copy(xmlNode *msg, gboolean with_data);
int cib_get_operation_id(const char *op, int *operation);
cib_op_t *cib_op_func(int call_type);
gboolean cib_op_modifies(int call_type);
int cib_op_prepare(int call_type, xmlNode *request, xmlNode **input,
                   const char **section);
int cib_op_cleanup(int call_type, int options, xmlNode **input,
                   xmlNode **output);
int cib_op_can_run(int call_type, int call_options, gboolean privileged,
                   gboolean global_update);
void cib_diff_notify(int options, const char *client, const char *call_id,
                     const char *op, xmlNode *update, int result,
                     xmlNode *old_cib);
void cib_replace_notify(const char *origin, xmlNode *update, int result,
                        xmlNode *diff, uint32_t change_section);

static inline const char *
cib_config_lookup(const char *opt)
{
    return g_hash_table_lookup(config_hash, opt);
}

#endif // PACEMAKER_BASED__H
