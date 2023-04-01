/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

#define OUR_NODENAME (stand_alone? "localhost" : crm_cluster->uname)

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

/*!
 * \internal
 * \enum cib_op_attr
 * \brief Bit flags for CIB operation attributes
 */
enum cib_op_attr {
    cib_op_attr_none           = 0,         //!< No special attributes
    cib_op_attr_modifies       = (1 << 1),  //!< Modifies CIB
    cib_op_attr_privileged     = (1 << 2),  //!< Requires privileges
    cib_op_attr_local          = (1 << 3),  //!< Must only be processed locally
    cib_op_attr_replaces       = (1 << 4),  //!< Replaces CIB
    cib_op_attr_writes_through = (1 << 5),  //!< Writes to disk on success
};

typedef struct cib_operation_s {
    const char *name;
    uint32_t flags; //!< Group of <tt>enum cib_op_attr</tt> flags
    int (*prepare) (xmlNode *, xmlNode **, const char **);
    int (*cleanup) (int, xmlNode **, xmlNode **);
    cib_op_t fn;
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
int cib_process_request(xmlNode *request, gboolean privileged,
                        const pcmk__client_t *cib_client);
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
void send_sync_request(const char *host);
int sync_our_cib(xmlNode *request, gboolean all);

int cib_get_operation(const char *op, const cib_operation_t **operation);
void cib_diff_notify(const char *op, int result, const char *call_id,
                     const char *client_id, const char *client_name,
                     const char *origin, xmlNode *update, xmlNode *diff);
void cib_replace_notify(const char *op, int result, const char *call_id,
                        const char *client_id, const char *client_name,
                        const char *origin, xmlNode *update, xmlNode *diff,
                        uint32_t change_section);

static inline const char *
cib_config_lookup(const char *opt)
{
    return g_hash_table_lookup(config_hash, opt);
}

#endif // PACEMAKER_BASED__H
