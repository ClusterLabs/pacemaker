/*
 * Copyright 2012-2018 David Vossel <davidvossel@gmail.com>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKER_EXECD__H
#  define PACEMAKER_EXECD__H

#  include <glib.h>
#  include <crm/common/ipcs.h>
#  include <crm/lrmd.h>
#  include <crm/stonith-ng.h>

#  ifdef HAVE_GNUTLS_GNUTLS_H
#    undef KEYFILE
#    include <gnutls/gnutls.h>
#  endif

GHashTable *rsc_list;

typedef struct lrmd_rsc_s {
    char *rsc_id;
    char *class;
    char *provider;
    char *type;

    int call_opts;

    /* NEVER dereference this pointer,
     * It simply exists as a switch to let us know
     * when the currently active operation has completed */
    void *active;

    /* Operations in this list
     * have not been executed yet. */
    GList *pending_ops;
    /* Operations in this list are recurring operations
     * that have been handed off from the pending ops list. */
    GList *recurring_ops;

    int stonith_started;

    crm_trigger_t *work;
} lrmd_rsc_t;

#  ifdef HAVE_GNUTLS_GNUTLS_H
// in remoted_tls.c
int lrmd_init_remote_tls_server(void);
void lrmd_tls_server_destroy(void);
#  endif

int lrmd_server_send_reply(crm_client_t * client, uint32_t id, xmlNode * reply);

int lrmd_server_send_notify(crm_client_t * client, xmlNode * msg);

void notify_of_new_client(crm_client_t *new_client);

void process_lrmd_message(crm_client_t * client, uint32_t id, xmlNode * request);

void free_rsc(gpointer data);

void handle_shutdown_ack(void);

void handle_shutdown_nack(void);

void lrmd_client_destroy(crm_client_t *client);

void client_disconnect_cleanup(const char *client_id);

/*!
 * \brief Don't worry about freeing this connection. It is
 *        taken care of after mainloop exits by the main() function.
 */
stonith_t *get_stonith_connection(void);

/*!
 * \brief This is a callback that tells the lrmd
 * the current stonith connection has gone away. This allows
 * us to timeout any pending stonith commands
 */
void stonith_connection_failed(void);

#ifdef SUPPORT_REMOTE
void ipc_proxy_init(void);
void ipc_proxy_cleanup(void);
void ipc_proxy_add_provider(crm_client_t *client);
void ipc_proxy_remove_provider(crm_client_t *client);
void ipc_proxy_forward_client(crm_client_t *client, xmlNode *xml);
crm_client_t *ipc_proxy_get_provider(void);
int ipc_proxy_shutdown_req(crm_client_t *ipc_proxy);
#endif

int process_lrmd_alert_exec(crm_client_t *client, uint32_t id, xmlNode *request);
void lrmd_drain_alerts(GMainContext *ctx);

#endif // PACEMAKER_EXECD__H
