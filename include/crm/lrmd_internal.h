/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_LRMD_INTERNAL__H
#define PCMK__CRM_LRMD_INTERNAL__H

#include <stdint.h>                     // uint32_t

#include <glib.h>                       // GList, GHashTable, gpointer
#include <gnutls/gnutls.h>              // gnutls_datum_t
#include <libxml/tree.h>                // xmlNode

#include <crm/common/internal.h>        // pcmk__output_t, pcmk__remote_t, pcmk__action_result_t
#include <crm/common/ipc.h>             // crm_ipc_t
#include <crm/common/mainloop.h>        // mainloop_io_t, ipc_client_callbacks
#include <crm/common/results.h>         // ocf_exitcode
#include <crm/lrmd.h>                   // lrmd_t, lrmd_event_data_t, lrmd_rsc_info_t
#include <crm/lrmd_events.h>            // lrmd_event_data_t

#ifdef __cplusplus
extern "C" {
#endif

int lrmd__new(lrmd_t **api, const char *nodename, const char *server, int port);

int lrmd_send_attribute_alert(lrmd_t *lrmd, const GList *alert_list,
                              const char *node, uint32_t nodeid,
                              const char *attr_name, const char *attr_value);
int lrmd_send_node_alert(lrmd_t *lrmd, const GList *alert_list,
                         const char *node, uint32_t nodeid, const char *state);
int lrmd_send_fencing_alert(lrmd_t *lrmd, const GList *alert_list,
                            const char *target, const char *task,
                            const char *desc, int op_rc);
int lrmd_send_resource_alert(lrmd_t *lrmd, const GList *alert_list,
                             const char *node, const lrmd_event_data_t *op);

int lrmd__remote_send_xml(pcmk__remote_t *session, xmlNode *msg, uint32_t id,
                          const char *msg_type);

int lrmd__metadata_async(const lrmd_rsc_info_t *rsc,
                         void (*callback)(int pid,
                                          const pcmk__action_result_t *result,
                                          void *user_data),
                         void *user_data);

void lrmd__set_result(lrmd_event_data_t *event, enum ocf_exitcode rc,
                      int op_status, const char *exit_reason);

void lrmd__reset_result(lrmd_event_data_t *event);

time_t lrmd__uptime(lrmd_t *lrmd);
const char *lrmd__node_start_state(lrmd_t *lrmd);

/* Shared functions for IPC proxy back end */

typedef struct {
    char *node_name;
    char *session_id;

    gboolean is_local;

    crm_ipc_t *ipc;
    mainloop_io_t *source;
    uint32_t last_request_id;
    lrmd_t *lrm;

} remote_proxy_t;

remote_proxy_t *remote_proxy_new(lrmd_t *lrmd,
                                 struct ipc_client_callbacks *proxy_callbacks,
                                 const char *node_name, const char *session_id,
                                 const char *channel);

int lrmd__validate_remote_settings(lrmd_t *lrmd, GHashTable *hash);
void remote_proxy_cb(lrmd_t *lrmd, const char *node_name, xmlNode *msg);
void remote_proxy_ack_shutdown(lrmd_t *lrmd);
void remote_proxy_nack_shutdown(lrmd_t *lrmd);

int  remote_proxy_dispatch(const char *buffer, ssize_t length,
                           gpointer userdata);
void remote_proxy_disconnected(gpointer data);
void remote_proxy_free(gpointer data);

void remote_proxy_relay_event(remote_proxy_t *proxy, xmlNode *msg);
void remote_proxy_relay_response(remote_proxy_t *proxy, xmlNode *msg,
                                 int msg_id);

void lrmd__register_messages(pcmk__output_t *out);

int lrmd__init_remote_key(gnutls_datum_t *key);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_LRMD_INTERNAL__H
