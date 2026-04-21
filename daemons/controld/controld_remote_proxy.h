/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_REMOTE_PROXY_H
#define CONTROLD_REMOTE_PROXY_H

#include <stdint.h>                 // uint32_t
#include <sys/types.h>              // ssize_t

#include <glib.h>                   // gboolean, gpointer
#include <libxml/tree.h>            // xmlNode

#include <crm/common/ipc.h>         // crm_ipc_t
#include <crm/common/mainloop.h>    // ipc_client_callbacks, mainloop_io_t
#include <crm/lrmd.h>               // lrmd_t

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

void remote_proxy_cb(lrmd_t *lrmd, const char *node_name, xmlNode *msg);
void remote_proxy_ack_shutdown(lrmd_t *lrmd);
void remote_proxy_nack_shutdown(lrmd_t *lrmd);

int remote_proxy_dispatch(const char *buffer, ssize_t length,
                          gpointer userdata);
void remote_proxy_disconnected(gpointer data);
void remote_proxy_free(gpointer data);

void remote_proxy_relay_event(remote_proxy_t *proxy, xmlNode *msg);
void remote_proxy_relay_response(remote_proxy_t *proxy, xmlNode *msg,
                                 int msg_id);

#endif  // CONTROLD_REMOTE_PROXY_H
