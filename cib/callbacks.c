/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

#include <crm/common/xml.h>


#include <cibio.h>
#include <callbacks.h>
#include <cibmessages.h>
#include <notify.h>
#include "common.h"

extern GMainLoop *mainloop;
extern gboolean cib_shutdown_flag;
extern gboolean stand_alone;
extern const char *cib_root;

static unsigned long cib_local_bcast_num = 0;

typedef struct cib_local_notify_s {
    xmlNode *notify_src;
    char *client_id;
    gboolean from_peer;
    gboolean sync_reply;
} cib_local_notify_t;

qb_ipcs_service_t *ipcs_ro = NULL;
qb_ipcs_service_t *ipcs_rw = NULL;
qb_ipcs_service_t *ipcs_shm = NULL;

extern crm_cluster_t crm_cluster;

extern int cib_update_counter(xmlNode * xml_obj, const char *field, gboolean reset);

extern void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data);

gint cib_GCompareFunc(gconstpointer a, gconstpointer b);
gboolean can_write(int flags);
void send_cib_replace(const xmlNode * sync_request, const char *host);
void cib_process_request(xmlNode * request, gboolean privileged, gboolean force_synchronous,
                         gboolean from_peer, cib_client_t * cib_client);

extern GHashTable *client_list;
extern GHashTable *local_notify_queue;

int next_client_id = 0;
extern const char *cib_our_uname;
extern unsigned long cib_num_ops, cib_num_local, cib_num_updates, cib_num_fail;
extern unsigned long cib_bad_connects, cib_num_timeouts;
extern int cib_status;

int cib_process_command(xmlNode * request, xmlNode ** reply,
                                    xmlNode ** cib_diff, gboolean privileged);

gboolean cib_common_callback(qb_ipcs_connection_t *c, void *data, size_t size, gboolean privileged);

static int32_t
cib_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    cib_client_t *new_client = NULL;
#if ENABLE_ACL
    struct group *crm_grp = NULL;
#endif

    crm_trace("Connecting %p for uid=%d gid=%d pid=%d", c, uid, gid, crm_ipcs_client_pid(c));
    if (cib_shutdown_flag) {
        crm_info("Ignoring new client [%d] during shutdown", crm_ipcs_client_pid(c));
        return -EPERM;
    }

    new_client = calloc(1, sizeof(cib_client_t));
    new_client->ipc = c;

    CRM_CHECK(new_client->id == NULL, free(new_client->id));
    new_client->id = crm_generate_uuid();

#if ENABLE_ACL
    crm_grp = getgrnam(CRM_DAEMON_GROUP);
    if (crm_grp) {
        qb_ipcs_connection_auth_set(c, -1, crm_grp->gr_gid, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    }

    new_client->user = uid2username(uid);
#endif

    /* make sure we can find ourselves later for sync calls
     * redirected to the master instance
     */
    g_hash_table_insert(client_list, new_client->id, new_client);

    qb_ipcs_context_set(c, new_client);

    return 0;
}

static void
cib_ipc_created(qb_ipcs_connection_t *c)
{
    cib_client_t *cib_client = qb_ipcs_context_get(c);

    crm_trace("%p connected for client %s", c, cib_client->id);
}

static int32_t
cib_ipc_dispatch_rw(qb_ipcs_connection_t *c, void *data, size_t size)
{
    cib_client_t *cib_client = qb_ipcs_context_get(c);
    crm_trace("%p message from %s", c, cib_client->id);
    return cib_common_callback(c, data, size, TRUE);
}

static int32_t
cib_ipc_dispatch_ro(qb_ipcs_connection_t *c, void *data, size_t size)
{
    cib_client_t *cib_client = qb_ipcs_context_get(c);
    crm_trace("%p message from %s", c, cib_client->id);
    return cib_common_callback(c, data, size, FALSE);
}

/* Error code means? */
static int32_t
cib_ipc_closed(qb_ipcs_connection_t *c) 
{
    cib_client_t *cib_client = qb_ipcs_context_get(c);
    crm_trace("Connection %p closed", c);

    CRM_ASSERT(cib_client != NULL);
    CRM_ASSERT(cib_client->id != NULL);

    if (!g_hash_table_remove(client_list, cib_client->id)) {
        crm_err("Client %s not found in the hashtable", cib_client->name);
    }

    return 0;
}

static void
cib_ipc_destroy(qb_ipcs_connection_t *c) 
{
    cib_client_t *cib_client = qb_ipcs_context_get(c);

    CRM_ASSERT(cib_client != NULL);
    CRM_ASSERT(cib_client->id != NULL);

    /* In case we arrive here without a call to cib_ipc_close() */
    g_hash_table_remove(client_list, cib_client->id);

    crm_trace("Destroying %s (%p)", cib_client->name, c);
    free(cib_client->name);
    free(cib_client->callback_id);
    free(cib_client->id);
    free(cib_client->user);
    free(cib_client);
    crm_trace("Freed the cib client");

    if (cib_shutdown_flag) {
        cib_shutdown(0);
    }
}

struct qb_ipcs_service_handlers ipc_ro_callbacks = 
{
    .connection_accept = cib_ipc_accept,
    .connection_created = cib_ipc_created,
    .msg_process = cib_ipc_dispatch_ro,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

struct qb_ipcs_service_handlers ipc_rw_callbacks = 
{
    .connection_accept = cib_ipc_accept,
    .connection_created = cib_ipc_created,
    .msg_process = cib_ipc_dispatch_rw,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

void
cib_common_callback_worker(uint32_t id, uint32_t flags, xmlNode * op_request, cib_client_t * cib_client, gboolean privileged)
{
    const char *op = crm_element_value(op_request, F_CIB_OPERATION);

    if (crm_str_eq(op, CRM_OP_REGISTER, TRUE)) {
        if(flags & crm_ipc_client_response) {
            xmlNode *ack = create_xml_node(NULL, __FUNCTION__);

            crm_xml_add(ack, F_CIB_OPERATION, CRM_OP_REGISTER);
            crm_xml_add(ack, F_CIB_CLIENTID, cib_client->id);
            crm_ipcs_send(cib_client->ipc, id, ack, FALSE);
            cib_client->request_id = 0;
            free_xml(ack);
        }
        return;

    } else if (crm_str_eq(op, T_CIB_NOTIFY, TRUE)) {
        /* Update the notify filters for this client */
        int on_off = 0;
        const char *type = crm_element_value(op_request, F_CIB_NOTIFY_TYPE);
        crm_element_value_int(op_request, F_CIB_NOTIFY_ACTIVATE, &on_off);

        crm_debug("Setting %s callbacks for %s (%s): %s",
                  type, cib_client->name, cib_client->id, on_off ? "on" : "off");

        if (safe_str_eq(type, T_CIB_POST_NOTIFY)) {
            cib_client->post_notify = on_off;

        } else if (safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
            cib_client->pre_notify = on_off;

        } else if (safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
            cib_client->confirmations = on_off;

        } else if (safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
            cib_client->diffs = on_off;

        } else if (safe_str_eq(type, T_CIB_REPLACE_NOTIFY)) {
            cib_client->replace = on_off;
        }

        if(flags & crm_ipc_client_response) {
            /* TODO - include rc */
            crm_ipcs_send_ack(cib_client->ipc, id, "ack", __FUNCTION__, __LINE__);
            cib_client->request_id = 0;
        }
        return;
    }

    cib_client->num_calls++;
    cib_process_request(op_request, FALSE, privileged, FALSE, cib_client);
}

int32_t
cib_common_callback(qb_ipcs_connection_t *c, void *data, size_t size, gboolean privileged)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    int call_options = 0;
    xmlNode *op_request = crm_ipcs_recv(c, data, size, &id, &flags);
    cib_client_t *cib_client = qb_ipcs_context_get(c);

    if(op_request) {
        crm_element_value_int(op_request, F_CIB_CALLOPTS, &call_options);
    }

    crm_trace("Inbound: %.200s", data);
    if (op_request == NULL || cib_client == NULL) {
        crm_ipcs_send_ack(c, id, "nack", __FUNCTION__, __LINE__);
        return 0;
    }

    if(is_set(call_options, cib_sync_call)) {
        CRM_ASSERT(flags & crm_ipc_client_response);
    }

    if(flags & crm_ipc_client_response) {
        CRM_LOG_ASSERT(cib_client->request_id == 0); /* This means the client has two synchronous events in-flight */
        cib_client->request_id = id;                 /* Reply only to the last one */
    }

    
    if (cib_client->name == NULL) {
        const char *value = crm_element_value(op_request, F_CIB_CLIENTNAME);
        if (value == NULL) {
            cib_client->name = crm_itoa(crm_ipcs_client_pid(c));
        } else {
            cib_client->name = strdup(value);
        }
    }

    if (cib_client->callback_id == NULL) {
        const char *value = crm_element_value(op_request, F_CIB_CALLBACK_TOKEN);
        if (value != NULL) {
            cib_client->callback_id = strdup(value);
            
        } else {
            cib_client->callback_id = strdup(cib_client->id);
        }
    }
    
    crm_xml_add(op_request, F_CIB_CLIENTID, cib_client->id);
    crm_xml_add(op_request, F_CIB_CLIENTNAME, cib_client->name);

#if ENABLE_ACL
    determine_request_user(cib_client->user, op_request, F_CIB_USER);
#endif

    crm_log_xml_trace(op_request, "Client[inbound]");

    cib_common_callback_worker(id, flags, op_request, cib_client, privileged);
    free_xml(op_request);

    return 0;
}

static void
do_local_notify(xmlNode * notify_src, const char *client_id,
                gboolean sync_reply, gboolean from_peer)
{
    /* send callback to originating child */
    cib_client_t *client_obj = NULL;
    int local_rc = pcmk_ok;

    if (client_id != NULL) {
        client_obj = g_hash_table_lookup(client_list, client_id);
    } else {
        crm_trace("No client to sent the response to. F_CIB_CLIENTID not set.");
    }

    if (client_obj == NULL) {
        local_rc = -ECONNRESET;

    } else {
        int rid = 0;

        if(sync_reply) {
            CRM_LOG_ASSERT(client_obj->request_id);

            rid = client_obj->request_id;
            client_obj->request_id = 0;

            crm_trace("Sending response %d to %s %s",
                      rid, client_obj->name, from_peer?"(originator of delegated request)":"");

        } else {
            crm_trace("Sending an event to %s %s",
                      client_obj->name, from_peer?"(originator of delegated request)":"");
        }

        if (client_obj->ipc && crm_ipcs_send(client_obj->ipc, rid, notify_src, !sync_reply) < 0) {
            local_rc = -ENOMSG;

#ifdef HAVE_GNUTLS_GNUTLS_H
        } else if (client_obj->session) {
            crm_send_remote_msg(client_obj->session, notify_src, client_obj->encrypted);
#endif
        } else if(client_obj->ipc == NULL) {
            crm_err("Unknown transport for %s", client_obj->name);
        }
    }

    if (local_rc != pcmk_ok && client_obj != NULL) {
        crm_warn("%sSync reply to %s failed: %s",
                 sync_reply ? "" : "A-",
                 client_obj ? client_obj->name : "<unknown>", pcmk_strerror(local_rc));
    }
}

static void
local_notify_destroy_callback(gpointer data)
{
    cib_local_notify_t *notify = data;

    free_xml(notify->notify_src);
    free(notify->client_id);
    free(notify);
}

static void
check_local_notify(int bcast_id)
{
    cib_local_notify_t *notify = NULL;

    if (!local_notify_queue) {
        return;
    }

    notify = g_hash_table_lookup(local_notify_queue, GINT_TO_POINTER(bcast_id));

    if (notify) {
        do_local_notify(notify->notify_src, notify->client_id, notify->sync_reply, notify->from_peer);
        g_hash_table_remove(local_notify_queue, GINT_TO_POINTER(bcast_id));
    }
}

static void
queue_local_notify(xmlNode * notify_src, const char *client_id, gboolean sync_reply, gboolean from_peer)
{
    cib_local_notify_t *notify = calloc(1, sizeof(cib_local_notify_t));

    notify->notify_src = notify_src;
    notify->client_id = strdup(client_id);
    notify->sync_reply = sync_reply;
    notify->from_peer = from_peer;

    if (!local_notify_queue) {
        local_notify_queue = g_hash_table_new_full(g_direct_hash,
            g_direct_equal, NULL, local_notify_destroy_callback);
    }

    g_hash_table_insert(local_notify_queue, GINT_TO_POINTER(cib_local_bcast_num), notify);
}

static void
parse_local_options(cib_client_t * cib_client, int call_type, int call_options, const char *host,
                    const char *op, gboolean * local_notify, gboolean * needs_reply,
                    gboolean * process, gboolean * needs_forward)
{
    if (cib_op_modifies(call_type)
        && !(call_options & cib_inhibit_bcast)) {
        /* we need to send an update anyway */
        *needs_reply = TRUE;
    } else {
        *needs_reply = FALSE;
    }

    if (host == NULL && (call_options & cib_scope_local)) {
        crm_trace("Processing locally scoped %s op from %s", op, cib_client->name);
        *local_notify = TRUE;

    } else if (host == NULL && cib_is_master) {
        crm_trace("Processing master %s op locally from %s", op, cib_client->name);
        *local_notify = TRUE;

    } else if (safe_str_eq(host, cib_our_uname)) {
        crm_trace("Processing locally addressed %s op from %s", op, cib_client->name);
        *local_notify = TRUE;

    } else if (stand_alone) {
        *needs_forward = FALSE;
        *local_notify = TRUE;
        *process = TRUE;

    } else {
        crm_trace("%s op from %s needs to be forwarded to %s",
                    op, cib_client->name, host ? host : "the master instance");
        *needs_forward = TRUE;
        *process = FALSE;
    }
}

static gboolean
parse_peer_options(int call_type, xmlNode * request,
                   gboolean * local_notify, gboolean * needs_reply, gboolean * process,
                   gboolean * needs_forward)
{
    const char *op = NULL;
    const char *host = NULL;
    const char *delegated = NULL;
    const char *originator = crm_element_value(request, F_ORIG);
    const char *reply_to = crm_element_value(request, F_CIB_ISREPLY);
    const char *update = crm_element_value(request, F_CIB_GLOBAL_UPDATE);

    gboolean is_reply = safe_str_eq(reply_to, cib_our_uname);

    if (crm_is_true(update)) {
        *needs_reply = FALSE;
        if (is_reply) {
            *local_notify = TRUE;
            crm_trace("Processing global/peer update from %s"
                      " that originated from us", originator);
        } else {
            crm_trace("Processing global/peer update from %s", originator);
        }
        return TRUE;
    }

    host = crm_element_value(request, F_CIB_HOST);
    if (host != NULL && safe_str_eq(host, cib_our_uname)) {
        crm_trace("Processing request sent to us from %s", originator);
        return TRUE;

    } else if (host == NULL && cib_is_master == TRUE) {
        crm_trace("Processing request sent to master instance from %s", originator);
        return TRUE;
    }

    op = crm_element_value(request, F_CIB_OPERATION);
    if(safe_str_eq(op, "cib_shutdown_req")) {
        /* Always process these */
        *local_notify = FALSE;
        if(reply_to == NULL || is_reply) {
            *process = TRUE;
        }
        if(is_reply) {
            *needs_reply = FALSE;
        }
        return *process;
    }

    if (is_reply) {
        crm_trace("Forward reply sent from %s to local clients", originator);
        *process = FALSE;
        *needs_reply = FALSE;
        *local_notify = TRUE;
        return TRUE;
    }

    delegated = crm_element_value(request, F_CIB_DELEGATED);
    if (delegated != NULL) {
        crm_trace("Ignoring msg for master instance");

    } else if (host != NULL) {
        /* this is for a specific instance and we're not it */
        crm_trace("Ignoring msg for instance on %s", crm_str(host));

    } else if (reply_to == NULL && cib_is_master == FALSE) {
        /* this is for the master instance and we're not it */
        crm_trace("Ignoring reply to %s", crm_str(reply_to));

    } else if (safe_str_eq(op, "cib_shutdown_req")) {
        if (reply_to != NULL) {
            crm_debug("Processing %s from %s", op, host);
            *needs_reply = FALSE;

        } else {
            crm_debug("Processing %s reply from %s", op, host);
        }
        return TRUE;

    } else {
        crm_err("Nothing for us to do?");
        crm_log_xml_err(request, "Peer[inbound]");
    }

    return FALSE;
}

static void
forward_request(xmlNode * request, cib_client_t * cib_client, int call_options)
{
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *host = crm_element_value(request, F_CIB_HOST);

    crm_xml_add(request, F_CIB_DELEGATED, cib_our_uname);

    if (host != NULL) {
        crm_trace("Forwarding %s op to %s", op, host);
        send_cluster_message(crm_get_peer(0, host), crm_msg_cib, request, FALSE);

    } else {
        crm_trace("Forwarding %s op to master instance", op);
        send_cluster_message(NULL, crm_msg_cib, request, FALSE);
    }

    /* Return the request to its original state */
    xml_remove_prop(request, F_CIB_DELEGATED);

    if (call_options & cib_discard_reply) {
        crm_trace("Client not interested in reply");
    }
}

static gboolean
send_peer_reply(xmlNode * msg, xmlNode * result_diff, const char *originator, gboolean broadcast)
{
    CRM_ASSERT(msg != NULL);

    if (broadcast) {
        /* this (successful) call modified the CIB _and_ the
         * change needs to be broadcast...
         *   send via HA to other nodes
         */
        int diff_add_updates = 0;
        int diff_add_epoch = 0;
        int diff_add_admin_epoch = 0;

        int diff_del_updates = 0;
        int diff_del_epoch = 0;
        int diff_del_admin_epoch = 0;

        const char *digest = NULL;

        digest = crm_element_value(result_diff, XML_ATTR_DIGEST);
        cib_diff_version_details(result_diff,
                                 &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                                 &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

        crm_trace("Sending update diff %d.%d.%d -> %d.%d.%d %s",
                    diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
                  diff_add_admin_epoch, diff_add_epoch, diff_add_updates, digest);

        crm_xml_add(msg, F_CIB_ISREPLY, originator);
        crm_xml_add(msg, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
        crm_xml_add(msg, F_CIB_OPERATION, CIB_OP_APPLY_DIFF);

        CRM_ASSERT(digest != NULL);

        add_message_xml(msg, F_CIB_UPDATE_DIFF, result_diff);
        crm_log_xml_trace(msg, "copy");
        return send_cluster_message(NULL, crm_msg_cib, msg, TRUE);

    } else if (originator != NULL) {
        /* send reply via HA to originating node */
        crm_trace("Sending request result to originator only");
        crm_xml_add(msg, F_CIB_ISREPLY, originator);
        return send_cluster_message(crm_get_peer(0, originator), crm_msg_cib, msg, FALSE);
    }

    return FALSE;
}

void
cib_process_request(xmlNode * request, gboolean force_synchronous, gboolean privileged,
                    gboolean from_peer, cib_client_t * cib_client)
{
    int call_type = 0;
    int call_options = 0;

    gboolean process = TRUE;
    gboolean is_update = TRUE;
    gboolean needs_reply = TRUE;
    gboolean local_notify = FALSE;
    gboolean needs_forward = FALSE;
    gboolean global_update = crm_is_true(crm_element_value(request, F_CIB_GLOBAL_UPDATE));

    xmlNode *op_reply = NULL;
    xmlNode *result_diff = NULL;

    int rc = pcmk_ok;
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *originator = crm_element_value(request, F_ORIG);
    const char *host = crm_element_value(request, F_CIB_HOST);
    const char *client_id = crm_element_value(request, F_CIB_CLIENTID);

    crm_trace("%s Processing msg %s", cib_our_uname, crm_element_value(request, F_SEQ));

    cib_num_ops++;
    if (cib_num_ops == 0) {
        cib_num_fail = 0;
        cib_num_local = 0;
        cib_num_updates = 0;
        crm_info("Stats wrapped around");
    }

    if (host != NULL && strlen(host) == 0) {
        host = NULL;
    }

    crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);
    if (force_synchronous) {
        call_options |= cib_sync_call;
    }

    crm_trace("Processing %s message (%s) for %s...",
                from_peer ? "peer" : "local",
                from_peer ? originator : cib_our_uname, host ? host : "master");

    rc = cib_get_operation_id(op, &call_type);
    if (rc != pcmk_ok) {
        /* TODO: construct error reply? */
        crm_err("Pre-processing of command failed: %s", pcmk_strerror(rc));
        return;
    }

    is_update = cib_op_modifies(call_type);
    if (is_update) {
        cib_num_updates++;
    }

    if (from_peer == FALSE) {
        parse_local_options(cib_client, call_type, call_options, host, op,
                            &local_notify, &needs_reply, &process, &needs_forward);

    } else if (parse_peer_options(call_type, request, &local_notify,
                                  &needs_reply, &process, &needs_forward) == FALSE) {
        return;
    }
    crm_trace("Finished determining processing actions");

    if (call_options & cib_discard_reply) {
        needs_reply = is_update;
        local_notify = FALSE;
    }

    if (needs_forward) {
        forward_request(request, cib_client, call_options);
        return;
    }

    if (cib_status != pcmk_ok) {
        rc = cib_status;
        crm_err("Operation ignored, cluster configuration is invalid."
                " Please repair and restart: %s", pcmk_strerror(cib_status));
        op_reply = cib_construct_reply(request, the_cib, cib_status);

    } else if (process) {
        int level = LOG_INFO;
        const char *section = crm_element_value(request, F_CIB_SECTION);

        cib_num_local++;
        rc = cib_process_command(request, &op_reply, &result_diff, privileged);

        if (global_update) {
            switch (rc) {
                case pcmk_ok:
                case -pcmk_err_old_data:
                case -pcmk_err_diff_resync:
                case -pcmk_err_diff_failed:
                    level = LOG_DEBUG_2;
                    break;
                default:
                    level = LOG_ERR;
            }

        } else if (safe_str_eq(op, CIB_OP_QUERY)) {
            level = LOG_DEBUG_2;

        } else if (rc != pcmk_ok) {
            cib_num_fail++;
            level = LOG_WARNING;

        } else if (safe_str_eq(op, CIB_OP_SLAVE)) {
            level = LOG_DEBUG_2;

        } else if (safe_str_eq(section, XML_CIB_TAG_STATUS)) {
            level = LOG_DEBUG_2;
        }

        do_crm_log_unlikely(level,
                       "Operation complete: op %s for section %s (origin=%s/%s/%s, version=%s.%s.%s): %s (rc=%d)",
                       op, section ? section : "'all'", originator ? originator : "local",
                       crm_element_value(request, F_CIB_CLIENTNAME), crm_element_value(request,
                                                                                       F_CIB_CALLID),
                       the_cib ? crm_element_value(the_cib, XML_ATTR_GENERATION_ADMIN) : "0",
                       the_cib ? crm_element_value(the_cib, XML_ATTR_GENERATION) : "0",
                       the_cib ? crm_element_value(the_cib, XML_ATTR_NUMUPDATES) : "0",
                       pcmk_strerror(rc), rc);

        if (op_reply == NULL && (needs_reply || local_notify)) {
            crm_err("Unexpected NULL reply to message");
            crm_log_xml_err(request, "null reply");
            needs_reply = FALSE;
            local_notify = FALSE;
        }
    }
    crm_trace("processing response cases %.16x %.16x", call_options, cib_sync_call);

    /* from now on we are the server */
    if (needs_reply == FALSE || stand_alone) {
        /* nothing more to do...
         * this was a non-originating slave update
         */
        crm_trace("Completed slave update");

    } else if (rc == pcmk_ok && result_diff != NULL && !(call_options & cib_inhibit_bcast)) {
        gboolean broadcast = FALSE;

        cib_local_bcast_num++;
        crm_xml_add_int(request, F_CIB_LOCAL_NOTIFY_ID, cib_local_bcast_num);
        broadcast = send_peer_reply(request, result_diff, originator, TRUE);

        if (broadcast &&
            client_id &&
            local_notify &&
            op_reply) {

            /* If we have been asked to sync the reply,
             * and a bcast msg has gone out, we queue the local notify
             * until we know the bcast message has been received */
            local_notify = FALSE;
            queue_local_notify(op_reply, client_id, (call_options & cib_sync_call), from_peer);
            op_reply = NULL; /* the reply is queued, so don't free here */
        }

    } else if (call_options & cib_discard_reply) {
        crm_trace("Caller isn't interested in reply");

    } else if (from_peer) {
        if (is_update == FALSE || result_diff == NULL) {
            crm_trace("Request not broadcast: R/O call");

        } else if (call_options & cib_inhibit_bcast) {
            crm_trace("Request not broadcast: inhibited");

        } else if (rc != pcmk_ok) {
            crm_trace("Request not broadcast: call failed: %s", pcmk_strerror(rc));
        } else {
            crm_trace("Directing reply to %s", originator);
        }

        send_peer_reply(op_reply, result_diff, originator, FALSE);
    }

    if (local_notify && client_id) {
        if (process == FALSE) {
            do_local_notify(request, client_id, call_options & cib_sync_call, from_peer);
        } else {
            do_local_notify(op_reply, client_id, call_options & cib_sync_call, from_peer);
        }
    }

    free_xml(op_reply);
    free_xml(result_diff);

    return;
}

xmlNode *
cib_construct_reply(xmlNode * request, xmlNode * output, int rc)
{
    int lpc = 0;
    xmlNode *reply = NULL;
    const char *name = NULL;
    const char *value = NULL;

    const char *names[] = {
        F_CIB_OPERATION,
        F_CIB_CALLID,
        F_CIB_CLIENTID,
        F_CIB_CALLOPTS
    };
    static int max = DIMOF(names);

    crm_trace("Creating a basic reply");
    reply = create_xml_node(NULL, "cib-reply");
    crm_xml_add(reply, F_TYPE, T_CIB);

    for (lpc = 0; lpc < max; lpc++) {
        name = names[lpc];
        value = crm_element_value(request, name);
        crm_xml_add(reply, name, value);
    }

    crm_xml_add_int(reply, F_CIB_RC, rc);

    if (output != NULL) {
        crm_trace("Attaching reply output");
        add_message_xml(reply, F_CIB_CALLDATA, output);
    }
    return reply;
}

int
cib_process_command(xmlNode * request, xmlNode ** reply, xmlNode ** cib_diff, gboolean privileged)
{
    xmlNode *input = NULL;
    xmlNode *output = NULL;
    xmlNode *result_cib = NULL;
    xmlNode *current_cib = NULL;

#if ENABLE_ACL
    xmlNode *filtered_current_cib = NULL;
#endif

    int call_type = 0;
    int call_options = 0;
    int log_level = LOG_DEBUG_4;

    const char *op = NULL;
    const char *section = NULL;

    int rc = pcmk_ok;
    int rc2 = pcmk_ok;

    gboolean send_r_notify = FALSE;
    gboolean global_update = FALSE;
    gboolean config_changed = FALSE;
    gboolean manage_counters = TRUE;

    CRM_ASSERT(cib_status == pcmk_ok);

    *reply = NULL;
    *cib_diff = NULL;
    current_cib = the_cib;

    /* Start processing the request... */
    op = crm_element_value(request, F_CIB_OPERATION);
    crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);
    rc = cib_get_operation_id(op, &call_type);

    if (rc == pcmk_ok && privileged == FALSE) {
        rc = cib_op_can_run(call_type, call_options, privileged, global_update);
    }

    rc2 = cib_op_prepare(call_type, request, &input, &section);
    if (rc == pcmk_ok) {
        rc = rc2;
    }

    if (rc != pcmk_ok) {
        crm_trace("Call setup failed: %s", pcmk_strerror(rc));
        goto done;

    } else if (cib_op_modifies(call_type) == FALSE) {
#if ENABLE_ACL
        if (acl_enabled(config_hash) == FALSE
            || acl_filter_cib(request, current_cib, current_cib, &filtered_current_cib) == FALSE) {
            rc = cib_perform_op(op, call_options, cib_op_func(call_type), TRUE,
                                section, request, input, FALSE, &config_changed,
                                current_cib, &result_cib, NULL, &output);

        } else if (filtered_current_cib == NULL) {
            crm_debug("Pre-filtered the entire cib");
            rc = -EACCES;

        } else {
            crm_debug("Pre-filtered the queried cib according to the ACLs");
            rc = cib_perform_op(op, call_options, cib_op_func(call_type), TRUE,
                                section, request, input, FALSE, &config_changed,
                                filtered_current_cib, &result_cib, NULL, &output);
        }
#else
        rc = cib_perform_op(op, call_options, cib_op_func(call_type), TRUE,
                            section, request, input, FALSE, &config_changed,
                            current_cib, &result_cib, NULL, &output);

#endif

        CRM_CHECK(result_cib == NULL, free_xml(result_cib));
        goto done;
    }

    /* Handle a valid write action */
    global_update = crm_is_true(crm_element_value(request, F_CIB_GLOBAL_UPDATE));
    if (global_update) {
        manage_counters = FALSE;
        call_options |= cib_force_diff;

        CRM_CHECK(call_type == 3 || call_type == 4, crm_err("Call type: %d", call_type);
                  crm_log_xml_err(request, "bad op"));
    }
#ifdef SUPPORT_PRENOTIFY
    if ((call_options & cib_inhibit_notify) == 0) {
        cib_pre_notify(call_options, op, the_cib, input);
    }
#endif

    if (rc == pcmk_ok) {
        if (call_options & cib_inhibit_bcast) {
            /* skip */
            crm_trace("Skipping update: inhibit broadcast");
            manage_counters = FALSE;
        }

        rc = cib_perform_op(op, call_options, cib_op_func(call_type), FALSE,
                            section, request, input, manage_counters, &config_changed,
                            current_cib, &result_cib, cib_diff, &output);

#if ENABLE_ACL
        if (acl_enabled(config_hash) == TRUE
            && acl_check_diff(request, current_cib, result_cib, *cib_diff) == FALSE) {
            rc = -EACCES;
        }
#endif

        if (rc == pcmk_ok && config_changed) {
            time_t now;
            char *now_str = NULL;
            const char *validation = crm_element_value(result_cib, XML_ATTR_VALIDATION);

            if (validation) {
                int current_version = get_schema_version(validation);
                int support_version = get_schema_version("pacemaker-1.1");

                /* Once the later schemas support the "update-*" attributes, change "==" to ">=" -- Changed */
                if (current_version >= support_version) {
                    const char *origin = crm_element_value(request, F_ORIG);

                    crm_xml_replace(result_cib, XML_ATTR_UPDATE_ORIG,
                                    origin ? origin : cib_our_uname);
                    crm_xml_replace(result_cib, XML_ATTR_UPDATE_CLIENT,
                                    crm_element_value(request, F_CIB_CLIENTNAME));
#if ENABLE_ACL
                    crm_xml_replace(result_cib, XML_ATTR_UPDATE_USER,
                                    crm_element_value(request, F_CIB_USER));
#endif
                }
            }

            now = time(NULL);
            now_str = ctime(&now);
            now_str[24] = EOS;  /* replace the newline */
            crm_xml_replace(result_cib, XML_CIB_ATTR_WRITTEN, now_str);
        }

        if (manage_counters == FALSE) {
            config_changed = cib_config_changed(current_cib, result_cib, cib_diff);
        }

        /* Always write to disk for replace ops,
         * this negates the need to detect ordering changes
         */
        if (config_changed == FALSE && crm_str_eq(CIB_OP_REPLACE, op, TRUE)) {
            config_changed = TRUE;
        }
    }

    cib_add_digest(result_cib, *cib_diff);

    if (rc == pcmk_ok && (call_options & cib_dryrun) == 0) {
        rc = activateCibXml(result_cib, config_changed, op);
        if (rc == pcmk_ok && cib_internal_config_changed(*cib_diff)) {
            cib_read_config(config_hash, result_cib);
        }

        if (crm_str_eq(CIB_OP_REPLACE, op, TRUE)) {
            if (section == NULL) {
                send_r_notify = TRUE;

            } else if (safe_str_eq(section, XML_TAG_CIB)) {
                send_r_notify = TRUE;

            } else if (safe_str_eq(section, XML_CIB_TAG_NODES)) {
                send_r_notify = TRUE;

            } else if (safe_str_eq(section, XML_CIB_TAG_STATUS)) {
                send_r_notify = TRUE;
            }

        } else if (crm_str_eq(CIB_OP_ERASE, op, TRUE)) {
            send_r_notify = TRUE;
        }

    } else if (rc == -pcmk_err_dtd_validation) {
        if (output != NULL) {
            crm_log_xml_info(output, "cib:output");
            free_xml(output);
        }
#if ENABLE_ACL
        {
            xmlNode *filtered_result_cib = NULL;

            if (acl_enabled(config_hash) == FALSE
                || acl_filter_cib(request, current_cib, result_cib,
                                  &filtered_result_cib) == FALSE) {
                output = result_cib;

            } else {
                crm_debug("Filtered the result cib for output according to the ACLs");
                output = filtered_result_cib;
                if (result_cib != NULL) {
                    free_xml(result_cib);
                }
            }
        }
#else
        output = result_cib;
#endif

    } else {
        free_xml(result_cib);
    }

    if ((call_options & cib_inhibit_notify) == 0) {
        const char *call_id = crm_element_value(request, F_CIB_CALLID);
        const char *client = crm_element_value(request, F_CIB_CLIENTNAME);

#ifdef SUPPORT_POSTNOTIFY
        cib_post_notify(call_options, op, input, rc, the_cib);
#endif
        cib_diff_notify(call_options, client, call_id, op, input, rc, *cib_diff);
    }

    if (send_r_notify) {
        const char *origin = crm_element_value(request, F_ORIG);

        cib_replace_notify(origin, the_cib, rc, *cib_diff);
    }

    if (rc != pcmk_ok) {
        log_level = LOG_DEBUG_4;
        if (rc == -pcmk_err_dtd_validation && global_update) {
            log_level = LOG_WARNING;
            crm_log_xml_info(input, "cib:global_update");
        }

    } else if (config_changed) {
        log_level = LOG_DEBUG_3;
        if (cib_is_master) {
            log_level = LOG_NOTICE;
        }

    } else if (cib_is_master) {
        log_level = LOG_DEBUG_2;
    }

    log_cib_diff(log_level, *cib_diff, "cib:diff");

  done:
    if ((call_options & cib_discard_reply) == 0) {
        *reply = cib_construct_reply(request, output, rc);
        crm_log_xml_trace(*reply, "cib:reply");
    }
#if ENABLE_ACL
    if (filtered_current_cib != NULL) {
        free_xml(filtered_current_cib);
    }
#endif

    if (call_type >= 0) {
        cib_op_cleanup(call_type, call_options, &input, &output);
    }
    return rc;
}

gint
cib_GCompareFunc(gconstpointer a, gconstpointer b)
{
    const xmlNode *a_msg = a;
    const xmlNode *b_msg = b;

    int msg_a_id = 0;
    int msg_b_id = 0;
    const char *value = NULL;

    value = crm_element_value_const(a_msg, F_CIB_CALLID);
    msg_a_id = crm_parse_int(value, NULL);

    value = crm_element_value_const(b_msg, F_CIB_CALLID);
    msg_b_id = crm_parse_int(value, NULL);

    if (msg_a_id == msg_b_id) {
        return 0;
    } else if (msg_a_id < msg_b_id) {
        return -1;
    }
    return 1;
}

#if SUPPORT_HEARTBEAT
void
cib_ha_peer_callback(HA_Message * msg, void *private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);

    cib_peer_callback(xml, private_data);
    free_xml(xml);
}
#endif

void
cib_peer_callback(xmlNode * msg, void *private_data)
{
    const char *reason = NULL;
    const char *originator = crm_element_value(msg, F_ORIG);

    if (originator == NULL || crm_str_eq(originator, cib_our_uname, TRUE)) {
        /* message is from ourselves */
        int bcast_id = 0;
        if (!(crm_element_value_int(msg, F_CIB_LOCAL_NOTIFY_ID, &bcast_id))) {
            check_local_notify(bcast_id);
        }
        return;

    } else if (crm_peer_cache == NULL) {
        reason = "membership not established";
        goto bail;
    }

    if (crm_element_value(msg, F_CIB_CLIENTNAME) == NULL) {
        crm_xml_add(msg, F_CIB_CLIENTNAME, originator);
    }

    /* crm_log_xml_trace("Peer[inbound]", msg); */
    cib_process_request(msg, FALSE, TRUE, TRUE, NULL);
    return;

  bail:
    if (reason) {
        const char *seq = crm_element_value(msg, F_SEQ);
        const char *op = crm_element_value(msg, F_CIB_OPERATION);

        crm_warn("Discarding %s message (%s) from %s: %s", op, seq, originator, reason);
    }
}


#if SUPPORT_HEARTBEAT
extern oc_ev_t *cib_ev_token;
static void *ccm_library = NULL;
int (*ccm_api_callback_done) (void *cookie) = NULL;
int (*ccm_api_handle_event) (const oc_ev_t * token) = NULL;

void
cib_client_status_callback(const char *node, const char *client, const char *status, void *private)
{
    crm_node_t *peer = NULL;

    if (safe_str_eq(client, CRM_SYSTEM_CIB)) {
        crm_info("Status update: Client %s/%s now has status [%s]", node, client, status);

        if (safe_str_eq(status, JOINSTATUS)) {
            status = ONLINESTATUS;

        } else if (safe_str_eq(status, LEAVESTATUS)) {
            status = OFFLINESTATUS;
        }

        peer = crm_get_peer(0, node);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cib, status);
    }
    return;
}

int
cib_ccm_dispatch(gpointer user_data)
{
    int rc = 0;
    oc_ev_t *ccm_token = (oc_ev_t *) user_data;

    crm_trace("received callback");

    if (ccm_api_handle_event == NULL) {
        ccm_api_handle_event =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_handle_event", 1);
    }

    rc = (*ccm_api_handle_event) (ccm_token);
    if (0 == rc) {
        return 0;
    }

    crm_err("CCM connection appears to have failed: rc=%d.", rc);

    /* eventually it might be nice to recover and reconnect... but until then... */
    crm_err("Exiting to recover from CCM connection failure");
    exit(2);

    return -1;
}

int current_instance = 0;
void
cib_ccm_msg_callback(oc_ed_t event, void *cookie, size_t size, const void *data)
{
    gboolean update_id = FALSE;
    const oc_ev_membership_t *membership = data;

    CRM_ASSERT(membership != NULL);

    crm_info("Processing CCM event=%s (id=%d)", ccm_event_name(event), membership->m_instance);

    if (current_instance > membership->m_instance) {
        crm_err("Membership instance ID went backwards! %d->%d",
                current_instance, membership->m_instance);
        CRM_ASSERT(current_instance <= membership->m_instance);
    }

    switch (event) {
        case OC_EV_MS_NEW_MEMBERSHIP:
        case OC_EV_MS_INVALID:
            update_id = TRUE;
            break;
        case OC_EV_MS_PRIMARY_RESTORED:
            update_id = TRUE;
            break;
        case OC_EV_MS_NOT_PRIMARY:
            crm_trace("Ignoring transitional CCM event: %s", ccm_event_name(event));
            break;
        case OC_EV_MS_EVICTED:
            crm_err("Evicted from CCM: %s", ccm_event_name(event));
            break;
        default:
            crm_err("Unknown CCM event: %d", event);
    }

    if (update_id) {
        unsigned int lpc = 0;

        CRM_CHECK(membership != NULL, return);

        current_instance = membership->m_instance;

        for (lpc = 0; lpc < membership->m_n_out; lpc++) {
            crm_update_ccm_node(membership, lpc + membership->m_out_idx, CRM_NODE_LOST,
                                current_instance);
        }

        for (lpc = 0; lpc < membership->m_n_member; lpc++) {
            crm_update_ccm_node(membership, lpc + membership->m_memb_idx, CRM_NODE_ACTIVE,
                                current_instance);
        }
    }

    if (ccm_api_callback_done == NULL) {
        ccm_api_callback_done =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_callback_done", 1);
    }
    (*ccm_api_callback_done) (cookie);
    return;
}
#endif

gboolean
can_write(int flags)
{
    return TRUE;
}

static gboolean
cib_force_exit(gpointer data)
{
    crm_notice("Forcing exit!");
    terminate_cib(__FUNCTION__, TRUE);
    return FALSE;
}

static void
disconnect_remote_client(gpointer key, gpointer value, gpointer user_data)
{
    cib_client_t *a_client = value;
    crm_err("Disconnecting %s... Not implemented", crm_str(a_client->name));
}

void
cib_shutdown(int nsig)
{
    struct qb_ipcs_stats srv_stats;
    if (cib_shutdown_flag == FALSE) {
        int disconnects = 0;
        qb_ipcs_connection_t *c = NULL;

        cib_shutdown_flag = TRUE;

        c = qb_ipcs_connection_first_get(ipcs_rw);
        while(c != NULL) {
            qb_ipcs_connection_t *last = c;
            c = qb_ipcs_connection_next_get(ipcs_rw, last);

            crm_debug("Disconnecting r/w client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        c = qb_ipcs_connection_first_get(ipcs_ro);
        while(c != NULL) {
            qb_ipcs_connection_t *last = c;
            c = qb_ipcs_connection_next_get(ipcs_ro, last);

            crm_debug("Disconnecting r/o client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        c = qb_ipcs_connection_first_get(ipcs_shm);
        while(c != NULL) {
            qb_ipcs_connection_t *last = c;
            c = qb_ipcs_connection_next_get(ipcs_shm, last);

            crm_debug("Disconnecting non-blocking r/w client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        disconnects += g_hash_table_size(client_list);

        crm_debug("Disconnecting %d remote clients", g_hash_table_size(client_list));
        g_hash_table_foreach(client_list, disconnect_remote_client, NULL);
        crm_info("Disconnected %d clients", disconnects);
    }

    qb_ipcs_stats_get(ipcs_rw, &srv_stats, QB_FALSE);
    
    if(g_hash_table_size(client_list) == 0) {
        crm_info("All clients disconnected (%d)", srv_stats.active_connections);
        initiate_exit();
        
    } else {
        crm_info("Waiting on %d clients to disconnect (%d)", g_hash_table_size(client_list), srv_stats.active_connections);
    }
}

void
initiate_exit(void)
{
    int active = 0;
    xmlNode *leaving = NULL;

    active = crm_active_peers();
    if (active < 2) {
        terminate_cib(__FUNCTION__, FALSE);
        return;
    }

    crm_info("Sending disconnect notification to %d peers...", active);

    leaving = create_xml_node(NULL, "exit-notification");
    crm_xml_add(leaving, F_TYPE, "cib");
    crm_xml_add(leaving, F_CIB_OPERATION, "cib_shutdown_req");

    send_cluster_message(NULL, crm_msg_cib, leaving, TRUE);
    free_xml(leaving);

    g_timeout_add(crm_get_msec("5s"), cib_force_exit, NULL);
}

extern int remote_fd;
extern int remote_tls_fd;
extern void terminate_cs_connection(void);

void
terminate_cib(const char *caller, gboolean fast)
{
    if (remote_fd > 0) {
        close(remote_fd);
        remote_fd = 0;
    }
    if (remote_tls_fd > 0) {
        close(remote_tls_fd);
        remote_tls_fd = 0;
    }
    
    if(!fast) {
        crm_info("%s: Disconnecting from cluster infrastructure", caller);
        crm_cluster_disconnect(&crm_cluster);
    }

    uninitializeCib();

    crm_info("%s: Exiting%s...", caller, fast?" fast":mainloop?" from mainloop":"");

    if(fast == FALSE && mainloop != NULL && g_main_is_running(mainloop)) {
        g_main_quit(mainloop);

    } else {
        qb_ipcs_destroy(ipcs_ro);
        qb_ipcs_destroy(ipcs_rw);
        qb_ipcs_destroy(ipcs_shm);
        qb_log_fini();

        if (fast) {
            exit(EX_USAGE);
        } else {
            exit(EX_OK);
        }
    }
}
