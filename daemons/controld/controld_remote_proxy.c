/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // EACCES
#include <stdbool.h>                    // true
#include <stddef.h>                     // NULL
#include <stdint.h>                     // uint32_t
#include <stdlib.h>                     // free
#include <string.h>                     // strdup
#include <sys/types.h>                  // ssize_t
#include <time.h>                       // time

#include <glib.h>                       // g_*, etc.
#include <libxml/tree.h>                // xmlNode

#include <crm/cib.h>                    // cib_*
#include <crm/common/internal.h>        // pcmk__xe_*, pcmk__xml_*, etc.
#include <crm/common/ipc.h>             // crm_ipc_*
#include <crm/common/iso8601.h>         // crm_time_*
#include <crm/common/logging.h>         // CRM_CHECK, crm_log_xml_explicit
#include <crm/common/mainloop.h>        // ipc_client_callbacks, mainloop_*
#include <crm/common/nvpair.h>          // pcmk_unpack_nvpair_blocks
#include <crm/common/options.h>         // PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS
#include <crm/common/results.h>         // pcmk_ok, pcmk_rc_*, pcmk_strerror
#include <crm/common/rules.h>           // pcmk_rule_input_t
#include <crm/common/xml.h>             // PCMK_XA_*, PCMK_XE_*, etc.
#include <crm/crm.h>                    // crm_system_name
#include <crm/lrmd.h>                   // lrmd_t
#include <crm/lrmd_internal.h>          // lrmd__validate_remote_settings

#include "pacemaker-controld.h"         // remote_proxy_*

int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
GHashTable *proxy_table = NULL;

static void
remote_proxy_notify_destroy(lrmd_t *lrmd, const char *session_id)
{
    /* sending to the remote node that an ipc connection has been destroyed */
    xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_DESTROY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, session_id);
    lrmd_internal_proxy_send(lrmd, msg);
    pcmk__xml_free(msg);
}

/*!
 * \internal
 * \brief Acknowledge a remote proxy shutdown request
 *
 * \param[in,out] lrmd  Connection to proxy
 */
void
remote_proxy_ack_shutdown(lrmd_t *lrmd)
{
    xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_ACK);
    lrmd_internal_proxy_send(lrmd, msg);
    pcmk__xml_free(msg);
}

/*!
 * \internal
 * \brief Reject a remote proxy shutdown request
 *
 * \param[in,out] lrmd  Connection to proxy
 */
void
remote_proxy_nack_shutdown(lrmd_t *lrmd)
{
    xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_NACK);
    lrmd_internal_proxy_send(lrmd, msg);
    pcmk__xml_free(msg);
}

void
remote_proxy_relay_event(controld_remote_proxy_t *proxy, xmlNode *msg)
{
    /* sending to the remote node an event msg. */
    xmlNode *event = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    xmlNode *wrapper = NULL;

    pcmk__xe_set(event, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_EVENT);
    pcmk__xe_set(event, PCMK__XA_LRMD_IPC_SESSION, proxy->session_id);

    wrapper = pcmk__xe_create(event, PCMK__XE_LRMD_IPC_MSG);
    pcmk__xml_copy(wrapper, msg);

    crm_log_xml_explicit(event, "EventForProxy");
    lrmd_internal_proxy_send(proxy->lrm, event);
    pcmk__xml_free(event);
}

void
remote_proxy_relay_response(controld_remote_proxy_t *proxy, xmlNode *msg,
                            int msg_id)
{
    /* sending to the remote node a response msg. */
    xmlNode *response = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    xmlNode *wrapper = NULL;

    pcmk__xe_set(response, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_RESPONSE);
    pcmk__xe_set(response, PCMK__XA_LRMD_IPC_SESSION, proxy->session_id);
    pcmk__xe_set_int(response, PCMK__XA_LRMD_IPC_MSG_ID, msg_id);

    wrapper = pcmk__xe_create(response, PCMK__XE_LRMD_IPC_MSG);
    pcmk__xml_copy(wrapper, msg);

    lrmd_internal_proxy_send(proxy->lrm, response);
    pcmk__xml_free(response);
}

static void
remote_proxy_end_session(controld_remote_proxy_t *proxy)
{
    if (proxy == NULL) {
        return;
    }
    pcmk__trace("Ending session ID %s", proxy->session_id);

    if (proxy->source) {
        mainloop_del_ipc_client(proxy->source);
    }
}

void
remote_proxy_free(gpointer data)
{
    controld_remote_proxy_t *proxy = data;

    pcmk__trace("Freed proxy session ID %s", proxy->session_id);
    free(proxy->node_name);
    free(proxy->session_id);
    free(proxy);
}

int
remote_proxy_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    // Async responses from servers to clients via the remote executor
    xmlNode *xml = NULL;
    uint32_t flags = 0;
    controld_remote_proxy_t *proxy = userdata;

    xml = pcmk__xml_parse(buffer);
    if (xml == NULL) {
        pcmk__warn("Received a NULL msg from IPC service.");
        return 1;
    }

    flags = crm_ipc_buffer_flags(proxy->ipc);
    if (flags & crm_ipc_proxied_relay_response) {
        pcmk__trace("Passing response back to %.8s on %s: %.200s - request id: "
                    "%d", proxy->session_id, proxy->node_name, buffer,
                    proxy->last_request_id);
        remote_proxy_relay_response(proxy, xml, proxy->last_request_id);
        proxy->last_request_id = 0;

    } else {
        pcmk__trace("Passing event back to %.8s on %s: %.200s",
                    proxy->session_id, proxy->node_name, buffer);
        remote_proxy_relay_event(proxy, xml);
    }
    pcmk__xml_free(xml);
    return 1;
}


void
remote_proxy_disconnected(gpointer userdata)
{
    controld_remote_proxy_t *proxy = userdata;

    proxy->source = NULL;
    proxy->ipc = NULL;

    if(proxy->lrm) {
        remote_proxy_notify_destroy(proxy->lrm, proxy->session_id);
        proxy->lrm = NULL;
    }

    g_hash_table_remove(proxy_table, proxy->session_id);
}

static controld_remote_proxy_t *
remote_proxy_new(lrmd_t *lrmd, const char *node_name, const char *session_id,
                 const char *channel)
{
    static struct ipc_client_callbacks callbacks = {
        .dispatch = remote_proxy_dispatch,
        .destroy = remote_proxy_disconnected
    };

    controld_remote_proxy_t *proxy = NULL;

    if(channel == NULL) {
        pcmk__err("No channel specified to proxy");
        remote_proxy_notify_destroy(lrmd, session_id);
        return NULL;
    }

    proxy = pcmk__assert_alloc(1, sizeof(controld_remote_proxy_t));

    proxy->node_name = strdup(node_name);
    proxy->session_id = strdup(session_id);
    proxy->lrm = lrmd;

    if ((pcmk__parse_server(crm_system_name) == pcmk_ipc_controld)
        && (pcmk__parse_server(channel) == pcmk_ipc_controld)) {
        // The controller doesn't need to connect to itself
        proxy->is_local = true;

    } else {
        proxy->source = mainloop_add_ipc_client(channel, G_PRIORITY_LOW, 0,
                                                proxy, &callbacks);
        proxy->ipc = mainloop_get_ipc_client(proxy->source);
        if (proxy->source == NULL) {
            remote_proxy_free(proxy);
            remote_proxy_notify_destroy(lrmd, session_id);
            return NULL;
        }
    }

    pcmk__trace("New remote proxy client established to %s on %s, session id "
                "%s", channel, node_name, session_id);
    g_hash_table_insert(proxy_table, proxy->session_id, proxy);

    return proxy;
}

static void
remote_config_check(xmlNode *msg, int call_id, int rc, xmlNode *output,
                    void *user_data)
{
    if (rc != pcmk_ok) {
        pcmk__err("Query resulted in an error: %s", pcmk_strerror(rc));

        if (rc == -EACCES || rc == -pcmk_err_schema_validation) {
            pcmk__err("The cluster is mis-configured - shutting down and "
                      "staying down");
        }

    } else {
        lrmd_t * lrmd = (lrmd_t *)user_data;
        crm_time_t *now = crm_time_new(NULL);
        GHashTable *config_hash = pcmk__strkey_table(free, free);
        pcmk_rule_input_t rule_input = {
            .now = now,
        };

        pcmk__debug("Call %d : Parsing CIB options", call_id);
        pcmk_unpack_nvpair_blocks(output, PCMK_XE_CLUSTER_PROPERTY_SET,
                                  PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, &rule_input,
                                  config_hash, NULL);

        /* Now send it to the remote peer */
        lrmd__validate_remote_settings(lrmd, config_hash);

        g_hash_table_destroy(config_hash);
        crm_time_free(now);
    }
}

static void
crmd_proxy_dispatch(const char *session, xmlNode *msg)
{
    pcmk__trace("Processing proxied IPC message from session %s", session);
    pcmk__log_xml_trace(msg, "controller[inbound]");
    pcmk__xe_set(msg, PCMK__XA_CRM_SYS_FROM, session);
    if (controld_authorize_ipc_message(msg, NULL, session)) {
        route_message(C_IPC_MESSAGE, msg);
    }
    controld_trigger_fsa();
}

void
controld_remote_proxy_cb(lrmd_t *lrmd, void *user_data, xmlNode *msg)
{
    lrm_state_t *lrm_state = user_data;
    const char *op = pcmk__xe_get(msg, PCMK__XA_LRMD_IPC_OP);
    const char *session = pcmk__xe_get(msg, PCMK__XA_LRMD_IPC_SESSION);
    controld_remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);
    int msg_id = 0;

    /* sessions are raw ipc connections to IPC,
     * all we do is proxy requests/responses exactly
     * like they are given to us at the ipc level. */

    CRM_CHECK((op != NULL) && (session != NULL), return);

    pcmk__xe_get_int(msg, PCMK__XA_LRMD_IPC_MSG_ID, &msg_id);
    /* This is msg from remote ipc client going to real ipc server */

    if (pcmk__str_eq(op, LRMD_IPC_OP_NEW, pcmk__str_casei)) {
        const char *channel = pcmk__xe_get(msg, PCMK__XA_LRMD_IPC_SERVER);

        proxy = remote_proxy_new(lrmd, lrm_state->node_name, session, channel);

        if (!remote_ra_controlling_guest(lrm_state)) {
            if (proxy != NULL) {
                cib_t *cib_conn = controld_globals.cib_conn;

                /* Look up PCMK_OPT_FENCING_WATCHDOG_TIMEOUT and send to the
                 * remote peer for validation
                 */
                int rc = cib_conn->cmds->query(cib_conn, PCMK_XE_CRM_CONFIG,
                                               NULL, cib_none);
                cib_conn->cmds->register_callback_full(cib_conn, rc, 10, FALSE,
                                                       lrmd,
                                                       "remote_config_check",
                                                       remote_config_check,
                                                       NULL);
            }
        } else {
            pcmk__debug("Skipping remote_config_check for guest-nodes");
        }

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_SHUTDOWN_REQ, pcmk__str_casei)) {
        char *now_s = NULL;

        pcmk__notice("%s requested shutdown of its remote connection",
                     lrm_state->node_name);

        if (!remote_ra_is_in_maintenance(lrm_state)) {
            now_s = pcmk__ttoa(time(NULL));
            update_attrd(lrm_state->node_name, PCMK__NODE_ATTR_SHUTDOWN, now_s,
                         true);
            free(now_s);

            remote_proxy_ack_shutdown(lrmd);

            pcmk__warn("Reconnection attempts to %s may result in failures "
                       "that must be cleared",
                       lrm_state->node_name);
        } else {
            remote_proxy_nack_shutdown(lrmd);

            pcmk__notice("Remote resource for %s is not managed so no ordered "
                         "shutdown happening",
                         lrm_state->node_name);
        }
        return;

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_REQUEST, pcmk__str_casei)
               && (proxy != NULL) && proxy->is_local) {
        /* This is for the controller, which we are, so don't try
         * to send to ourselves over IPC -- do it directly.
         */
        uint32_t flags = 0U;
        int rc = pcmk_rc_ok;
        xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_LRMD_IPC_MSG,
                                                NULL, NULL);
        xmlNode *request = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

        CRM_CHECK(request != NULL, return);
        CRM_CHECK(lrm_state->node_name, return);
        pcmk__xe_set(request, PCMK_XE_ACL_ROLE, "pacemaker-remote");
        pcmk__update_acl_user(request, PCMK__XA_LRMD_IPC_USER,
                              lrm_state->node_name);

        /* Pacemaker Remote nodes don't know their own names (as known to the
         * cluster). When getting a node info request with no name or ID, add
         * the name, so we don't return info for ourselves instead of the
         * Pacemaker Remote node.
         */
        if (pcmk__str_eq(pcmk__xe_get(request, PCMK__XA_CRM_TASK),
                         CRM_OP_NODE_INFO, pcmk__str_none)) {
            int node_id = 0;

            pcmk__xe_get_int(request, PCMK_XA_ID, &node_id);
            if ((node_id <= 0)
                && (pcmk__xe_get(request, PCMK_XA_UNAME) == NULL)) {
                pcmk__xe_set(request, PCMK_XA_UNAME, lrm_state->node_name);
            }
        }

        crmd_proxy_dispatch(session, request);

        rc = pcmk__xe_get_flags(msg, PCMK__XA_LRMD_IPC_MSG_FLAGS, &flags, 0U);
        if (rc != pcmk_rc_ok) {
            pcmk__warn("Couldn't parse controller flags from remote request: "
                       "%s",
                       pcmk_rc_str(rc));
        }
        if (pcmk__is_set(flags, crm_ipc_client_response)) {
            int msg_id = 0;
            xmlNode *op_reply = pcmk__xe_create(NULL, PCMK__XE_ACK);

            pcmk__xe_set(op_reply, PCMK_XA_FUNCTION, __func__);
            pcmk__xe_set_int(op_reply, PCMK__XA_LINE, __LINE__);

            pcmk__xe_get_int(msg, PCMK__XA_LRMD_IPC_MSG_ID, &msg_id);
            remote_proxy_relay_response(proxy, op_reply, msg_id);

            pcmk__xml_free(op_reply);
        }

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_DESTROY, pcmk__str_casei)) {
        remote_proxy_end_session(proxy);

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_REQUEST, pcmk__str_casei)) {
        uint32_t flags = 0U;
        int rc = pcmk_rc_ok;
        const char *name = pcmk__xe_get(msg, PCMK__XA_LRMD_IPC_CLIENT);

        xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_LRMD_IPC_MSG,
                                                NULL, NULL);
        xmlNode *request = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

        CRM_CHECK(request != NULL, return);

        if (proxy == NULL) {
            /* proxy connection no longer exists */
            remote_proxy_notify_destroy(lrmd, session);
            return;
        }

        // Controller requests MUST be handled by the controller, not us
        CRM_CHECK(!proxy->is_local,
                  remote_proxy_end_session(proxy); return);

        if (!crm_ipc_connected(proxy->ipc)) {
            remote_proxy_end_session(proxy);
            return;
        }
        proxy->last_request_id = 0;
        pcmk__xe_set(request, PCMK_XE_ACL_ROLE, "pacemaker-remote");

        rc = pcmk__xe_get_flags(msg, PCMK__XA_LRMD_IPC_MSG_FLAGS, &flags, 0U);
        if (rc != pcmk_rc_ok) {
            pcmk__warn("Couldn't parse controller flags from remote request: "
                       "%s",
                       pcmk_rc_str(rc));
        }

        pcmk__assert(lrm_state->node_name != NULL);
        pcmk__update_acl_user(request, PCMK__XA_LRMD_IPC_USER,
                              lrm_state->node_name);

        if (pcmk__is_set(flags, crm_ipc_proxied)) {
            const char *type = pcmk__xe_get(request, PCMK__XA_T);
            int rc = 0;

            if (pcmk__str_eq(type, PCMK__VALUE_ATTRD, pcmk__str_none)
                && (pcmk__xe_get(request, PCMK__XA_ATTR_HOST) == NULL)
                && pcmk__str_any_of(pcmk__xe_get(request, PCMK_XA_TASK),
                                    PCMK__ATTRD_CMD_UPDATE,
                                    PCMK__ATTRD_CMD_UPDATE_BOTH,
                                    PCMK__ATTRD_CMD_UPDATE_DELAY, NULL)) {

                pcmk__xe_set(request, PCMK__XA_ATTR_HOST, proxy->node_name);
            }

            rc = crm_ipc_send(proxy->ipc, request, flags, 5000, NULL);

            if (rc < 0) {
                xmlNode *op_reply = pcmk__xe_create(NULL, PCMK__XE_NACK);

                pcmk__err("Could not relay request %d from %s to %s for %s: "
                          "%s (%d)",
                          msg_id, proxy->node_name, crm_ipc_name(proxy->ipc),
                          name, pcmk_strerror(rc), rc);

                /* Send a NACK to the caller (for instance, a program like
                 * cibadmin or crm_mon running on the remote node) so it doesn't
                 * block waiting for a reply.  Nothing actually checks that it
                 * receives a PCMK__XE_NACK, but it's got to receive something
                 * and since this message isn't being used anywhere else, it's
                 * a good one to use.
                 */
                pcmk__xe_set(op_reply, PCMK_XA_FUNCTION, __func__);
                pcmk__xe_set_int(op_reply, PCMK__XA_LINE, __LINE__);
                pcmk__xe_set_int(op_reply, PCMK_XA_RC, rc);
                remote_proxy_relay_response(proxy, op_reply, msg_id);
                pcmk__xml_free(op_reply);
                return;
            }

            pcmk__trace("Relayed request %d from %s to %s for %s", msg_id,
                        proxy->node_name, crm_ipc_name(proxy->ipc), name);
            proxy->last_request_id = msg_id;

        } else {
            int rc = pcmk_ok;
            xmlNode *op_reply = NULL;
            // @COMPAT pacemaker_remoted <= 1.1.10

            pcmk__trace("Relaying request %d from %s to %s for %s", msg_id,
                        proxy->node_name, crm_ipc_name(proxy->ipc), name);

            rc = crm_ipc_send(proxy->ipc, request, flags, 10000, &op_reply);
            if(rc < 0) {
                pcmk__err("Could not relay request %d from %s to %s for %s: "
                          "%s (%d)",
                          msg_id, proxy->node_name, crm_ipc_name(proxy->ipc),
                          name, pcmk_strerror(rc), rc);
            } else {
                pcmk__trace("Relayed request %d from %s to %s for %s", msg_id,
                            proxy->node_name, crm_ipc_name(proxy->ipc), name);
            }

            if(op_reply) {
                remote_proxy_relay_response(proxy, op_reply, msg_id);
                pcmk__xml_free(op_reply);
            }
        }
    } else {
        pcmk__err("Unknown proxy operation: %s", op);
    }
}
