/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EINVAL, ENOMEM, ENOTCONN
#include <stdbool.h>                // true, bool, false
#include <stdint.h>                 // uint32_t, uint64_t
#include <stdlib.h>                 // NULL, free, calloc
#include <string.h>                 // strdup, strcmp, strlen
#include <sys/types.h>              // time_t, ssize_t
#include <time.h>                   // time
#include <unistd.h>                 // close

#include <glib.h>                   // g_list_free_full, gpointer
#include <gnutls/gnutls.h>          // gnutls_deinit, gnutls_bye
#include <libxml/parser.h>          // xmlNode
#include <qb/qbdefs.h>              // QB_MAX
#include <qb/qblog.h>               // QB_XS

#include <crm/common/actions.h>     // PCMK_DEFAULT_ACTION_TIMEOUT_MS
#include <crm/common/agents.h>      // PCMK_RESOURCE_CLASS_STONITH
#include <crm/common/internal.h>
#include <crm/common/ipc.h>         // crm_ipc_*
#include <crm/common/logging.h>     // CRM_CHECK, CRM_LOG_ASSERT
#include <crm/common/mainloop.h>    // mainloop_set_trigger
#include <crm/common/nvpair.h>      // hash2smartfield, xml2list
#include <crm/common/options.h>     // PCMK_OPT_FENCING_WATCHDOG_TIMEOUT
#include <crm/common/results.h>     // pcmk_rc_*, pcmk_rc2legacy
#include <crm/common/util.h>        // crm_default_remote_port
#include <crm/crm.h>                // CRM_OP_REGISTER, CRM_SYSTEM_LRMD
#include <crm/fencing/internal.h>   // stonith__*
#include <crm/lrmd.h>               // lrmd_t, lrmd_s, lrmd_key_value_t
#include <crm/lrmd_events.h>        // lrmd_event_*
#include <crm/lrmd_internal.h>      // lrmd__init_remote_key
#include <crm/services.h>           // services_action_free
#include <crm/services_internal.h>  // services__copy_result

#define MAX_TLS_RECV_WAIT 10000

static int lrmd_api_disconnect(lrmd_t * lrmd);
static int lrmd_api_is_connected(lrmd_t * lrmd);

/* IPC proxy functions */
int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
static void lrmd_internal_proxy_dispatch(lrmd_t *lrmd, xmlNode *msg);
void lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg));

// GnuTLS client handshake timeout in seconds
#define TLS_HANDSHAKE_TIMEOUT 5

static void lrmd_tls_disconnect(lrmd_t * lrmd);
static int global_remote_msg_id = 0;
static void lrmd_tls_connection_destroy(gpointer userdata);
static int add_tls_to_mainloop(lrmd_t *lrmd, bool do_api_handshake);

static gnutls_datum_t remote_key = { NULL, 0 };

typedef struct {
    uint64_t type;
    char *token;
    mainloop_io_t *source;

    /* IPC parameters */
    crm_ipc_t *ipc;

    pcmk__remote_t *remote;

    /* Extra TLS parameters */
    char *remote_nodename;
    char *server;
    int port;
    pcmk__tls_t *tls;

    /* while the async connection is occurring, this is the id
     * of the connection timeout timer. */
    int async_timer;
    int sock;
    /* since tls requires a round trip across the network for a
     * request/reply, there are times where we just want to be able
     * to send a request from the client and not wait around (or even care
     * about) what the reply is. */
    int expected_late_replies;
    GList *pending_notify;
    crm_trigger_t *process_notify;
    crm_trigger_t *handshake_trigger;

    lrmd_event_callback callback;

    /* Internal IPC proxy msg passing for remote guests */
    void (*proxy_callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg);
    void *proxy_callback_userdata;
    char *peer_version;
} lrmd_private_t;

static int process_lrmd_handshake_reply(xmlNode *reply, lrmd_private_t *native);
static void report_async_connection_result(lrmd_t * lrmd, int rc);

static lrmd_list_t *
lrmd_list_add(lrmd_list_t * head, const char *value)
{
    lrmd_list_t *p, *end;

    p = pcmk__assert_alloc(1, sizeof(lrmd_list_t));
    p->val = strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
lrmd_list_freeall(lrmd_list_t * head)
{
    lrmd_list_t *p;

    while (head) {
        char *val = (char *)head->val;

        p = head->next;
        free(val);
        free(head);
        head = p;
    }
}

lrmd_key_value_t *
lrmd_key_value_add(lrmd_key_value_t * head, const char *key, const char *value)
{
    lrmd_key_value_t *p, *end;

    p = pcmk__assert_alloc(1, sizeof(lrmd_key_value_t));
    p->key = strdup(key);
    p->value = strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
lrmd_key_value_freeall(lrmd_key_value_t * head)
{
    lrmd_key_value_t *p;

    while (head) {
        p = head->next;
        free(head->key);
        free(head->value);
        free(head);
        head = p;
    }
}

/*!
 * \brief Create a new lrmd_event_data_t object
 *
 * \param[in] rsc_id       ID of resource involved in event
 * \param[in] task         Action name
 * \param[in] interval_ms  Action interval
 *
 * \return Newly allocated and initialized lrmd_event_data_t
 * \note This functions asserts on memory errors, so the return value is
 *       guaranteed to be non-NULL. The caller is responsible for freeing the
 *       result with lrmd_free_event().
 */
lrmd_event_data_t *
lrmd_new_event(const char *rsc_id, const char *task, guint interval_ms)
{
    lrmd_event_data_t *event = pcmk__assert_alloc(1, sizeof(lrmd_event_data_t));

    // lrmd_event_data_t has (const char *) members that lrmd_free_event() frees
    event->rsc_id = pcmk__str_copy(rsc_id);
    event->op_type = pcmk__str_copy(task);
    event->interval_ms = interval_ms;
    return event;
}

lrmd_event_data_t *
lrmd_copy_event(lrmd_event_data_t * event)
{
    lrmd_event_data_t *copy = NULL;

    copy = pcmk__assert_alloc(1, sizeof(lrmd_event_data_t));

    copy->type = event->type;

    // lrmd_event_data_t has (const char *) members that lrmd_free_event() frees
    copy->rsc_id = pcmk__str_copy(event->rsc_id);
    copy->op_type = pcmk__str_copy(event->op_type);
    copy->user_data = pcmk__str_copy(event->user_data);
    copy->output = pcmk__str_copy(event->output);
    copy->remote_nodename = pcmk__str_copy(event->remote_nodename);
    copy->exit_reason = pcmk__str_copy(event->exit_reason);

    copy->call_id = event->call_id;
    copy->timeout = event->timeout;
    copy->interval_ms = event->interval_ms;
    copy->start_delay = event->start_delay;
    copy->rsc_deleted = event->rsc_deleted;
    copy->rc = event->rc;
    copy->op_status = event->op_status;
    copy->t_run = event->t_run;
    copy->t_rcchange = event->t_rcchange;
    copy->exec_time = event->exec_time;
    copy->queue_time = event->queue_time;
    copy->connection_rc = event->connection_rc;
    copy->params = pcmk__str_table_dup(event->params);

    return copy;
}

/*!
 * \brief Free an executor event
 *
 * \param[in,out]  Executor event object to free
 */
void
lrmd_free_event(lrmd_event_data_t *event)
{
    if (event == NULL) {
        return;
    }
    // @TODO Why are these const char *?
    free((void *) event->rsc_id);
    free((void *) event->op_type);
    free((void *) event->user_data);
    free((void *) event->remote_nodename);
    lrmd__reset_result(event);
    if (event->params != NULL) {
        g_hash_table_destroy(event->params);
    }
    free(event);
}

static void
lrmd_dispatch_internal(gpointer data, gpointer user_data)
{
    xmlNode *msg = data;
    lrmd_t *lrmd = user_data;

    const char *type;
    const char *proxy_session = pcmk__xe_get(msg, PCMK__XA_LRMD_IPC_SESSION);
    lrmd_private_t *native = lrmd->lrmd_private;
    lrmd_event_data_t event = { 0, };

    if (proxy_session != NULL) {
        /* this is proxy business */
        lrmd_internal_proxy_dispatch(lrmd, msg);
        return;
    } else if (!native->callback) {
        /* no callback set */
        pcmk__trace("notify event received but client has not set callback");
        return;
    }

    event.remote_nodename = native->remote_nodename;
    type = pcmk__xe_get(msg, PCMK__XA_LRMD_OP);
    pcmk__xe_get_int(msg, PCMK__XA_LRMD_CALLID, &event.call_id);
    event.rsc_id = pcmk__xe_get(msg, PCMK__XA_LRMD_RSC_ID);

    if (pcmk__str_eq(type, LRMD_OP_RSC_REG, pcmk__str_none)) {
        event.type = lrmd_event_register;
    } else if (pcmk__str_eq(type, LRMD_OP_RSC_UNREG, pcmk__str_none)) {
        event.type = lrmd_event_unregister;
    } else if (pcmk__str_eq(type, LRMD_OP_RSC_EXEC, pcmk__str_none)) {
        int rc = 0;
        int exec_time = 0;
        int queue_time = 0;

        pcmk__xe_get_int(msg, PCMK__XA_LRMD_TIMEOUT, &event.timeout);
        pcmk__xe_get_guint(msg, PCMK__XA_LRMD_RSC_INTERVAL, &event.interval_ms);
        pcmk__xe_get_int(msg, PCMK__XA_LRMD_RSC_START_DELAY,
                         &event.start_delay);

        pcmk__xe_get_int(msg, PCMK__XA_LRMD_EXEC_RC, &rc);
        event.rc = (enum ocf_exitcode) rc;

        pcmk__xe_get_int(msg, PCMK__XA_LRMD_EXEC_OP_STATUS, &event.op_status);
        pcmk__xe_get_int(msg, PCMK__XA_LRMD_RSC_DELETED, &event.rsc_deleted);

        pcmk__xe_get_time(msg, PCMK__XA_LRMD_RUN_TIME, &event.t_run);
        pcmk__xe_get_time(msg, PCMK__XA_LRMD_RCCHANGE_TIME, &event.t_rcchange);

        pcmk__xe_get_int(msg, PCMK__XA_LRMD_EXEC_TIME, &exec_time);
        CRM_LOG_ASSERT(exec_time >= 0);
        event.exec_time = QB_MAX(0, exec_time);

        pcmk__xe_get_int(msg, PCMK__XA_LRMD_QUEUE_TIME, &queue_time);
        event.queue_time = QB_MAX(0, queue_time);

        event.op_type = pcmk__xe_get(msg, PCMK__XA_LRMD_RSC_ACTION);
        event.user_data = pcmk__xe_get(msg, PCMK__XA_LRMD_RSC_USERDATA_STR);
        event.type = lrmd_event_exec_complete;

        /* output and exit_reason may be freed by a callback */
        event.output = pcmk__xe_get_copy(msg, PCMK__XA_LRMD_RSC_OUTPUT);
        lrmd__set_result(&event, event.rc, event.op_status,
                         pcmk__xe_get(msg, PCMK__XA_LRMD_RSC_EXIT_REASON));

        event.params = xml2list(msg);
    } else if (pcmk__str_eq(type, LRMD_OP_NEW_CLIENT, pcmk__str_none)) {
        event.type = lrmd_event_new_client;
    } else if (pcmk__str_eq(type, LRMD_OP_POKE, pcmk__str_none)) {
        event.type = lrmd_event_poke;
    } else {
        return;
    }

    pcmk__trace("op %s notify event received", type);
    native->callback(&event);

    if (event.params) {
        g_hash_table_destroy(event.params);
    }
    lrmd__reset_result(&event);
}

// \return Always 0, to indicate that IPC mainloop source should be kept
static int
lrmd_ipc_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->callback != NULL) {
        xmlNode *msg = pcmk__xml_parse(buffer);

        lrmd_dispatch_internal(msg, lrmd);
        pcmk__xml_free(msg);
    }
    return 0;
}

static void
lrmd_free_xml(gpointer userdata)
{
    pcmk__xml_free((xmlNode *) userdata);
}

static bool
remote_executor_connected(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    return (native->remote->tls_session != NULL);
}

static void
handle_remote_msg(xmlNode *xml, lrmd_t *lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;
    const char *msg_type = NULL;

    msg_type = pcmk__xe_get(xml, PCMK__XA_LRMD_REMOTE_MSG_TYPE);
    if (pcmk__str_eq(msg_type, "notify", pcmk__str_casei)) {
        lrmd_dispatch_internal(xml, lrmd);
    } else if (pcmk__str_eq(msg_type, "reply", pcmk__str_casei)) {
        const char *op = pcmk__xe_get(xml, PCMK__XA_LRMD_OP);

        if (native->expected_late_replies > 0) {
            native->expected_late_replies--;

            /* The register op message we get as a response to lrmd_handshake_async
             * is a reply, so we have to handle that here.
             */
            if (pcmk__str_eq(op, "register", pcmk__str_casei)) {
                int rc = process_lrmd_handshake_reply(xml, native);
                report_async_connection_result(lrmd, pcmk_rc2legacy(rc));
            }
        } else {
            int reply_id = 0;

            pcmk__xe_get_int(xml, PCMK__XA_LRMD_CALLID, &reply_id);
            /* if this happens, we want to know about it */
            pcmk__err("Got outdated Pacemaker Remote reply %d", reply_id);
        }
    }
}

/*!
 * \internal
 * \brief Notify trigger handler
 *
 * \param[in,out] userdata API connection
 *
 * \return Always return G_SOURCE_CONTINUE to leave this trigger handler in the
 *         mainloop
 */
static int
process_pending_notifies(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->pending_notify == NULL) {
        return G_SOURCE_CONTINUE;
    }

    pcmk__trace("Processing pending notifies");
    g_list_foreach(native->pending_notify, lrmd_dispatch_internal, lrmd);
    g_list_free_full(native->pending_notify, lrmd_free_xml);
    native->pending_notify = NULL;
    return G_SOURCE_CONTINUE;
}

/*!
 * \internal
 * \brief TLS dispatch function for file descriptor sources
 *
 * \param[in,out] userdata  API connection
 *
 * \return -1 on error to remove the source from the mainloop, or 0 otherwise
 *         to leave it in the mainloop
 */
static int
lrmd_tls_dispatch(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *xml = NULL;
    int rc = pcmk_rc_ok;

    if (!remote_executor_connected(lrmd)) {
        pcmk__trace("TLS dispatch triggered after disconnect");
        return -1;
    }

    pcmk__trace("TLS dispatch triggered");

    rc = pcmk__remote_ready(native->remote, 0);
    if (rc == pcmk_rc_ok) {
        rc = pcmk__read_remote_message(native->remote, -1);
    }

    if (rc != pcmk_rc_ok && rc != ETIME) {
        pcmk__info("Lost %s executor connection while reading data",
                   pcmk__s(native->remote_nodename, "local"));
        lrmd_tls_disconnect(lrmd);
        return -1;
    }

    /* If rc is ETIME, there was nothing to read but we may already have a
     * full message in the buffer
     */
    xml = pcmk__remote_message_xml(native->remote);

    if (xml == NULL) {
        return 0;
    }

    handle_remote_msg(xml, lrmd);
    pcmk__xml_free(xml);
    return 0;
}

/* Not used with mainloop */
int
lrmd_poll(lrmd_t * lrmd, int timeout)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            return crm_ipc_ready(native->ipc);

        case pcmk__client_tls:
            if (native->pending_notify) {
                return 1;
            } else {
                int rc = pcmk__remote_ready(native->remote, 0);

                switch (rc) {
                    case pcmk_rc_ok:
                        return 1;
                    case ETIME:
                        return 0;
                    default:
                        return pcmk_rc2legacy(rc);
                }
            }
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            return -EPROTONOSUPPORT;
    }
}

/* Not used with mainloop */
bool
lrmd_dispatch(lrmd_t * lrmd)
{
    lrmd_private_t *private = NULL;

    pcmk__assert(lrmd != NULL);

    private = lrmd->lrmd_private;
    switch (private->type) {
        case pcmk__client_ipc:
            while (crm_ipc_ready(private->ipc)) {
                if (crm_ipc_read(private->ipc) > 0) {
                    const char *msg = crm_ipc_buffer(private->ipc);

                    lrmd_ipc_dispatch(msg, strlen(msg), lrmd);
                    pcmk__ipc_free_client_buffer(private->ipc);
                }
            }
            break;
        case pcmk__client_tls:
            lrmd_tls_dispatch(lrmd);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      private->type);
    }

    if (lrmd_api_is_connected(lrmd) == FALSE) {
        pcmk__err("Connection closed");
        return FALSE;
    }

    return TRUE;
}

static xmlNode *
lrmd_create_op(const char *token, const char *op, xmlNode *data, int timeout,
               enum lrmd_call_options options)
{
    xmlNode *op_msg = NULL;

    CRM_CHECK(token != NULL, return NULL);

    op_msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_COMMAND);
    pcmk__xe_set(op_msg, PCMK__XA_T, PCMK__VALUE_LRMD);
    pcmk__xe_set(op_msg, PCMK__XA_LRMD_OP, op);
    pcmk__xe_set_int(op_msg, PCMK__XA_LRMD_TIMEOUT, timeout);
    pcmk__xe_set_int(op_msg, PCMK__XA_LRMD_CALLOPT, options);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(op_msg, PCMK__XE_LRMD_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    pcmk__trace("Created executor %s command with call options %.8lx (%d)",
                op, (long) options, options);
    return op_msg;
}

static void
lrmd_ipc_connection_destroy(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            pcmk__info("Disconnected from local executor");
            break;
        case pcmk__client_tls:
            pcmk__info("Disconnected from remote executor on %s",
                       native->remote_nodename);
            break;
        default:
            pcmk__err("Unsupported executor connection type %d (bug?)",
                      native->type);
    }

    /* Prevent these from being cleaned up in lrmd_api_disconnect() */
    native->ipc = NULL;
    native->source = NULL;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.type = lrmd_event_disconnect;
        event.remote_nodename = native->remote_nodename;
        native->callback(&event);
    }
}

static void
lrmd_tls_connection_destroy(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;

    pcmk__info("TLS connection destroyed");

    if (native->remote->tls_session) {
        gnutls_bye(native->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(native->remote->tls_session);
        native->remote->tls_session = NULL;
    }
    if (native->tls) {
        pcmk__free_tls(native->tls);
        native->tls = NULL;
    }
    if (native->sock >= 0) {
        close(native->sock);
    }
    if (native->process_notify) {
        mainloop_destroy_trigger(native->process_notify);
        native->process_notify = NULL;
    }
    if (native->pending_notify) {
        g_list_free_full(native->pending_notify, lrmd_free_xml);
        native->pending_notify = NULL;
    }
    if (native->handshake_trigger != NULL) {
        mainloop_destroy_trigger(native->handshake_trigger);
        native->handshake_trigger = NULL;
    }

    free(native->remote->buffer);
    free(native->remote->start_state);
    native->remote->buffer = NULL;
    native->remote->start_state = NULL;
    native->source = 0;
    native->sock = -1;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.remote_nodename = native->remote_nodename;
        event.type = lrmd_event_disconnect;
        native->callback(&event);
    }
}

// \return Standard Pacemaker return code
int
lrmd__remote_send_xml(pcmk__remote_t *session, xmlNode *msg, uint32_t id,
                      const char *msg_type)
{
    pcmk__xe_set_int(msg, PCMK__XA_LRMD_REMOTE_MSG_ID, id);
    pcmk__xe_set(msg, PCMK__XA_LRMD_REMOTE_MSG_TYPE, msg_type);
    return pcmk__remote_send_xml(session, msg);
}

// \return Standard Pacemaker return code
static int
read_remote_reply(lrmd_t *lrmd, int total_timeout, int expected_reply_id,
                  xmlNode **reply)
{
    lrmd_private_t *native = lrmd->lrmd_private;
    time_t start = time(NULL);
    const char *msg_type = NULL;
    int reply_id = 0;
    int remaining_timeout = 0;
    int rc = pcmk_rc_ok;

    /* A timeout of 0 here makes no sense.  We have to wait a period of time
     * for the response to come back.  If -1 or 0, default to 10 seconds. */
    if (total_timeout <= 0 || total_timeout > MAX_TLS_RECV_WAIT) {
        total_timeout = MAX_TLS_RECV_WAIT;
    }

    for (*reply = NULL; *reply == NULL; ) {

        *reply = pcmk__remote_message_xml(native->remote);
        if (*reply == NULL) {
            /* read some more off the tls buffer if we still have time left. */
            if (remaining_timeout) {
                remaining_timeout = total_timeout - ((time(NULL) - start) * 1000);
            } else {
                remaining_timeout = total_timeout;
            }
            if (remaining_timeout <= 0) {
                return ETIME;
            }

            rc = pcmk__read_remote_message(native->remote, remaining_timeout);
            if (rc != pcmk_rc_ok) {
                return rc;
            }

            *reply = pcmk__remote_message_xml(native->remote);
            if (*reply == NULL) {
                return ENOMSG;
            }
        }

        pcmk__xe_get_int(*reply, PCMK__XA_LRMD_REMOTE_MSG_ID, &reply_id);
        msg_type = pcmk__xe_get(*reply, PCMK__XA_LRMD_REMOTE_MSG_TYPE);

        if (!msg_type) {
            pcmk__err("Empty msg type received while waiting for reply");
            pcmk__xml_free(*reply);
            *reply = NULL;
        } else if (pcmk__str_eq(msg_type, "notify", pcmk__str_casei)) {
            /* got a notify while waiting for reply, trigger the notify to be processed later */
            pcmk__info("queueing notify");
            native->pending_notify = g_list_append(native->pending_notify, *reply);
            if (native->process_notify) {
                pcmk__info("notify trigger set");
                mainloop_set_trigger(native->process_notify);
            }
            *reply = NULL;
        } else if (!pcmk__str_eq(msg_type, "reply", pcmk__str_casei)) {
            /* msg isn't a reply, make some noise */
            pcmk__err("Expected a reply, got %s", msg_type);
            pcmk__xml_free(*reply);
            *reply = NULL;
        } else if (reply_id != expected_reply_id) {
            if (native->expected_late_replies > 0) {
                native->expected_late_replies--;
            } else {
                pcmk__err("Got outdated reply, expected id %d got id %d",
                          expected_reply_id, reply_id);
            }
            pcmk__xml_free(*reply);
            *reply = NULL;
        }
    }

    if (native->remote->buffer && native->process_notify) {
        mainloop_set_trigger(native->process_notify);
    }

    return rc;
}

// \return Standard Pacemaker return code
static int
send_remote_message(lrmd_t *lrmd, xmlNode *msg)
{
    int rc = pcmk_rc_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    global_remote_msg_id++;
    if (global_remote_msg_id <= 0) {
        global_remote_msg_id = 1;
    }

    rc = lrmd__remote_send_xml(native->remote, msg, global_remote_msg_id,
                               "request");
    if (rc != pcmk_rc_ok) {
        pcmk__err("Disconnecting because TLS message could not be sent to "
                  "Pacemaker Remote: %s",
                  pcmk_rc_str(rc));
        lrmd_tls_disconnect(lrmd);
    }
    return rc;
}

static int
lrmd_tls_send_recv(lrmd_t * lrmd, xmlNode * msg, int timeout, xmlNode ** reply)
{
    int rc = 0;
    xmlNode *xml = NULL;

    if (!remote_executor_connected(lrmd)) {
        return -ENOTCONN;
    }

    rc = send_remote_message(lrmd, msg);
    if (rc != pcmk_rc_ok) {
        return pcmk_rc2legacy(rc);
    }

    rc = read_remote_reply(lrmd, timeout, global_remote_msg_id, &xml);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Disconnecting remote after request %d reply not received: "
                  "%s " QB_XS " rc=%d timeout=%dms",
                  global_remote_msg_id, pcmk_rc_str(rc), rc, timeout);
        lrmd_tls_disconnect(lrmd);
    }

    if (reply) {
        *reply = xml;
    } else {
        pcmk__xml_free(xml);
    }

    return pcmk_rc2legacy(rc);
}

static int
lrmd_send_xml(lrmd_t * lrmd, xmlNode * msg, int timeout, xmlNode ** reply)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            rc = crm_ipc_send(native->ipc, msg, crm_ipc_client_response, timeout, reply);
            break;
        case pcmk__client_tls:
            rc = lrmd_tls_send_recv(lrmd, msg, timeout, reply);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            rc = -EPROTONOSUPPORT;
    }

    return rc;
}

static int
lrmd_send_xml_no_reply(lrmd_t * lrmd, xmlNode * msg)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            rc = crm_ipc_send(native->ipc, msg, crm_ipc_flags_none, 0, NULL);
            break;
        case pcmk__client_tls:
            rc = send_remote_message(lrmd, msg);
            if (rc == pcmk_rc_ok) {
                /* we don't want to wait around for the reply, but
                 * since the request/reply protocol needs to behave the same
                 * as libqb, a reply will eventually come later anyway. */
                native->expected_late_replies++;
            }
            rc = pcmk_rc2legacy(rc);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            rc = -EPROTONOSUPPORT;
    }

    return rc;
}

static int
lrmd_api_is_connected(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            return crm_ipc_connected(native->ipc);
        case pcmk__client_tls:
            return remote_executor_connected(lrmd);
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            return 0;
    }
}

/*!
 * \internal
 * \brief Send a prepared API command to the executor
 *
 * \param[in,out] lrmd          Existing connection to the executor
 * \param[in]     op            Name of API command to send
 * \param[in]     data          Command data XML to add to the sent command
 * \param[out]    output_data   If expecting a reply, it will be stored here
 * \param[in]     timeout       Timeout in milliseconds (if 0, defaults to
 *                              a sensible value per the type of connection,
 *                              standard vs. pacemaker remote);
 *                              also propagated to the command XML
 * \param[in]     call_options  Call options to pass to server when sending
 * \param[in]     expect_reply  If true, wait for a reply from the server;
 *                              must be true for IPC (as opposed to TLS) clients
 *
 * \return pcmk_ok on success, -errno on error
 */
static int
lrmd_send_command(lrmd_t *lrmd, const char *op, xmlNode *data,
                  xmlNode **output_data, int timeout,
                  enum lrmd_call_options options, bool expect_reply)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    if (!lrmd_api_is_connected(lrmd)) {
        return -ENOTCONN;
    }

    if (op == NULL) {
        pcmk__err("No operation specified");
        return -EINVAL;
    }

    CRM_LOG_ASSERT(native->token != NULL);
    pcmk__trace("Sending %s op to executor", op);

    op_msg = lrmd_create_op(native->token, op, data, timeout, options);

    if (op_msg == NULL) {
        return -EINVAL;
    }

    if (expect_reply) {
        rc = lrmd_send_xml(lrmd, op_msg, timeout, &op_reply);
    } else {
        rc = lrmd_send_xml_no_reply(lrmd, op_msg);
        goto done;
    }

    if (rc < 0) {
        pcmk__err("Couldn't perform %s operation (timeout=%d): %d", op, timeout,
                  pcmk_strerror(rc));
        goto done;

    } else if (op_reply == NULL) {
        rc = -ENOMSG;
        goto done;
    }

    rc = pcmk_ok;
    pcmk__trace("%s op reply received", op);
    if (pcmk__xe_get_int(op_reply, PCMK__XA_LRMD_RC, &rc) != pcmk_rc_ok) {
        rc = -ENOMSG;
        goto done;
    }

    pcmk__log_xml_trace(op_reply, "Reply");

    if (output_data) {
        *output_data = op_reply;
        op_reply = NULL;        /* Prevent subsequent free */
    }

  done:
    if (lrmd_api_is_connected(lrmd) == FALSE) {
        pcmk__err("Executor disconnected");
    }

    pcmk__xml_free(op_msg);
    pcmk__xml_free(op_reply);
    return rc;
}

static int
lrmd_api_poke_connection(lrmd_t * lrmd)
{
    int rc;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    rc = lrmd_send_command(lrmd, LRMD_OP_POKE, data, NULL, 0, 0,
                           (native->type == pcmk__client_ipc));
    pcmk__xml_free(data);

    return rc < 0 ? rc : pcmk_ok;
}

// \return Standard Pacemaker return code
int
lrmd__validate_remote_settings(lrmd_t *lrmd, GHashTable *hash)
{
    int rc = pcmk_rc_ok;
    const char *value;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XA_LRMD_OP);

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);

    value = g_hash_table_lookup(hash, PCMK_OPT_FENCING_WATCHDOG_TIMEOUT);
    if ((value) &&
        (stonith__watchdog_fencing_enabled_for_node(native->remote_nodename))) {
       pcmk__xe_set(data, PCMK__XA_LRMD_WATCHDOG, value);
    }

    rc = lrmd_send_command(lrmd, LRMD_OP_CHECK, data, NULL, 0, 0,
                           (native->type == pcmk__client_ipc));
    pcmk__xml_free(data);
    return (rc < 0)? pcmk_legacy2rc(rc) : pcmk_rc_ok;
}

static xmlNode *
lrmd_handshake_hello_msg(const char *name, bool is_proxy)
{
    xmlNode *hello = pcmk__xe_create(NULL, PCMK__XE_LRMD_COMMAND);

    pcmk__xe_set(hello, PCMK__XA_T, PCMK__VALUE_LRMD);
    pcmk__xe_set(hello, PCMK__XA_LRMD_OP, CRM_OP_REGISTER);
    pcmk__xe_set(hello, PCMK__XA_LRMD_CLIENTNAME, name);
    pcmk__xe_set(hello, PCMK__XA_LRMD_PROTOCOL_VERSION, LRMD_PROTOCOL_VERSION);

    /* advertise that we are a proxy provider */
    if (is_proxy) {
        pcmk__xe_set_bool(hello, PCMK__XA_LRMD_IS_IPC_PROVIDER, true);
    }

    return hello;
}

static int
process_lrmd_handshake_reply(xmlNode *reply, lrmd_private_t *native)
{
    int rc = pcmk_rc_ok;
    const char *version = pcmk__xe_get(reply, PCMK__XA_LRMD_PROTOCOL_VERSION);
    const char *msg_type = pcmk__xe_get(reply, PCMK__XA_LRMD_OP);
    const char *tmp_ticket = pcmk__xe_get(reply, PCMK__XA_LRMD_CLIENTID);
    const char *start_state = pcmk__xe_get(reply, PCMK__XA_NODE_START_STATE);

    pcmk__xe_get_int(reply, PCMK__XA_LRMD_RC, &rc);
    rc = pcmk_legacy2rc(rc);

    /* The remote executor may add its uptime to the XML reply, which is useful
     * in handling transient attributes when the connection to the remote node
     * unexpectedly drops.  If no parameter is given, just default to -1.
     */
    native->remote->uptime = -1;
    pcmk__xe_get_time(reply, PCMK__XA_UPTIME, &native->remote->uptime);

    if (start_state) {
        native->remote->start_state = strdup(start_state);
    }

    if (rc == EPROTO) {
        pcmk__err("Executor protocol version mismatch between client "
                  "(" LRMD_PROTOCOL_VERSION ") and server (%s)",
                  version);
        pcmk__log_xml_err(reply, "Protocol Error");
    } else if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_casei)) {
        pcmk__err("Invalid registration message: %s", msg_type);
        pcmk__log_xml_err(reply, "Bad reply");
        rc = EPROTO;
    } else if (tmp_ticket == NULL) {
        pcmk__err("No registration token provided");
        pcmk__log_xml_err(reply, "Bad reply");
        rc = EPROTO;
    } else {
        pcmk__trace("Obtained registration token: %s", tmp_ticket);
        native->token = strdup(tmp_ticket);
        native->peer_version = strdup(version?version:"1.0"); /* Included since 1.1 */
        rc = pcmk_rc_ok;
    }

    return rc;
}

static int
lrmd_handshake(lrmd_t * lrmd, const char *name)
{
    int rc = pcmk_rc_ok;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *reply = NULL;
    xmlNode *hello = lrmd_handshake_hello_msg(name, native->proxy_callback != NULL);

    rc = lrmd_send_xml(lrmd, hello, -1, &reply);

    if (rc < 0) {
        pcmk__debug("Couldn't complete registration with the executor API: %s",
                    pcmk_strerror(rc));
        rc = ECOMM;
    } else if (reply == NULL) {
        pcmk__err("Did not receive registration reply");
        rc = EPROTO;
    } else {
        rc = process_lrmd_handshake_reply(reply, native);
    }

    pcmk__xml_free(reply);
    pcmk__xml_free(hello);

    if (rc != pcmk_rc_ok) {
        lrmd_api_disconnect(lrmd);
    }

    return rc;
}

static int
lrmd_handshake_async(lrmd_t * lrmd, const char *name)
{
    int rc = pcmk_rc_ok;
    lrmd_private_t *native = lrmd->lrmd_private;
    xmlNode *hello = lrmd_handshake_hello_msg(name, native->proxy_callback != NULL);

    rc = send_remote_message(lrmd, hello);

    if (rc == pcmk_rc_ok) {
        native->expected_late_replies++;
    } else {
        lrmd_api_disconnect(lrmd);
    }

    pcmk__xml_free(hello);
    return rc;
}

static int
lrmd_ipc_connect(lrmd_t * lrmd, int *fd)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    struct ipc_client_callbacks lrmd_callbacks = {
        .dispatch = lrmd_ipc_dispatch,
        .destroy = lrmd_ipc_connection_destroy
    };

    pcmk__info("Connecting to executor");

    if (fd) {
        /* No mainloop */
        native->ipc = crm_ipc_new(CRM_SYSTEM_LRMD, 0);
        if (native->ipc != NULL) {
            rc = pcmk__connect_generic_ipc(native->ipc);
            if (rc == pcmk_rc_ok) {
                rc = pcmk__ipc_fd(native->ipc, fd);
            }
            if (rc != pcmk_rc_ok) {
                pcmk__err("Connection to executor failed: %s", pcmk_rc_str(rc));
                rc = -ENOTCONN;
            }
        }
    } else {
        native->source = mainloop_add_ipc_client(CRM_SYSTEM_LRMD, G_PRIORITY_HIGH, 0, lrmd, &lrmd_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (native->ipc == NULL) {
        pcmk__debug("Could not connect to the executor API");
        rc = -ENOTCONN;
    }

    return rc;
}

/*!
 * \internal
 * \brief Initialize the Pacemaker Remote authentication key
 *
 * Try loading the Pacemaker Remote authentication key from cache if available,
 * otherwise from these locations, in order of preference:
 *
 * - The value of the PCMK_authkey_location environment variable, if set
 * - The Pacemaker default key file location
 *
 * \param[out] key  Where to store key
 *
 * \return Standard Pacemaker return code
 */
int
lrmd__init_remote_key(gnutls_datum_t *key)
{
    static const char *env_location = NULL;
    static bool need_env = true;

    int rc = pcmk_rc_ok;

    if (need_env) {
        env_location = pcmk__env_option(PCMK__ENV_AUTHKEY_LOCATION);
        need_env = false;
    }

    if (remote_key.data != NULL) {
        pcmk__copy_key(key, &remote_key);
        return pcmk_rc_ok;
    }

    // Try location in environment variable, if set
    if (env_location != NULL) {
        rc = pcmk__load_key(env_location, &remote_key);

        if (rc == pcmk_rc_ok) {
            pcmk__copy_key(key, &remote_key);
            return pcmk_rc_ok;
        }

        pcmk__warn("Could not read Pacemaker Remote key from %s: %s",
                   env_location, pcmk_rc_str(rc));
        return ENOKEY;
    }

    // Try default location, if environment wasn't explicitly set to it
    rc = pcmk__load_key(DEFAULT_REMOTE_KEY_LOCATION, &remote_key);

    if (rc == pcmk_rc_ok) {
        pcmk__copy_key(key, &remote_key);
        return pcmk_rc_ok;
    }

    pcmk__warn("Could not read Pacemaker Remote key from default location "
               DEFAULT_REMOTE_KEY_LOCATION ": %s",
               pcmk_rc_str(rc));
    return ENOKEY;
}

static void
report_async_connection_result(lrmd_t * lrmd, int rc)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.type = lrmd_event_connect;
        event.remote_nodename = native->remote_nodename;
        event.connection_rc = rc;
        native->callback(&event);
    }
}

static void
tls_handshake_failed(lrmd_t *lrmd, int tls_rc, int rc)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    pcmk__warn("Disconnecting after TLS handshake with Pacemaker Remote server "
               "%s:%d failed: %s",
               native->server, native->port,
               ((rc == EPROTO)? gnutls_strerror(tls_rc) : pcmk_rc_str(rc)));
    report_async_connection_result(lrmd, pcmk_rc2legacy(rc));

    gnutls_deinit(native->remote->tls_session);
    native->remote->tls_session = NULL;
    lrmd_tls_connection_destroy(lrmd);
}

static void
tls_handshake_succeeded(lrmd_t *lrmd)
{
    int rc = pcmk_rc_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    /* Now that the handshake is done, see if any client TLS certificate is
     * close to its expiration date and log if so.  If a TLS certificate is not
     * in use, this function will just return so we don't need to check for the
     * session type here.
     */
    pcmk__tls_check_cert_expiration(native->remote->tls_session);

    pcmk__info("TLS connection to Pacemaker Remote server %s:%d succeeded",
               native->server, native->port);
    rc = add_tls_to_mainloop(lrmd, true);

    /* If add_tls_to_mainloop failed, report that right now.  Otherwise, we have
     * to wait until we read the async reply to report anything.
     */
    if (rc != pcmk_rc_ok) {
        report_async_connection_result(lrmd, pcmk_rc2legacy(rc));
    }
}

/*!
 * \internal
 * \brief Perform a TLS client handshake with a Pacemaker Remote server
 *
 * \param[in] lrmd  Newly established Pacemaker Remote executor connection
 *
 * \return Standard Pacemaker return code
 */
static int
tls_client_handshake(lrmd_t *lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;
    int tls_rc = GNUTLS_E_SUCCESS;
    int rc = pcmk__tls_client_handshake(native->remote, TLS_HANDSHAKE_TIMEOUT,
                                        &tls_rc);

    if (rc != pcmk_rc_ok) {
        tls_handshake_failed(lrmd, tls_rc, rc);
    }

    return rc;
}

/*!
 * \internal
 * \brief Add trigger and file descriptor mainloop sources for TLS
 *
 * \param[in,out] lrmd              API connection with established TLS session
 * \param[in]     do_api_handshake  Whether to perform executor handshake
 *
 * \return Standard Pacemaker return code
 */
static int
add_tls_to_mainloop(lrmd_t *lrmd, bool do_api_handshake)
{
    lrmd_private_t *native = lrmd->lrmd_private;
    int rc = pcmk_rc_ok;

    char *name = pcmk__assert_asprintf("pacemaker-remote-%s:%d",
                                       native->server, native->port);

    struct mainloop_fd_callbacks tls_fd_callbacks = {
        .dispatch = lrmd_tls_dispatch,
        .destroy = lrmd_tls_connection_destroy,
    };

    native->process_notify = mainloop_add_trigger(G_PRIORITY_HIGH,
                                                  process_pending_notifies, lrmd);
    native->source = mainloop_add_fd(name, G_PRIORITY_HIGH, native->sock, lrmd,
                                     &tls_fd_callbacks);

    /* Async connections lose the client name provided by the API caller, so we
     * have to use our generated name here to perform the executor handshake.
     *
     * @TODO Keep track of the caller-provided name. Perhaps we should be using
     * that name in this function instead of generating one anyway.
     */
    if (do_api_handshake) {
        rc = lrmd_handshake_async(lrmd, name);
    }
    free(name);
    return rc;
}

struct handshake_data_s {
    lrmd_t *lrmd;
    time_t start_time;
    int timeout_sec;
};

static gboolean
try_handshake_cb(gpointer user_data)
{
    struct handshake_data_s *hs = user_data;
    lrmd_t *lrmd = hs->lrmd;
    lrmd_private_t *native = lrmd->lrmd_private;
    pcmk__remote_t *remote = native->remote;

    int rc = pcmk_rc_ok;
    int tls_rc = GNUTLS_E_SUCCESS;

    if (time(NULL) >= hs->start_time + hs->timeout_sec) {
        rc = ETIME;

        tls_handshake_failed(lrmd, GNUTLS_E_TIMEDOUT, rc);
        free(hs);
        return 0;
    }

    rc = pcmk__tls_client_try_handshake(remote, &tls_rc);

    if (rc == pcmk_rc_ok) {
        tls_handshake_succeeded(lrmd);
        free(hs);
        return 0;
    } else if (rc == EAGAIN) {
        mainloop_set_trigger(native->handshake_trigger);
        return 1;
    } else {
        rc = EKEYREJECTED;
        tls_handshake_failed(lrmd, tls_rc, rc);
        free(hs);
        return 0;
    }
}

static void
lrmd_tcp_connect_cb(void *userdata, int rc, int sock)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->lrmd_private;
    int tls_rc = GNUTLS_E_SUCCESS;

    native->async_timer = 0;

    if (rc != pcmk_rc_ok) {
        lrmd_tls_connection_destroy(lrmd);
        pcmk__info("Could not connect to Pacemaker Remote at %s:%d: %s "
                   QB_XS " rc=%d",
                   native->server, native->port, pcmk_rc_str(rc), rc);
        report_async_connection_result(lrmd, pcmk_rc2legacy(rc));
        return;
    }

    /* The TCP connection was successful, so establish the TLS connection. */

    native->sock = sock;

    if (native->tls == NULL) {
        rc = pcmk__init_tls(&native->tls, false, true);

        if ((rc != pcmk_rc_ok) || (native->tls == NULL)) {
            lrmd_tls_connection_destroy(lrmd);
            report_async_connection_result(lrmd, pcmk_rc2legacy(rc));
            return;
        }
    }

    if (!pcmk__x509_enabled()) {
        gnutls_datum_t psk_key = { NULL, 0 };

        rc = lrmd__init_remote_key(&psk_key);
        if (rc != pcmk_rc_ok) {
            pcmk__info("Could not connect to Pacemaker Remote at %s:%d: %s "
                       QB_XS " rc=%d",
                       native->server, native->port, pcmk_rc_str(rc), rc);
            lrmd_tls_connection_destroy(lrmd);
            report_async_connection_result(lrmd, pcmk_rc2legacy(rc));
            return;
        }

        pcmk__tls_add_psk_key(native->tls, &psk_key);
        gnutls_free(psk_key.data);
    }

    native->remote->tls_session = pcmk__new_tls_session(native->tls, sock);
    if (native->remote->tls_session == NULL) {
        lrmd_tls_connection_destroy(lrmd);
        report_async_connection_result(lrmd, -EPROTO);
        return;
    }

    /* If the TLS handshake immediately succeeds or fails, we can handle that
     * now without having to deal with mainloops and retries.  Otherwise, add a
     * trigger to keep trying until we get a result (or it times out).
     */
    rc = pcmk__tls_client_try_handshake(native->remote, &tls_rc);
    if (rc == EAGAIN) {
        struct handshake_data_s *hs = NULL;

        if (native->handshake_trigger != NULL) {
            return;
        }

        hs = pcmk__assert_alloc(1, sizeof(struct handshake_data_s));
        hs->lrmd = lrmd;
        hs->start_time = time(NULL);
        hs->timeout_sec = TLS_HANDSHAKE_TIMEOUT;

        native->handshake_trigger = mainloop_add_trigger(G_PRIORITY_LOW, try_handshake_cb, hs);
        mainloop_set_trigger(native->handshake_trigger);

    } else if (rc == pcmk_rc_ok) {
        tls_handshake_succeeded(lrmd);

    } else {
        tls_handshake_failed(lrmd, tls_rc, rc);
    }
}

static int
lrmd_tls_connect_async(lrmd_t * lrmd, int timeout /*ms */ )
{
    int rc = pcmk_rc_ok;
    int timer_id = 0;
    lrmd_private_t *native = lrmd->lrmd_private;

    native->sock = -1;
    rc = pcmk__connect_remote(native->server, native->port, timeout, &timer_id,
                              &(native->sock), lrmd, lrmd_tcp_connect_cb);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Pacemaker Remote connection to %s:%d failed: %s "
                   QB_XS " rc=%d",
                   native->server, native->port, pcmk_rc_str(rc), rc);
        return rc;
    }
    native->async_timer = timer_id;
    return rc;
}

static int
lrmd_tls_connect(lrmd_t * lrmd, int *fd)
{
    int rc = pcmk_rc_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    native->sock = -1;
    rc = pcmk__connect_remote(native->server, native->port, 0, NULL,
                              &(native->sock), NULL, NULL);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Pacemaker Remote connection to %s:%d failed: %s "
                   QB_XS " rc=%d",
                   native->server, native->port, pcmk_rc_str(rc), rc);
        lrmd_tls_connection_destroy(lrmd);
        return ENOTCONN;
    }

    if (native->tls == NULL) {
        rc = pcmk__init_tls(&native->tls, false, true);

        if ((rc != pcmk_rc_ok) || (native->tls == NULL)) {
            lrmd_tls_connection_destroy(lrmd);
            return rc;
        }
    }

    if (!pcmk__x509_enabled()) {
        gnutls_datum_t psk_key = { NULL, 0 };

        rc = lrmd__init_remote_key(&psk_key);
        if (rc != pcmk_rc_ok) {
            lrmd_tls_connection_destroy(lrmd);
            return rc;
        }

        pcmk__tls_add_psk_key(native->tls, &psk_key);
        gnutls_free(psk_key.data);
    }

    native->remote->tls_session = pcmk__new_tls_session(native->tls, native->sock);
    if (native->remote->tls_session == NULL) {
        lrmd_tls_connection_destroy(lrmd);
        return EPROTO;
    }

    if (tls_client_handshake(lrmd) != pcmk_rc_ok) {
        return EKEYREJECTED;
    }

    pcmk__info("Client TLS connection established with Pacemaker Remote server "
               "%s:%d",
               native->server, native->port);

    if (fd) {
        *fd = native->sock;
    } else {
        rc = add_tls_to_mainloop(lrmd, false);
    }
    return rc;
}

static int
lrmd_api_connect(lrmd_t * lrmd, const char *name, int *fd)
{
    int rc = -ENOTCONN;
    lrmd_private_t *native = lrmd->lrmd_private;

    switch (native->type) {
        case pcmk__client_ipc:
            rc = lrmd_ipc_connect(lrmd, fd);
            break;
        case pcmk__client_tls:
            rc = lrmd_tls_connect(lrmd, fd);
            rc = pcmk_rc2legacy(rc);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            rc = -EPROTONOSUPPORT;
    }

    if (rc == pcmk_ok) {
        rc = lrmd_handshake(lrmd, name);
        rc = pcmk_rc2legacy(rc);
    }

    return rc;
}

static int
lrmd_api_connect_async(lrmd_t * lrmd, const char *name, int timeout)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->lrmd_private;

    CRM_CHECK(native && native->callback, return -EINVAL);

    switch (native->type) {
        case pcmk__client_ipc:
            /* fake async connection with ipc.  it should be fast
             * enough that we gain very little from async */
            rc = lrmd_api_connect(lrmd, name, NULL);
            if (!rc) {
                report_async_connection_result(lrmd, rc);
            }
            break;
        case pcmk__client_tls:
            rc = lrmd_tls_connect_async(lrmd, timeout);
            rc = pcmk_rc2legacy(rc);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            rc = -EPROTONOSUPPORT;
    }

    return rc;
}

static void
lrmd_ipc_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->source != NULL) {
        /* Attached to mainloop */
        mainloop_del_ipc_client(native->source);
        native->source = NULL;
        native->ipc = NULL;

    } else if (native->ipc) {
        /* Not attached to mainloop */
        crm_ipc_t *ipc = native->ipc;

        native->ipc = NULL;
        crm_ipc_close(ipc);
        crm_ipc_destroy(ipc);
    }
}

static void
lrmd_tls_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->remote->tls_session) {
        gnutls_bye(native->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(native->remote->tls_session);
        native->remote->tls_session = NULL;
    }

    if (native->async_timer) {
        g_source_remove(native->async_timer);
        native->async_timer = 0;
    }

    if (native->source != NULL) {
        /* Attached to mainloop */
        mainloop_del_ipc_client(native->source);
        native->source = NULL;

    } else if (native->sock >= 0) {
        close(native->sock);
        native->sock = -1;
    }

    if (native->pending_notify) {
        g_list_free_full(native->pending_notify, lrmd_free_xml);
        native->pending_notify = NULL;
    }
}

static int
lrmd_api_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;
    int rc = pcmk_ok;

    switch (native->type) {
        case pcmk__client_ipc:
            pcmk__debug("Disconnecting from local executor");
            lrmd_ipc_disconnect(lrmd);
            break;
        case pcmk__client_tls:
            pcmk__debug("Disconnecting from remote executor on %s",
                        native->remote_nodename);
            lrmd_tls_disconnect(lrmd);
            break;
        default:
            pcmk__err("Unsupported executor connection type (bug?): %d",
                      native->type);
            rc = -EPROTONOSUPPORT;
    }

    free(native->token);
    native->token = NULL;

    free(native->peer_version);
    native->peer_version = NULL;
    return rc;
}

static int
lrmd_api_register_rsc(lrmd_t * lrmd,
                      const char *rsc_id,
                      const char *class,
                      const char *provider, const char *type, enum lrmd_call_options options)
{
    int rc = pcmk_ok;
    xmlNode *data = NULL;

    if (!class || !type || !rsc_id) {
        return -EINVAL;
    }
    if (pcmk__is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)
        && (provider == NULL)) {
        return -EINVAL;
    }

    data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    pcmk__xe_set(data, PCMK__XA_LRMD_CLASS, class);
    pcmk__xe_set(data, PCMK__XA_LRMD_PROVIDER, provider);
    pcmk__xe_set(data, PCMK__XA_LRMD_TYPE, type);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_REG, data, NULL, 0, options, true);
    pcmk__xml_free(data);

    return rc;
}

static int
lrmd_api_unregister_rsc(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    int rc = pcmk_ok;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_UNREG, data, NULL, 0, options, true);
    pcmk__xml_free(data);

    return rc;
}

lrmd_rsc_info_t *
lrmd_new_rsc_info(const char *rsc_id, const char *standard,
                  const char *provider, const char *type)
{
    lrmd_rsc_info_t *rsc_info = pcmk__assert_alloc(1, sizeof(lrmd_rsc_info_t));

    rsc_info->id = pcmk__str_copy(rsc_id);
    rsc_info->standard = pcmk__str_copy(standard);
    rsc_info->provider = pcmk__str_copy(provider);
    rsc_info->type = pcmk__str_copy(type);
    return rsc_info;
}

lrmd_rsc_info_t *
lrmd_copy_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    return lrmd_new_rsc_info(rsc_info->id, rsc_info->standard,
                             rsc_info->provider, rsc_info->type);
}

void
lrmd_free_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    if (!rsc_info) {
        return;
    }
    free(rsc_info->id);
    free(rsc_info->type);
    free(rsc_info->standard);
    free(rsc_info->provider);
    free(rsc_info);
}

static lrmd_rsc_info_t *
lrmd_api_get_rsc_info(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    lrmd_rsc_info_t *rsc_info = NULL;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);
    xmlNode *output = NULL;
    const char *class = NULL;
    const char *provider = NULL;
    const char *type = NULL;

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    lrmd_send_command(lrmd, LRMD_OP_RSC_INFO, data, &output, 0, options, true);
    pcmk__xml_free(data);

    if (!output) {
        return NULL;
    }

    class = pcmk__xe_get(output, PCMK__XA_LRMD_CLASS);
    provider = pcmk__xe_get(output, PCMK__XA_LRMD_PROVIDER);
    type = pcmk__xe_get(output, PCMK__XA_LRMD_TYPE);

    if (!class || !type) {
        pcmk__xml_free(output);
        return NULL;
    } else if (pcmk__is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_provider)
               && (provider == NULL)) {
        pcmk__xml_free(output);
        return NULL;
    }

    rsc_info = lrmd_new_rsc_info(rsc_id, class, provider, type);
    pcmk__xml_free(output);
    return rsc_info;
}

void
lrmd_free_op_info(lrmd_op_info_t *op_info)
{
    if (op_info) {
        free(op_info->rsc_id);
        free(op_info->action);
        free(op_info->interval_ms_s);
        free(op_info->timeout_ms_s);
        free(op_info);
    }
}

static int
lrmd_api_get_recurring_ops(lrmd_t *lrmd, const char *rsc_id, int timeout_ms,
                           enum lrmd_call_options options, GList **output)
{
    xmlNode *data = NULL;
    xmlNode *output_xml = NULL;
    int rc = pcmk_ok;

    if (output == NULL) {
        return -EINVAL;
    }
    *output = NULL;

    // Send request
    if (rsc_id) {
        data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);
        pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
        pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    }
    rc = lrmd_send_command(lrmd, LRMD_OP_GET_RECURRING, data, &output_xml,
                           timeout_ms, options, true);
    if (data) {
        pcmk__xml_free(data);
    }

    // Process reply
    if ((rc != pcmk_ok) || (output_xml == NULL)) {
        return rc;
    }
    for (const xmlNode *rsc_xml = pcmk__xe_first_child(output_xml,
                                                       PCMK__XE_LRMD_RSC, NULL,
                                                       NULL);
         (rsc_xml != NULL) && (rc == pcmk_ok);
         rsc_xml = pcmk__xe_next(rsc_xml, PCMK__XE_LRMD_RSC)) {

        rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);
        if (rsc_id == NULL) {
            pcmk__err("Could not parse recurring operation information from "
                      "executor");
            continue;
        }
        for (const xmlNode *op_xml = pcmk__xe_first_child(rsc_xml,
                                                          PCMK__XE_LRMD_RSC_OP,
                                                          NULL, NULL);
             op_xml != NULL;
             op_xml = pcmk__xe_next(op_xml, PCMK__XE_LRMD_RSC_OP)) {

            lrmd_op_info_t *op_info = calloc(1, sizeof(lrmd_op_info_t));

            if (op_info == NULL) {
                rc = -ENOMEM;
                break;
            }
            op_info->rsc_id = strdup(rsc_id);
            op_info->action = pcmk__xe_get_copy(op_xml,
                                                PCMK__XA_LRMD_RSC_ACTION);
            op_info->interval_ms_s =
                pcmk__xe_get_copy(op_xml, PCMK__XA_LRMD_RSC_INTERVAL);
            op_info->timeout_ms_s = pcmk__xe_get_copy(op_xml,
                                                      PCMK__XA_LRMD_TIMEOUT);
            *output = g_list_prepend(*output, op_info);
        }
    }
    pcmk__xml_free(output_xml);
    return rc;
}


static void
lrmd_api_set_callback(lrmd_t * lrmd, lrmd_event_callback callback)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    native->callback = callback;
}

void
lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg))
{
    lrmd_private_t *native = lrmd->lrmd_private;

    native->proxy_callback = callback;
    native->proxy_callback_userdata = userdata;
}

void
lrmd_internal_proxy_dispatch(lrmd_t *lrmd, xmlNode *msg)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->proxy_callback) {
        pcmk__log_xml_trace(msg, "PROXY_INBOUND");
        native->proxy_callback(lrmd, native->proxy_callback_userdata, msg);
    }
}

int
lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg)
{
    if (lrmd == NULL) {
        return -ENOTCONN;
    }
    pcmk__xe_set(msg, PCMK__XA_LRMD_OP, CRM_OP_IPC_FWD);

    pcmk__log_xml_trace(msg, "PROXY_OUTBOUND");
    return lrmd_send_xml_no_reply(lrmd, msg);
}

static int
stonith_get_metadata(const char *type, char **output)
{
    int rc = pcmk_ok;
    stonith_t *stonith_api = stonith__api_new();

    if (stonith_api == NULL) {
        pcmk__err("Could not get fence agent meta-data: API memory allocation "
                  "failed");
        return -ENOMEM;
    }

    rc = stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, type, NULL,
                                     output, 0);
    if ((rc == pcmk_ok) && (*output == NULL)) {
        rc = -EIO;
    }
    stonith_api->cmds->free(stonith_api);
    return rc;
}

static int
lrmd_api_get_metadata(lrmd_t *lrmd, const char *standard, const char *provider,
                      const char *type, char **output,
                      enum lrmd_call_options options)
{
    return lrmd->cmds->get_metadata_params(lrmd, standard, provider, type,
                                           output, options, NULL);
}

static int
lrmd_api_get_metadata_params(lrmd_t *lrmd, const char *standard,
                             const char *provider, const char *type,
                             char **output, enum lrmd_call_options options,
                             lrmd_key_value_t *params)
{
    svc_action_t *action = NULL;
    GHashTable *params_table = NULL;

    if (!standard || !type) {
        lrmd_key_value_freeall(params);
        return -EINVAL;
    }

    if (pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        lrmd_key_value_freeall(params);

        // stonith-class resources don't support a provider
        return stonith_get_metadata(type, output);
    }

    params_table = pcmk__strkey_table(free, free);
    for (const lrmd_key_value_t *param = params; param; param = param->next) {
        pcmk__insert_dup(params_table, param->key, param->value);
    }
    action = services__create_resource_action(type, standard, provider, type,
                                              PCMK_ACTION_META_DATA, 0,
                                              PCMK_DEFAULT_ACTION_TIMEOUT_MS,
                                              params_table, 0);
    lrmd_key_value_freeall(params);

    if (action == NULL) {
        return -ENOMEM;
    }
    if (action->rc != PCMK_OCF_UNKNOWN) {
        services_action_free(action);
        return -EINVAL;
    }

    if (!services_action_sync(action)) {
        pcmk__err("Failed to retrieve meta-data for %s:%s:%s", standard,
                  provider, type);
        services_action_free(action);
        return -EIO;
    }

    if (!action->stdout_data) {
        pcmk__err("Failed to receive meta-data for %s:%s:%s", standard,
                  provider, type);
        services_action_free(action);
        return -EIO;
    }

    *output = strdup(action->stdout_data);
    services_action_free(action);

    return pcmk_ok;
}

static int
lrmd_api_exec(lrmd_t *lrmd, const char *rsc_id, const char *action,
              const char *userdata, guint interval_ms,
              int timeout,      /* ms */
              int start_delay,  /* ms */
              enum lrmd_call_options options, lrmd_key_value_t * params)
{
    int rc = pcmk_ok;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);
    xmlNode *args = pcmk__xe_create(data, PCMK__XE_ATTRIBUTES);
    lrmd_key_value_t *tmp = NULL;

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ACTION, action);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_USERDATA_STR, userdata);
    pcmk__xe_set_guint(data, PCMK__XA_LRMD_RSC_INTERVAL, interval_ms);
    pcmk__xe_set_int(data, PCMK__XA_LRMD_TIMEOUT, timeout);
    pcmk__xe_set_int(data, PCMK__XA_LRMD_RSC_START_DELAY, start_delay);

    for (tmp = params; tmp; tmp = tmp->next) {
        hash2smartfield((gpointer) tmp->key, (gpointer) tmp->value, args);
    }

    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_EXEC, data, NULL, timeout, options, true);
    pcmk__xml_free(data);

    lrmd_key_value_freeall(params);
    return rc;
}

/* timeout is in ms */
static int
lrmd_api_exec_alert(lrmd_t *lrmd, const char *alert_id, const char *alert_path,
                    int timeout, lrmd_key_value_t *params)
{
    int rc = pcmk_ok;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_ALERT);
    xmlNode *args = pcmk__xe_create(data, PCMK__XE_ATTRIBUTES);
    lrmd_key_value_t *tmp = NULL;

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_ALERT_ID, alert_id);
    pcmk__xe_set(data, PCMK__XA_LRMD_ALERT_PATH, alert_path);
    pcmk__xe_set_int(data, PCMK__XA_LRMD_TIMEOUT, timeout);

    for (tmp = params; tmp; tmp = tmp->next) {
        hash2smartfield((gpointer) tmp->key, (gpointer) tmp->value, args);
    }

    rc = lrmd_send_command(lrmd, LRMD_OP_ALERT_EXEC, data, NULL, timeout,
                           lrmd_opt_notify_orig_only, true);
    pcmk__xml_free(data);

    lrmd_key_value_freeall(params);
    return rc;
}

static int
lrmd_api_cancel(lrmd_t *lrmd, const char *rsc_id, const char *action,
                guint interval_ms)
{
    int rc = pcmk_ok;
    xmlNode *data = pcmk__xe_create(NULL, PCMK__XE_LRMD_RSC);

    pcmk__xe_set(data, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ACTION, action);
    pcmk__xe_set(data, PCMK__XA_LRMD_RSC_ID, rsc_id);
    pcmk__xe_set_guint(data, PCMK__XA_LRMD_RSC_INTERVAL, interval_ms);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_CANCEL, data, NULL, 0, 0, true);
    pcmk__xml_free(data);
    return rc;
}

static int
list_stonith_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    stonith_t *stonith_api = stonith__api_new();
    stonith_key_value_t *stonith_resources = NULL;
    stonith_key_value_t *dIter = NULL;

    if (stonith_api == NULL) {
        pcmk__err("Could not list fence agents: API memory allocation failed");
        return -ENOMEM;
    }
    stonith_api->cmds->list_agents(stonith_api, st_opt_sync_call, NULL,
                                   &stonith_resources, 0);
    stonith_api->cmds->free(stonith_api);

    for (dIter = stonith_resources; dIter; dIter = dIter->next) {
        rc++;
        if (resources) {
            *resources = lrmd_list_add(*resources, dIter->value);
        }
    }

    stonith__key_value_freeall(stonith_resources, true, false);
    return rc;
}

static int
lrmd_api_list_agents(lrmd_t * lrmd, lrmd_list_t ** resources, const char *class,
                     const char *provider)
{
    int rc = 0;
    int stonith_count = 0; // Initially, whether to include stonith devices

    if (pcmk__str_eq(class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        stonith_count = 1;

    } else {
        GList *gIter = NULL;
        GList *agents = resources_list_agents(class, provider);

        for (gIter = agents; gIter != NULL; gIter = gIter->next) {
            *resources = lrmd_list_add(*resources, (const char *)gIter->data);
            rc++;
        }
        g_list_free_full(agents, free);

        if (!class) {
            stonith_count = 1;
        }
    }

    if (stonith_count) {
        // Now, if stonith devices are included, how many there are
        stonith_count = list_stonith_agents(resources);
        if (stonith_count > 0) {
            rc += stonith_count;
        }
    }
    if (rc == 0) {
        pcmk__notice("No agents found for class %s", class);
        rc = -EPROTONOSUPPORT;
    }
    return rc;
}

static bool
does_provider_have_agent(const char *agent, const char *provider, const char *class)
{
    bool found = false;
    GList *agents = NULL;
    GList *gIter2 = NULL;

    agents = resources_list_agents(class, provider);
    for (gIter2 = agents; gIter2 != NULL; gIter2 = gIter2->next) {
        if (pcmk__str_eq(agent, gIter2->data, pcmk__str_casei)) {
            found = true;
        }
    }
    g_list_free_full(agents, free);
    return found;
}

static int
lrmd_api_list_ocf_providers(lrmd_t * lrmd, const char *agent, lrmd_list_t ** providers)
{
    int rc = pcmk_ok;
    char *provider = NULL;
    GList *ocf_providers = NULL;
    GList *gIter = NULL;

    ocf_providers = resources_list_providers(PCMK_RESOURCE_CLASS_OCF);

    for (gIter = ocf_providers; gIter != NULL; gIter = gIter->next) {
        provider = gIter->data;
        if (!agent || does_provider_have_agent(agent, provider,
                                               PCMK_RESOURCE_CLASS_OCF)) {
            *providers = lrmd_list_add(*providers, (const char *)gIter->data);
            rc++;
        }
    }

    g_list_free_full(ocf_providers, free);
    return rc;
}

static int
lrmd_api_list_standards(lrmd_t * lrmd, lrmd_list_t ** supported)
{
    int rc = 0;
    GList *standards = NULL;
    GList *gIter = NULL;

    standards = resources_list_standards();

    for (gIter = standards; gIter != NULL; gIter = gIter->next) {
        *supported = lrmd_list_add(*supported, (const char *)gIter->data);
        rc++;
    }

    if (list_stonith_agents(NULL) > 0) {
        *supported = lrmd_list_add(*supported, PCMK_RESOURCE_CLASS_STONITH);
        rc++;
    }

    g_list_free_full(standards, free);
    return rc;
}

/*!
 * \internal
 * \brief Create an executor API object
 *
 * \param[out] api       Will be set to newly created API object (it is the
 *                       caller's responsibility to free this value with
 *                       lrmd_api_delete() if this function succeeds)
 * \param[in]  nodename  If the object will be used for a remote connection,
 *                       the node name to use in cluster for remote executor
 * \param[in]  server    If the object will be used for a remote connection,
 *                       the resolvable host name to connect to
 * \param[in]  port      If the object will be used for a remote connection,
 *                       port number on \p server to connect to
 *
 * \return Standard Pacemaker return code
 * \note If the caller leaves one of \p nodename or \p server NULL, the other's
 *       value will be used for both. If the caller leaves both NULL, an API
 *       object will be created for a local executor connection.
 */
int
lrmd__new(lrmd_t **api, const char *nodename, const char *server, int port)
{
    lrmd_private_t *pvt = NULL;

    if (api == NULL) {
        return EINVAL;
    }
    *api = NULL;

    // Allocate all memory needed

    *api = calloc(1, sizeof(lrmd_t));
    if (*api == NULL) {
        return ENOMEM;
    }

    pvt = calloc(1, sizeof(lrmd_private_t));
    if (pvt == NULL) {
        lrmd_api_delete(*api);
        *api = NULL;
        return ENOMEM;
    }
    (*api)->lrmd_private = pvt;

    // @TODO Do we need to do this for local connections?
    pvt->remote = calloc(1, sizeof(pcmk__remote_t));

    (*api)->cmds = calloc(1, sizeof(lrmd_api_operations_t));

    if ((pvt->remote == NULL) || ((*api)->cmds == NULL)) {
        lrmd_api_delete(*api);
        *api = NULL;
        return ENOMEM;
    }

    // Set methods
    (*api)->cmds->connect = lrmd_api_connect;
    (*api)->cmds->connect_async = lrmd_api_connect_async;
    (*api)->cmds->is_connected = lrmd_api_is_connected;
    (*api)->cmds->poke_connection = lrmd_api_poke_connection;
    (*api)->cmds->disconnect = lrmd_api_disconnect;
    (*api)->cmds->register_rsc = lrmd_api_register_rsc;
    (*api)->cmds->unregister_rsc = lrmd_api_unregister_rsc;
    (*api)->cmds->get_rsc_info = lrmd_api_get_rsc_info;
    (*api)->cmds->get_recurring_ops = lrmd_api_get_recurring_ops;
    (*api)->cmds->set_callback = lrmd_api_set_callback;
    (*api)->cmds->get_metadata = lrmd_api_get_metadata;
    (*api)->cmds->exec = lrmd_api_exec;
    (*api)->cmds->cancel = lrmd_api_cancel;
    (*api)->cmds->list_agents = lrmd_api_list_agents;
    (*api)->cmds->list_ocf_providers = lrmd_api_list_ocf_providers;
    (*api)->cmds->list_standards = lrmd_api_list_standards;
    (*api)->cmds->exec_alert = lrmd_api_exec_alert;
    (*api)->cmds->get_metadata_params = lrmd_api_get_metadata_params;

    if ((nodename == NULL) && (server == NULL)) {
        pvt->type = pcmk__client_ipc;
    } else {
        if (nodename == NULL) {
            nodename = server;
        } else if (server == NULL) {
            server = nodename;
        }
        pvt->type = pcmk__client_tls;
        pvt->remote_nodename = strdup(nodename);
        pvt->server = strdup(server);
        if ((pvt->remote_nodename == NULL) || (pvt->server == NULL)) {
            lrmd_api_delete(*api);
            *api = NULL;
            return ENOMEM;
        }
        pvt->port = port;
        if (pvt->port == 0) {
            pvt->port = crm_default_remote_port();
        }
    }
    return pcmk_rc_ok;
}

lrmd_t *
lrmd_api_new(void)
{
    lrmd_t *api = NULL;

    pcmk__assert(lrmd__new(&api, NULL, NULL, 0) == pcmk_rc_ok);
    return api;
}

lrmd_t *
lrmd_remote_api_new(const char *nodename, const char *server, int port)
{
    lrmd_t *api = NULL;

    pcmk__assert(lrmd__new(&api, nodename, server, port) == pcmk_rc_ok);
    return api;
}

void
lrmd_api_delete(lrmd_t * lrmd)
{
    if (lrmd == NULL) {
        return;
    }
    if (lrmd->cmds != NULL) { // Never NULL, but make static analysis happy
        if (lrmd->cmds->disconnect != NULL) { // Also never really NULL
            lrmd->cmds->disconnect(lrmd); // No-op if already disconnected
        }
        free(lrmd->cmds);
    }
    if (lrmd->lrmd_private != NULL) {
        lrmd_private_t *native = lrmd->lrmd_private;

        free(native->server);
        free(native->remote_nodename);
        free(native->remote);
        free(native->token);
        free(native->peer_version);
        free(lrmd->lrmd_private);
    }
    free(lrmd);
}

struct metadata_cb {
     void (*callback)(int pid, const pcmk__action_result_t *result,
                      void *user_data);
     void *user_data;
};

/*!
 * \internal
 * \brief Process asynchronous metadata completion
 *
 * \param[in,out] action  Metadata action that completed
 */
static void
metadata_complete(svc_action_t *action)
{
    struct metadata_cb *metadata_cb = (struct metadata_cb *) action->cb_data;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    services__copy_result(action, &result);
    pcmk__set_result_output(&result, action->stdout_data, action->stderr_data);

    metadata_cb->callback(0, &result, metadata_cb->user_data);
    result.action_stdout = NULL; // Prevent free, because action owns it
    result.action_stderr = NULL; // Prevent free, because action owns it
    pcmk__reset_result(&result);
    free(metadata_cb);
}

/*!
 * \internal
 * \brief Retrieve agent metadata asynchronously
 *
 * \param[in]     rsc        Resource agent specification
 * \param[in]     callback   Function to call with result (this will always be
 *                           called, whether by this function directly or later
 *                           via the main loop, and on success the metadata will
 *                           be in its result argument's action_stdout)
 * \param[in,out] user_data  User data to pass to callback
 *
 * \return Standard Pacemaker return code
 * \note This function is not a lrmd_api_operations_t method because it does not
 *       need an lrmd_t object and does not go through the executor, but
 *       executes the agent directly.
 */
int
lrmd__metadata_async(const lrmd_rsc_info_t *rsc,
                     void (*callback)(int pid,
                                      const pcmk__action_result_t *result,
                                      void *user_data),
                     void *user_data)
{
    svc_action_t *action = NULL;
    struct metadata_cb *metadata_cb = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    CRM_CHECK(callback != NULL, return EINVAL);

    if ((rsc == NULL) || (rsc->standard == NULL) || (rsc->type == NULL)) {
        pcmk__set_result(&result, PCMK_OCF_NOT_CONFIGURED,
                         PCMK_EXEC_ERROR_FATAL,
                         "Invalid resource specification");
        callback(0, &result, user_data);
        pcmk__reset_result(&result);
        return EINVAL;
    }

    if (strcmp(rsc->standard, PCMK_RESOURCE_CLASS_STONITH) == 0) {
        return stonith__metadata_async(rsc->type,
                                       pcmk__timeout_ms2s(PCMK_DEFAULT_ACTION_TIMEOUT_MS),
                                       callback, user_data);
    }

    action = services__create_resource_action(pcmk__s(rsc->id, rsc->type),
                                              rsc->standard, rsc->provider,
                                              rsc->type,
                                              PCMK_ACTION_META_DATA, 0,
                                              PCMK_DEFAULT_ACTION_TIMEOUT_MS,
                                              NULL, 0);
    if (action == NULL) {
        pcmk__set_result(&result, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                         "Out of memory");
        callback(0, &result, user_data);
        pcmk__reset_result(&result);
        return ENOMEM;
    }
    if (action->rc != PCMK_OCF_UNKNOWN) {
        services__copy_result(action, &result);
        callback(0, &result, user_data);
        pcmk__reset_result(&result);
        services_action_free(action);
        return EINVAL;
    }

    action->cb_data = calloc(1, sizeof(struct metadata_cb));
    if (action->cb_data == NULL) {
        services_action_free(action);
        pcmk__set_result(&result, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                         "Out of memory");
        callback(0, &result, user_data);
        pcmk__reset_result(&result);
        return ENOMEM;
    }

    metadata_cb = (struct metadata_cb *) action->cb_data;
    metadata_cb->callback = callback;
    metadata_cb->user_data = user_data;
    if (!services_action_async(action, metadata_complete)) {
        services_action_free(action);
        return pcmk_rc_error; // @TODO Derive from action->rc and ->status
    }

    // The services library has taken responsibility for action
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Set the result of an executor event
 *
 * \param[in,out] event        Executor event to set
 * \param[in]     rc           OCF exit status of event
 * \param[in]     op_status    Executor status of event
 * \param[in]     exit_reason  Human-friendly description of event
 */
void
lrmd__set_result(lrmd_event_data_t *event, enum ocf_exitcode rc, int op_status,
                 const char *exit_reason)
{
    if (event == NULL) {
        return;
    }

    event->rc = rc;
    event->op_status = op_status;

    // lrmd_event_data_t has (const char *) members that lrmd_free_event() frees
    pcmk__str_update((char **) &event->exit_reason, exit_reason);
}

/*!
 * \internal
 * \brief Clear an executor event's exit reason, output, and error output
 *
 * \param[in,out] event  Executor event to reset
 */
void
lrmd__reset_result(lrmd_event_data_t *event)
{
    if (event == NULL) {
        return;
    }

    free((void *) event->exit_reason);
    event->exit_reason = NULL;

    free((void *) event->output);
    event->output = NULL;
}

/*!
 * \internal
 * \brief Get the uptime of a remote resource connection
 *
 * When the cluster connects to a remote resource, part of that resource's
 * handshake includes the uptime of the remote resource's connection.  This
 * uptime is stored in the lrmd_t object.
 *
 * \return The connection's uptime, or -1 if unknown
 */
time_t
lrmd__uptime(lrmd_t *lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->remote == NULL) {
        return -1;
    } else {
        return native->remote->uptime;
    }
}

const char *
lrmd__node_start_state(lrmd_t *lrmd)
{
    lrmd_private_t *native = lrmd->lrmd_private;

    if (native->remote == NULL) {
        return NULL;
    } else {
        return native->remote->start_state;
    }
}
