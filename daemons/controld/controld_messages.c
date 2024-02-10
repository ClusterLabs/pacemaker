/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <string.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include <crm/cib.h>
#include <crm/common/ipc_internal.h>

#include <pacemaker-controld.h>

static enum crmd_fsa_input handle_message(xmlNode *msg,
                                          enum crmd_fsa_cause cause);
static void handle_response(xmlNode *stored_msg);
static enum crmd_fsa_input handle_request(xmlNode *stored_msg,
                                          enum crmd_fsa_cause cause);
static enum crmd_fsa_input handle_shutdown_request(xmlNode *stored_msg);
static void send_msg_via_ipc(xmlNode * msg, const char *sys);

/* debug only, can wrap all it likes */
static int last_data_id = 0;

void
register_fsa_error_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                       fsa_data_t * cur_data, void *new_data, const char *raised_from)
{
    /* save the current actions if any */
    if (controld_globals.fsa_actions != A_NOTHING) {
        register_fsa_input_adv(cur_data ? cur_data->fsa_cause : C_FSA_INTERNAL,
                               I_NULL, cur_data ? cur_data->data : NULL,
                               controld_globals.fsa_actions, TRUE, __func__);
    }

    /* reset the action list */
    crm_info("Resetting the current action list");
    fsa_dump_actions(controld_globals.fsa_actions, "Drop");
    controld_globals.fsa_actions = A_NOTHING;

    /* register the error */
    register_fsa_input_adv(cause, input, new_data, A_NOTHING, TRUE, raised_from);
}

void
register_fsa_input_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                       void *data, uint64_t with_actions,
                       gboolean prepend, const char *raised_from)
{
    unsigned old_len = g_list_length(controld_globals.fsa_message_queue);
    fsa_data_t *fsa_data = NULL;

    if (raised_from == NULL) {
        raised_from = "<unknown>";
    }

    if (input == I_NULL && with_actions == A_NOTHING /* && data == NULL */ ) {
        /* no point doing anything */
        crm_err("Cannot add entry to queue: no input and no action");
        return;
    }

    if (input == I_WAIT_FOR_EVENT) {
        controld_set_global_flags(controld_fsa_is_stalled);
        crm_debug("Stalling the FSA pending further input: source=%s cause=%s data=%p queue=%d",
                  raised_from, fsa_cause2string(cause), data, old_len);

        if (old_len > 0) {
            fsa_dump_queue(LOG_TRACE);
            prepend = FALSE;
        }

        if (data == NULL) {
            controld_set_fsa_action_flags(with_actions);
            fsa_dump_actions(with_actions, "Restored");
            return;
        }

        /* Store everything in the new event and reset
         * controld_globals.fsa_actions
         */
        with_actions |= controld_globals.fsa_actions;
        controld_globals.fsa_actions = A_NOTHING;
    }

    last_data_id++;
    crm_trace("%s %s FSA input %d (%s) due to %s, %s data",
              raised_from, (prepend? "prepended" : "appended"), last_data_id,
              fsa_input2string(input), fsa_cause2string(cause),
              (data? "with" : "without"));

    fsa_data = calloc(1, sizeof(fsa_data_t));
    fsa_data->id = last_data_id;
    fsa_data->fsa_input = input;
    fsa_data->fsa_cause = cause;
    fsa_data->origin = raised_from;
    fsa_data->data = NULL;
    fsa_data->data_type = fsa_dt_none;
    fsa_data->actions = with_actions;

    if (with_actions != A_NOTHING) {
        crm_trace("Adding actions %.16llx to input",
                  (unsigned long long) with_actions);
    }

    if (data != NULL) {
        switch (cause) {
            case C_FSA_INTERNAL:
            case C_CRMD_STATUS_CALLBACK:
            case C_IPC_MESSAGE:
            case C_HA_MESSAGE:
                CRM_CHECK(((ha_msg_input_t *) data)->msg != NULL,
                          crm_err("Bogus data from %s", raised_from));
                crm_trace("Copying %s data from %s as cluster message data",
                          fsa_cause2string(cause), raised_from);
                fsa_data->data = copy_ha_msg_input(data);
                fsa_data->data_type = fsa_dt_ha_msg;
                break;

            case C_LRM_OP_CALLBACK:
                crm_trace("Copying %s data from %s as lrmd_event_data_t",
                          fsa_cause2string(cause), raised_from);
                fsa_data->data = lrmd_copy_event((lrmd_event_data_t *) data);
                fsa_data->data_type = fsa_dt_lrm;
                break;

            case C_TIMER_POPPED:
            case C_SHUTDOWN:
            case C_UNKNOWN:
            case C_STARTUP:
                crm_crit("Copying %s data (from %s) is not yet implemented",
                         fsa_cause2string(cause), raised_from);
                crmd_exit(CRM_EX_SOFTWARE);
                break;
        }
    }

    /* make sure to free it properly later */
    if (prepend) {
        controld_globals.fsa_message_queue
            = g_list_prepend(controld_globals.fsa_message_queue, fsa_data);
    } else {
        controld_globals.fsa_message_queue
            = g_list_append(controld_globals.fsa_message_queue, fsa_data);
    }

    crm_trace("FSA message queue length is %d",
              g_list_length(controld_globals.fsa_message_queue));

    /* fsa_dump_queue(LOG_TRACE); */

    if (old_len == g_list_length(controld_globals.fsa_message_queue)) {
        crm_err("Couldn't add message to the queue");
    }

    if (input != I_WAIT_FOR_EVENT) {
        controld_trigger_fsa();
    }
}

void
fsa_dump_queue(int log_level)
{
    int offset = 0;

    for (GList *iter = controld_globals.fsa_message_queue; iter != NULL;
         iter = iter->next) {
        fsa_data_t *data = (fsa_data_t *) iter->data;

        do_crm_log_unlikely(log_level,
                            "queue[%d.%d]: input %s raised by %s(%p.%d)\t(cause=%s)",
                            offset++, data->id, fsa_input2string(data->fsa_input),
                            data->origin, data->data, data->data_type,
                            fsa_cause2string(data->fsa_cause));
    }
}

ha_msg_input_t *
copy_ha_msg_input(ha_msg_input_t * orig)
{
    ha_msg_input_t *copy = calloc(1, sizeof(ha_msg_input_t));

    CRM_ASSERT(copy != NULL);
    copy->msg = (orig != NULL)? pcmk__xml_copy(NULL, orig->msg) : NULL;
    copy->xml = get_message_xml(copy->msg, PCMK__XE_CRM_XML);
    return copy;
}

void
delete_fsa_input(fsa_data_t * fsa_data)
{
    lrmd_event_data_t *op = NULL;
    xmlNode *foo = NULL;

    if (fsa_data == NULL) {
        return;
    }
    crm_trace("About to free %s data", fsa_cause2string(fsa_data->fsa_cause));

    if (fsa_data->data != NULL) {
        switch (fsa_data->data_type) {
            case fsa_dt_ha_msg:
                delete_ha_msg_input(fsa_data->data);
                break;

            case fsa_dt_xml:
                foo = fsa_data->data;
                free_xml(foo);
                break;

            case fsa_dt_lrm:
                op = (lrmd_event_data_t *) fsa_data->data;
                lrmd_free_event(op);
                break;

            case fsa_dt_none:
                if (fsa_data->data != NULL) {
                    crm_err("Don't know how to free %s data from %s",
                            fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
                    crmd_exit(CRM_EX_SOFTWARE);
                }
                break;
        }
        crm_trace("%s data freed", fsa_cause2string(fsa_data->fsa_cause));
    }

    free(fsa_data);
}

/* returns the next message */
fsa_data_t *
get_message(void)
{
    fsa_data_t *message
        = (fsa_data_t *) controld_globals.fsa_message_queue->data;

    controld_globals.fsa_message_queue
        = g_list_remove(controld_globals.fsa_message_queue, message);
    crm_trace("Processing input %d", message->id);
    return message;
}

void *
fsa_typed_data_adv(fsa_data_t * fsa_data, enum fsa_data_type a_type, const char *caller)
{
    void *ret_val = NULL;

    if (fsa_data == NULL) {
        crm_err("%s: No FSA data available", caller);

    } else if (fsa_data->data == NULL) {
        crm_err("%s: No message data available. Origin: %s", caller, fsa_data->origin);

    } else if (fsa_data->data_type != a_type) {
        crm_crit("%s: Message data was the wrong type! %d vs. requested=%d.  Origin: %s",
                 caller, fsa_data->data_type, a_type, fsa_data->origin);
        CRM_ASSERT(fsa_data->data_type == a_type);
    } else {
        ret_val = fsa_data->data;
    }

    return ret_val;
}

/*	A_MSG_ROUTE	*/
void
do_msg_route(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);

    route_message(msg_data->fsa_cause, input->msg);
}

void
route_message(enum crmd_fsa_cause cause, xmlNode * input)
{
    ha_msg_input_t fsa_input;
    enum crmd_fsa_input result = I_NULL;

    fsa_input.msg = input;
    CRM_CHECK(cause == C_IPC_MESSAGE || cause == C_HA_MESSAGE, return);

    /* try passing the buck first */
    if (relay_message(input, cause == C_IPC_MESSAGE)) {
        return;
    }

    /* handle locally */
    result = handle_message(input, cause);

    /* done or process later? */
    switch (result) {
        case I_NULL:
        case I_CIB_OP:
        case I_ROUTER:
        case I_NODE_JOIN:
        case I_JOIN_REQUEST:
        case I_JOIN_RESULT:
            break;
        default:
            /* Defering local processing of message */
            register_fsa_input_later(cause, result, &fsa_input);
            return;
    }

    if (result != I_NULL) {
        /* add to the front of the queue */
        register_fsa_input(cause, result, &fsa_input);
    }
}

gboolean
relay_message(xmlNode * msg, gboolean originated_locally)
{
    enum crm_ais_msg_types dest = crm_msg_ais;
    bool is_for_dc = false;
    bool is_for_dcib = false;
    bool is_for_te = false;
    bool is_for_crm = false;
    bool is_for_cib = false;
    bool is_local = false;
    bool broadcast = false;
    const char *host_to = NULL;
    const char *sys_to = NULL;
    const char *sys_from = NULL;
    const char *type = NULL;
    const char *task = NULL;
    const char *ref = NULL;
    crm_node_t *node_to = NULL;

    CRM_CHECK(msg != NULL, return TRUE);

    host_to = crm_element_value(msg, PCMK__XA_CRM_HOST_TO);
    sys_to = crm_element_value(msg, PCMK__XA_CRM_SYS_TO);
    sys_from = crm_element_value(msg, PCMK__XA_CRM_SYS_FROM);
    type = crm_element_value(msg, PCMK__XA_T);
    task = crm_element_value(msg, PCMK__XA_CRM_TASK);
    ref = crm_element_value(msg, PCMK_XA_REFERENCE);

    broadcast = pcmk__str_empty(host_to);

    if (ref == NULL) {
        ref = "without reference ID";
    }

    if (pcmk__str_eq(task, CRM_OP_HELLO, pcmk__str_casei)) {
        crm_trace("Received hello %s from %s (no processing needed)",
                  ref, pcmk__s(sys_from, "unidentified source"));
        crm_log_xml_trace(msg, "hello");
        return TRUE;
    }

    // Require message type (set by create_request())
    if (!pcmk__str_eq(type, PCMK__VALUE_CRMD, pcmk__str_none)) {
        crm_warn("Ignoring invalid message %s with type '%s' "
                 "(not '" PCMK__VALUE_CRMD "')",
                 ref, pcmk__s(type, ""));
        crm_log_xml_trace(msg, "ignored");
        return TRUE;
    }

    // Require a destination subsystem (also set by create_request())
    if (sys_to == NULL) {
        crm_warn("Ignoring invalid message %s with no " PCMK__XA_CRM_SYS_TO,
                 ref);
        crm_log_xml_trace(msg, "ignored");
        return TRUE;
    }

    // Get the message type appropriate to the destination subsystem
    if (is_corosync_cluster()) {
        dest = text2msg_type(sys_to);
        if ((dest < crm_msg_ais) || (dest > crm_msg_stonith_ng)) {
            /* Unrecognized value, use a sane default
             *
             * @TODO Maybe we should bail instead
             */
            dest = crm_msg_crmd;
        }
    }

    is_for_dc = (strcasecmp(CRM_SYSTEM_DC, sys_to) == 0);
    is_for_dcib = (strcasecmp(CRM_SYSTEM_DCIB, sys_to) == 0);
    is_for_te = (strcasecmp(CRM_SYSTEM_TENGINE, sys_to) == 0);
    is_for_cib = (strcasecmp(CRM_SYSTEM_CIB, sys_to) == 0);
    is_for_crm = (strcasecmp(CRM_SYSTEM_CRMD, sys_to) == 0);

    // Check whether message should be processed locally
    is_local = false;
    if (broadcast) {
        if (is_for_dc || is_for_te) {
            is_local = false;

        } else if (is_for_crm) {
            if (pcmk__strcase_any_of(task, CRM_OP_NODE_INFO,
                                     PCMK__CONTROLD_CMD_NODES, NULL)) {
                /* Node info requests do not specify a host, which is normally
                 * treated as "all hosts", because the whole point is that the
                 * client may not know the local node name. Always handle these
                 * requests locally.
                 */
                is_local = true;
            } else {
                is_local = !originated_locally;
            }

        } else {
            is_local = true;
        }

    } else if (pcmk__str_eq(controld_globals.our_nodename, host_to,
                            pcmk__str_casei)) {
        is_local = true;

    } else if (is_for_crm && pcmk__str_eq(task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        xmlNode *msg_data = get_message_xml(msg, PCMK__XE_CRM_XML);
        const char *mode = crm_element_value(msg_data, PCMK__XA_MODE);

        if (pcmk__str_eq(mode, PCMK__VALUE_CIB, pcmk__str_none)) {
            // Local delete of an offline node's resource history
            is_local = true;
        }
    }

    // Check whether message should be relayed

    if (is_for_dc || is_for_dcib || is_for_te) {
        if (AM_I_DC) {
            if (is_for_te) {
                crm_trace("Route message %s locally as transition request",
                          ref);
                crm_log_xml_trace(msg, sys_to);
                send_msg_via_ipc(msg, sys_to);
                return TRUE; // No further processing of message is needed
            }
            crm_trace("Route message %s locally as DC request", ref);
            return FALSE; // More to be done by caller
        }

        if (originated_locally
            && !pcmk__strcase_any_of(sys_from, CRM_SYSTEM_PENGINE,
                                     CRM_SYSTEM_TENGINE, NULL)) {
            crm_trace("Relay message %s to DC (via %s)",
                      ref, pcmk__s(host_to, "broadcast"));
            crm_log_xml_trace(msg, "relayed");
            if (!broadcast) {
                node_to = pcmk__get_node(0, host_to, NULL,
                                         pcmk__node_search_cluster);
            }
            send_cluster_message(node_to, dest, msg, TRUE);
            return TRUE;
        }

        /* Transition engine and scheduler messages are sent only to the DC on
         * the same node. If we are no longer the DC, discard this message.
         */
        crm_trace("Ignoring message %s because we are no longer DC", ref);
        crm_log_xml_trace(msg, "ignored");
        return TRUE; // No further processing of message is needed
    }

    if (is_local) {
        if (is_for_crm || is_for_cib) {
            crm_trace("Route message %s locally as controller request", ref);
            return FALSE; // More to be done by caller
        }
        crm_trace("Relay message %s locally to %s", ref, sys_to);
        crm_log_xml_trace(msg, "IPC-relay");
        send_msg_via_ipc(msg, sys_to);
        return TRUE;
    }

    if (!broadcast) {
        node_to = pcmk__search_node_caches(0, host_to,
                                           pcmk__node_search_cluster);
        if (node_to == NULL) {
            crm_warn("Ignoring message %s because node %s is unknown",
                     ref, host_to);
            crm_log_xml_trace(msg, "ignored");
            return TRUE;
        }
    }

    crm_trace("Relay message %s to %s",
              ref, pcmk__s(host_to, "all peers"));
    crm_log_xml_trace(msg, "relayed");
    send_cluster_message(node_to, dest, msg, TRUE);
    return TRUE;
}

// Return true if field contains a positive integer
static bool
authorize_version(xmlNode *message_data, const char *field,
                  const char *client_name, const char *ref, const char *uuid)
{
    const char *version = crm_element_value(message_data, field);
    long long version_num;

    if ((pcmk__scan_ll(version, &version_num, -1LL) != pcmk_rc_ok)
        || (version_num < 0LL)) {

        crm_warn("Rejected IPC hello from %s: '%s' is not a valid protocol %s "
                 CRM_XS " ref=%s uuid=%s",
                 client_name, ((version == NULL)? "" : version),
                 field, (ref? ref : "none"), uuid);
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Check whether a client IPC message is acceptable
 *
 * If a given client IPC message is a hello, "authorize" it by ensuring it has
 * valid information such as a protocol version, and return false indicating
 * that nothing further needs to be done with the message. If the message is not
 * a hello, just return true to indicate it needs further processing.
 *
 * \param[in]     client_msg     XML of IPC message
 * \param[in,out] curr_client    If IPC is not proxied, client that sent message
 * \param[in]     proxy_session  If IPC is proxied, the session ID
 *
 * \return true if message needs further processing, false if it doesn't
 */
bool
controld_authorize_ipc_message(const xmlNode *client_msg, pcmk__client_t *curr_client,
                               const char *proxy_session)
{
    xmlNode *message_data = NULL;
    const char *client_name = NULL;
    const char *op = crm_element_value(client_msg, PCMK__XA_CRM_TASK);
    const char *ref = crm_element_value(client_msg, PCMK_XA_REFERENCE);
    const char *uuid = (curr_client? curr_client->id : proxy_session);

    if (uuid == NULL) {
        crm_warn("IPC message from client rejected: No client identifier "
                 CRM_XS " ref=%s", (ref? ref : "none"));
        goto rejected;
    }

    if (!pcmk__str_eq(CRM_OP_HELLO, op, pcmk__str_casei)) {
        // Only hello messages need to be authorized
        return true;
    }

    message_data = get_message_xml(client_msg, PCMK__XE_CRM_XML);

    client_name = crm_element_value(message_data, PCMK__XA_CLIENT_NAME);
    if (pcmk__str_empty(client_name)) {
        crm_warn("IPC hello from client rejected: No client name",
                 CRM_XS " ref=%s uuid=%s", (ref? ref : "none"), uuid);
        goto rejected;
    }
    if (!authorize_version(message_data, PCMK__XA_MAJOR_VERSION, client_name,
                           ref, uuid)) {
        goto rejected;
    }
    if (!authorize_version(message_data, PCMK__XA_MINOR_VERSION, client_name,
                           ref, uuid)) {
        goto rejected;
    }

    crm_trace("Validated IPC hello from client %s", client_name);
    crm_log_xml_trace(client_msg, "hello");
    if (curr_client) {
        curr_client->userdata = strdup(client_name);
    }
    controld_trigger_fsa();
    return false;

rejected:
    crm_log_xml_trace(client_msg, "rejected");
    if (curr_client) {
        qb_ipcs_disconnect(curr_client->ipcs);
    }
    return false;
}

static enum crmd_fsa_input
handle_message(xmlNode *msg, enum crmd_fsa_cause cause)
{
    const char *type = NULL;

    CRM_CHECK(msg != NULL, return I_NULL);

    type = crm_element_value(msg, PCMK__XA_SUBT);
    if (pcmk__str_eq(type, PCMK__VALUE_REQUEST, pcmk__str_none)) {
        return handle_request(msg, cause);
    }

    if (pcmk__str_eq(type, PCMK__VALUE_RESPONSE, pcmk__str_none)) {
        handle_response(msg);
        return I_NULL;
    }

    crm_warn("Ignoring message with unknown " PCMK__XA_SUBT" '%s'",
             pcmk__s(type, ""));
    crm_log_xml_trace(msg, "bad");
    return I_NULL;
}

static enum crmd_fsa_input
handle_failcount_op(xmlNode * stored_msg)
{
    const char *rsc = NULL;
    const char *uname = NULL;
    const char *op = NULL;
    char *interval_spec = NULL;
    guint interval_ms = 0;
    gboolean is_remote_node = FALSE;
    xmlNode *xml_op = get_message_xml(stored_msg, PCMK__XE_CRM_XML);

    if (xml_op) {
        xmlNode *xml_rsc = first_named_child(xml_op, PCMK_XE_PRIMITIVE);
        xmlNode *xml_attrs = first_named_child(xml_op, PCMK__XE_ATTRIBUTES);

        if (xml_rsc) {
            rsc = pcmk__xe_id(xml_rsc);
        }
        if (xml_attrs) {
            op = crm_element_value(xml_attrs,
                                   CRM_META "_" PCMK__META_CLEAR_FAILURE_OP);
            crm_element_value_ms(xml_attrs,
                                 CRM_META "_" PCMK__META_CLEAR_FAILURE_INTERVAL,
                                 &interval_ms);
        }
    }
    uname = crm_element_value(xml_op, PCMK__META_ON_NODE);

    if ((rsc == NULL) || (uname == NULL)) {
        crm_log_xml_warn(stored_msg, "invalid failcount op");
        return I_NULL;
    }

    if (crm_element_value(xml_op, PCMK__XA_ROUTER_NODE)) {
        is_remote_node = TRUE;
    }

    crm_debug("Clearing failures for %s-interval %s on %s "
              "from attribute manager, CIB, and executor state",
              pcmk__readable_interval(interval_ms), rsc, uname);

    if (interval_ms) {
        interval_spec = crm_strdup_printf("%ums", interval_ms);
    }
    update_attrd_clear_failures(uname, rsc, op, interval_spec, is_remote_node);
    free(interval_spec);

    controld_cib_delete_last_failure(rsc, uname, op, interval_ms);

    lrm_clear_last_failure(rsc, uname, op, interval_ms);

    return I_NULL;
}

static enum crmd_fsa_input
handle_lrm_delete(xmlNode *stored_msg)
{
    const char *mode = NULL;
    xmlNode *msg_data = get_message_xml(stored_msg, PCMK__XE_CRM_XML);

    CRM_CHECK(msg_data != NULL, return I_NULL);

    /* CRM_OP_LRM_DELETE has two distinct modes. The default behavior is to
     * relay the operation to the affected node, which will unregister the
     * resource from the local executor, clear the resource's history from the
     * CIB, and do some bookkeeping in the controller.
     *
     * However, if the affected node is offline, the client will specify
     * mode=PCMK__VALUE_CIB which means the controller receiving the operation
     * should clear the resource's history from the CIB and nothing else. This
     * is used to clear shutdown locks.
     */
    mode = crm_element_value(msg_data, PCMK__XA_MODE);
    if (!pcmk__str_eq(mode, PCMK__VALUE_CIB, pcmk__str_none)) {
        // Relay to affected node
        crm_xml_add(stored_msg, PCMK__XA_CRM_SYS_TO, CRM_SYSTEM_LRMD);
        return I_ROUTER;

    } else {
        // Delete CIB history locally (compare with do_lrm_delete())
        const char *from_sys = NULL;
        const char *user_name = NULL;
        const char *rsc_id = NULL;
        const char *node = NULL;
        xmlNode *rsc_xml = NULL;
        int rc = pcmk_rc_ok;

        rsc_xml = first_named_child(msg_data, PCMK_XE_PRIMITIVE);
        CRM_CHECK(rsc_xml != NULL, return I_NULL);

        rsc_id = pcmk__xe_id(rsc_xml);
        from_sys = crm_element_value(stored_msg, PCMK__XA_CRM_SYS_FROM);
        node = crm_element_value(msg_data, PCMK__META_ON_NODE);
        user_name = pcmk__update_acl_user(stored_msg, PCMK__XA_CRM_USER, NULL);
        crm_debug("Handling " CRM_OP_LRM_DELETE " for %s on %s locally%s%s "
                  "(clearing CIB resource history only)", rsc_id, node,
                  (user_name? " for user " : ""), (user_name? user_name : ""));
        rc = controld_delete_resource_history(rsc_id, node, user_name,
                                              cib_dryrun|cib_sync_call);
        if (rc == pcmk_rc_ok) {
            rc = controld_delete_resource_history(rsc_id, node, user_name,
                                                  crmd_cib_smart_opt());
        }

        /* Notify client. Also notify tengine if mode=PCMK__VALUE_CIB and
         * op=CRM_OP_LRM_DELETE.
         */
        if (from_sys) {
            lrmd_event_data_t *op = NULL;
            const char *from_host = crm_element_value(stored_msg, PCMK__XA_SRC);
            const char *transition;

            if (strcmp(from_sys, CRM_SYSTEM_TENGINE)) {
                transition = crm_element_value(msg_data,
                                               PCMK__XA_TRANSITION_KEY);
            } else {
                transition = crm_element_value(stored_msg,
                                               PCMK__XA_TRANSITION_KEY);
            }

            crm_info("Notifying %s on %s that %s was%s deleted",
                     from_sys, (from_host? from_host : "local node"), rsc_id,
                     ((rc == pcmk_rc_ok)? "" : " not"));
            op = lrmd_new_event(rsc_id, PCMK_ACTION_DELETE, 0);
            op->type = lrmd_event_exec_complete;
            op->user_data = strdup(transition? transition : FAKE_TE_ID);
            op->params = pcmk__strkey_table(free, free);
            pcmk__insert_dup(op->params, PCMK_XA_CRM_FEATURE_SET,
                             CRM_FEATURE_SET);
            controld_rc2event(op, rc);
            controld_ack_event_directly(from_host, from_sys, NULL, op, rsc_id);
            lrmd_free_event(op);
            controld_trigger_delete_refresh(from_sys, rsc_id);
        }
        return I_NULL;
    }
}

/*!
 * \brief Handle a CRM_OP_REMOTE_STATE message by updating remote peer cache
 *
 * \param[in] msg  Message XML
 *
 * \return Next FSA input
 */
static enum crmd_fsa_input
handle_remote_state(const xmlNode *msg)
{
    const char *conn_host = NULL;
    const char *remote_uname = pcmk__xe_id(msg);
    crm_node_t *remote_peer;
    bool remote_is_up = false;
    int rc = pcmk_rc_ok;

    rc = pcmk__xe_get_bool_attr(msg, PCMK__XA_IN_CCM, &remote_is_up);

    CRM_CHECK(remote_uname && rc == pcmk_rc_ok, return I_NULL);

    remote_peer = crm_remote_peer_get(remote_uname);
    CRM_CHECK(remote_peer, return I_NULL);

    pcmk__update_peer_state(__func__, remote_peer,
                            remote_is_up ? CRM_NODE_MEMBER : CRM_NODE_LOST,
                            0);

    conn_host = crm_element_value(msg, PCMK__XA_CONNECTION_HOST);
    if (conn_host) {
        pcmk__str_update(&remote_peer->conn_host, conn_host);
    } else if (remote_peer->conn_host) {
        free(remote_peer->conn_host);
        remote_peer->conn_host = NULL;
    }

    return I_NULL;
}

/*!
 * \brief Handle a CRM_OP_PING message
 *
 * \param[in] msg  Message XML
 *
 * \return Next FSA input
 */
static enum crmd_fsa_input
handle_ping(const xmlNode *msg)
{
    const char *value = NULL;
    xmlNode *ping = NULL;
    xmlNode *reply = NULL;

    // Build reply

    ping = pcmk__xe_create(NULL, PCMK__XE_PING_RESPONSE);
    value = crm_element_value(msg, PCMK__XA_CRM_SYS_TO);
    crm_xml_add(ping, PCMK__XA_CRM_SUBSYSTEM, value);

    // Add controller state
    value = fsa_state2string(controld_globals.fsa_state);
    crm_xml_add(ping, PCMK__XA_CRMD_STATE, value);
    crm_notice("Current ping state: %s", value); // CTS needs this

    // Add controller health
    // @TODO maybe do some checks to determine meaningful status
    crm_xml_add(ping, PCMK_XA_RESULT, "ok");

    // Send reply
    reply = create_reply(msg, ping);
    free_xml(ping);
    if (reply != NULL) {
        (void) relay_message(reply, TRUE);
        free_xml(reply);
    }

    // Nothing further to do
    return I_NULL;
}

/*!
 * \brief Handle a PCMK__CONTROLD_CMD_NODES message
 *
 * \param[in] request  Message XML
 *
 * \return Next FSA input
 */
static enum crmd_fsa_input
handle_node_list(const xmlNode *request)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;
    xmlNode *reply = NULL;
    xmlNode *reply_data = NULL;

    // Create message data for reply
    reply_data = pcmk__xe_create(NULL, PCMK_XE_NODES);
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
        xmlNode *xml = pcmk__xe_create(reply_data, PCMK_XE_NODE);

        crm_xml_add_ll(xml, PCMK_XA_ID, (long long) node->id); // uint32_t
        crm_xml_add(xml, PCMK_XA_UNAME, node->uname);
        crm_xml_add(xml, PCMK__XA_IN_CCM, node->state);
    }

    // Create and send reply
    reply = create_reply(request, reply_data);
    free_xml(reply_data);
    if (reply) {
        (void) relay_message(reply, TRUE);
        free_xml(reply);
    }

    // Nothing further to do
    return I_NULL;
}

/*!
 * \brief Handle a CRM_OP_NODE_INFO request
 *
 * \param[in] msg  Message XML
 *
 * \return Next FSA input
 */
static enum crmd_fsa_input
handle_node_info_request(const xmlNode *msg)
{
    const char *value = NULL;
    crm_node_t *node = NULL;
    int node_id = 0;
    xmlNode *reply = NULL;
    xmlNode *reply_data = NULL;

    // Build reply

    reply_data = pcmk__xe_create(NULL, PCMK_XE_NODE);
    crm_xml_add(reply_data, PCMK__XA_CRM_SUBSYSTEM, CRM_SYSTEM_CRMD);

    // Add whether current partition has quorum
    pcmk__xe_set_bool_attr(reply_data, PCMK_XA_HAVE_QUORUM,
                           pcmk_is_set(controld_globals.flags,
                                       controld_has_quorum));

    // Check whether client requested node info by ID and/or name
    crm_element_value_int(msg, PCMK_XA_ID, &node_id);
    if (node_id < 0) {
        node_id = 0;
    }
    value = crm_element_value(msg, PCMK_XA_UNAME);

    // Default to local node if none given
    if ((node_id == 0) && (value == NULL)) {
        value = controld_globals.our_nodename;
    }

    node = pcmk__search_node_caches(node_id, value, pcmk__node_search_any);
    if (node) {
        crm_xml_add(reply_data, PCMK_XA_ID, node->uuid);
        crm_xml_add(reply_data, PCMK_XA_UNAME, node->uname);
        crm_xml_add(reply_data, PCMK_XA_CRMD, node->state);
        pcmk__xe_set_bool_attr(reply_data, PCMK_XA_REMOTE_NODE,
                               pcmk_is_set(node->flags, crm_remote_node));
    }

    // Send reply
    reply = create_reply(msg, reply_data);
    free_xml(reply_data);
    if (reply != NULL) {
        (void) relay_message(reply, TRUE);
        free_xml(reply);
    }

    // Nothing further to do
    return I_NULL;
}

static void
verify_feature_set(xmlNode *msg)
{
    const char *dc_version = crm_element_value(msg, PCMK_XA_CRM_FEATURE_SET);

    if (dc_version == NULL) {
        /* All we really know is that the DC feature set is older than 3.1.0,
         * but that's also all that really matters.
         */
        dc_version = "3.0.14";
    }

    if (feature_set_compatible(dc_version, CRM_FEATURE_SET)) {
        crm_trace("Local feature set (%s) is compatible with DC's (%s)",
                  CRM_FEATURE_SET, dc_version);
    } else {
        crm_err("Local feature set (%s) is incompatible with DC's (%s)",
                CRM_FEATURE_SET, dc_version);

        // Nothing is likely to improve without administrator involvement
        controld_set_fsa_input_flags(R_STAYDOWN);
        crmd_exit(CRM_EX_FATAL);
    }
}

// DC gets own shutdown all-clear
static enum crmd_fsa_input
handle_shutdown_self_ack(xmlNode *stored_msg)
{
    const char *host_from = crm_element_value(stored_msg, PCMK__XA_SRC);

    if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        // The expected case -- we initiated own shutdown sequence
        crm_info("Shutting down controller");
        return I_STOP;
    }

    if (pcmk__str_eq(host_from, controld_globals.dc_name, pcmk__str_casei)) {
        // Must be logic error -- DC confirming its own unrequested shutdown
        crm_err("Shutting down controller immediately due to "
                "unexpected shutdown confirmation");
        return I_TERMINATE;
    }

    if (controld_globals.fsa_state != S_STOPPING) {
        // Shouldn't happen -- non-DC confirming unrequested shutdown
        crm_err("Starting new DC election because %s is "
                "confirming shutdown we did not request",
                (host_from? host_from : "another node"));
        return I_ELECTION;
    }

    // Shouldn't happen, but we are already stopping anyway
    crm_debug("Ignoring unexpected shutdown confirmation from %s",
              (host_from? host_from : "another node"));
    return I_NULL;
}

// Non-DC gets shutdown all-clear from DC
static enum crmd_fsa_input
handle_shutdown_ack(xmlNode *stored_msg)
{
    const char *host_from = crm_element_value(stored_msg, PCMK__XA_SRC);

    if (host_from == NULL) {
        crm_warn("Ignoring shutdown request without origin specified");
        return I_NULL;
    }

    if (pcmk__str_eq(host_from, controld_globals.dc_name,
                     pcmk__str_null_matches|pcmk__str_casei)) {

        if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
            crm_info("Shutting down controller after confirmation from %s",
                     host_from);
        } else {
            crm_err("Shutting down controller after unexpected "
                    "shutdown request from %s", host_from);
            controld_set_fsa_input_flags(R_STAYDOWN);
        }
        return I_STOP;
    }

    crm_warn("Ignoring shutdown request from %s because DC is %s",
             host_from, controld_globals.dc_name);
    return I_NULL;
}

static enum crmd_fsa_input
handle_request(xmlNode *stored_msg, enum crmd_fsa_cause cause)
{
    xmlNode *msg = NULL;
    const char *op = crm_element_value(stored_msg, PCMK__XA_CRM_TASK);

    /* Optimize this for the DC - it has the most to do */

    crm_log_xml_trace(stored_msg, "request");
    if (op == NULL) {
        crm_warn("Ignoring request without " PCMK__XA_CRM_TASK);
        return I_NULL;
    }

    if (strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
        const char *from = crm_element_value(stored_msg, PCMK__XA_SRC);
        crm_node_t *node = pcmk__search_node_caches(0, from,
                                                    pcmk__node_search_cluster);

        pcmk__update_peer_expected(__func__, node, CRMD_JOINSTATE_DOWN);
        if(AM_I_DC == FALSE) {
            return I_NULL; /* Done */
        }
    }

    /*========== DC-Only Actions ==========*/
    if (AM_I_DC) {
        if (strcmp(op, CRM_OP_JOIN_ANNOUNCE) == 0) {
            return I_NODE_JOIN;

        } else if (strcmp(op, CRM_OP_JOIN_REQUEST) == 0) {
            return I_JOIN_REQUEST;

        } else if (strcmp(op, CRM_OP_JOIN_CONFIRM) == 0) {
            return I_JOIN_RESULT;

        } else if (strcmp(op, CRM_OP_SHUTDOWN) == 0) {
            return handle_shutdown_self_ack(stored_msg);

        } else if (strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
            // Another controller wants to shut down its node
            return handle_shutdown_request(stored_msg);
        }
    }

    /*========== common actions ==========*/
    if (strcmp(op, CRM_OP_NOVOTE) == 0) {
        ha_msg_input_t fsa_input;

        fsa_input.msg = stored_msg;
        register_fsa_input_adv(C_HA_MESSAGE, I_NULL, &fsa_input,
                               A_ELECTION_COUNT | A_ELECTION_CHECK, FALSE,
                               __func__);

    } else if (strcmp(op, CRM_OP_REMOTE_STATE) == 0) {
        /* a remote connection host is letting us know the node state */
        return handle_remote_state(stored_msg);

    } else if (strcmp(op, CRM_OP_THROTTLE) == 0) {
        throttle_update(stored_msg);
        if (AM_I_DC && (controld_globals.transition_graph != NULL)
            && !controld_globals.transition_graph->complete) {

            crm_debug("The throttle changed. Trigger a graph.");
            trigger_graph();
        }
        return I_NULL;

    } else if (strcmp(op, CRM_OP_CLEAR_FAILCOUNT) == 0) {
        return handle_failcount_op(stored_msg);

    } else if (strcmp(op, CRM_OP_VOTE) == 0) {
        /* count the vote and decide what to do after that */
        ha_msg_input_t fsa_input;

        fsa_input.msg = stored_msg;
        register_fsa_input_adv(C_HA_MESSAGE, I_NULL, &fsa_input,
                               A_ELECTION_COUNT | A_ELECTION_CHECK, FALSE,
                               __func__);

        /* Sometimes we _must_ go into S_ELECTION */
        if (controld_globals.fsa_state == S_HALT) {
            crm_debug("Forcing an election from S_HALT");
            return I_ELECTION;
        }

    } else if (strcmp(op, CRM_OP_JOIN_OFFER) == 0) {
        verify_feature_set(stored_msg);
        crm_debug("Raising I_JOIN_OFFER: join-%s",
                  crm_element_value(stored_msg, PCMK__XA_JOIN_ID));
        return I_JOIN_OFFER;

    } else if (strcmp(op, CRM_OP_JOIN_ACKNAK) == 0) {
        crm_debug("Raising I_JOIN_RESULT: join-%s",
                  crm_element_value(stored_msg, PCMK__XA_JOIN_ID));
        return I_JOIN_RESULT;

    } else if (strcmp(op, CRM_OP_LRM_DELETE) == 0) {
        return handle_lrm_delete(stored_msg);

    } else if ((strcmp(op, CRM_OP_LRM_FAIL) == 0)
               || (strcmp(op, CRM_OP_LRM_REFRESH) == 0) // @COMPAT
               || (strcmp(op, CRM_OP_REPROBE) == 0)) {

        crm_xml_add(stored_msg, PCMK__XA_CRM_SYS_TO, CRM_SYSTEM_LRMD);
        return I_ROUTER;

    } else if (strcmp(op, CRM_OP_NOOP) == 0) {
        return I_NULL;

    } else if (strcmp(op, CRM_OP_PING) == 0) {
        return handle_ping(stored_msg);

    } else if (strcmp(op, CRM_OP_NODE_INFO) == 0) {
        return handle_node_info_request(stored_msg);

    } else if (strcmp(op, CRM_OP_RM_NODE_CACHE) == 0) {
        int id = 0;
        const char *name = NULL;

        crm_element_value_int(stored_msg, PCMK_XA_ID, &id);
        name = crm_element_value(stored_msg, PCMK_XA_UNAME);

        if(cause == C_IPC_MESSAGE) {
            msg = create_request(CRM_OP_RM_NODE_CACHE, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);
            if (send_cluster_message(NULL, crm_msg_crmd, msg, TRUE) == FALSE) {
                crm_err("Could not instruct peers to remove references to node %s/%u", name, id);
            } else {
                crm_notice("Instructing peers to remove references to node %s/%u", name, id);
            }
            free_xml(msg);

        } else {
            reap_crm_member(id, name);

            /* If we're forgetting this node, also forget any failures to fence
             * it, so we don't carry that over to any node added later with the
             * same name.
             */
            st_fail_count_reset(name);
        }

    } else if (strcmp(op, CRM_OP_MAINTENANCE_NODES) == 0) {
        xmlNode *xml = get_message_xml(stored_msg, PCMK__XE_CRM_XML);

        remote_ra_process_maintenance_nodes(xml);

    } else if (strcmp(op, PCMK__CONTROLD_CMD_NODES) == 0) {
        return handle_node_list(stored_msg);

        /*========== (NOT_DC)-Only Actions ==========*/
    } else if (!AM_I_DC) {

        if (strcmp(op, CRM_OP_SHUTDOWN) == 0) {
            return handle_shutdown_ack(stored_msg);
        }

    } else {
        crm_err("Unexpected request (%s) sent to %s", op, AM_I_DC ? "the DC" : "non-DC node");
        crm_log_xml_err(stored_msg, "Unexpected");
    }

    return I_NULL;
}

static void
handle_response(xmlNode *stored_msg)
{
    const char *op = crm_element_value(stored_msg, PCMK__XA_CRM_TASK);

    crm_log_xml_trace(stored_msg, "reply");
    if (op == NULL) {
        crm_warn("Ignoring reply without " PCMK__XA_CRM_TASK);

    } else if (AM_I_DC && strcmp(op, CRM_OP_PECALC) == 0) {
        // Check whether scheduler answer been superseded by subsequent request
        const char *msg_ref = crm_element_value(stored_msg, PCMK_XA_REFERENCE);

        if (msg_ref == NULL) {
            crm_err("%s - Ignoring calculation with no reference", op);

        } else if (pcmk__str_eq(msg_ref, controld_globals.fsa_pe_ref,
                                pcmk__str_none)) {
            ha_msg_input_t fsa_input;

            controld_stop_sched_timer();
            fsa_input.msg = stored_msg;
            register_fsa_input_later(C_IPC_MESSAGE, I_PE_SUCCESS, &fsa_input);

        } else {
            crm_info("%s calculation %s is obsolete", op, msg_ref);
        }

    } else if (strcmp(op, CRM_OP_VOTE) == 0
               || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0 || strcmp(op, CRM_OP_SHUTDOWN) == 0) {

    } else {
        const char *host_from = crm_element_value(stored_msg, PCMK__XA_SRC);

        crm_err("Unexpected response (op=%s, src=%s) sent to the %s",
                op, host_from, AM_I_DC ? "DC" : "controller");
    }
}

static enum crmd_fsa_input
handle_shutdown_request(xmlNode * stored_msg)
{
    /* handle here to avoid potential version issues
     *   where the shutdown message/procedure may have
     *   been changed in later versions.
     *
     * This way the DC is always in control of the shutdown
     */

    char *now_s = NULL;
    const char *host_from = crm_element_value(stored_msg, PCMK__XA_SRC);

    if (host_from == NULL) {
        /* we're shutting down and the DC */
        host_from = controld_globals.our_nodename;
    }

    crm_info("Creating shutdown request for %s (state=%s)", host_from,
             fsa_state2string(controld_globals.fsa_state));
    crm_log_xml_trace(stored_msg, "message");

    now_s = pcmk__ttoa(time(NULL));
    update_attrd(host_from, PCMK__NODE_ATTR_SHUTDOWN, now_s, NULL, FALSE);
    free(now_s);

    /* will be picked up by the TE as long as its running */
    return I_NULL;
}

static void
send_msg_via_ipc(xmlNode * msg, const char *sys)
{
    pcmk__client_t *client_channel = NULL;

    CRM_CHECK(sys != NULL, return);

    client_channel = pcmk__find_client_by_id(sys);

    if (crm_element_value(msg, PCMK__XA_SRC) == NULL) {
        crm_xml_add(msg, PCMK__XA_SRC, controld_globals.our_nodename);
    }

    if (client_channel != NULL) {
        /* Transient clients such as crmadmin */
        pcmk__ipc_send_xml(client_channel, 0, msg, crm_ipc_server_event);

    } else if (pcmk__str_eq(sys, CRM_SYSTEM_TENGINE, pcmk__str_none)) {
        xmlNode *data = get_message_xml(msg, PCMK__XE_CRM_XML);

        process_te_message(msg, data);

    } else if (pcmk__str_eq(sys, CRM_SYSTEM_LRMD, pcmk__str_none)) {
        fsa_data_t fsa_data;
        ha_msg_input_t fsa_input;

        fsa_input.msg = msg;
        fsa_input.xml = get_message_xml(msg, PCMK__XE_CRM_XML);

        fsa_data.id = 0;
        fsa_data.actions = 0;
        fsa_data.data = &fsa_input;
        fsa_data.fsa_input = I_MESSAGE;
        fsa_data.fsa_cause = C_IPC_MESSAGE;
        fsa_data.origin = __func__;
        fsa_data.data_type = fsa_dt_ha_msg;

        do_lrm_invoke(A_LRM_INVOKE, C_IPC_MESSAGE, controld_globals.fsa_state,
                      I_MESSAGE, &fsa_data);

    } else if (crmd_is_proxy_session(sys)) {
        crmd_proxy_send(sys, msg);

    } else {
        crm_info("Received invalid request: unknown subsystem '%s'", sys);
    }
}

void
delete_ha_msg_input(ha_msg_input_t * orig)
{
    if (orig == NULL) {
        return;
    }
    free_xml(orig->msg);
    free(orig);
}

/*!
 * \internal
 * \brief Notify the cluster of a remote node state change
 *
 * \param[in] node_name  Node's name
 * \param[in] node_up    true if node is up, false if down
 */
void
broadcast_remote_state_message(const char *node_name, bool node_up)
{
    xmlNode *msg = create_request(CRM_OP_REMOTE_STATE, NULL, NULL,
                                  CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    crm_info("Notifying cluster of Pacemaker Remote node %s %s",
             node_name, node_up? "coming up" : "going down");

    crm_xml_add(msg, PCMK_XA_ID, node_name);
    pcmk__xe_set_bool_attr(msg, PCMK__XA_IN_CCM, node_up);

    if (node_up) {
        crm_xml_add(msg, PCMK__XA_CONNECTION_HOST,
                    controld_globals.our_nodename);
    }

    send_cluster_message(NULL, crm_msg_crmd, msg, TRUE);
    free_xml(msg);
}

