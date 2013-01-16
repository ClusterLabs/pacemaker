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
#include <crm/crm.h>
#include <string.h>
#include <time.h>
#include <crmd_fsa.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cluster/internal.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_lrm.h>

GListPtr fsa_message_queue = NULL;
extern void crm_shutdown(int nsig);

void handle_response(xmlNode * stored_msg);
enum crmd_fsa_input handle_request(xmlNode * stored_msg);
enum crmd_fsa_input handle_shutdown_request(xmlNode * stored_msg);

#ifdef MSG_LOG
#  define ROUTER_RESULT(x)	crm_trace("Router result: %s", x);	\
    crm_log_xml_trace(msg, "router.log");
#else
#  define ROUTER_RESULT(x)	crm_trace("Router result: %s", x)
#endif
/* debug only, can wrap all it likes */
int last_data_id = 0;

void
register_fsa_error_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                       fsa_data_t * cur_data, void *new_data, const char *raised_from)
{
    /* save the current actions if any */
    if (fsa_actions != A_NOTHING) {
        register_fsa_input_adv(cur_data ? cur_data->fsa_cause : C_FSA_INTERNAL,
                               I_NULL, cur_data ? cur_data->data : NULL,
                               fsa_actions, TRUE, __FUNCTION__);
    }

    /* reset the action list */
    fsa_actions = A_NOTHING;

    /* register the error */
    register_fsa_input_adv(cause, input, new_data, A_NOTHING, TRUE, raised_from);
}

int
register_fsa_input_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                       void *data, long long with_actions,
                       gboolean prepend, const char *raised_from)
{
    unsigned old_len = g_list_length(fsa_message_queue);
    fsa_data_t *fsa_data = NULL;

    last_data_id++;
    CRM_CHECK(raised_from != NULL, raised_from = "<unknown>");

    crm_trace("%s %s FSA input %d (%s) (cause=%s) %s data",
                raised_from, prepend ? "prepended" : "appended", last_data_id,
                fsa_input2string(input), fsa_cause2string(cause), data ? "with" : "without");

    if (input == I_WAIT_FOR_EVENT) {
        do_fsa_stall = TRUE;
        crm_debug("Stalling the FSA pending further input: cause=%s", fsa_cause2string(cause));
        if (old_len > 0) {
            crm_warn("%s stalled the FSA with pending inputs", raised_from);
            fsa_dump_queue(LOG_DEBUG);
            crm_write_blackbox(0, NULL);
            prepend = FALSE;
        }
        if (data == NULL) {
            set_bit(fsa_actions, with_actions);
            with_actions = A_NOTHING;
            return 0;
        }
        crm_debug("%s stalled the FSA with data - this may be broken", raised_from);
    }

    if (input == I_NULL && with_actions == A_NOTHING /* && data == NULL */ ) {
        /* no point doing anything */
        crm_err("Cannot add entry to queue: no input and no action");
        return 0;
    }

    fsa_data = calloc(1, sizeof(fsa_data_t));
    fsa_data->id = last_data_id;
    fsa_data->fsa_input = input;
    fsa_data->fsa_cause = cause;
    fsa_data->origin = raised_from;
    fsa_data->data = NULL;
    fsa_data->data_type = fsa_dt_none;
    fsa_data->actions = with_actions;

    if (with_actions != A_NOTHING) {
        crm_trace("Adding actions %.16llx to input", with_actions);
    }

    if (data != NULL) {
        switch (cause) {
            case C_FSA_INTERNAL:
            case C_CRMD_STATUS_CALLBACK:
            case C_IPC_MESSAGE:
            case C_HA_MESSAGE:
                crm_trace("Copying %s data from %s as a HA msg",
                            fsa_cause2string(cause), raised_from);
                CRM_CHECK(((ha_msg_input_t *) data)->msg != NULL,
                          crm_err("Bogus data from %s", raised_from));
                fsa_data->data = copy_ha_msg_input(data);
                fsa_data->data_type = fsa_dt_ha_msg;
                break;

            case C_LRM_OP_CALLBACK:
                crm_trace("Copying %s data from %s as lrmd_event_data_t",
                            fsa_cause2string(cause), raised_from);
                fsa_data->data = lrmd_copy_event((lrmd_event_data_t *) data);
                fsa_data->data_type = fsa_dt_lrm;
                break;

            case C_CCM_CALLBACK:
            case C_SUBSYSTEM_CONNECT:
            case C_LRM_MONITOR_CALLBACK:
            case C_TIMER_POPPED:
            case C_SHUTDOWN:
            case C_HEARTBEAT_FAILED:
            case C_HA_DISCONNECT:
            case C_ILLEGAL:
            case C_UNKNOWN:
            case C_STARTUP:
                crm_err("Copying %s data (from %s)"
                        " not yet implemented", fsa_cause2string(cause), raised_from);
                crmd_exit(1);
                break;
        }
        crm_trace("%s data copied", fsa_cause2string(fsa_data->fsa_cause));
    }

    /* make sure to free it properly later */
    if (prepend) {
        crm_trace("Prepending input");
        fsa_message_queue = g_list_prepend(fsa_message_queue, fsa_data);
    } else {
        fsa_message_queue = g_list_append(fsa_message_queue, fsa_data);
    }

    crm_trace("Queue len: %d", g_list_length(fsa_message_queue));

    /* fsa_dump_queue(LOG_DEBUG_2); */

    if (old_len == g_list_length(fsa_message_queue)) {
        crm_err("Couldnt add message to the queue");
    }

    if (fsa_source) {
        crm_trace("Triggering FSA: %s", __FUNCTION__);
        mainloop_set_trigger(fsa_source);
    }
    return last_data_id;
}

void
fsa_dump_queue(int log_level)
{
    int offset = 0;
    GListPtr lpc = NULL;

    for (lpc = fsa_message_queue; lpc != NULL; lpc = lpc->next) {
        fsa_data_t *data = (fsa_data_t *) lpc->data;

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
    ha_msg_input_t *copy = NULL;
    xmlNodePtr data = NULL;

    if (orig != NULL) {
        crm_trace("Copy msg");
        data = copy_xml(orig->msg);

    } else {
        crm_trace("No message to copy");
    }
    copy = new_ha_msg_input(data);
    if (orig && orig->msg != NULL) {
        CRM_CHECK(copy->msg != NULL, crm_err("copy failed"));
    }
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
                    crm_err("Dont know how to free %s data from %s",
                            fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
                    crmd_exit(1);
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
    fsa_data_t *message = g_list_nth_data(fsa_message_queue, 0);

    fsa_message_queue = g_list_remove(fsa_message_queue, message);
    crm_trace("Processing input %d", message->id);
    return message;
}

/* returns the current head of the FIFO queue */
gboolean
is_message(void)
{
    return (g_list_length(fsa_message_queue) > 0);
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
    result = handle_message(input);

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
    int dest = 1;
    int is_for_dc = 0;
    int is_for_dcib = 0;
    int is_for_te = 0;
    int is_for_crm = 0;
    int is_for_cib = 0;
    int is_local = 0;
    gboolean processing_complete = FALSE;
    const char *host_to = crm_element_value(msg, F_CRM_HOST_TO);
    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);
    const char *type = crm_element_value(msg, F_TYPE);
    const char *msg_error = NULL;

    crm_trace("Routing message %s", crm_element_value(msg, XML_ATTR_REFERENCE));

    if (msg == NULL) {
        msg_error = "Cannot route empty message";

    } else if (safe_str_eq(CRM_OP_HELLO, crm_element_value(msg, F_CRM_TASK))) {
        /* quietly ignore */
        processing_complete = TRUE;

    } else if (safe_str_neq(type, T_CRM)) {
        msg_error = "Bad message type";

    } else if (sys_to == NULL) {
        msg_error = "Bad message destination: no subsystem";
    }

    if (msg_error != NULL) {
        processing_complete = TRUE;
        crm_err("%s", msg_error);
        crm_log_xml_warn(msg, "bad msg");
    }

    if (processing_complete) {
        return TRUE;
    }

    processing_complete = TRUE;

    is_for_dc = (strcasecmp(CRM_SYSTEM_DC, sys_to) == 0);
    is_for_dcib = (strcasecmp(CRM_SYSTEM_DCIB, sys_to) == 0);
    is_for_te = (strcasecmp(CRM_SYSTEM_TENGINE, sys_to) == 0);
    is_for_cib = (strcasecmp(CRM_SYSTEM_CIB, sys_to) == 0);
    is_for_crm = (strcasecmp(CRM_SYSTEM_CRMD, sys_to) == 0);

    is_local = 0;
    if (host_to == NULL || strlen(host_to) == 0) {
        if (is_for_dc || is_for_te) {
            is_local = 0;

        } else if (is_for_crm && originated_locally) {
            is_local = 0;

        } else {
            is_local = 1;
        }

    } else if (safe_str_eq(fsa_our_uname, host_to)) {
        is_local = 1;
    }

    if (is_for_dc || is_for_dcib || is_for_te) {
        if (AM_I_DC && is_for_te) {
            ROUTER_RESULT("Message result: Local relay");
            send_msg_via_ipc(msg, sys_to);

        } else if (AM_I_DC) {
            ROUTER_RESULT("Message result: DC/CRMd process");
            processing_complete = FALSE;        /* more to be done by caller */
        } else if (originated_locally && safe_str_neq(sys_from, CRM_SYSTEM_PENGINE)
                   && safe_str_neq(sys_from, CRM_SYSTEM_TENGINE)) {

            /* Neither the TE or PE should be sending messages
             *   to DC's on other nodes
             *
             * By definition, if we are no longer the DC, then
             *   the PE or TE's data should be discarded
             */

#if SUPPORT_COROSYNC
            if (is_openais_cluster()) {
                dest = text2msg_type(sys_to);
            }
#endif
            ROUTER_RESULT("Message result: External relay to DC");
            send_cluster_message(host_to ? crm_get_peer(0, host_to) : NULL, dest, msg, TRUE);

        } else {
            /* discard */
            ROUTER_RESULT("Message result: Discard, not DC");
        }

    } else if (is_local && (is_for_crm || is_for_cib)) {
        ROUTER_RESULT("Message result: CRMd process");
        processing_complete = FALSE;    /* more to be done by caller */

    } else if (is_local) {
        ROUTER_RESULT("Message result: Local relay");
        send_msg_via_ipc(msg, sys_to);

    } else {
#if SUPPORT_COROSYNC
        if (is_openais_cluster()) {
            dest = text2msg_type(sys_to);
        }
#endif
        ROUTER_RESULT("Message result: External relay");
        send_cluster_message(host_to ? crm_get_peer(0, host_to) : NULL, dest, msg, TRUE);
    }

    return processing_complete;
}

static gboolean
process_hello_message(xmlNode * hello,
                      char **uuid, char **client_name, char **major_version, char **minor_version)
{
    const char *local_uuid;
    const char *local_client_name;
    const char *local_major_version;
    const char *local_minor_version;

    *uuid = NULL;
    *client_name = NULL;
    *major_version = NULL;
    *minor_version = NULL;

    if (hello == NULL) {
        return FALSE;
    }

    local_uuid = crm_element_value(hello, "client_uuid");
    local_client_name = crm_element_value(hello, "client_name");
    local_major_version = crm_element_value(hello, "major_version");
    local_minor_version = crm_element_value(hello, "minor_version");

    if (local_uuid == NULL || strlen(local_uuid) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "uuid");
        return FALSE;

    } else if (local_client_name == NULL || strlen(local_client_name) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "client name");
        return FALSE;

    } else if (local_major_version == NULL || strlen(local_major_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "major version");
        return FALSE;

    } else if (local_minor_version == NULL || strlen(local_minor_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "minor version");
        return FALSE;
    }

    *uuid = strdup(local_uuid);
    *client_name = strdup(local_client_name);
    *major_version = strdup(local_major_version);
    *minor_version = strdup(local_minor_version);

    crm_trace("Hello message ok");
    return TRUE;
}

gboolean
crmd_authorize_message(xmlNode * client_msg, crmd_client_t * curr_client)
{
    /* check the best case first */
    const char *sys_from = crm_element_value(client_msg, F_CRM_SYS_FROM);
    char *uuid = NULL;
    char *client_name = NULL;
    char *major_version = NULL;
    char *minor_version = NULL;
    const char *filtered_from;
    gpointer table_key = NULL;
    gboolean auth_result = FALSE;
    gboolean can_reply = FALSE; /* no-one has registered with this id */

    xmlNode *xml = NULL;
    const char *op = crm_element_value(client_msg, F_CRM_TASK);

    if (safe_str_neq(CRM_OP_HELLO, op)) {

        if (sys_from == NULL) {
            crm_warn("Message [%s] was had no value for %s... discarding",
                     crm_element_value(client_msg, XML_ATTR_REFERENCE), F_CRM_SYS_FROM);
            return FALSE;
        }

        filtered_from = sys_from;

        /* The CIB can have two names on the DC */
        if (strcasecmp(sys_from, CRM_SYSTEM_DCIB) == 0)
            filtered_from = CRM_SYSTEM_CIB;

        if (g_hash_table_lookup(ipc_clients, filtered_from) != NULL) {
            can_reply = TRUE;   /* reply can be routed */
        }

        crm_trace("Message reply can%s be routed from %s.", can_reply ? "" : " not", sys_from);

        if (can_reply == FALSE) {
            crm_warn("Message [%s] not authorized",
                     crm_element_value(client_msg, XML_ATTR_REFERENCE));
        }

        return can_reply;
    }

    crm_trace("received client join msg");
    crm_log_xml_trace(client_msg, "join");
    xml = get_message_xml(client_msg, F_CRM_DATA);
    auth_result = process_hello_message(xml, &uuid, &client_name, &major_version, &minor_version);

    if (auth_result == TRUE) {
        if (client_name == NULL || uuid == NULL) {
            crm_err("Bad client details (client_name=%s, uuid=%s)",
                    crm_str(client_name), crm_str(uuid));
            auth_result = FALSE;
        }
    }

    if (auth_result == TRUE) {
        /* check version */
        int mav = atoi(major_version);
        int miv = atoi(minor_version);

        crm_trace("Checking client version number");
        if (mav < 0 || miv < 0) {
            crm_err("Client version (%d:%d) is not acceptable", mav, miv);
            auth_result = FALSE;
        }
    }

    table_key = (gpointer) generate_hash_key(client_name, uuid);

    if (auth_result == TRUE) {
        crm_trace("Accepted client %s", crm_str(table_key));

        curr_client->table_key = table_key;
        curr_client->sub_sys = strdup(client_name);
        curr_client->uuid = strdup(uuid);

        g_hash_table_insert(ipc_clients, table_key, curr_client->ipc);
        crm_trace("Updated client list with %s", crm_str(table_key));

        crm_trace("Triggering FSA: %s", __FUNCTION__);
        mainloop_set_trigger(fsa_source);

    } else {
        free(table_key);
        crm_warn("Rejected client logon request");
        qb_ipcs_disconnect(curr_client->ipc);
    }

    free(uuid);
    free(minor_version);
    free(major_version);
    free(client_name);

    /* hello messages should never be processed further */
    return FALSE;
}

enum crmd_fsa_input
handle_message(xmlNode * msg)
{
    const char *type = NULL;

    CRM_CHECK(msg != NULL, return I_NULL);

    type = crm_element_value(msg, F_CRM_MSG_TYPE);
    if (crm_str_eq(type, XML_ATTR_REQUEST, TRUE)) {
        return handle_request(msg);

    } else if (crm_str_eq(type, XML_ATTR_RESPONSE, TRUE)) {
        handle_response(msg);
        return I_NULL;
    }

    crm_err("Unknown message type: %s", type);
    return I_NULL;
}

static enum crmd_fsa_input
handle_failcount_op(xmlNode * stored_msg)
{
    const char *rsc = NULL;
    xmlNode *xml_rsc = get_xpath_object("//" XML_CIB_TAG_RESOURCE, stored_msg, LOG_ERR);

    if (xml_rsc) {
        rsc = ID(xml_rsc);
    }

    if (rsc) {
        char *attr = NULL;

        crm_info("Removing failcount for %s", rsc);

        attr = crm_concat("fail-count", rsc, '-');
        update_attrd(NULL, attr, NULL, NULL);
        free(attr);

        attr = crm_concat("last-failure", rsc, '-');
        update_attrd(NULL, attr, NULL, NULL);
        free(attr);

        lrm_clear_last_failure(rsc);
    } else {
        crm_log_xml_warn(stored_msg, "invalid failcount op");
    }

    return I_NULL;
}

enum crmd_fsa_input
handle_request(xmlNode * stored_msg)
{
    xmlNode *msg = NULL;
    const char *op = crm_element_value(stored_msg, F_CRM_TASK);

    /* Optimize this for the DC - it has the most to do */

    if (op == NULL) {
        crm_log_xml_err(stored_msg, "Bad message");
        return I_NULL;
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
            const char *host_from = crm_element_value(stored_msg, F_CRM_HOST_FROM);
            gboolean dc_match = safe_str_eq(host_from, fsa_our_dc);

            if (is_set(fsa_input_register, R_SHUTDOWN)) {
                crm_info("Shutting ourselves down (DC)");
                return I_STOP;

            } else if (dc_match) {
                crm_err("We didnt ask to be shut down, yet our"
                        " TE is telling us too." " Better get out now!");
                return I_TERMINATE;

            } else if (fsa_state != S_STOPPING) {
                crm_err("Another node is asking us to shutdown" " but we think we're ok.");
                return I_ELECTION;
            }

        } else if (strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
            /* a slave wants to shut down */
            /* create cib fragment and add to message */
            return handle_shutdown_request(stored_msg);
        }
    }

    /*========== common actions ==========*/
    if (strcmp(op, CRM_OP_NOVOTE) == 0) {
        ha_msg_input_t fsa_input;

        fsa_input.msg = stored_msg;
        register_fsa_input_adv(C_HA_MESSAGE, I_NULL, &fsa_input,
                               A_ELECTION_COUNT | A_ELECTION_CHECK, FALSE, __FUNCTION__);

    } else if (strcmp(op, CRM_OP_CLEAR_FAILCOUNT) == 0) {
        return handle_failcount_op(stored_msg);

    } else if (strcmp(op, CRM_OP_VOTE) == 0) {
        /* count the vote and decide what to do after that */
        ha_msg_input_t fsa_input;

        fsa_input.msg = stored_msg;
        register_fsa_input_adv(C_HA_MESSAGE, I_NULL, &fsa_input,
                               A_ELECTION_COUNT | A_ELECTION_CHECK, FALSE, __FUNCTION__);

        /* Sometimes we _must_ go into S_ELECTION */
        if (fsa_state == S_HALT) {
            crm_debug("Forcing an election from S_HALT");
            return I_ELECTION;
#if 0
        } else if (AM_I_DC) {
            /* This is the old way of doing things but what is gained? */
            return I_ELECTION;
#endif
        }

    } else if (strcmp(op, CRM_OP_JOIN_OFFER) == 0) {
        crm_debug("Raising I_JOIN_OFFER: join-%s", crm_element_value(stored_msg, F_CRM_JOIN_ID));
        return I_JOIN_OFFER;

    } else if (strcmp(op, CRM_OP_JOIN_ACKNAK) == 0) {
        crm_debug("Raising I_JOIN_RESULT: join-%s", crm_element_value(stored_msg, F_CRM_JOIN_ID));
        return I_JOIN_RESULT;

    } else if (strcmp(op, CRM_OP_LRM_DELETE) == 0
               || strcmp(op, CRM_OP_LRM_FAIL) == 0
               || strcmp(op, CRM_OP_LRM_REFRESH) == 0 || strcmp(op, CRM_OP_REPROBE) == 0) {

        crm_xml_add(stored_msg, F_CRM_SYS_TO, CRM_SYSTEM_LRMD);
        return I_ROUTER;

    } else if (strcmp(op, CRM_OP_NOOP) == 0) {
        return I_NULL;

    } else if (strcmp(op, CRM_OP_LOCAL_SHUTDOWN) == 0) {

        crm_shutdown(SIGTERM);
        /*return I_SHUTDOWN; */
        return I_NULL;

        /*========== (NOT_DC)-Only Actions ==========*/
    } else if (AM_I_DC == FALSE && strcmp(op, CRM_OP_SHUTDOWN) == 0) {

        const char *host_from = crm_element_value(stored_msg, F_CRM_HOST_FROM);
        gboolean dc_match = safe_str_eq(host_from, fsa_our_dc);

        if (dc_match || fsa_our_dc == NULL) {
            if (is_set(fsa_input_register, R_SHUTDOWN) == FALSE) {
                crm_err("We didn't ask to be shut down, yet our" " DC is telling us too.");
                set_bit(fsa_input_register, R_STAYDOWN);
                return I_STOP;
            }
            crm_info("Shutting down");
            return I_STOP;

        } else {
            crm_warn("Discarding %s op from %s", op, host_from);
        }

    } else if (strcmp(op, CRM_OP_PING) == 0) {
        /* eventually do some stuff to figure out
         * if we /are/ ok
         */
        const char *sys_to = crm_element_value(stored_msg, F_CRM_SYS_TO);
        xmlNode *ping = create_xml_node(NULL, XML_CRM_TAG_PING);

        crm_xml_add(ping, XML_PING_ATTR_STATUS, "ok");
        crm_xml_add(ping, XML_PING_ATTR_SYSFROM, sys_to);
        crm_xml_add(ping, "crmd_state", fsa_state2string(fsa_state));

        /* Ok, so technically not so interesting, but CTS needs to see this */
        crm_notice("Current ping state: %s", fsa_state2string(fsa_state));

        msg = create_reply(stored_msg, ping);
        relay_message(msg, TRUE);

        free_xml(ping);
        free_xml(msg);

    } else if (strcmp(op, CRM_OP_RM_NODE_CACHE) == 0) {
        int id = 0;
        const char *name = NULL;
        xmlNode *options = get_xpath_object("//"XML_TAG_OPTIONS, stored_msg, LOG_ERR);

        if (options) {
           crm_element_value_int(options, XML_ATTR_ID, &id);
           name = crm_element_value(options, XML_ATTR_UNAME);
        }

        reap_crm_member(id, name);

    } else {
        crm_err("Unexpected request (%s) sent to %s", op, AM_I_DC ? "the DC" : "non-DC node");
        crm_log_xml_err(stored_msg, "Unexpected");
    }

    return I_NULL;
}

void
handle_response(xmlNode * stored_msg)
{
    const char *op = crm_element_value(stored_msg, F_CRM_TASK);

    if (op == NULL) {
        crm_log_xml_err(stored_msg, "Bad message");

    } else if (AM_I_DC && strcmp(op, CRM_OP_PECALC) == 0) {
        /* Check if the PE answer been superceeded by a subsequent request? */
        const char *msg_ref = crm_element_value(stored_msg, XML_ATTR_REFERENCE);

        if (msg_ref == NULL) {
            crm_err("%s - Ignoring calculation with no reference", op);

        } else if (safe_str_eq(msg_ref, fsa_pe_ref)) {
            ha_msg_input_t fsa_input;

            fsa_input.msg = stored_msg;
            register_fsa_input_later(C_IPC_MESSAGE, I_PE_SUCCESS, &fsa_input);
            crm_trace("Completed: %s...", fsa_pe_ref);

        } else {
            crm_info("%s calculation %s is obsolete", op, msg_ref);
        }

    } else if (strcmp(op, CRM_OP_VOTE) == 0
               || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0 || strcmp(op, CRM_OP_SHUTDOWN) == 0) {

    } else {
        const char *host_from = crm_element_value(stored_msg, F_CRM_HOST_FROM);

        crm_err("Unexpected response (op=%s, src=%s) sent to the %s",
                op, host_from, AM_I_DC ? "DC" : "CRMd");
    }
}

enum crmd_fsa_input
handle_shutdown_request(xmlNode * stored_msg)
{
    /* handle here to avoid potential version issues
     *   where the shutdown message/proceedure may have
     *   been changed in later versions.
     *
     * This way the DC is always in control of the shutdown
     */

    char *now_s = NULL;
    time_t now = time(NULL);
    const char *host_from = crm_element_value(stored_msg, F_CRM_HOST_FROM);

    if (host_from == NULL) {
        /* we're shutting down and the DC */
        host_from = fsa_our_uname;
    }

    crm_info("Creating shutdown request for %s (state=%s)", host_from, fsa_state2string(fsa_state));
    crm_log_xml_trace(stored_msg, "message");

    now_s = crm_itoa(now);
    update_attrd(host_from, XML_CIB_ATTR_SHUTDOWN, now_s, NULL);
    free(now_s);

    /* will be picked up by the TE as long as its running */
    return I_NULL;
}

/* msg is deleted by the time this returns */
extern gboolean process_te_message(xmlNode * msg, xmlNode * xml_data);

gboolean
send_msg_via_ipc(xmlNode * msg, const char *sys)
{
    gboolean send_ok = TRUE;
    qb_ipcs_connection_t *client_channel;

    client_channel = (qb_ipcs_connection_t *) g_hash_table_lookup(ipc_clients, sys);

    if (crm_element_value(msg, F_CRM_HOST_FROM) == NULL) {
        crm_xml_add(msg, F_CRM_HOST_FROM, fsa_our_uname);
    }

    if (client_channel != NULL) {
        /* Transient clients such as crmadmin */
        send_ok = crm_ipcs_send(client_channel, 0, msg, TRUE);

    } else if (sys != NULL && strcmp(sys, CRM_SYSTEM_TENGINE) == 0) {
        xmlNode *data = get_message_xml(msg, F_CRM_DATA);

        process_te_message(msg, data);

    } else if (sys != NULL && strcmp(sys, CRM_SYSTEM_LRMD) == 0) {
        fsa_data_t fsa_data;
        ha_msg_input_t fsa_input;

        fsa_input.msg = msg;
        fsa_input.xml = get_message_xml(msg, F_CRM_DATA);

        fsa_data.id = 0;
        fsa_data.actions = 0;
        fsa_data.data = &fsa_input;
        fsa_data.fsa_input = I_MESSAGE;
        fsa_data.fsa_cause = C_IPC_MESSAGE;
        fsa_data.origin = __FUNCTION__;
        fsa_data.data_type = fsa_dt_ha_msg;

#ifdef FSA_TRACE
        crm_trace("Invoking action A_LRM_INVOKE (%.16llx)", A_LRM_INVOKE);
#endif
        do_lrm_invoke(A_LRM_INVOKE, C_IPC_MESSAGE, fsa_state, I_MESSAGE, &fsa_data);

    } else {
        crm_err("Unknown Sub-system (%s)... discarding message.", crm_str(sys));
        send_ok = FALSE;
    }

    return send_ok;
}

ha_msg_input_t *
new_ha_msg_input(xmlNode * orig)
{
    ha_msg_input_t *input_copy = NULL;

    input_copy = calloc(1, sizeof(ha_msg_input_t));
    input_copy->msg = orig;
    input_copy->xml = get_message_xml(input_copy->msg, F_CRM_DATA);
    return input_copy;
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

