/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pacemaker-schedulerd.h"

static GHashTable *schedulerd_handlers = NULL;

static pe_working_set_t *
init_working_set(void)
{
    pe_working_set_t *data_set = pe_new_working_set();

    CRM_ASSERT(data_set != NULL);

    crm_config_error = FALSE;
    crm_config_warning = FALSE;

    was_processing_error = FALSE;
    was_processing_warning = FALSE;

    data_set->priv = logger_out;
    return data_set;
}

static xmlNode *
handle_pecalc_request(pcmk__request_t *request)
{
    static struct series_s {
        const char *name;
        const char *param;

        /* Maximum number of inputs of this kind to save to disk.
         * If -1, save all; if 0, save none.
         */
        int wrap;
    } series[] = {
        { "pe-error", "pe-error-series-max", -1 },
        { "pe-warn",  "pe-warn-series-max",  5000 },
        { "pe-input", "pe-input-series-max", 4000 },
    };

    xmlNode *msg = request->xml;
    xmlNode *xml_data = get_message_xml(msg, F_CRM_DATA);

    static char *last_digest = NULL;
    static char *filename = NULL;

    unsigned int seq;
    int series_id = 0;
    int series_wrap = 0;
    char *digest = NULL;
    const char *value = NULL;
    time_t execution_date = time(NULL);
    xmlNode *converted = NULL;
    xmlNode *reply = NULL;
    bool is_repoke = false;
    bool process = true;
    pe_working_set_t *data_set = init_working_set();

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_INDETERMINATE);

    digest = calculate_xml_versioned_digest(xml_data, FALSE, FALSE,
                                            CRM_FEATURE_SET);
    converted = copy_xml(xml_data);
    if (!cli_config_update(&converted, NULL, TRUE)) {
        data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);
        crm_xml_add_int(data_set->graph, "transition_id", 0);
        crm_xml_add_int(data_set->graph, "cluster-delay", 0);
        process = false;
        free(digest);

    } else if (pcmk__str_eq(digest, last_digest, pcmk__str_casei)) {
        is_repoke = true;
        free(digest);

    } else {
        free(last_digest);
        last_digest = digest;
    }

    if (process) {
        pcmk__schedule_actions(converted,
                               pe_flag_no_counts
                               |pe_flag_no_compat
                               |pe_flag_show_utilization, data_set);
    }

    // Get appropriate index into series[] array
    if (was_processing_error) {
        series_id = 0;
    } else if (was_processing_warning) {
        series_id = 1;
    } else {
        series_id = 2;
    }

    value = pe_pref(data_set->config_hash, series[series_id].param);
    if ((value == NULL)
        || (pcmk__scan_min_int(value, &series_wrap, -1) != pcmk_rc_ok)) {
        series_wrap = series[series_id].wrap;
    }

    if (pcmk__read_series_sequence(PE_STATE_DIR, series[series_id].name,
                                   &seq) != pcmk_rc_ok) {
        // @TODO maybe handle errors better ...
        seq = 0;
    }
    crm_trace("Series %s: wrap=%d, seq=%u, pref=%s",
              series[series_id].name, series_wrap, seq, value);

    data_set->input = NULL;
    reply = create_reply(msg, data_set->graph);

    if (reply == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Failed building ping reply for client %s",
                            pcmk__client_name(request->ipc_client));
        goto done;
    }

    if (series_wrap == 0) { // Don't save any inputs of this kind
        free(filename);
        filename = NULL;

    } else if (!is_repoke) { // Input changed, save to disk
        free(filename);
        filename = pcmk__series_filename(PE_STATE_DIR,
                                         series[series_id].name, seq, true);
    }

    crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
    crm_xml_add_int(reply, PCMK__XA_GRAPH_ERRORS, was_processing_error);
    crm_xml_add_int(reply, PCMK__XA_GRAPH_WARNINGS, was_processing_warning);
    crm_xml_add_int(reply, PCMK__XA_CONFIG_ERRORS, crm_config_error);
    crm_xml_add_int(reply, PCMK__XA_CONFIG_WARNINGS, crm_config_warning);

    pcmk__log_transition_summary(filename);

    if (series_wrap == 0) {
        crm_debug("Not saving input to disk (disabled by configuration)");

    } else if (is_repoke) {
        crm_info("Input has not changed since last time, not saving to disk");

    } else {
        unlink(filename);
        crm_xml_add_ll(xml_data, "execution-date", (long long) execution_date);
        write_xml_file(xml_data, filename, TRUE);
        pcmk__write_series_sequence(PE_STATE_DIR, series[series_id].name,
                                    ++seq, series_wrap);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

done:
    free_xml(converted);
    pe_free_working_set(data_set);

    return reply;
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_INVALID_PARAM);

    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown IPC request type '%s' (bug?)",
                        pcmk__client_name(request->ipc_client));
    return NULL;
}

static xmlNode *
handle_hello_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_INDETERMINATE);

    crm_trace("Received IPC hello from %s", pcmk__client_name(request->ipc_client));

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static void
schedulerd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_HELLO, handle_hello_request },
        { CRM_OP_PECALC, handle_pecalc_request },
        { NULL, handle_unknown_request },
    };

    schedulerd_handlers = pcmk__register_handlers(handlers);
}

static int32_t
pe_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static int32_t
pe_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    xmlNode *msg = NULL;
    pcmk__client_t *c = pcmk__find_client(qbc);
    const char *sys_to = NULL;

    CRM_CHECK(c != NULL, return 0);

    if (schedulerd_handlers == NULL) {
        schedulerd_register_handlers();
    }

    msg = pcmk__client_data2xml(c, data, &id, &flags);
    if (msg == NULL) {
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    sys_to = crm_element_value(msg, F_CRM_SYS_TO);

    if (pcmk__str_eq(crm_element_value(msg, F_CRM_MSG_TYPE),
                            XML_ATTR_RESPONSE, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_INDETERMINATE);
        crm_info("Ignoring IPC reply from %s", pcmk__client_name(c));

    } else if (!pcmk__str_eq(sys_to, CRM_SYSTEM_PENGINE, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_INDETERMINATE);
        crm_info("Ignoring invalid IPC message: to '%s' not "
                 CRM_SYSTEM_PENGINE, pcmk__s(sys_to, ""));

    } else {
        char *log_msg = NULL;
        const char *reason = NULL;
        xmlNode *reply = NULL;

        pcmk__request_t request = {
            .ipc_client     = c,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = NULL,
            .xml            = msg,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = crm_element_value_copy(request.xml, F_CRM_TASK);
        CRM_CHECK(request.op != NULL, return 0);

        reply = pcmk__process_request(&request, schedulerd_handlers);

        if (reply != NULL) {
            pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event);
            free_xml(reply);
        }

        reason = request.result.exit_reason;

        log_msg = crm_strdup_printf("Processed %s request from %s %s: %s%s%s%s",
                                    request.op, pcmk__request_origin_type(&request),
                                    pcmk__request_origin(&request),
                                    pcmk_exec_status_str(request.result.execution_status),
                                    (reason == NULL)? "" : " (",
                                    (reason == NULL)? "" : reason,
                                    (reason == NULL)? "" : ")");

        if (!pcmk__result_ok(&request.result)) {
            crm_warn("%s", log_msg);
        } else {
            crm_debug("%s", log_msg);
        }

        free(log_msg);
        pcmk__reset_request(&request);
    }

    free_xml(msg);
    return 0;
}

/* Error code means? */
static int32_t
pe_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    pcmk__free_client(client);
    return 0;
}

static void
pe_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
    pe_ipc_closed(c);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = pe_ipc_accept,
    .connection_created = NULL,
    .msg_process = pe_ipc_dispatch,
    .connection_closed = pe_ipc_closed,
    .connection_destroyed = pe_ipc_destroy
};
