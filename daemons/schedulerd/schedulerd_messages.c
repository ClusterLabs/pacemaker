/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pacemaker-schedulerd.h"

static GHashTable *schedulerd_handlers = NULL;

static pcmk_scheduler_t *
init_scheduler(void)
{
    pcmk_scheduler_t *scheduler = pcmk_new_scheduler();

    pcmk__mem_assert(scheduler);
    scheduler->priv->out = logger_out;
    return scheduler;
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
        { "pe-error", PCMK_OPT_PE_ERROR_SERIES_MAX, -1 },
        { "pe-warn",  PCMK_OPT_PE_WARN_SERIES_MAX, 5000 },
        { "pe-input", PCMK_OPT_PE_INPUT_SERIES_MAX, 4000 },
    };

    xmlNode *msg = request->xml;
    xmlNode *wrapper = pcmk__xe_first_child(msg, PCMK__XE_CRM_XML, NULL, NULL);
    xmlNode *xml_data = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    static char *last_digest = NULL;
    static char *filename = NULL;

    unsigned int seq = 0U;
    int series_id = 0;
    int series_wrap = 0;
    char *digest = NULL;
    const char *value = NULL;
    time_t execution_date = time(NULL);
    xmlNode *converted = NULL;
    xmlNode *reply = NULL;
    bool is_repoke = false;
    bool process = true;
    pcmk_scheduler_t *scheduler = init_scheduler();

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       PCMK__XE_ACK, NULL, CRM_EX_INDETERMINATE);

    digest = pcmk__digest_xml(xml_data, false);
    converted = pcmk__xml_copy(NULL, xml_data);
    if (pcmk__update_configured_schema(&converted, true) != pcmk_rc_ok) {
        scheduler->priv->graph = pcmk__xe_create(NULL,
                                                 PCMK__XE_TRANSITION_GRAPH);
        crm_xml_add_int(scheduler->priv->graph, "transition_id", 0);
        crm_xml_add_int(scheduler->priv->graph, PCMK_OPT_CLUSTER_DELAY, 0);
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
        scheduler->input = converted;
        pcmk__set_scheduler_flags(scheduler,
                                  pcmk__sched_no_counts
                                  |pcmk__sched_show_utilization);
        cluster_status(scheduler);
        pcmk__schedule_actions(scheduler);

        // Don't free converted as part of scheduler
        scheduler->input = NULL;
    }

    // Get appropriate index into series[] array
    if (pcmk_is_set(scheduler->flags, pcmk__sched_processing_error)
        || pcmk__config_has_error) {
        series_id = 0;
    } else if (pcmk_is_set(scheduler->flags, pcmk__sched_processing_warning)
               || pcmk__config_has_warning) {
        series_id = 1;
    } else {
        series_id = 2;
    }

    value = pcmk__cluster_option(scheduler->priv->options,
                                 series[series_id].param);
    if ((value == NULL)
        || (pcmk__scan_min_int(value, &series_wrap, -1) != pcmk_rc_ok)) {
        series_wrap = series[series_id].wrap;
    }

    if (pcmk__read_series_sequence(PCMK_SCHEDULER_INPUT_DIR, series[series_id].name,
                                   &seq) != pcmk_rc_ok) {
        // @TODO maybe handle errors better ...
        seq = 0U;
    }
    crm_trace("Series %s: wrap=%d, seq=%u, pref=%s",
              series[series_id].name, series_wrap, seq, value);

    reply = pcmk__new_reply(msg, scheduler->priv->graph);

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
        filename = pcmk__series_filename(PCMK_SCHEDULER_INPUT_DIR,
                                         series[series_id].name, seq, true);
    }

    crm_xml_add(reply, PCMK__XA_CRM_TGRAPH_IN, filename);

    pcmk__log_transition_summary(scheduler, filename);

    if (series_wrap == 0) {
        crm_debug("Not saving input to disk (disabled by configuration)");

    } else if (is_repoke) {
        crm_info("Input has not changed since last time, not saving to disk");

    } else {
        unlink(filename);
        crm_xml_add_ll(xml_data, PCMK_XA_EXECUTION_DATE,
                       (long long) execution_date);
        pcmk__xml_write_file(xml_data, filename, true);
        pcmk__write_series_sequence(PCMK_SCHEDULER_INPUT_DIR, series[series_id].name,
                                    ++seq, series_wrap);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

done:
    pcmk__xml_free(converted);
    pcmk_free_scheduler(scheduler);

    return reply;
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       PCMK__XE_ACK, NULL, CRM_EX_INVALID_PARAM);

    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown IPC request type '%s' (bug?)",
                        pcmk__client_name(request->ipc_client));
    return NULL;
}

static xmlNode *
handle_hello_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       PCMK__XE_ACK, NULL, CRM_EX_INDETERMINATE);

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
        return -ENOMEM;
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
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    sys_to = crm_element_value(msg, PCMK__XA_CRM_SYS_TO);

    if (pcmk__str_eq(crm_element_value(msg, PCMK__XA_SUBT),
                     PCMK__VALUE_RESPONSE, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
        crm_info("Ignoring IPC reply from %s", pcmk__client_name(c));

    } else if (!pcmk__str_eq(sys_to, CRM_SYSTEM_PENGINE, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
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

        request.op = crm_element_value_copy(request.xml, PCMK__XA_CRM_TASK);
        CRM_CHECK(request.op != NULL, return 0);

        reply = pcmk__process_request(&request, schedulerd_handlers);

        if (reply != NULL) {
            pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event);
            pcmk__xml_free(reply);
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

    pcmk__xml_free(msg);
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
