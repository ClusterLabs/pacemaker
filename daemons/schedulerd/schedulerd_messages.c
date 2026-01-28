/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                    // true, false, bool
#include <stdlib.h>                     // NULL, free
#include <sys/types.h>                  // time_t
#include <time.h>                       // time
#include <unistd.h>                     // unlink

#include <glib.h>                       // g_hash_table_destroy
#include <libxml/tree.h>                // xmlNode

#include <crm_config.h>                 // PCMK_SCHEDULER_INPUT_DIR
#include <crm/crm.h>                    // CRM_OP_HELLO, CRM_OP_PECALC
#include <crm/common/ipc.h>             // crm_ipc_flags
#include <crm/common/options.h>         // PCMK_OPT_CLUSTER_DELAY
#include <crm/common/results.h>         // crm_exit_e, pcmk_exec_status_str, pcmk_rc_*
#include <crm/common/scheduler.h>       // pcmk__scheduler, pcmk_free_scheduler
#include <crm/common/scheduler_types.h> // pcmk_scheduler_t
#include <crm/common/xml_names.h>       // PCMK_XA_EXECUTION_DATE
#include <pacemaker-internal.h>         // pcmk__schedule_actions

#include "pacemaker-schedulerd.h"       // logger_out, schedulerd_*

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
                       NULL, CRM_EX_INDETERMINATE);

    digest = pcmk__digest_xml(xml_data, false);
    converted = pcmk__xml_copy(NULL, xml_data);
    if (pcmk__update_configured_schema(&converted, true) != pcmk_rc_ok) {
        scheduler->priv->graph = pcmk__xe_create(NULL,
                                                 PCMK__XE_TRANSITION_GRAPH);
        pcmk__xe_set_int(scheduler->priv->graph, "transition_id", 0);
        pcmk__xe_set_int(scheduler->priv->graph, PCMK_OPT_CLUSTER_DELAY, 0);
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
        pcmk__schedule_actions(scheduler);

        // Don't free converted as part of scheduler
        scheduler->input = NULL;
    }

    // Get appropriate index into series[] array
    if (pcmk__is_set(scheduler->flags, pcmk__sched_processing_error)
        || pcmk__config_has_error) {
        series_id = 0;
    } else if (pcmk__is_set(scheduler->flags, pcmk__sched_processing_warning)
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
    pcmk__trace("Series %s: wrap=%d, seq=%u, pref=%s", series[series_id].name,
                series_wrap, seq, value);

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

    pcmk__xe_set(reply, PCMK__XA_CRM_TGRAPH_IN, filename);

    pcmk__log_transition_summary(scheduler, filename);

    if (series_wrap == 0) {
        pcmk__debug("Not saving input to disk (disabled by configuration)");

    } else if (is_repoke) {
        pcmk__info("Input has not changed since last time, not saving to disk");

    } else {
        unlink(filename);
        pcmk__xe_set_time(xml_data, PCMK_XA_EXECUTION_DATE, execution_date);
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
                       NULL, CRM_EX_PROTOCOL);

    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)",
                        pcmk__s(request->op, ""));
    return NULL;
}

static xmlNode *
handle_hello_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       NULL, CRM_EX_INDETERMINATE);

    pcmk__trace("Received IPC hello from %s",
                pcmk__client_name(request->ipc_client));

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

void
schedulerd_unregister_handlers(void)
{
    if (schedulerd_handlers != NULL) {
        g_hash_table_destroy(schedulerd_handlers);
        schedulerd_handlers = NULL;
    }
}

void
schedulerd_handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    char *log_msg = NULL;
    const char *exec_status_s = NULL;
    const char *reason = NULL;

    if (schedulerd_handlers == NULL) {
        schedulerd_register_handlers();
    }

    reply = pcmk__process_request(request, schedulerd_handlers);

    if (reply != NULL) {
        pcmk__log_xml_trace(reply, "Reply");

        pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                           crm_ipc_server_event);
        pcmk__xml_free(reply);
    }

    exec_status_s = pcmk_exec_status_str(request->result.execution_status);
    reason = request->result.exit_reason;

    log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: %s%s%s%s",
                                    request->op,
                                    pcmk__request_origin_type(request),
                                    pcmk__request_origin(request),
                                    exec_status_s,
                                    (reason == NULL)? "" : " (",
                                    pcmk__s(reason, ""),
                                    (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        pcmk__warn("%s", log_msg);
    } else {
        pcmk__debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}
