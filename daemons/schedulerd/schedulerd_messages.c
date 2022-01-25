/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pacemaker-schedulerd.h"

static void
init_working_set(void)
{
    crm_config_error = FALSE;
    crm_config_warning = FALSE;

    was_processing_error = FALSE;
    was_processing_warning = FALSE;

    if (sched_data_set == NULL) {
        sched_data_set = pe_new_working_set();
        CRM_ASSERT(sched_data_set != NULL);
        pe__set_working_set_flags(sched_data_set,
                                  pe_flag_no_counts|pe_flag_no_compat);
        pe__set_working_set_flags(sched_data_set,
                                  pe_flag_show_utilization);
        sched_data_set->priv = logger_out;
    } else {
        pe_reset_working_set(sched_data_set);
    }
}

static void
handle_pecalc_op(xmlNode *msg, xmlNode *xml_data, pcmk__client_t *sender)
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

    init_working_set();

    digest = calculate_xml_versioned_digest(xml_data, FALSE, FALSE,
                                            CRM_FEATURE_SET);
    converted = copy_xml(xml_data);
    if (!cli_config_update(&converted, NULL, TRUE)) {
        sched_data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);
        crm_xml_add_int(sched_data_set->graph, "transition_id", 0);
        crm_xml_add_int(sched_data_set->graph, "cluster-delay", 0);
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
        pcmk__schedule_actions(converted, sched_data_set);
    }

    // Get appropriate index into series[] array
    if (was_processing_error) {
        series_id = 0;
    } else if (was_processing_warning) {
        series_id = 1;
    } else {
        series_id = 2;
    }

    value = pe_pref(sched_data_set->config_hash, series[series_id].param);
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

    sched_data_set->input = NULL;
    reply = create_reply(msg, sched_data_set->graph);
    CRM_ASSERT(reply != NULL);

    if (series_wrap == 0) { // Don't save any inputs of this kind
        free(filename);
        filename = NULL;

    } else if (!is_repoke) { // Input changed, save to disk
        free(filename);
        filename = pcmk__series_filename(PE_STATE_DIR,
                                         series[series_id].name, seq, true);
    }

    crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
    crm_xml_add_int(reply, "graph-errors", was_processing_error);
    crm_xml_add_int(reply, "graph-warnings", was_processing_warning);
    crm_xml_add_int(reply, "config-errors", crm_config_error);
    crm_xml_add_int(reply, "config-warnings", crm_config_warning);

    if (pcmk__ipc_send_xml(sender, 0, reply,
                           crm_ipc_server_event) != pcmk_rc_ok) {
        int graph_file_fd = 0;
        char *graph_file = NULL;
        umask(S_IWGRP | S_IWOTH | S_IROTH);

        graph_file = crm_strdup_printf("%s/pengine.graph.XXXXXX",
                                       PE_STATE_DIR);
        graph_file_fd = mkstemp(graph_file);

        crm_err("Couldn't send transition graph to peer, writing to %s instead",
                graph_file);

        crm_xml_add(reply, F_CRM_TGRAPH, graph_file);
        write_xml_fd(sched_data_set->graph, graph_file, graph_file_fd, FALSE);

        free(graph_file);
        free_xml(first_named_child(reply, F_CRM_DATA));
        CRM_ASSERT(pcmk__ipc_send_xml(sender, 0, reply,
                                      crm_ipc_server_event) == pcmk_rc_ok);
    }

    free_xml(reply);
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

    free_xml(converted);
}

static void
process_pe_message(xmlNode *msg, xmlNode *xml_data, pcmk__client_t *sender)
{
    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *ref = crm_element_value(msg, F_CRM_REFERENCE);

    crm_trace("Processing %s op (ref=%s)...", op, ref);

    if (op == NULL) {
        /* error */

    } else if (strcasecmp(op, CRM_OP_HELLO) == 0) {
        /* ignore */

    } else if (pcmk__str_eq(crm_element_value(msg, F_CRM_MSG_TYPE), XML_ATTR_RESPONSE, pcmk__str_casei)) {
        /* ignore */

    } else if (sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
        crm_trace("Bad sys-to %s", crm_str(sys_to));

    } else if (strcasecmp(op, CRM_OP_PECALC) == 0) {
        handle_pecalc_op(msg, xml_data, sender);
    }
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
    pcmk__client_t *c = pcmk__find_client(qbc);
    xmlNode *msg = pcmk__client_data2xml(c, data, &id, &flags);

    pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_INDETERMINATE);
    if (msg != NULL) {
        xmlNode *data_xml = get_message_xml(msg, F_CRM_DATA);

        process_pe_message(msg, data_xml, c);
        free_xml(msg);
    }
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
