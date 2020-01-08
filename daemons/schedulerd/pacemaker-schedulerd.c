/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/parser.h>

#include <crm/common/ipcs.h>
#include <crm/common/mainloop.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>
#include <crm/msg_xml.h>

#define OPTARGS	"hVc"

static GMainLoop *mainloop = NULL;
static qb_ipcs_service_t *ipcs = NULL;
static pe_working_set_t *sched_data_set = NULL;

#define get_series() 	was_processing_error?1:was_processing_warning?2:3

typedef struct series_s {
    const char *name;
    const char *param;
    int wrap;
} series_t;

series_t series[] = {
    {"pe-unknown", "_do_not_match_anything_", -1},
    {"pe-error", "pe-error-series-max", -1},
    {"pe-warn", "pe-warn-series-max", 200},
    {"pe-input", "pe-input-series-max", 400},
};

void pengine_shutdown(int nsig);

static gboolean
process_pe_message(xmlNode * msg, xmlNode * xml_data, crm_client_t * sender)
{
    static char *last_digest = NULL;
    static char *filename = NULL;

    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *ref = crm_element_value(msg, F_CRM_REFERENCE);

    crm_trace("Processing %s op (ref=%s)...", op, ref);

    if (op == NULL) {
        /* error */

    } else if (strcasecmp(op, CRM_OP_HELLO) == 0) {
        /* ignore */

    } else if (safe_str_eq(crm_element_value(msg, F_CRM_MSG_TYPE), XML_ATTR_RESPONSE)) {
        /* ignore */

    } else if (sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
        crm_trace("Bad sys-to %s", crm_str(sys_to));
        return FALSE;

    } else if (strcasecmp(op, CRM_OP_PECALC) == 0) {
        unsigned int seq;
        int series_id = 0;
        int series_wrap = 0;
        char *digest = NULL;
        const char *value = NULL;
        time_t execution_date = time(NULL);
        xmlNode *converted = NULL;
        xmlNode *reply = NULL;
        gboolean is_repoke = FALSE;
        gboolean process = TRUE;

        crm_config_error = FALSE;
        crm_config_warning = FALSE;

        was_processing_error = FALSE;
        was_processing_warning = FALSE;

        if (sched_data_set == NULL) {
            sched_data_set = pe_new_working_set();
            CRM_ASSERT(sched_data_set != NULL);
            set_bit(sched_data_set->flags, pe_flag_no_counts);
        }

        digest = calculate_xml_versioned_digest(xml_data, FALSE, FALSE, CRM_FEATURE_SET);
        converted = copy_xml(xml_data);
        if (cli_config_update(&converted, NULL, TRUE) == FALSE) {
            sched_data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);
            crm_xml_add_int(sched_data_set->graph, "transition_id", 0);
            crm_xml_add_int(sched_data_set->graph, "cluster-delay", 0);
            process = FALSE;
            free(digest);

        } else if (safe_str_eq(digest, last_digest)) {
            crm_info("Input has not changed since last time, not saving to disk");
            is_repoke = TRUE;
            free(digest);

        } else {
            free(last_digest);
            last_digest = digest;
        }

        if (process) {
            pcmk__schedule_actions(sched_data_set, converted, NULL);
        }

        series_id = get_series();
        series_wrap = series[series_id].wrap;
        value = pe_pref(sched_data_set->config_hash, series[series_id].param);

        if (value != NULL) {
            series_wrap = crm_int_helper(value, NULL);
            if (errno != 0) {
                series_wrap = series[series_id].wrap;
            }

        } else {
            crm_config_warn("No value specified for cluster"
                            " preference: %s", series[series_id].param);
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

        if (is_repoke == FALSE) {
            free(filename);
            filename = pcmk__series_filename(PE_STATE_DIR,
                                             series[series_id].name, seq, true);
        }

        crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
        crm_xml_add_int(reply, "graph-errors", was_processing_error);
        crm_xml_add_int(reply, "graph-warnings", was_processing_warning);
        crm_xml_add_int(reply, "config-errors", crm_config_error);
        crm_xml_add_int(reply, "config-warnings", crm_config_warning);

        if (crm_ipcs_send(sender, 0, reply, crm_ipc_server_event) == FALSE) {
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
            CRM_ASSERT(crm_ipcs_send(sender, 0, reply, crm_ipc_server_event));
        }

        free_xml(reply);
        pe_reset_working_set(sched_data_set);
        pcmk__log_transition_summary(filename);

        if (is_repoke == FALSE && series_wrap != 0) {
            unlink(filename);
            crm_xml_add_ll(xml_data, "execution-date", (long long) execution_date);
            write_xml_file(xml_data, filename, TRUE);
            pcmk__write_series_sequence(PE_STATE_DIR, series[series_id].name,
                                        ++seq, series_wrap);
        } else {
            crm_trace("Not writing out %s: %d & %d", filename, is_repoke, series_wrap);
        }

        free_xml(converted);
    }

    return TRUE;
}

static int32_t
pe_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
pe_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

gboolean process_pe_message(xmlNode * msg, xmlNode * xml_data, crm_client_t * sender);

static int32_t
pe_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *c = crm_client_get(qbc);
    xmlNode *msg = crm_ipcs_recv(c, data, size, &id, &flags);

    crm_ipcs_send_ack(c, id, flags, "ack", __FUNCTION__, __LINE__);
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
    crm_client_t *client = crm_client_get(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    crm_client_destroy(client);
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
    .connection_created = pe_ipc_created,
    .msg_process = pe_ipc_dispatch,
    .connection_closed = pe_ipc_closed,
    .connection_destroyed = pe_ipc_destroy
};

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int flag;
    int index = 0;
    int argerr = 0;

    crm_log_preinit(NULL, argc, argv);
    crm_set_options(NULL, "[options]",
                    long_options, "Daemon for calculating the cluster's response to events");

    mainloop_add_signal(SIGTERM, pengine_shutdown);

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                crm_help('?', CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        pe_metadata();
        return CRM_EX_OK;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker scheduler");

    if (pcmk__daemon_can_write(PE_STATE_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " PE_STATE_DIR);
        fprintf(stderr,
                "ERROR: Bad permissions on " PE_STATE_DIR " (see logs for details)\n");
        fflush(stderr);
        return CRM_EX_FATAL;
    }

    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_PENGINE, QB_IPC_SHM, &ipc_callbacks);
    if (ipcs == NULL) {
        crm_err("Failed to create IPC server: shutting down and inhibiting respawn");
        crm_exit(CRM_EX_FATAL);
    }

    /* Create the mainloop and run it... */
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker scheduler successfully started and accepting connections");
    g_main_loop_run(mainloop);

    pe_free_working_set(sched_data_set);
    crm_info("Exiting %s", crm_system_name);
    crm_exit(CRM_EX_OK);
}

void
pengine_shutdown(int nsig)
{
    mainloop_del_ipc_server(ipcs);
    pe_free_working_set(sched_data_set);
    crm_exit(CRM_EX_OK);
}
