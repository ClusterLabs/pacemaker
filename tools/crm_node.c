/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/ipc_controld.h>

#include <pacemaker-internal.h>

#define SUMMARY "crm_node - Tool for displaying low-level node information"

struct {
    gboolean corosync;
    gboolean dangerous_cmd;
    gboolean force_flag;
    char command;
    int nodeid;
    char *target_uname;
} options = {
    .command = '\0',
    .force_flag = FALSE
};

gboolean command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean name_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean remove_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GError *error = NULL;
static GMainLoop *mainloop = NULL;
static crm_exit_t exit_code = CRM_EX_OK;
static pcmk__output_t *out = NULL;

#define INDENT "                           "

static GOptionEntry command_entries[] = {
    { "cluster-id", 'i', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display this node's cluster id",
      NULL },
    { "list", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display all known members (past and present) of this cluster",
      NULL },
    { "name", 'n', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the name used by the cluster for this node",
      NULL },
    { "partition", 'p', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the members of this partition",
      NULL },
    { "quorum", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display a 1 if our partition has quorum, 0 if not",
      NULL },
    { "name-for-id", 'N', 0, G_OPTION_ARG_CALLBACK, name_cb,
      "Display the name used by the cluster for the node with the specified ID",
      "ID" },
    { "remove", 'R', 0, G_OPTION_ARG_CALLBACK, remove_cb,
      "(Advanced) Remove the (stopped) node with the specified name from Pacemaker's\n"
      INDENT "configuration and caches (the node must already have been removed from\n"
      INDENT "the underlying cluster stack configuration",
      "NAME" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "force", 'f', 0, G_OPTION_ARG_NONE, &options.force_flag,
      NULL,
      NULL },
#if SUPPORT_COROSYNC
    /* Unused and deprecated */
    { "corosync", 'C', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.corosync,
      NULL,
      NULL },
#endif

    // @TODO add timeout option for when IPC replies are needed

    { NULL }
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_eq("-i", option_name, pcmk__str_casei) || pcmk__str_eq("--cluster-id", option_name, pcmk__str_casei)) {
        options.command = 'i';
    } else if (pcmk__str_eq("-l", option_name, pcmk__str_casei) || pcmk__str_eq("--list", option_name, pcmk__str_casei)) {
        options.command = 'l';
    } else if (pcmk__str_eq("-n", option_name, pcmk__str_casei) || pcmk__str_eq("--name", option_name, pcmk__str_casei)) {
        options.command = 'n';
    } else if (pcmk__str_eq("-p", option_name, pcmk__str_casei) || pcmk__str_eq("--partition", option_name, pcmk__str_casei)) {
        options.command = 'p';
    } else if (pcmk__str_eq("-q", option_name, pcmk__str_casei) || pcmk__str_eq("--quorum", option_name, pcmk__str_casei)) {
        options.command = 'q';
    } else {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "Unknown param passed to command_cb: %s", option_name);
        return FALSE;
    }

    return TRUE;
}

gboolean
name_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'N';
    pcmk__scan_min_int(optarg, &(options.nodeid), 0);
    return TRUE;
}

gboolean
remove_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (optarg == NULL) {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "-R option requires an argument");
        return FALSE;
    }

    options.command = 'R';
    options.dangerous_cmd = TRUE;
    pcmk__str_update(&options.target_uname, optarg);
    return TRUE;
}

PCMK__OUTPUT_ARGS("node-id", "uint32_t")
static int
node_id_default(pcmk__output_t *out, va_list args) {
    uint32_t node_id = va_arg(args, uint32_t);

    out->info(out, "%" PRIu32, node_id);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-id", "uint32_t")
static int
node_id_xml(pcmk__output_t *out, va_list args) {
    uint32_t node_id = va_arg(args, uint32_t);

    char *id_s = pcmk__assert_asprintf("%" PRIu32, node_id);

    pcmk__output_create_xml_node(out, PCMK_XE_NODE_INFO,
                                 PCMK_XA_NODEID, id_s,
                                 NULL);

    free(id_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("simple-node-list", "GList *")
static int
simple_node_list_default(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;
        out->info(out, "%" PRIu32 " %s %s", node->id, pcmk__s(node->uname, ""),
                  pcmk__s(node->state, ""));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("simple-node-list", "GList *")
static int
simple_node_list_xml(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    out->begin_list(out, NULL, NULL, PCMK_XE_NODES);

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;
        char *id_s = pcmk__assert_asprintf("%" PRIu32, node->id);

        pcmk__output_create_xml_node(out, PCMK_XE_NODE,
                                     PCMK_XA_ID, id_s,
                                     PCMK_XA_NAME, node->uname,
                                     PCMK_XA_STATE, node->state,
                                     NULL);

        free(id_s);
    }

    out->end_list(out);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-name", "uint32_t", "const char *")
static int
node_name_default(pcmk__output_t *out, va_list args) {
    uint32_t node_id G_GNUC_UNUSED = va_arg(args, uint32_t);
    const char *node_name = va_arg(args, const char *);

    out->info(out, "%s", node_name);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-name", "uint32_t", "const char *")
static int
node_name_xml(pcmk__output_t *out, va_list args) {
    uint32_t node_id = va_arg(args, uint32_t);
    const char *node_name = va_arg(args, const char *);

    char *id_s = pcmk__assert_asprintf("%" PRIu32, node_id);

    pcmk__output_create_xml_node(out, PCMK_XE_NODE_INFO,
                                 PCMK_XA_NODEID, id_s,
                                 PCMK_XA_UNAME, node_name,
                                 NULL);

    free(id_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("partition-list", "GList *")
static int
partition_list_default(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    GString *buffer = NULL;

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;

        if (pcmk__str_eq(node->state, "member", pcmk__str_none)
            && !pcmk__str_empty(node->uname)) {

            pcmk__add_word(&buffer, 128, node->uname);
        }
    }

    if (buffer != NULL) {
        out->info(out, "%s", buffer->str);
        g_string_free(buffer, TRUE);
        return pcmk_rc_ok;
    }

    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("partition-list", "GList *")
static int
partition_list_xml(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    out->begin_list(out, NULL, NULL, PCMK_XE_NODES);

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;

        if (pcmk__str_eq(node->state, "member", pcmk__str_none)) {
            char *id_s = pcmk__assert_asprintf("%" PRIu32, node->id);

            pcmk__output_create_xml_node(out, PCMK_XE_NODE,
                                         PCMK_XA_ID, id_s,
                                         PCMK_XA_NAME, node->uname,
                                         PCMK_XA_STATE, node->state,
                                         NULL);
            free(id_s);
        }
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("quorum", "bool")
static int
quorum_default(pcmk__output_t *out, va_list args) {
    bool have_quorum = va_arg(args, int);

    out->info(out, "%d", have_quorum);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("quorum", "bool")
static int
quorum_xml(pcmk__output_t *out, va_list args) {
    bool have_quorum = va_arg(args, int);

    pcmk__output_create_xml_node(out, PCMK_XE_CLUSTER_INFO,
                                 PCMK_XA_QUORUM, pcmk__btoa(have_quorum),
                                 NULL);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "node-id", "default", node_id_default },
    { "node-id", "xml", node_id_xml },
    { "node-name", "default", node_name_default },
    { "node-name", "xml", node_name_xml },
    { "partition-list", "default", partition_list_default },
    { "partition-list", "xml", partition_list_xml },
    { "quorum", "default", quorum_default },
    { "quorum", "xml", quorum_xml },
    { "simple-node-list", "default", simple_node_list_default },
    { "simple-node-list", "xml", simple_node_list_xml },

    { NULL, NULL, NULL }
};

static gint
sort_node(gconstpointer a, gconstpointer b)
{
    const pcmk_controld_api_node_t *node_a = a;
    const pcmk_controld_api_node_t *node_b = b;

    return pcmk__numeric_strcasecmp((node_a->uname? node_a->uname : ""),
                                    (node_b->uname? node_b->uname : ""));
}

static void
controller_event_cb(pcmk_ipc_api_t *controld_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_controld_api_reply_t *reply = event_data;

    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            if (exit_code == CRM_EX_DISCONNECT) { // Unexpected
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Lost connection to controller");
            }
            goto done;
            break;

        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (status != CRM_EX_OK) {
        exit_code = status;
        g_set_error(&error, PCMK__EXITC_ERROR, status,
                    "Bad reply from controller: %s",
                    crm_exit_str(status));
        goto done;
    }

    if (reply->reply_type != pcmk_controld_reply_nodes) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_INDETERMINATE,
                    "Unknown reply type %d from controller",
                    reply->reply_type);
        goto done;
    }

    reply->data.nodes = g_list_sort(reply->data.nodes, sort_node);

    if (options.command == 'p') {
        out->message(out, "partition-list", reply->data.nodes);
    } else if (options.command == 'l') {
        out->message(out, "simple-node-list", reply->data.nodes);
    }

    // Success
    exit_code = CRM_EX_OK;
done:
    pcmk_disconnect_ipc(controld_api);
    pcmk_quit_main_loop(mainloop, 10);
}

static void
run_controller_mainloop(void)
{
    pcmk_ipc_api_t *controld_api = NULL;
    int rc;

    // Set disconnect exit code to handle unexpected disconnects
    exit_code = CRM_EX_DISCONNECT;

    // Create controller IPC object
    rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to controller: %s",
                    pcmk_rc_str(rc));
        return;
    }
    pcmk_register_ipc_callback(controld_api, controller_event_cb, NULL);

    // Connect to controller
    rc = pcmk__connect_ipc(controld_api, pcmk_ipc_dispatch_main, 5);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to %s: %s",
                    pcmk_ipc_name(controld_api, true), pcmk_rc_str(rc));
        return;
    }

    rc = pcmk_controld_api_list_nodes(controld_api);

    if (rc != pcmk_rc_ok) {
        pcmk_disconnect_ipc(controld_api);
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not ping controller: %s", pcmk_rc_str(rc));
        return;
    }

    // Run main loop to get controller reply via controller_event_cb()
    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);
    mainloop = NULL;
    pcmk_free_ipc_api(controld_api);
}

static void
print_node_id(void)
{
    uint32_t nodeid = 0;
    int rc = pcmk__query_node_info(out, &nodeid, NULL, NULL, NULL, NULL, NULL,
                                   false, 0);

    if (rc != pcmk_rc_ok) {
        /* pcmk__query_node_info already sets an error message on the output object,
         * so there's no need to call g_set_error here.  That would just create a
         * duplicate error message in the output.
         */
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    rc = out->message(out, "node-id", nodeid);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not print node ID: %s",
                    pcmk_rc_str(rc));
    }

    exit_code = pcmk_rc2exitc(rc);
}

static void
print_node_name(uint32_t nodeid)
{
    int rc = pcmk_rc_ok;
    char *node_name = NULL;

    if (nodeid == 0) {
        // Check environment first (i.e. when called by resource agent)
        const char *name = getenv("OCF_RESKEY_" CRM_META "_"
                                  PCMK__META_ON_NODE);

        if (name != NULL) {
            rc = out->message(out, "node-name", 0UL, name);
            goto done;
        }
    }

    // Otherwise ask the controller

    /* pcmk__query_node_name already sets an error message on the output object,
     * so there's no need to call g_set_error here.  That would just create a
     * duplicate error message in the output.
     */
    rc = pcmk__query_node_name(out, nodeid, &node_name, 0);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    rc = out->message(out, "node-name", 0UL, node_name);

done:
    if (node_name != NULL) {
        free(node_name);
    }

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not print node name: %s",
                    pcmk_rc_str(rc));
    }

    exit_code = pcmk_rc2exitc(rc);
}

static void
print_quorum(void)
{
    bool quorum;
    int rc = pcmk__query_node_info(out, NULL, NULL, NULL, NULL, &quorum, NULL,
                                   false, 0);

    if (rc != pcmk_rc_ok) {
        /* pcmk__query_node_info already sets an error message on the output object,
         * so there's no need to call g_set_error here.  That would just create a
         * duplicate error message in the output.
         */
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    rc = out->message(out, "quorum", quorum);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not print quorum status: %s",
                    pcmk_rc_str(rc));
    }

    exit_code = pcmk_rc2exitc(rc);
}

/*!
 * \internal
 * \brief Extend a transaction by removing a node from a CIB section
 *
 * \param[in,out] cib        Active CIB connection
 * \param[in]     element    CIB element containing node name and/or ID
 * \param[in]     section    CIB section that \p element is in
 * \param[in]     node_name  Name of node to purge (NULL to leave unspecified)
 * \param[in]     node_id    Node ID of node to purge (0 to leave unspecified)
 *
 * \note At least one of node_name and node_id must be specified.
 * \return Standard Pacemaker return code
 */
static int
remove_from_section(cib_t *cib, const char *element, const char *section,
                    const char *node_name, long node_id)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml = pcmk__xe_create(NULL, element);

    pcmk__xe_set(xml, PCMK_XA_UNAME, node_name);
    if (node_id > 0) {
        pcmk__xe_set_ll(xml, PCMK_XA_ID, (long long) node_id);
    }

    rc = cib->cmds->remove(cib, section, xml, cib_transaction);
    pcmk__xml_free(xml);
    return (rc >= 0)? pcmk_rc_ok : pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Purge a node from CIB
 *
 * \param[in] node_name  Name of node to purge (or NULL to leave unspecified)
 * \param[in] node_id    Node ID of node to purge (or 0 to leave unspecified)
 *
 * \note At least one of node_name and node_id must be specified.
 * \return Standard Pacemaker return code
 */
static int
purge_node_from_cib(const char *node_name, long node_id)
{
    int rc = pcmk_rc_ok;
    int commit_rc = pcmk_rc_ok;
    cib_t *cib = NULL;

    // Connect to CIB and start a transaction
    rc = cib__create_signon(&cib);
    if (rc == pcmk_rc_ok) {
        rc = cib->cmds->init_transaction(cib);
        rc = pcmk_legacy2rc(rc);
    }
    if (rc != pcmk_rc_ok) {
        cib__clean_up_connection(&cib);
        return rc;
    }

    // Remove from configuration and status
    rc = remove_from_section(cib, PCMK_XE_NODE, PCMK_XE_NODES, node_name,
                             node_id);
    if (rc == pcmk_rc_ok) {
        rc = remove_from_section(cib, PCMK__XE_NODE_STATE, PCMK_XE_STATUS,
                                 node_name, node_id);
    }

    // Commit the transaction
    commit_rc = cib->cmds->end_transaction(cib, (rc == pcmk_rc_ok),
                                           cib_sync_call);
    cib__clean_up_connection(&cib);

    if ((rc == pcmk_rc_ok) && (commit_rc == pcmk_ok)) {
        pcmk__debug("Purged node %s (%ld) from CIB",
                    pcmk__s(node_name, "by ID"), node_id);
    }
    return rc;
}

/*!
 * \internal
 * \brief Purge a node from a single server's peer cache
 *
 * \param[in] server     IPC server to send request to
 * \param[in] node_name  Name of node to purge (or NULL to leave unspecified)
 * \param[in] node_id    Node ID of node to purge (or 0 to leave unspecified)
 *
 * \note At least one of node_name and node_id must be specified.
 * \return Standard Pacemaker return code
 */
static int
purge_node_from(enum pcmk_ipc_server server, const char *node_name,
                long node_id)
{
    pcmk_ipc_api_t *api = NULL;
    int rc;

    rc = pcmk_new_ipc_api(&api, server);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__connect_ipc(api, pcmk_ipc_dispatch_sync, 5);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk_ipc_purge_node(api, node_name, node_id);
done:
    if (rc != pcmk_rc_ok) { // Debug message already logged on success
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not purge node %s from %s: %s",
                    pcmk__s(node_name, "by ID"), pcmk_ipc_name(api, true),
                    pcmk_rc_str(rc));
    }
    pcmk_free_ipc_api(api);
    return rc;
}

/*!
 * \internal
 * \brief Purge a node from the fencer's peer cache
 *
 * \param[in] node_name  Name of node to purge (or NULL to leave unspecified)
 * \param[in] node_id    Node ID of node to purge (or 0 to leave unspecified)
 *
 * \note At least one of node_name and node_id must be specified.
 * \return Standard Pacemaker return code
 */
static int
purge_node_from_fencer(const char *node_name, long node_id)
{
    int rc = pcmk_rc_ok;
    crm_ipc_t *conn = NULL;
    xmlNode *cmd = NULL;

    conn = crm_ipc_new("stonith-ng", 0);
    if (conn == NULL) {
        rc = ENOTCONN;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to fencer to purge node %s",
                    pcmk__s(node_name, "by ID"));
        return rc;
    }

    rc = pcmk__connect_generic_ipc(conn);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to fencer to purge node %s: %s",
                    pcmk__s(node_name, "by ID"), pcmk_rc_str(rc));
        crm_ipc_destroy(conn);
        return rc;
    }

    cmd = pcmk__new_request(pcmk_ipc_fenced, crm_system_name, NULL,
                            PCMK__VALUE_STONITH_NG, CRM_OP_RM_NODE_CACHE, NULL);
    if (node_id > 0) {
        pcmk__xe_set_ll(cmd, PCMK_XA_ID, (long long) node_id);
    }
    pcmk__xe_set(cmd, PCMK_XA_UNAME, node_name);

    rc = crm_ipc_send(conn, cmd, 0, 0, NULL);
    if (rc >= 0) {
        rc = pcmk_rc_ok;
        pcmk__debug("Purged node %s (%ld) from fencer",
                    pcmk__s(node_name, "by ID"), node_id);
    } else {
        rc = pcmk_legacy2rc(rc);
        fprintf(stderr, "Could not purge node %s from fencer: %s\n",
                pcmk__s(node_name, "by ID"), pcmk_rc_str(rc));
    }
    pcmk__xml_free(cmd);
    crm_ipc_close(conn);
    crm_ipc_destroy(conn);
    return rc;
}

static void
remove_node(const char *target_uname)
{
    int rc = pcmk_rc_ok;
    long nodeid = 0;
    const char *node_name = NULL;
    char *endptr = NULL;
    const enum pcmk_ipc_server servers[] = {
        pcmk_ipc_controld,
        pcmk_ipc_attrd,
    };

    // Check whether node was specified by name or numeric ID
    errno = 0;
    nodeid = strtol(target_uname, &endptr, 10);
    if ((errno != 0) || (endptr == target_uname) || (*endptr != '\0')
        || (nodeid <= 0)) {
        // It's not a positive integer, so assume it's a node name
        nodeid = 0;
        node_name = target_uname;
    }

    for (int i = 0; i < PCMK__NELEM(servers); ++i) {
        rc = purge_node_from(servers[i], node_name, nodeid);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            return;
        }
    }

    // The fencer hasn't been converted to pcmk_ipc_api_t yet
    rc = purge_node_from_fencer(node_name, nodeid);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    // Lastly, purge the node from the CIB itself
    rc = purge_node_from_cib(node_name, nodeid);
    exit_code = pcmk_rc2exitc(rc);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Be less descriptive in output.",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command help", command_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "NR");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_node", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    if (options.command == 0) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        out->err(out, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.dangerous_cmd && options.force_flag == FALSE) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "The supplied command is considered dangerous."
                    "  To prevent accidental destruction of the cluster,"
                    " the --force flag is required in order to proceed.");
        goto done;
    }

    pcmk__register_lib_messages(out);
    pcmk__register_messages(out, fmt_functions);

    switch (options.command) {
        case 'i':
            print_node_id();
            break;

        case 'n':
            print_node_name(0);
            break;

        case 'q':
            print_quorum();
            break;

        case 'N':
            print_node_name(options.nodeid);
            break;

        case 'R':
            remove_node(options.target_uname);
            break;

        case 'l':
        case 'p':
            run_controller_mainloop();
            break;

        default:
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    return crm_exit(exit_code);
}
