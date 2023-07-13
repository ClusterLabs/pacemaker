/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/mainloop.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/attrd_internal.h>

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

    char *id_s = crm_strdup_printf("%" PRIu32, node_id);

    pcmk__output_create_xml_node(out, "node-info",
                                 "nodeid", id_s,
                                 NULL);

    free(id_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-list", "GList *")
static int
node_list_default(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;
        out->info(out, "%" PRIu32 " %s %s", node->id, pcmk__s(node->uname, ""),
                  pcmk__s(node->state, ""));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("node-list", "GList *")
static int
node_list_xml(pcmk__output_t *out, va_list args)
{
    GList *nodes = va_arg(args, GList *);

    out->begin_list(out, NULL, NULL, "nodes");

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;
        char *id_s = crm_strdup_printf("%" PRIu32, node->id);

        pcmk__output_create_xml_node(out, "node",
                                     "id", id_s,
                                     "name", node->uname,
                                     "state", node->state,
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

    char *id_s = crm_strdup_printf("%" PRIu32, node_id);

    pcmk__output_create_xml_node(out, "node-info",
                                 "nodeid", id_s,
                                 XML_ATTR_UNAME, node_name,
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
        if (pcmk__str_eq(node->state, "member", pcmk__str_none)) {
            pcmk__add_separated_word(&buffer, 128, pcmk__s(node->uname, ""), " ");
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

    out->begin_list(out, NULL, NULL, "nodes");

    for (GList *node_iter = nodes; node_iter != NULL; node_iter = node_iter->next) {
        pcmk_controld_api_node_t *node = node_iter->data;

        if (pcmk__str_eq(node->state, "member", pcmk__str_none)) {
            char *id_s = crm_strdup_printf("%" PRIu32, node->id);

            pcmk__output_create_xml_node(out, "node",
                                         "id", id_s,
                                         "name", node->uname,
                                         "state", node->state,
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

    pcmk__output_create_xml_node(out, "cluster-info",
                                 "quorum", have_quorum ? "true" : "false",
                                 NULL);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "node-id", "default", node_id_default },
    { "node-id", "xml", node_id_xml },
    { "node-list", "default", node_list_default },
    { "node-list", "xml", node_list_xml },
    { "node-name", "default", node_name_default },
    { "node-name", "xml", node_name_xml },
    { "quorum", "default", quorum_default },
    { "quorum", "xml", quorum_xml },
    { "partition-list", "default", partition_list_default },
    { "partition-list", "xml", partition_list_xml },

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
        out->message(out, "node-list", reply->data.nodes);
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
    uint32_t nodeid;
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
        const char *name = getenv("OCF_RESKEY_" CRM_META "_" XML_LRM_ATTR_TARGET);

        if (name != NULL) {
            rc = out->message(out, "node-name", 0, name);
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

    rc = out->message(out, "node-name", 0, node_name);

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

/* Returns a standard Pacemaker return code */
static int
cib_remove_node(long id, const char *name)
{
    int rc;
    cib_t *cib = NULL;
    xmlNode *node = NULL;
    xmlNode *node_state = NULL;

    crm_trace("Removing %s from the CIB", name);

    if (name == NULL && id == 0) {
        exit_code = pcmk_rc2exitc(ENOTUNIQ);

        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Neither node ID nor name given");
        return ENOTUNIQ;
    }

    node = create_xml_node(NULL, XML_CIB_TAG_NODE);
    node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);

    crm_xml_add(node, XML_ATTR_UNAME, name);
    crm_xml_add(node_state, XML_ATTR_UNAME, name);
    if (id > 0) {
        crm_xml_set_id(node, "%ld", id);
        crm_xml_add(node_state, XML_ATTR_ID, ID(node));
    }

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);

    rc = cib->cmds->remove(cib, XML_CIB_TAG_NODES, node, cib_sync_call);
    if (rc != pcmk_ok) {
        rc = pcmk_legacy2rc(rc);
        exit_code = pcmk_rc2exitc(rc);

        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not remove %s[%ld] from " XML_CIB_TAG_NODES ": %s",
                    name, id, pcmk_strerror(rc));
    }
    rc = cib->cmds->remove(cib, XML_CIB_TAG_STATUS, node_state, cib_sync_call);
    if (rc != pcmk_ok) {
        rc = pcmk_legacy2rc(rc);
        exit_code = pcmk_rc2exitc(rc);

        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not remove %s[%ld] from " XML_CIB_TAG_STATUS ": %s",
                    name, id, pcmk_strerror(rc));
    }

    cib__clean_up_connection(&cib);
    return rc;
}

static int
controller_remove_node(const char *node_name, long nodeid)
{
    pcmk_ipc_api_t *controld_api = NULL;
    int rc;

    // Create controller IPC object
    rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to controller: %s", pcmk_rc_str(rc));
        return ENOTCONN;
    }

    // Connect to controller (without main loop)
    rc = pcmk__connect_ipc(controld_api, pcmk_ipc_dispatch_sync, 5);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to %s: %s",
                    pcmk_ipc_name(controld_api, true), pcmk_rc_str(rc));
        pcmk_free_ipc_api(controld_api);
        return rc;
    }

    rc = pcmk_ipc_purge_node(controld_api, node_name, nodeid);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not clear node from controller's cache: %s",
                    pcmk_rc_str(rc));
    }

    pcmk_free_ipc_api(controld_api);
    return pcmk_rc_ok;
}

/* Returns a standard Pacemaker return code */
static int
tools_remove_node_cache(const char *node_name, long nodeid, const char *target)
{
    int rc = -1;
    crm_ipc_t *conn = NULL;
    xmlNode *cmd = NULL;

    conn = crm_ipc_new(target, 0);
    if (!conn) {
        exit_code = pcmk_rc2exitc(ENOTCONN);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to controller");
        return ENOTCONN;
    }

    rc = pcmk__connect_generic_ipc(conn);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to controller: %s", pcmk_rc_str(rc));
        crm_ipc_destroy(conn);
        return rc;
    }

    crm_trace("Removing %s[%ld] from the %s membership cache",
              node_name, nodeid, target);

    if(pcmk__str_eq(target, T_ATTRD, pcmk__str_casei)) {
        cmd = create_xml_node(NULL, __func__);

        crm_xml_add(cmd, F_TYPE, T_ATTRD);
        crm_xml_add(cmd, F_ORIG, crm_system_name);

        crm_xml_add(cmd, PCMK__XA_TASK, PCMK__ATTRD_CMD_PEER_REMOVE);

        pcmk__xe_add_node(cmd, node_name, nodeid);

    } else { // Fencer or pacemakerd
        cmd = create_request(CRM_OP_RM_NODE_CACHE, NULL, NULL, target,
                             crm_system_name, NULL);
        if (nodeid > 0) {
            crm_xml_set_id(cmd, "%ld", nodeid);
        }
        crm_xml_add(cmd, XML_ATTR_UNAME, node_name);
    }

    rc = crm_ipc_send(conn, cmd, 0, 0, NULL);
    crm_debug("%s peer cache cleanup for %s (%ld): %d",
              target, node_name, nodeid, rc);

    if (rc > 0) {
        // @TODO Should this be done just once after all the rest?
        rc = cib_remove_node(nodeid, node_name);
    } else {
        rc = -rc;
        exit_code = pcmk_rc2exitc(rc);

        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not send IPC request: %s", pcmk_rc_str(rc));
    }

    if (conn) {
        crm_ipc_close(conn);
        crm_ipc_destroy(conn);
    }
    free_xml(cmd);
    return rc;
}

static void
remove_node(const char *target_uname)
{
    int rc;
    int d = 0;
    long nodeid = 0;
    const char *node_name = NULL;
    char *endptr = NULL;
    const char *daemons[] = {
        "stonith-ng",
        T_ATTRD,
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

    rc = controller_remove_node(node_name, nodeid);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    for (d = 0; d < PCMK__NELEM(daemons); d++) {
        if (tools_remove_node_cache(node_name, nodeid, daemons[d]) != pcmk_rc_ok) {
            return;
        }
    }

    exit_code = CRM_EX_OK;
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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (!pcmk__force_args(context, &error, "%s --xml-simple-list", g_get_prgname())) {
        exit_code = CRM_EX_SOFTWARE;
        goto done;
    }

    if (args->version) {
        out->version(out, false);
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
