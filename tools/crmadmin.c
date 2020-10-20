/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>             // atoi()

#include <glib.h>               // gboolean, GMainLoop, etc.
#include <libxml/tree.h>        // xmlNode

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/ipc_pacemakerd.h>
#include <crm/common/mainloop.h>

#define SUMMARY "query and manage the Pacemaker controller"

#define DEFAULT_MESSAGE_TIMEOUT_MS 30000

static guint message_timer_id = 0;
static guint message_timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS;
static GMainLoop *mainloop = NULL;

bool need_controld_api = true;
bool need_pacemakerd_api = false;

bool do_work(pcmk_ipc_api_t *api);
static char *ipc_name = NULL;

gboolean admin_message_timeout(gpointer data);

static enum {
    cmd_none,
    cmd_shutdown,
    cmd_health,
    cmd_elect_dc,
    cmd_whois_dc,
    cmd_list_nodes,
    cmd_pacemakerd_health,
} command = cmd_none;

static gboolean BE_VERBOSE = FALSE;
static gboolean BASH_EXPORT = FALSE;
static char *dest_node = NULL;
static crm_exit_t exit_code = CRM_EX_OK;
pcmk__output_t *out = NULL;


struct {
    gboolean health;
    gint timeout;
} options;

gboolean command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry command_options[] = {
    { "status", 'S', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of the specified node."
      "\n                          Result is state of node's internal finite state"
      "\n                          machine, which can be useful for debugging",
      NULL
    },
    { "pacemakerd", 'P', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of local pacemakerd."
      "\n                          Result is the state of the sub-daemons watched"
      "\n                          by pacemakerd.",
      NULL
    },
    { "dc_lookup", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of the node co-ordinating the cluster."
      "\n                          This is an internal detail rarely useful to"
      "\n                          administrators except when deciding on which"
      "\n                          node to examine the logs.",
      NULL
    },
    { "nodes", 'N', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of all member nodes",
      NULL
    },
    { "election", 'E', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Start an election for the cluster co-ordinator",
      NULL
    },
    { "kill", 'K', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Stop controller (not rest of cluster stack) on specified node",
      NULL
    },
    { "health", 'H', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.health,
      NULL,
      NULL
    },

    { NULL }
};

static GOptionEntry additional_options[] = {
    { "timeout", 't', 0, G_OPTION_ARG_INT, &options.timeout,
      "Time (in milliseconds) to wait before declaring the"
      "\n                          operation failed",
      NULL
    },
    { "bash-export", 'B', 0, G_OPTION_ARG_NONE, &BASH_EXPORT,
      "Display nodes as shell commands of the form 'export uname=uuid'"
      "\n                          (valid with -N/--nodes)",
    },
    { "ipc-name", 'i', 0, G_OPTION_ARG_STRING, &ipc_name,
      "Name to use for ipc instead of 'crmadmin' (with -P/--pacemakerd).",
      NULL
    },

    { NULL }
};

gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error)
{
    if (!strcmp(option_name, "--status") || !strcmp(option_name, "-S")) {
        command = cmd_health;
        crm_trace("Option %c => %s", 'S', optarg);
    }

    if (!strcmp(option_name, "--pacemakerd") || !strcmp(option_name, "-P")) {
        command = cmd_pacemakerd_health;
        need_pacemakerd_api = true;
        need_controld_api = false;
    }

    if (!strcmp(option_name, "--dc_lookup") || !strcmp(option_name, "-D")) {
        command = cmd_whois_dc;
    }

    if (!strcmp(option_name, "--nodes") || !strcmp(option_name, "-N")) {
        command = cmd_list_nodes;
        need_controld_api = false;
    }

    if (!strcmp(option_name, "--election") || !strcmp(option_name, "-E")) {
        command = cmd_elect_dc;
    }

    if (!strcmp(option_name, "--kill") || !strcmp(option_name, "-K")) {
        command = cmd_shutdown;
        crm_trace("Option %c => %s", 'K', optarg);
    }

    if (optarg) {
        if (dest_node != NULL) {
            free(dest_node);
        }
        dest_node = strdup(optarg);
    }

    return TRUE;
}

PCMK__OUTPUT_ARGS("health", "char *", "char *", "char *", "char *")
static int
health_text(pcmk__output_t *out, va_list args)
{
    char *sys_from = va_arg(args, char *);
    char *host_from = va_arg(args, char *);
    char *fsa_state = va_arg(args, char *);
    char *result = va_arg(args, char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Status of %s@%s: %s (%s)", crm_str(sys_from),
                       crm_str(host_from), crm_str(fsa_state), crm_str(result));
    } else if (fsa_state != NULL) {
        out->info(out, "%s", fsa_state);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("health", "char *", "char *", "char *", "char *")
static int
health_xml(pcmk__output_t *out, va_list args)
{
    char *sys_from = va_arg(args, char *);
    char *host_from = va_arg(args, char *);
    char *fsa_state = va_arg(args, char *);
    char *result = va_arg(args, char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, crm_str(sys_from));
    xmlSetProp(node, (pcmkXmlStr) "node_name", (pcmkXmlStr) crm_str(host_from));
    xmlSetProp(node, (pcmkXmlStr) "state", (pcmkXmlStr) crm_str(fsa_state));
    xmlSetProp(node, (pcmkXmlStr) "result", (pcmkXmlStr) crm_str(result));

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "char *", "char *", "char *")
static int
pacemakerd_health_text(pcmk__output_t *out, va_list args)
{
    char *sys_from = va_arg(args, char *);
    char *state = va_arg(args, char *);
    char *last_updated = va_arg(args, char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Status of %s: '%s' %s %s", crm_str(sys_from),
                  crm_str(state), (!pcmk__str_empty(last_updated))?
                  "last updated":"", crm_str(last_updated));
    } else {
        out->info(out, "%s", crm_str(state));
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("pacemakerd-health", "char *", "char *", "char *")
static int
pacemakerd_health_xml(pcmk__output_t *out, va_list args)
{
    char *sys_from = va_arg(args, char *);
    char *state = va_arg(args, char *);
    char *last_updated = va_arg(args, char *);


    xmlNodePtr node = pcmk__output_create_xml_node(out, crm_str(sys_from));
    xmlSetProp(node, (pcmkXmlStr) "state", (pcmkXmlStr) crm_str(state));
    xmlSetProp(node, (pcmkXmlStr) "last_updated", (pcmkXmlStr) crm_str(last_updated));

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "char *")
static int
dc_text(pcmk__output_t *out, va_list args)
{
    char *dc = va_arg(args, char *);

    if (!out->is_quiet(out)) {
        out->info(out, "Designated Controller is: %s", crm_str(dc));
    } else if (dc != NULL) {
        out->info(out, "%s", dc);
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("dc", "char *")
static int
dc_xml(pcmk__output_t *out, va_list args)
{
    char *dc = va_arg(args, char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "dc");
    xmlSetProp(node, (pcmkXmlStr) "node_name", (pcmkXmlStr) crm_str(dc));

    return pcmk_rc_ok;
}


PCMK__OUTPUT_ARGS("crmadmin-node-list", "xmlNode *")
static int
crmadmin_node_list(pcmk__output_t *out, va_list args)
{
    xmlNode *xml_node = va_arg(args, xmlNode *);
    int found = 0;
    xmlNode *node = NULL;
    xmlNode *nodes = get_object_root(XML_CIB_TAG_NODES, xml_node);

    out->begin_list(out, NULL, NULL, "nodes");

    for (node = first_named_child(nodes, XML_CIB_TAG_NODE); node != NULL;
         node = crm_next_same_xml(node)) {
        const char *node_type = BASH_EXPORT ? NULL :
                     crm_element_value(node, XML_ATTR_TYPE);
        out->message(out, "crmadmin-node", node_type,
                     crm_str(crm_element_value(node, XML_ATTR_UNAME)),
                     crm_str(crm_element_value(node, XML_ATTR_ID)));

        found++;
    }
    // @TODO List Pacemaker Remote nodes that don't have a <node> entry

    out->end_list(out);

    if (found == 0) {
        out->info(out, "No nodes configured");
    }

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "char *", "char *", "char *")
static int
crmadmin_node_text(pcmk__output_t *out, va_list args)
{
        char *type = va_arg(args, char *);
        char *name = va_arg(args, char *);
        char *id = va_arg(args, char *);

        if (BASH_EXPORT) {
            out->info(out, "export %s=%s", crm_str(name), crm_str(id));
        } else {
            out->info(out, "%s node: %s (%s)", type ? type : "member",
                      crm_str(name), crm_str(id));
        }

        return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("crmadmin-node", "char *", "char *", "char *")
static int
crmadmin_node_xml(pcmk__output_t *out, va_list args)
{
    char *type = va_arg(args, char *);
    char *name = va_arg(args, char *);
    char *id = va_arg(args, char *);

    xmlNodePtr node = pcmk__output_create_xml_node(out, "node");
    xmlSetProp(node, (pcmkXmlStr) "type", (pcmkXmlStr) (type ? type : "member"));
    xmlSetProp(node, (pcmkXmlStr) "name", (pcmkXmlStr) crm_str(name));
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) crm_str(id));

    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    {"health", "default", health_text },
    {"health", "xml", health_xml },
    {"pacemakerd-health", "default", pacemakerd_health_text },
    {"pacemakerd-health", "xml", pacemakerd_health_xml },
    {"dc", "default", dc_text },
    {"dc", "xml", dc_xml },
    {"crmadmin-node-list", "default", crmadmin_node_list },
    {"crmadmin-node", "default", crmadmin_node_text },
    {"crmadmin-node", "xml", crmadmin_node_xml },

    { NULL, NULL, NULL }
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static void
quit_main_loop(crm_exit_t ec)
{
    exit_code = ec;
    if (mainloop != NULL) {
        GMainLoop *mloop = mainloop;

        mainloop = NULL; // Don't re-enter this block
        pcmk_quit_main_loop(mloop, 10);
        g_main_loop_unref(mloop);
    }
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
                out->err(out, "error: Lost connection to controller");
            }
            goto done;
            break;

        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (message_timer_id != 0) {
        g_source_remove(message_timer_id);
        message_timer_id = 0;
    }

    if (status != CRM_EX_OK) {
        out->err(out, "error: Bad reply from controller: %s",
                crm_exit_str(status));
        exit_code = status;
        goto done;
    }

    if (reply->reply_type != pcmk_controld_reply_ping) {
        out->err(out, "error: Unknown reply type %d from controller",
                reply->reply_type);
        goto done;
    }

    // Parse desired information from reply
    switch (command) {
        case cmd_health:
            out->message(out, "health",
                   reply->data.ping.sys_from,
                   reply->host_from,
                   reply->data.ping.fsa_state,
                   reply->data.ping.result);
            exit_code = CRM_EX_OK;
            break;

        case cmd_whois_dc:
            out->message(out, "dc", reply->host_from);
            exit_code = CRM_EX_OK;
            break;

        default: // Not really possible here
            exit_code = CRM_EX_SOFTWARE;
            break;
    }

done:
    pcmk_disconnect_ipc(controld_api);
    quit_main_loop(exit_code);
}

static void
pacemakerd_event_cb(pcmk_ipc_api_t *pacemakerd_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_pacemakerd_api_reply_t *reply = event_data;

    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            if (exit_code == CRM_EX_DISCONNECT) { // Unexpected
                out->err(out, "error: Lost connection to pacemakerd");
            }
            goto done;
            break;

        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (message_timer_id != 0) {
        g_source_remove(message_timer_id);
        message_timer_id = 0;
    }

    if (status != CRM_EX_OK) {
        out->err(out, "error: Bad reply from pacemakerd: %s",
                crm_exit_str(status));
        exit_code = status;
        goto done;
    }

    if (reply->reply_type != pcmk_pacemakerd_reply_ping) {
        out->err(out, "error: Unknown reply type %d from pacemakerd",
                reply->reply_type);
        goto done;
    }

    // Parse desired information from reply
    switch (command) {
        case cmd_pacemakerd_health:
            {
                crm_time_t *crm_when = crm_time_new(NULL);
                char *pinged_buf = NULL;

                crm_time_set_timet(crm_when, &reply->data.ping.last_good);
                pinged_buf = crm_time_as_string(crm_when,
                    crm_time_log_date | crm_time_log_timeofday |
                        crm_time_log_with_timezone);

                out->message(out, "pacemakerd-health",
                    reply->data.ping.sys_from,
                    (reply->data.ping.status == pcmk_rc_ok)?
                        pcmk_pacemakerd_api_daemon_state_enum2text(
                            reply->data.ping.state):"query failed",
                    (reply->data.ping.status == pcmk_rc_ok)?pinged_buf:"");
                exit_code = CRM_EX_OK;
                free(pinged_buf);
            }
            break;

        default: // Not really possible here
            exit_code = CRM_EX_SOFTWARE;
            break;
    }

done:
    pcmk_disconnect_ipc(pacemakerd_api);
    quit_main_loop(exit_code);
}

// \return Standard Pacemaker return code
static int
list_nodes()
{
    cib_t *the_cib = cib_new();
    xmlNode *output = NULL;
    int rc;

    if (the_cib == NULL) {
        return ENOMEM;
    }
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        return pcmk_legacy2rc(rc);
    }

    rc = the_cib->cmds->query(the_cib, NULL, &output,
                              cib_scope_local | cib_sync_call);
    if (rc == pcmk_ok) {
        out->message(out, "crmadmin-node-list", output);
        free_xml(output);
    }
    the_cib->cmds->signoff(the_cib);
    return pcmk_legacy2rc(rc);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    const char *description = "Report bugs to users@clusterlabs.org";

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Display only the essential query information",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "command", "Commands:",
                        "Show command options", command_options);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", additional_options);
    return context;
}

int
main(int argc, char **argv)
{
    int argerr = 0;
    int rc;
    pcmk_ipc_api_t *controld_api = NULL;
    pcmk_ipc_api_t *pacemakerd_api = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);

    GError *error = NULL;
    GOptionContext *context = NULL;
    GOptionGroup *output_group = NULL;
    gchar **processed_args = NULL;

    context = build_arg_context(args, &output_group);
    pcmk__register_formats(output_group, formats);

    crm_log_cli_init("crmadmin");

    processed_args = pcmk__cmdline_preproc(argv, "itBDEHKNPS");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        fprintf(stderr, "%s: %s\n", g_get_prgname(), error->message);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    for (int i = 0; i < args->verbosity; i++) {
        BE_VERBOSE = TRUE;
        crm_bump_log_level(argc, argv);
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Error creating output format %s: %s\n",
                args->output_ty, pcmk_rc_str(rc));
        exit_code = CRM_EX_ERROR;
        goto done;
    }

    out->quiet = args->quiet;

    pcmk__register_messages(out, fmt_functions);

    if (!pcmk__force_args(context, &error, "%s --xml-simple-list --xml-substitute", g_get_prgname())) {
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.timeout) {
        message_timeout_ms = (guint) options.timeout;
        if (message_timeout_ms < 1) {
            message_timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS;
        }
    }

    if (options.health) {
        out->err(out, "Cluster-wide health option not supported");
        ++argerr;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (command == cmd_none) {
        out->err(out, "error: Must specify a command option");
        ++argerr;
    }

    if (argerr) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        out->err(out, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    // Connect to the controller if needed
    if (need_controld_api) {
        rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
        if (controld_api == NULL) {
            out->err(out, "error: Could not connect to controller: %s",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
        pcmk_register_ipc_callback(controld_api, controller_event_cb, NULL);
        rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_main);
        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Could not connect to controller: %s",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    // Connect to pacemakerd if needed
    if (need_pacemakerd_api) {
        rc = pcmk_new_ipc_api(&pacemakerd_api, pcmk_ipc_pacemakerd);
        if (pacemakerd_api == NULL) {
            out->err(out, "error: Could not connect to pacemakerd: %s",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
        pcmk_register_ipc_callback(pacemakerd_api, pacemakerd_event_cb, NULL);
        rc = pcmk_connect_ipc(pacemakerd_api, pcmk_ipc_dispatch_main);
        if (rc != pcmk_rc_ok) {
            out->err(out, "error: Could not connect to pacemakerd: %s",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    if (do_work(controld_api?controld_api:pacemakerd_api)) {
        // A reply is needed from controller, so run main loop to get it
        exit_code = CRM_EX_DISCONNECT; // For unexpected disconnects
        mainloop = g_main_loop_new(NULL, FALSE);
        message_timer_id = g_timeout_add(message_timeout_ms,
                                         admin_message_timeout, NULL);
        g_main_loop_run(mainloop);
    }

done:

    if (controld_api != NULL) {
        pcmk_ipc_api_t *capi = controld_api;
        controld_api = NULL; // Ensure we can't free this twice
        pcmk_free_ipc_api(capi);
    }

    if (pacemakerd_api != NULL) {
        pcmk_ipc_api_t *capi = pacemakerd_api;
        pacemakerd_api = NULL; // Ensure we can't free this twice
        pcmk_free_ipc_api(capi);
    }

    if (mainloop != NULL) {
        g_main_loop_unref(mainloop);
        mainloop = NULL;
    }
    g_strfreev(processed_args);
    g_clear_error(&error);
    pcmk__free_arg_context(context);
    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    return crm_exit(exit_code);

}

// \return True if reply from controller is needed
bool
do_work(pcmk_ipc_api_t *api)
{
    bool need_reply = false;
    int rc = pcmk_rc_ok;

    switch (command) {
        case cmd_shutdown:
            rc = pcmk_controld_api_shutdown(api, dest_node);
            break;

        case cmd_health:    // dest_node != NULL
        case cmd_whois_dc:  // dest_node == NULL
            rc = pcmk_controld_api_ping(api, dest_node);
            need_reply = true;
            break;

        case cmd_elect_dc:
            rc = pcmk_controld_api_start_election(api);
            break;

        case cmd_list_nodes:
            rc = list_nodes();
            break;

        case cmd_pacemakerd_health:
            rc = pcmk_pacemakerd_api_ping(api, ipc_name);
            need_reply = true;
            break;

        case cmd_none: // not actually possible here
            break;
    }
    if (rc != pcmk_rc_ok) {
        out->err(out, "error: Command failed: %s", pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);
    }
    return need_reply;
}

gboolean
admin_message_timeout(gpointer data)
{
    out->err(out,
            "error: No reply received from controller before timeout (%dms)",
            message_timeout_ms);
    message_timer_id = 0;
    quit_main_loop(CRM_EX_TIMEOUT);
    return FALSE; // Tells glib to remove source
}
