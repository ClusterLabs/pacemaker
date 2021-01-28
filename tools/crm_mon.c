/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <sys/utsname.h>

#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/lrmd.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/curses_internal.h>
#include <crm/common/internal.h>  // pcmk__ends_with_ext()
#include <crm/common/ipc.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/output_internal.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include "crm_mon.h"

#define SUMMARY "Provides a summary of cluster's current state.\n\n" \
                "Outputs varying levels of detail in a number of different formats."

/*
 * Definitions indicating which items to print
 */

static unsigned int show;

/*
 * Definitions indicating how to output
 */

static mon_output_format_t output_format = mon_output_unset;

/* other globals */
static GIOChannel *io_channel = NULL;
static GMainLoop *mainloop = NULL;
static guint reconnect_timer = 0;
static mainloop_timer_t *refresh_timer = NULL;
static pe_working_set_t *mon_data_set = NULL;

static cib_t *cib = NULL;
static stonith_t *st = NULL;
static xmlNode *current_cib = NULL;

static GError *error = NULL;
static pcmk__common_args_t *args = NULL;
static pcmk__output_t *out = NULL;
static GOptionContext *context = NULL;
static gchar **processed_args = NULL;

static time_t last_refresh = 0;
crm_trigger_t *refresh_trigger = NULL;

static gboolean on_remote_node = FALSE;

int interactive_fence_level = 0;

static pcmk__supported_format_t formats[] = {
#if CURSES_ENABLED
    CRM_MON_SUPPORTED_FORMAT_CURSES,
#endif
    PCMK__SUPPORTED_FORMAT_HTML,
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

/* Define exit codes for monitoring-compatible output
 * For nagios plugins, the possibilities are
 * OK=0, WARN=1, CRIT=2, and UNKNOWN=3
 */
#define MON_STATUS_WARN    CRM_EX_ERROR
#define MON_STATUS_CRIT    CRM_EX_INVALID_PARAM
#define MON_STATUS_UNKNOWN CRM_EX_UNIMPLEMENT_FEATURE

#define RECONNECT_MSECS 5000

struct {
    int reconnect_msec;
    gboolean daemonize;
    gboolean show_bans;
    char *pid_file;
    char *external_agent;
    char *external_recipient;
    char *neg_location_prefix;
    char *only_node;
    char *only_rsc;
    unsigned int mon_ops;
    GSList *user_includes_excludes;
    GSList *includes_excludes;
} options = {
    .reconnect_msec = RECONNECT_MSECS,
    .mon_ops = mon_op_default
};

static void clean_up_cib_connection(void);
static void clean_up_fencing_connection(void);
static crm_exit_t clean_up(crm_exit_t exit_code);
static void crm_diff_update(const char *event, xmlNode * msg);
static void handle_connection_failures(int rc);
static int mon_refresh_display(gpointer user_data);
static int cib_connect(gboolean full);
static int fencing_connect(void);
static int pacemakerd_status(void);
static void mon_st_callback_event(stonith_t * st, stonith_event_t * e);
static void mon_st_callback_display(stonith_t * st, stonith_event_t * e);
static void refresh_after_event(gboolean data_updated, gboolean enforce);

static unsigned int
all_includes(mon_output_format_t fmt) {
    if (fmt == mon_output_monitor || fmt == mon_output_plain || fmt == mon_output_console) {
        return ~mon_show_options;
    } else {
        return mon_show_all;
    }
}

static unsigned int
default_includes(mon_output_format_t fmt) {
    switch (fmt) {
        case mon_output_monitor:
        case mon_output_plain:
        case mon_output_console:
            return mon_show_stack | mon_show_dc | mon_show_times | mon_show_counts |
                   mon_show_nodes | mon_show_resources | mon_show_failures;

        case mon_output_xml:
        case mon_output_legacy_xml:
            return all_includes(fmt);

        case mon_output_html:
        case mon_output_cgi:
            return mon_show_summary | mon_show_nodes | mon_show_resources |
                   mon_show_failures;

        default:
            return 0;
    }
}

struct {
    const char *name;
    unsigned int bit;
} sections[] = {
    { "attributes", mon_show_attributes },
    { "bans", mon_show_bans },
    { "counts", mon_show_counts },
    { "dc", mon_show_dc },
    { "failcounts", mon_show_failcounts },
    { "failures", mon_show_failures },
    { "fencing", mon_show_fencing_all },
    { "fencing-failed", mon_show_fence_failed },
    { "fencing-pending", mon_show_fence_pending },
    { "fencing-succeeded", mon_show_fence_worked },
    { "nodes", mon_show_nodes },
    { "operations", mon_show_operations },
    { "options", mon_show_options },
    { "resources", mon_show_resources },
    { "stack", mon_show_stack },
    { "summary", mon_show_summary },
    { "tickets", mon_show_tickets },
    { "times", mon_show_times },
    { NULL }
};

static unsigned int
find_section_bit(const char *name) {
    for (int i = 0; sections[i].name != NULL; i++) {
        if (pcmk__str_eq(sections[i].name, name, pcmk__str_casei)) {
            return sections[i].bit;
        }
    }

    return 0;
}

static gboolean
apply_exclude(const gchar *excludes, GError **error) {
    char **parts = NULL;
    gboolean result = TRUE;

    parts = g_strsplit(excludes, ",", 0);
    for (char **s = parts; *s != NULL; s++) {
        unsigned int bit = find_section_bit(*s);

        if (pcmk__str_eq(*s, "all", pcmk__str_none)) {
            show = 0;
        } else if (pcmk__str_eq(*s, "none", pcmk__str_none)) {
            show = all_includes(output_format);
        } else if (bit != 0) {
            show &= ~bit;
        } else {
            g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "--exclude options: all, attributes, bans, counts, dc, "
                        "failcounts, failures, fencing, fencing-failed, "
                        "fencing-pending, fencing-succeeded, nodes, none, "
                        "operations, options, resources, stack, summary, "
                        "tickets, times");
            result = FALSE;
            break;
        }
    }
    g_strfreev(parts);
    return result;
}

static gboolean
apply_include(const gchar *includes, GError **error) {
    char **parts = NULL;
    gboolean result = TRUE;

    parts = g_strsplit(includes, ",", 0);
    for (char **s = parts; *s != NULL; s++) {
        unsigned int bit = find_section_bit(*s);

        if (pcmk__str_eq(*s, "all", pcmk__str_none)) {
            show = all_includes(output_format);
        } else if (pcmk__starts_with(*s, "bans")) {
            show |= mon_show_bans;
            if (options.neg_location_prefix != NULL) {
                free(options.neg_location_prefix);
                options.neg_location_prefix = NULL;
            }

            if (strlen(*s) > 4 && (*s)[4] == ':') {
                options.neg_location_prefix = strdup(*s+5);
            }
        } else if (pcmk__str_any_of(*s, "default", "defaults", NULL)) {
            show |= default_includes(output_format);
        } else if (pcmk__str_eq(*s, "none", pcmk__str_none)) {
            show = 0;
        } else if (bit != 0) {
            show |= bit;
        } else {
            g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "--include options: all, attributes, bans[:PREFIX], counts, dc, "
                        "default, failcounts, failures, fencing, fencing-failed, "
                        "fencing-pending, fencing-succeeded, nodes, none, operations, "
                        "options, resources, stack, summary, tickets, times");
            result = FALSE;
            break;
        }
    }
    g_strfreev(parts);
    return result;
}

static gboolean
apply_include_exclude(GSList *lst, mon_output_format_t fmt, GError **error) {
    gboolean rc = TRUE;
    GSList *node = lst;

    /* Set the default of what to display here.  Note that we OR everything to
     * show instead of set show directly because it could have already had some
     * settings applied to it in main.
     */
    show |= default_includes(fmt);

    while (node != NULL) {
        char *s = node->data;

        if (pcmk__starts_with(s, "--include=")) {
            rc = apply_include(s+10, error);
        } else if (pcmk__starts_with(s, "-I=")) {
            rc = apply_include(s+3, error);
        } else if (pcmk__starts_with(s, "--exclude=")) {
            rc = apply_exclude(s+10, error);
        } else if (pcmk__starts_with(s, "-U=")) {
            rc = apply_exclude(s+3, error);
        }

        if (rc != TRUE) {
            break;
        }

        node = node->next;
    }

    return rc;
}

static gboolean
user_include_exclude_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    char *s = crm_strdup_printf("%s=%s", option_name, optarg);

    options.user_includes_excludes = g_slist_append(options.user_includes_excludes, s);
    return TRUE;
}

static gboolean
include_exclude_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    char *s = crm_strdup_printf("%s=%s", option_name, optarg);

    options.includes_excludes = g_slist_append(options.includes_excludes, s);
    return TRUE;
}

static gboolean
as_cgi_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (args->output_ty != NULL) {
        free(args->output_ty);
    }

    args->output_ty = strdup("html");
    output_format = mon_output_cgi;
    options.mon_ops |= mon_op_one_shot;
    return TRUE;
}

static gboolean
as_html_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (args->output_ty != NULL) {
        free(args->output_ty);
    }

    if (args->output_dest != NULL) {
        free(args->output_dest);
        args->output_dest = NULL;
    }

    if (optarg != NULL) {
        args->output_dest = strdup(optarg);
    }

    args->output_ty = strdup("html");
    output_format = mon_output_html;
    umask(S_IWGRP | S_IWOTH);
    return TRUE;
}

static gboolean
as_simple_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (args->output_ty != NULL) {
        free(args->output_ty);
    }

    args->output_ty = strdup("text");
    output_format = mon_output_monitor;
    options.mon_ops |= mon_op_one_shot;
    return TRUE;
}

static gboolean
as_xml_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (args->output_ty != NULL) {
        free(args->output_ty);
    }

    args->output_ty = strdup("xml");
    output_format = mon_output_legacy_xml;
    options.mon_ops |= mon_op_one_shot;
    return TRUE;
}

static gboolean
fence_history_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    interactive_fence_level = crm_atoi(optarg, "2");

    switch (interactive_fence_level) {
        case 3:
            options.mon_ops |= mon_op_fence_full_history | mon_op_fence_history | mon_op_fence_connect;
            return include_exclude_cb("--include", "fencing", data, err);

        case 2:
            options.mon_ops |= mon_op_fence_history | mon_op_fence_connect;
            return include_exclude_cb("--include", "fencing", data, err);

        case 1:
            options.mon_ops |= mon_op_fence_history | mon_op_fence_connect;
            return include_exclude_cb("--include", "fencing-failed,fencing-pending", data, err);

        case 0:
            options.mon_ops &= ~(mon_op_fence_history | mon_op_fence_connect);
            return include_exclude_cb("--exclude", "fencing", data, err);

        default:
            g_set_error(err, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "Fence history must be 0-3");
            return FALSE;
    }
}

static gboolean
group_by_node_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_group_by_node;
    return TRUE;
}

static gboolean
hide_headers_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return include_exclude_cb("--exclude", "summary", data, err);
}

static gboolean
inactive_resources_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_inactive_resources;
    return TRUE;
}

static gboolean
no_curses_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    output_format = mon_output_plain;
    return TRUE;
}

static gboolean
one_shot_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_one_shot;
    return TRUE;
}

static gboolean
print_brief_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_print_brief;
    return TRUE;
}

static gboolean
print_clone_detail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_print_clone_detail;
    return TRUE;
}

static gboolean
print_pending_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_print_pending;
    return TRUE;
}

static gboolean
print_timing_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_print_timing;
    return include_exclude_cb("--include", "operations", data, err);
}

static gboolean
reconnect_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    int rc = crm_get_msec(optarg);

    if (rc == -1) {
        g_set_error(err, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "Invalid value for -i: %s", optarg);
        return FALSE;
    } else {
        options.reconnect_msec = crm_parse_interval_spec(optarg);
    }

    return TRUE;
}

static gboolean
show_attributes_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return include_exclude_cb("--include", "attributes", data, err);
}

static gboolean
show_bans_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (optarg != NULL) {
        char *s = crm_strdup_printf("bans:%s", optarg);
        gboolean rc = include_exclude_cb("--include", s, data, err);
        free(s);
        return rc;
    } else {
        return include_exclude_cb("--include", "bans", data, err);
    }
}

static gboolean
show_failcounts_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return include_exclude_cb("--include", "failcounts", data, err);
}

static gboolean
show_operations_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return include_exclude_cb("--include", "failcounts,operations", data, err);
}

static gboolean
show_tickets_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return include_exclude_cb("--include", "tickets", data, err);
}

static gboolean
use_cib_file_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    setenv("CIB_file", optarg, 1);
    options.mon_ops |= mon_op_one_shot;
    return TRUE;
}

static gboolean
watch_fencing_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.mon_ops |= mon_op_watch_fencing;
    return TRUE;
}

#define INDENT "                                    "

/* *INDENT-OFF* */
static GOptionEntry addl_entries[] = {
    { "interval", 'i', 0, G_OPTION_ARG_CALLBACK, reconnect_cb,
      "Update frequency (default is 5 seconds)",
      "TIMESPEC" },

    { "one-shot", '1', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, one_shot_cb,
      "Display the cluster status once on the console and exit",
      NULL },

    { "daemonize", 'd', 0, G_OPTION_ARG_NONE, &options.daemonize,
      "Run in the background as a daemon.\n"
      INDENT "Requires at least one of --output-to and --external-agent.",
      NULL },

    { "pid-file", 'p', 0, G_OPTION_ARG_FILENAME, &options.pid_file,
      "(Advanced) Daemon pid file location",
      "FILE" },

    { "external-agent", 'E', 0, G_OPTION_ARG_FILENAME, &options.external_agent,
      "A program to run when resource operations take place",
      "FILE" },

    { "external-recipient", 'e', 0, G_OPTION_ARG_STRING, &options.external_recipient,
      "A recipient for your program (assuming you want the program to send something to someone).",
      "RCPT" },

    { "watch-fencing", 'W', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, watch_fencing_cb,
      "Listen for fencing events. For use with --external-agent.",
      NULL },

    { "xml-file", 'x', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, use_cib_file_cb,
      NULL,
      NULL },

    { NULL }
};

static GOptionEntry display_entries[] = {
    { "include", 'I', 0, G_OPTION_ARG_CALLBACK, user_include_exclude_cb,
      "A list of sections to include in the output.\n"
      INDENT "See `Output Control` help for more information.",
      "SECTION(s)" },

    { "exclude", 'U', 0, G_OPTION_ARG_CALLBACK, user_include_exclude_cb,
      "A list of sections to exclude from the output.\n"
      INDENT "See `Output Control` help for more information.",
      "SECTION(s)" },

    { "node", 0, 0, G_OPTION_ARG_STRING, &options.only_node,
      "When displaying information about nodes, show only what's related to the given\n"
      INDENT "node, or to all nodes tagged with the given tag",
      "NODE" },

    { "resource", 0, 0, G_OPTION_ARG_STRING, &options.only_rsc,
      "When displaying information about resources, show only what's related to the given\n"
      INDENT "resource, or to all resources tagged with the given tag",
      "RSC" },

    { "group-by-node", 'n', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, group_by_node_cb,
      "Group resources by node",
      NULL },

    { "inactive", 'r', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, inactive_resources_cb,
      "Display inactive resources",
      NULL },

    { "failcounts", 'f', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, show_failcounts_cb,
      "Display resource fail counts",
      NULL },

    { "operations", 'o', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, show_operations_cb,
      "Display resource operation history",
      NULL },

    { "timing-details", 't', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, print_timing_cb,
      "Display resource operation history with timing details",
      NULL },

    { "tickets", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, show_tickets_cb,
      "Display cluster tickets",
      NULL },

    { "fence-history", 'm', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, fence_history_cb,
      "Show fence history:\n"
      INDENT "0=off, 1=failures and pending (default without option),\n"
      INDENT "2=add successes (default without value for option),\n"
      INDENT "3=show full history without reduction to most recent of each flavor",
      "LEVEL" },

    { "neg-locations", 'L', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, show_bans_cb,
      "Display negative location constraints [optionally filtered by id prefix]",
      NULL },

    { "show-node-attributes", 'A', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, show_attributes_cb,
      "Display node attributes",
      NULL },

    { "hide-headers", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, hide_headers_cb,
      "Hide all headers",
      NULL },

    { "show-detail", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, print_clone_detail_cb,
      "Show more details (node IDs, individual clone instances)",
      NULL },

    { "brief", 'b', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, print_brief_cb,
      "Brief output",
      NULL },

    { "pending", 'j', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, print_pending_cb,
      "Display pending state if 'record-pending' is enabled",
      NULL },

    { "simple-status", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, as_simple_cb,
      "Display the cluster status once as a simple one line output (suitable for nagios)",
      NULL },

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
    { "as-html", 'h', G_OPTION_FLAG_FILENAME, G_OPTION_ARG_CALLBACK, as_html_cb,
      "Write cluster status to the named HTML file.\n"
      INDENT "Use --output-as=html --output-to=FILE instead.",
      "FILE" },

    { "as-xml", 'X', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, as_xml_cb,
      "Write cluster status as XML to stdout. This will enable one-shot mode.\n"
      INDENT "Use --output-as=xml instead.",
      NULL },

    { "disable-ncurses", 'N', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, no_curses_cb,
      "Disable the use of ncurses.\n"
      INDENT "Use --output-as=text instead.",
      NULL },

    { "web-cgi", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, as_cgi_cb,
      "Web mode with output suitable for CGI (preselected when run as *.cgi).\n"
      INDENT "Use --output-as=html --html-cgi instead.",
      NULL },

    { NULL }
};
/* *INDENT-ON* */

/* Reconnect to the CIB and fencing agent after reconnect_msec has passed.  This sounds
 * like it would be more broadly useful, but only ever happens after a disconnect via
 * mon_cib_connection_destroy.
 */
static gboolean
reconnect_after_timeout(gpointer data)
{
#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        clear();
        refresh();
    }
#endif

    print_as(output_format, "Reconnecting...\n");
    if (pacemakerd_status() == pcmk_rc_ok) {
        fencing_connect();
        if (cib_connect(TRUE) == pcmk_rc_ok) {
            /* trigger redrawing the screen (needs reconnect_timer == 0) */
            reconnect_timer = 0;
            refresh_after_event(FALSE, TRUE);
            return G_SOURCE_REMOVE;
        }
    }

    reconnect_timer = g_timeout_add(options.reconnect_msec, reconnect_after_timeout, NULL);
    return G_SOURCE_REMOVE;
}

/* Called from various places when we are disconnected from the CIB or from the
 * fencing agent.  If the CIB connection is still valid, this function will also
 * attempt to sign off and reconnect.
 */
static void
mon_cib_connection_destroy(gpointer user_data)
{
    out->info(out, "Connection to the cluster-daemons terminated");

    if (refresh_timer != NULL) {
        /* we'll trigger a refresh after reconnect */
        mainloop_timer_stop(refresh_timer);
    }
    if (reconnect_timer) {
        /* we'll trigger a new reconnect-timeout at the end */
        g_source_remove(reconnect_timer);
        reconnect_timer = 0;
    }
    if (st) {
        /* the client API won't properly reconnect notifications
         * if they are still in the table - so remove them
         */
        clean_up_fencing_connection();
    }
    if (cib) {
        cib->cmds->signoff(cib);
        reconnect_timer = g_timeout_add(options.reconnect_msec, reconnect_after_timeout, NULL);
    }
    return;
}

/* Signal handler installed into the mainloop for normal program shutdown */
static void
mon_shutdown(int nsig)
{
    clean_up(CRM_EX_OK);
}

#if CURSES_ENABLED
static sighandler_t ncurses_winch_handler;

/* Signal handler installed the regular way (not into the main loop) for when
 * the screen is resized.  Commonly, this happens when running in an xterm and
 * the user changes its size.
 */
static void
mon_winresize(int nsig)
{
    static int not_done;
    int lines = 0, cols = 0;

    if (!not_done++) {
        if (ncurses_winch_handler)
            /* the original ncurses WINCH signal handler does the
             * magic of retrieving the new window size;
             * otherwise, we'd have to use ioctl or tgetent */
            (*ncurses_winch_handler) (SIGWINCH);
        getmaxyx(stdscr, lines, cols);
        resizeterm(lines, cols);
        /* Alert the mainloop code we'd like the refresh_trigger to run next
         * time the mainloop gets around to checking.
         */
        mainloop_set_trigger(refresh_trigger);
    }
    not_done--;
}
#endif

static int
fencing_connect(void)
{
    int rc = pcmk_ok;

    if (pcmk_is_set(options.mon_ops, mon_op_fence_connect) && (st == NULL)) {
        st = stonith_api_new();
    }

    if (!pcmk_is_set(options.mon_ops, mon_op_fence_connect) ||
        st == NULL || st->state != stonith_disconnected) {
        return rc;
    }

    rc = st->cmds->connect(st, crm_system_name, NULL);
    if (rc == pcmk_ok) {
        crm_trace("Setting up stonith callbacks");
        if (pcmk_is_set(options.mon_ops, mon_op_watch_fencing)) {
            st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT,
                                            mon_st_callback_event);
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback_event);
        } else {
            st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT,
                                            mon_st_callback_display);
            st->cmds->register_notification(st, T_STONITH_NOTIFY_HISTORY, mon_st_callback_display);
        }
    } else {
        clean_up_fencing_connection();
    }

    return rc;
}

static int
cib_connect(gboolean full)
{
    int rc = pcmk_rc_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if (cib->state == cib_connected_query ||
        cib->state == cib_connected_command) {
        return rc;
    }

    crm_trace("Connecting to the CIB");

    /* Hack: the CIB signon will print the prompt for a password if needed,
     * but to stderr. If we're in curses, show it on the screen instead.
     *
     * @TODO Add a password prompt (maybe including input) function to
     *       pcmk__output_t and use it in libcib.
     */
    if ((output_format == mon_output_console) &&
         need_pass &&
         (cib->variant == cib_remote)) {
        need_pass = FALSE;
        print_as(output_format, "Password:");
    }

    rc = pcmk_legacy2rc(cib->cmds->signon(cib, crm_system_name, cib_query));
    if (rc != pcmk_rc_ok) {
        out->err(out, "Could not connect to the CIB: %s",
                 pcmk_rc_str(rc));
        return rc;
    }

#if CURSES_ENABLED
    /* just show this if refresh is gonna remove all traces */
    if (output_format == mon_output_console) {
        print_as(output_format ,"Waiting for CIB ...\n");
    }
#endif

    rc = pcmk_legacy2rc(cib->cmds->query(cib, NULL, &current_cib,
                                         cib_scope_local | cib_sync_call));

    if (rc == pcmk_rc_ok && full) {
        rc = pcmk_legacy2rc(cib->cmds->set_connection_dnotify(cib,
            mon_cib_connection_destroy));
        if (rc == EPROTONOSUPPORT) {
            print_as(output_format,
                     "Notification setup not supported, won't be "
                     "able to reconnect after failure");
            if (output_format == mon_output_console) {
                sleep(2);
            }
            rc = pcmk_rc_ok;
        }

        if (rc == pcmk_rc_ok) {
            cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY,
                                           crm_diff_update);
            rc = pcmk_legacy2rc(cib->cmds->add_notify_callback(cib,
                                    T_CIB_DIFF_NOTIFY, crm_diff_update));
        }

        if (rc != pcmk_rc_ok) {
            out->err(out, "Notification setup failed, could not monitor CIB actions");
            clean_up_cib_connection();
            clean_up_fencing_connection();
        }
    }
    return rc;
}

/* This is used to set up the fencing options after the interactive UI has been stared.
 * fence_history_cb can't be used because it builds up a list of includes/excludes that
 * then have to be processed with apply_include_exclude and that could affect other
 * things.
 */
static void
set_fencing_options(int level)
{
    switch (level) {
        case 3:
            options.mon_ops |= mon_op_fence_full_history | mon_op_fence_history | mon_op_fence_connect;
            show |= mon_show_fencing_all;
            break;

        case 2:
            options.mon_ops |= mon_op_fence_history | mon_op_fence_connect;
            show |= mon_show_fencing_all;
            break;

        case 1:
            options.mon_ops |= mon_op_fence_history | mon_op_fence_connect;
            show |= mon_show_fence_failed | mon_show_fence_pending;
            break;

        default:
            level = 0;
            options.mon_ops &= ~(mon_op_fence_history | mon_op_fence_connect);
            show &= ~mon_show_fencing_all;
            break;
    }
}

/* Before trying to connect to fencer or cib check for state of
   pacemakerd - just no sense in trying till pacemakerd has
   taken care of starting all the sub-processes

   Only noteworthy thing to show here is when pacemakerd is
   waiting for startup-trigger from SBD.
 */
static void
pacemakerd_event_cb(pcmk_ipc_api_t *pacemakerd_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_pacemakerd_api_reply_t *reply = event_data;
    enum pcmk_pacemakerd_state *state =
        (enum pcmk_pacemakerd_state *) user_data;

    /* we are just interested in the latest reply */
    *state = pcmk_pacemakerd_state_invalid;

    switch (event_type) {
        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (status != CRM_EX_OK) {
        out->err(out, "Bad reply from pacemakerd: %s",
                 crm_exit_str(status));
        return;
    }

    if (reply->reply_type != pcmk_pacemakerd_reply_ping) {
        out->err(out, "Unknown reply type %d from pacemakerd",
                 reply->reply_type);
    } else {
        if ((reply->data.ping.last_good != (time_t) 0) &&
            (reply->data.ping.status == pcmk_rc_ok)) {
            *state = reply->data.ping.state;
        }
    }
}

static int
pacemakerd_status(void)
{
    int rc = pcmk_rc_ok;
    pcmk_ipc_api_t *pacemakerd_api = NULL;
    enum pcmk_pacemakerd_state state = pcmk_pacemakerd_state_invalid;

    if (!pcmk_is_set(options.mon_ops, mon_op_cib_native)) {
        /* we don't need fully functional pacemakerd otherwise */
        return rc;
    }
    if (cib != NULL &&
        (cib->state == cib_connected_query ||
         cib->state == cib_connected_command)) {
        /* As long as we have a cib-connection let's go with
         * that to fetch further cluster-status and avoid
         * unnecessary pings to pacemakerd.
         * If cluster is going down and fencer is down already
         * this will lead to a silently failing fencer reconnect.
         * On cluster startup we shouldn't see this situation
         * as first we do is wait for pacemakerd to report all
         * daemons running.
         */
        return rc;
    }
    rc = pcmk_new_ipc_api(&pacemakerd_api, pcmk_ipc_pacemakerd);
    if (pacemakerd_api == NULL) {
        out->err(out, "Could not connect to pacemakerd: %s",
                 pcmk_rc_str(rc));
        /* this is unrecoverable so return with rc we have */
        return rc;
    }
    pcmk_register_ipc_callback(pacemakerd_api, pacemakerd_event_cb, (void *) &state);
    rc = pcmk_connect_ipc(pacemakerd_api, pcmk_ipc_dispatch_poll);
    switch (rc) {
        case pcmk_rc_ok:
            rc = pcmk_pacemakerd_api_ping(pacemakerd_api, crm_system_name);
            if (rc == pcmk_rc_ok) {
                rc = pcmk_poll_ipc(pacemakerd_api, options.reconnect_msec/2);
                if (rc == pcmk_rc_ok) {
                    pcmk_dispatch_ipc(pacemakerd_api);
                    rc = ENOTCONN;
                    if ((output_format == mon_output_console) ||
                        (output_format == mon_output_plain)) {
                        switch (state) {
                            case pcmk_pacemakerd_state_running:
                                rc = pcmk_rc_ok;
                                break;
                            case pcmk_pacemakerd_state_starting_daemons:
                                print_as(output_format ,"Pacemaker daemons starting ...\n");
                                break;
                            case pcmk_pacemakerd_state_wait_for_ping:
                                print_as(output_format ,"Waiting for startup-trigger from SBD ...\n");
                                break;
                            case pcmk_pacemakerd_state_shutting_down:
                                print_as(output_format ,"Pacemaker daemons shutting down ...\n");
                                break;
                            case pcmk_pacemakerd_state_shutdown_complete:
                                /* assuming pacemakerd doesn't dispatch any pings after entering
                                * that state unless it is waiting for SBD
                                */
                                print_as(output_format ,"Pacemaker daemons shut down - reporting to SBD ...\n");
                                break;
                            default:
                                break;
                        }
                    } else {
                        switch (state) {
                            case pcmk_pacemakerd_state_running:
                                rc = pcmk_rc_ok;
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
            break;
        case EREMOTEIO:
            rc = pcmk_rc_ok;
            on_remote_node = TRUE;
#if CURSES_ENABLED
            /* just show this if refresh is gonna remove all traces */
            if (output_format == mon_output_console) {
                print_as(output_format ,
                    "Running on remote-node waiting to be connected by cluster ...\n");
            }
#endif
            break;
        default:
            break;
    }
    pcmk_free_ipc_api(pacemakerd_api);
    /* returning with ENOTCONN triggers a retry */
    return (rc == pcmk_rc_ok)?rc:ENOTCONN;
}

#if CURSES_ENABLED
static const char *
get_option_desc(char c)
{
    const char *desc = "No help available";

    for (GOptionEntry *entry = display_entries; entry != NULL; entry++) {
        if (entry->short_name == c) {
            desc = entry->description;
            break;
        }
    }
    return desc;
}

#define print_option_help(output_format, option, condition) \
    out->info(out, "%c %c: \t%s", ((condition)? '*': ' '), option, get_option_desc(option));

/* This function is called from the main loop when there is something to be read
 * on stdin, like an interactive user's keystroke.  All it does is read the keystroke,
 * set flags (or show the page showing which keystrokes are valid), and redraw the
 * screen.  It does not do anything with connections to the CIB or fencing agent
 * agent what would happen in mon_refresh_display.
 */
static gboolean
detect_user_input(GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
    int c;
    gboolean config_mode = FALSE;

    while (1) {

        /* Get user input */
        c = getchar();

        switch (c) {
            case 'm':
                interactive_fence_level++;
                if (interactive_fence_level > 3) {
                    interactive_fence_level = 0;
                }

                set_fencing_options(interactive_fence_level);
                break;
            case 'c':
                show ^= mon_show_tickets;
                break;
            case 'f':
                show ^= mon_show_failcounts;
                break;
            case 'n':
                options.mon_ops ^= mon_op_group_by_node;
                break;
            case 'o':
                show ^= mon_show_operations;
                if (!pcmk_is_set(show, mon_show_operations)) {
                    options.mon_ops &= ~mon_op_print_timing;
                }
                break;
            case 'r':
                options.mon_ops ^= mon_op_inactive_resources;
                break;
            case 'R':
                options.mon_ops ^= mon_op_print_clone_detail;
                break;
            case 't':
                options.mon_ops ^= mon_op_print_timing;
                if (pcmk_is_set(options.mon_ops, mon_op_print_timing)) {
                    show |= mon_show_operations;
                }
                break;
            case 'A':
                show ^= mon_show_attributes;
                break;
            case 'L':
                show ^= mon_show_bans;
                break;
            case 'D':
                /* If any header is shown, clear them all, otherwise set them all */
                if (pcmk_any_flags_set(show,
                                       mon_show_stack
                                       |mon_show_dc
                                       |mon_show_times
                                       |mon_show_counts)) {
                    show &= ~mon_show_summary;
                } else {
                    show |= mon_show_summary;
                }
                /* Regardless, we don't show options in console mode. */
                show &= ~mon_show_options;
                break;
            case 'b':
                options.mon_ops ^= mon_op_print_brief;
                break;
            case 'j':
                options.mon_ops ^= mon_op_print_pending;
                break;
            case '?':
                config_mode = TRUE;
                break;
            default:
                /* All other keys just redraw the screen. */
                goto refresh;
        }

        if (!config_mode)
            goto refresh;

        blank_screen();

        out->info(out, "%s", "Display option change mode\n");
        print_option_help(out, 'c', pcmk_is_set(show, mon_show_tickets));
        print_option_help(out, 'f', pcmk_is_set(show, mon_show_failcounts));
        print_option_help(out, 'n', pcmk_is_set(options.mon_ops, mon_op_group_by_node));
        print_option_help(out, 'o', pcmk_is_set(show, mon_show_operations));
        print_option_help(out, 'r', pcmk_is_set(options.mon_ops, mon_op_inactive_resources));
        print_option_help(out, 't', pcmk_is_set(options.mon_ops, mon_op_print_timing));
        print_option_help(out, 'A', pcmk_is_set(show, mon_show_attributes));
        print_option_help(out, 'L', pcmk_is_set(show,mon_show_bans));
        print_option_help(out, 'D', !pcmk_is_set(show, mon_show_summary));
        print_option_help(out, 'R', pcmk_is_set(options.mon_ops, mon_op_print_clone_detail));
        print_option_help(out, 'b', pcmk_is_set(options.mon_ops, mon_op_print_brief));
        print_option_help(out, 'j', pcmk_is_set(options.mon_ops, mon_op_print_pending));
        out->info(out, "%d m: \t%s", interactive_fence_level, get_option_desc('m'));
        out->info(out, "%s", "\nToggle fields via field letter, type any other key to return");
    }

refresh:
    refresh_after_event(FALSE, TRUE);

    return TRUE;
}
#endif

// Basically crm_signal_handler(SIGCHLD, SIG_IGN) plus the SA_NOCLDWAIT flag
static void
avoid_zombies(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    if (sigemptyset(&sa.sa_mask) < 0) {
        crm_warn("Cannot avoid zombies: %s", pcmk_strerror(errno));
        return;
    }
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART|SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        crm_warn("Cannot avoid zombies: %s", pcmk_strerror(errno));
    }
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

    const char *description = "Notes:\n\n"
                              "If this program is called as crm_mon.cgi, --output-as=html --html-cgi will\n"
                              "automatically be added to the command line arguments.\n\n"
                              "Time Specification:\n\n"
                              "The TIMESPEC in any command line option can be specified in many different\n"
                              "formats.  It can be just an integer number of seconds, a number plus units\n"
                              "(ms/msec/us/usec/s/sec/m/min/h/hr), or an ISO 8601 period specification.\n\n"
                              "Output Control:\n\n"
                              "By default, a certain list of sections are written to the output destination.\n"
                              "The default varies based on the output format - XML includes everything, while\n"
                              "other output formats will display less.  This list can be modified with the\n"
                              "--include and --exclude command line options.  Each option may be given multiple\n"
                              "times on the command line, and each can give a comma-separated list of sections.\n"
                              "The options are applied to the default set, from left to right as seen on the\n"
                              "command line.  For a list of valid sections, pass --include=list or --exclude=list.\n\n"
                              "Interactive Use:\n\n"
                              "When run interactively, crm_mon can be told to hide and display various sections\n"
                              "of output.  To see a help screen explaining the options, hit '?'.  Any key stroke\n"
                              "aside from those listed will cause the screen to refresh.\n\n"
                              "Examples:\n\n"
                              "Display the cluster status on the console with updates as they occur:\n\n"
                              "\tcrm_mon\n\n"
                              "Display the cluster status on the console just once then exit:\n\n"
                              "\tcrm_mon -1\n\n"
                              "Display your cluster status, group resources by node, and include inactive resources in the list:\n\n"
                              "\tcrm_mon --group-by-node --inactive\n\n"
                              "Start crm_mon as a background daemon and have it write the cluster status to an HTML file:\n\n"
                              "\tcrm_mon --daemonize --output-as html --output-to /path/to/docroot/filename.html\n\n"
                              "Start crm_mon and export the current cluster status as XML to stdout, then exit:\n\n"
                              "\tcrm_mon --output-as xml\n\n";

    context = pcmk__build_arg_context(args, "console (default), html, text, xml", group, NULL);
    pcmk__add_main_args(context, extra_prog_entries);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "display", "Display Options:",
                        "Show display options", display_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    pcmk__add_arg_group(context, "deprecated", "Deprecated Options:",
                        "Show deprecated options", deprecated_entries);

    return context;
}

/* If certain format options were specified, we want to set some extra
 * options.  We can just process these like they were given on the
 * command line.
 */
static void
add_output_args(void) {
    GError *err = NULL;

    if (output_format == mon_output_plain) {
        if (!pcmk__force_args(context, &err, "%s --text-fancy", g_get_prgname())) {
            g_propagate_error(&error, err);
            clean_up(CRM_EX_USAGE);
        }
    } else if (output_format == mon_output_cgi) {
        if (!pcmk__force_args(context, &err, "%s --html-cgi", g_get_prgname())) {
            g_propagate_error(&error, err);
            clean_up(CRM_EX_USAGE);
        }
    } else if (output_format == mon_output_xml) {
        if (!pcmk__force_args(context, &err, "%s --xml-simple-list --xml-substitute", g_get_prgname())) {
            g_propagate_error(&error, err);
            clean_up(CRM_EX_USAGE);
        }
    } else if (output_format == mon_output_legacy_xml) {
        output_format = mon_output_xml;
        if (!pcmk__force_args(context, &err, "%s --xml-legacy --xml-substitute", g_get_prgname())) {
            g_propagate_error(&error, err);
            clean_up(CRM_EX_USAGE);
        }
    }
}

/* Which output format to use could come from two places:  The --as-xml
 * style arguments we gave in deprecated_entries above, or the formatted output
 * arguments added by pcmk__register_formats.  If the latter were used,
 * output_format will be mon_output_unset.
 *
 * Call the callbacks as if those older style arguments were provided so
 * the various things they do get done.
 */
static void
reconcile_output_format(pcmk__common_args_t *args) {
    gboolean retval = TRUE;
    GError *err = NULL;

    if (output_format != mon_output_unset) {
        return;
    }

    if (pcmk__str_eq(args->output_ty, "html", pcmk__str_casei)) {
        char *dest = NULL;

        if (args->output_dest != NULL) {
            dest = strdup(args->output_dest);
        }

        retval = as_html_cb("h", dest, NULL, &err);
        free(dest);
    } else if (pcmk__str_eq(args->output_ty, "text", pcmk__str_casei)) {
        retval = no_curses_cb("N", NULL, NULL, &err);
    } else if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_casei)) {
        if (args->output_ty != NULL) {
            free(args->output_ty);
        }

        args->output_ty = strdup("xml");
        output_format = mon_output_xml;
        options.mon_ops |= mon_op_one_shot;
    } else if (pcmk_is_set(options.mon_ops, mon_op_one_shot)) {
        if (args->output_ty != NULL) {
            free(args->output_ty);
        }

        args->output_ty = strdup("text");
        output_format = mon_output_plain;
    } else {
        /* Neither old nor new arguments were given, so set the default. */
        if (args->output_ty != NULL) {
            free(args->output_ty);
        }

        args->output_ty = strdup("console");
        output_format = mon_output_console;
    }

    if (!retval) {
        g_propagate_error(&error, err);
        clean_up(CRM_EX_USAGE);
    }
}

static void
handle_connection_failures(int rc)
{
    if (rc == pcmk_rc_ok) {
        return;
    }

    if (output_format == mon_output_monitor) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "CLUSTER CRIT: Connection to cluster failed: %s",
                    pcmk_rc_str(rc));
        rc = MON_STATUS_CRIT;
    } else if (rc == ENOTCONN) {
        if (on_remote_node) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "Error: remote-node not connected to cluster");
        } else {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "Error: cluster is not available on this node");
        }
        rc = pcmk_rc2exitc(rc);
    } else {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "Connection to cluster failed: %s", pcmk_rc_str(rc));
        rc = pcmk_rc2exitc(rc);
    }

    clean_up(rc);
}

static void
one_shot(void)
{
    int rc;

    rc = pacemakerd_status();

    if (rc == pcmk_rc_ok) {
        fencing_connect();
        rc = cib_connect(FALSE);
    }

    if (rc == pcmk_rc_ok) {
        mon_refresh_display(NULL);
    } else {
        handle_connection_failures(rc);
    }

    clean_up(CRM_EX_OK);
}

int
main(int argc, char **argv)
{
    int rc = pcmk_ok;
    GOptionGroup *output_group = NULL;

    args = pcmk__new_common_args(SUMMARY);
    context = build_arg_context(args, &output_group);
    pcmk__register_formats(output_group, formats);

    options.pid_file = strdup("/tmp/ClusterMon.pid");
    crm_log_cli_init("crm_mon");

    // Avoid needing to wait for subprocesses forked for -E/--external-agent
    avoid_zombies();

    if (pcmk__ends_with_ext(argv[0], ".cgi")) {
        output_format = mon_output_cgi;
        options.mon_ops |= mon_op_one_shot;
    }

    processed_args = pcmk__cmdline_preproc(argv, "ehimpxEILU");

    fence_history_cb("--fence-history", "1", NULL, NULL);

    /* Set an HTML title regardless of what format we will eventually use.  This can't
     * be done in add_output_args.  That function is called after command line
     * arguments are processed in the next block, which means it'll override whatever
     * title the user provides.  Doing this here means the user can give their own
     * title on the command line.
     */
    if (!pcmk__force_args(context, &error, "%s --html-title \"Cluster Status\"",
                          g_get_prgname())) {
        return clean_up(CRM_EX_USAGE);
    }

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        return clean_up(CRM_EX_USAGE);
    }

    for (int i = 0; i < args->verbosity; i++) {
        crm_bump_log_level(argc, argv);
    }

    if (!args->version) {
        if (args->quiet) {
            include_exclude_cb("--exclude", "times", NULL, NULL);
        }

        if (pcmk_is_set(options.mon_ops, mon_op_watch_fencing)) {
            fence_history_cb("--fence-history", "0", NULL, NULL);
            options.mon_ops |= mon_op_fence_connect;
        }

        /* create the cib-object early to be able to do further
         * decisions based on the cib-source
         */
        cib = cib_new();

        if (cib == NULL) {
            rc = -EINVAL;
        } else {
            switch (cib->variant) {

                case cib_native:
                    /* cib & fencing - everything available */
                    options.mon_ops |= mon_op_cib_native;
                    break;

                case cib_file:
                    /* Don't try to connect to fencing as we
                     * either don't have a running cluster or
                     * the fencing-information would possibly
                     * not match the cib data from a file.
                     * As we don't expect cib-updates coming
                     * in enforce one-shot. */
                    fence_history_cb("--fence-history", "0", NULL, NULL);
                    options.mon_ops |= mon_op_one_shot;
                    break;

                case cib_remote:
                    /* updates coming in but no fencing */
                    fence_history_cb("--fence-history", "0", NULL, NULL);
                    break;

                case cib_undefined:
                case cib_database:
                default:
                    /* something is odd */
                    rc = -EINVAL;
                    break;
            }
        }

        if (pcmk_is_set(options.mon_ops, mon_op_one_shot)) {
            if (output_format == mon_output_console) {
                output_format = mon_output_plain;
            }

        } else if (options.daemonize) {
            if ((output_format == mon_output_console) || (output_format == mon_output_plain)) {
                output_format = mon_output_none;
            }
            crm_enable_stderr(FALSE);

            if (pcmk__str_eq(args->output_dest, "-", pcmk__str_null_matches | pcmk__str_casei) && !options.external_agent) {
                g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "--daemonize requires at least one of --output-to and --external-agent");
                return clean_up(CRM_EX_USAGE);
            }

            if (cib) {
                /* to be on the safe side don't have cib-object around
                 * when we are forking
                 */
                cib_delete(cib);
                cib = NULL;
                pcmk__daemonize(crm_system_name, options.pid_file);
                cib = cib_new();
                if (cib == NULL) {
                    rc = -EINVAL;
                }
                /* otherwise assume we've got the same cib-object we've just destroyed
                 * in our parent
                 */
            }


        } else if (output_format == mon_output_console) {
#if CURSES_ENABLED
            crm_enable_stderr(FALSE);
#else
            options.mon_ops |= mon_op_one_shot;
            output_format = mon_output_plain;
            printf("Defaulting to one-shot mode\n");
            printf("You need to have curses available at compile time to enable console mode\n");
#endif
        }
    }

    if (rc != pcmk_ok) {
        // Shouldn't really be possible
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "Invalid CIB source");
        return clean_up(CRM_EX_ERROR);
    }

    reconcile_output_format(args);
    add_output_args();

    if (args->version && output_format == mon_output_console) {
        /* Use the text output format here if we are in curses mode but were given
         * --version.  Displaying version information uses printf, and then we
         *  immediately exit.  We don't want to initialize curses for that.
         */
        rc = pcmk__output_new(&out, "text", args->output_dest, argv);
    } else {
        rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    }

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_ERROR, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        return clean_up(CRM_EX_ERROR);
    }

    /* output_format MUST NOT BE CHANGED AFTER THIS POINT. */

    /* Apply --include/--exclude flags we used internally.  There's no error reporting
     * here because this would be a programming error.
     */
    apply_include_exclude(options.includes_excludes, output_format, &error);

    /* And now apply any --include/--exclude flags the user gave on the command line.
     * These are done in a separate pass from the internal ones because we want to
     * make sure whatever the user specifies overrides whatever we do.
     */
    if (!apply_include_exclude(options.user_includes_excludes, output_format, &error)) {
        return clean_up(CRM_EX_USAGE);
    }

    /* Sync up the initial value of interactive_fence_level with whatever was set with
     * --include/--exclude= options.
     */
    if (pcmk_is_set(show, mon_show_fencing_all)) {
        interactive_fence_level = 3;
    } else if (pcmk_is_set(show, mon_show_fence_worked)) {
        interactive_fence_level = 2;
    } else if (pcmk_any_flags_set(show, mon_show_fence_failed | mon_show_fence_pending)) {
        interactive_fence_level = 1;
    } else {
        interactive_fence_level = 0;
    }

    crm_mon_register_messages(out);
    pe__register_messages(out);
    stonith__register_messages(out);

    if (args->version) {
        out->version(out, false);
        return clean_up(CRM_EX_OK);
    }

    /* Extra sanity checks when in CGI mode */
    if (output_format == mon_output_cgi) {
        if (cib->variant == cib_file) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "CGI mode used with CIB file");
            return clean_up(CRM_EX_USAGE);
        } else if (options.external_agent != NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "CGI mode cannot be used with --external-agent");
            return clean_up(CRM_EX_USAGE);
        } else if (options.daemonize == TRUE) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "CGI mode cannot be used with -d");
            return clean_up(CRM_EX_USAGE);
        }
    }

    if (output_format == mon_output_xml || output_format == mon_output_legacy_xml) {
        options.mon_ops |= mon_op_print_timing | mon_op_inactive_resources;
    }

    if ((output_format == mon_output_html || output_format == mon_output_cgi) &&
        out->dest != stdout) {
        pcmk__html_add_header("meta", "http-equiv", "refresh", "content",
                              crm_itoa(options.reconnect_msec/1000), NULL);
    }

    crm_info("Starting %s", crm_system_name);

    if (pcmk_is_set(options.mon_ops, mon_op_one_shot)) {
        one_shot();
    }

    do {
        print_as(output_format ,"Waiting until cluster is available on this node ...\n");

        rc = pacemakerd_status();
        if (rc == pcmk_rc_ok) {
            fencing_connect();
            rc = cib_connect(TRUE);
        }

        if (rc != pcmk_rc_ok) {
            sleep(options.reconnect_msec / 1000);
#if CURSES_ENABLED
            if (output_format == mon_output_console) {
                clear();
                refresh();
            }
#endif
        } else if (output_format == mon_output_html && out->dest != stdout) {
            printf("Writing html to %s ...\n", args->output_dest);
        }

    } while (rc == ENOTCONN);

    handle_connection_failures(rc);
    set_fencing_options(interactive_fence_level);
    mon_refresh_display(NULL);

    mainloop = g_main_loop_new(NULL, FALSE);

    mainloop_add_signal(SIGTERM, mon_shutdown);
    mainloop_add_signal(SIGINT, mon_shutdown);
#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        ncurses_winch_handler = crm_signal_handler(SIGWINCH, mon_winresize);
        if (ncurses_winch_handler == SIG_DFL ||
            ncurses_winch_handler == SIG_IGN || ncurses_winch_handler == SIG_ERR)
            ncurses_winch_handler = NULL;

        io_channel = g_io_channel_unix_new(STDIN_FILENO);
        g_io_add_watch(io_channel, G_IO_IN, detect_user_input, NULL);
    }
#endif

    /* When refresh_trigger->trigger is set to TRUE, call mon_refresh_display.  In
     * this file, that is anywhere mainloop_set_trigger is called.
     */
    refresh_trigger = mainloop_add_trigger(G_PRIORITY_LOW, mon_refresh_display, NULL);

    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    if (io_channel != NULL) {
        g_io_channel_shutdown(io_channel, TRUE, NULL);
    }

    crm_info("Exiting %s", crm_system_name);

    return clean_up(CRM_EX_OK);
}

/*!
 * \internal
 * \brief Print one-line status suitable for use with monitoring software
 *
 * \param[in] data_set  Working set of CIB state
 *
 * \note This function's output (and the return code when the program exits)
 *       should conform to https://www.monitoring-plugins.org/doc/guidelines.html
 */
static void
print_simple_status(pcmk__output_t *out, pe_working_set_t * data_set,
                    unsigned int mon_ops)
{
    GListPtr gIter = NULL;
    int nodes_online = 0;
    int nodes_standby = 0;
    int nodes_maintenance = 0;
    char *offline_nodes = NULL;
    size_t offline_nodes_len = 0;
    gboolean no_dc = FALSE;
    gboolean offline = FALSE;

    if (data_set->dc_node == NULL) {
        mon_ops |= mon_op_has_warnings;
        no_dc = TRUE;
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (node->details->standby && node->details->online) {
            nodes_standby++;
        } else if (node->details->maintenance && node->details->online) {
            nodes_maintenance++;
        } else if (node->details->online) {
            nodes_online++;
        } else {
            char *s = crm_strdup_printf("offline node: %s", node->details->uname);
            /* coverity[leaked_storage] False positive */
            pcmk__add_word(&offline_nodes, &offline_nodes_len, s);
            free(s);
            mon_ops |= mon_op_has_warnings;
            offline = TRUE;
        }
    }

    if (pcmk_is_set(mon_ops, mon_op_has_warnings)) {
        out->info(out, "CLUSTER WARN: %s%s%s",
                  no_dc ? "No DC" : "",
                  no_dc && offline ? ", " : "",
                  (offline? offline_nodes : ""));
        free(offline_nodes);
    } else {
        char *nodes_standby_s = NULL;
        char *nodes_maint_s = NULL;

        if (nodes_standby > 0) {
            nodes_standby_s = crm_strdup_printf(", %d standby node%s", nodes_standby,
                                                pcmk__plural_s(nodes_standby));
        }

        if (nodes_maintenance > 0) {
            nodes_maint_s = crm_strdup_printf(", %d maintenance node%s",
                                              nodes_maintenance,
                                              pcmk__plural_s(nodes_maintenance));
        }

        out->info(out, "CLUSTER OK: %d node%s online%s%s, "
                       "%d resource instance%s configured",
                  nodes_online, pcmk__plural_s(nodes_online),
                  nodes_standby_s != NULL ? nodes_standby_s : "",
                  nodes_maint_s != NULL ? nodes_maint_s : "",
                  data_set->ninstances, pcmk__plural_s(data_set->ninstances));

        free(nodes_standby_s);
        free(nodes_maint_s);
    }
    /* coverity[leaked_storage] False positive */
}

static int
send_custom_trap(const char *node, const char *rsc, const char *task, int target_rc, int rc,
                 int status, const char *desc)
{
    pid_t pid;

    /*setenv needs chars, these are ints */
    char *rc_s = crm_itoa(rc);
    char *status_s = crm_itoa(status);
    char *target_rc_s = crm_itoa(target_rc);

    crm_debug("Sending external notification to '%s' via '%s'", options.external_recipient, options.external_agent);

    if(rsc) {
        setenv("CRM_notify_rsc", rsc, 1);
    }
    if (options.external_recipient) {
        setenv("CRM_notify_recipient", options.external_recipient, 1);
    }
    setenv("CRM_notify_node", node, 1);
    setenv("CRM_notify_task", task, 1);
    setenv("CRM_notify_desc", desc, 1);
    setenv("CRM_notify_rc", rc_s, 1);
    setenv("CRM_notify_target_rc", target_rc_s, 1);
    setenv("CRM_notify_status", status_s, 1);

    pid = fork();
    if (pid == -1) {
        crm_perror(LOG_ERR, "notification fork() failed.");
    }
    if (pid == 0) {
        /* crm_debug("notification: I am the child. Executing the nofitication program."); */
        execl(options.external_agent, options.external_agent, NULL);
        exit(CRM_EX_ERROR);
    }

    crm_trace("Finished running custom notification program '%s'.", options.external_agent);
    free(target_rc_s);
    free(status_s);
    free(rc_s);
    return 0;
}

static void
handle_rsc_op(xmlNode * xml, const char *node_id)
{
    int rc = -1;
    int status = -1;
    int target_rc = -1;
    gboolean notify = TRUE;

    char *rsc = NULL;
    char *task = NULL;
    const char *desc = NULL;
    const char *magic = NULL;
    const char *id = NULL;
    const char *node = NULL;

    xmlNode *n = xml;
    xmlNode * rsc_op = xml;

    if(strcmp((const char*)xml->name, XML_LRM_TAG_RSC_OP) != 0) {
        xmlNode *cIter;

        for(cIter = xml->children; cIter; cIter = cIter->next) {
            handle_rsc_op(cIter, node_id);
        }

        return;
    }

    id = crm_element_value(rsc_op, XML_LRM_ATTR_TASK_KEY);
    if (id == NULL) {
        /* Compatibility with <= 1.1.5 */
        id = ID(rsc_op);
    }

    magic = crm_element_value(rsc_op, XML_ATTR_TRANSITION_MAGIC);
    if (magic == NULL) {
        /* non-change */
        return;
    }

    if (!decode_transition_magic(magic, NULL, NULL, NULL, &status, &rc,
                                 &target_rc)) {
        crm_err("Invalid event %s detected for %s", magic, id);
        return;
    }

    if (parse_op_key(id, &rsc, &task, NULL) == FALSE) {
        crm_err("Invalid event detected for %s", id);
        goto bail;
    }

    node = crm_element_value(rsc_op, XML_LRM_ATTR_TARGET);

    while (n != NULL && !pcmk__str_eq(XML_CIB_TAG_STATE, TYPE(n), pcmk__str_casei)) {
        n = n->parent;
    }

    if(node == NULL && n) {
        node = crm_element_value(n, XML_ATTR_UNAME);
    }

    if (node == NULL && n) {
        node = ID(n);
    }

    if (node == NULL) {
        node = node_id;
    }

    if (node == NULL) {
        crm_err("No node detected for event %s (%s)", magic, id);
        goto bail;
    }

    /* look up where we expected it to be? */
    desc = pcmk_strerror(pcmk_ok);
    if (status == PCMK_LRM_OP_DONE && target_rc == rc) {
        crm_notice("%s of %s on %s completed: %s", task, rsc, node, desc);
        if (rc == PCMK_OCF_NOT_RUNNING) {
            notify = FALSE;
        }

    } else if (status == PCMK_LRM_OP_DONE) {
        desc = services_ocf_exitcode_str(rc);
        crm_warn("%s of %s on %s failed: %s", task, rsc, node, desc);

    } else {
        desc = services_lrm_status_str(status);
        crm_warn("%s of %s on %s failed: %s", task, rsc, node, desc);
    }

    if (notify && options.external_agent) {
        send_custom_trap(node, rsc, task, target_rc, rc, status, desc);
    }
  bail:
    free(rsc);
    free(task);
}

/* This function is just a wrapper around mainloop_set_trigger so that it can be
 * called from a mainloop directly.  It's simply another way of ensuring the screen
 * gets redrawn.
 */
static gboolean
mon_trigger_refresh(gpointer user_data)
{
    mainloop_set_trigger(refresh_trigger);
    return FALSE;
}

static void
crm_diff_update_v2(const char *event, xmlNode * msg)
{
    xmlNode *change = NULL;
    xmlNode *diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    for (change = pcmk__xml_first_child(diff); change != NULL;
         change = pcmk__xml_next(change)) {
        const char *name = NULL;
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);
        xmlNode *match = NULL;
        const char *node = NULL;

        if(op == NULL) {
            continue;

        } else if(strcmp(op, "create") == 0) {
            match = change->children;

        } else if(strcmp(op, "move") == 0) {
            continue;

        } else if(strcmp(op, "delete") == 0) {
            continue;

        } else if(strcmp(op, "modify") == 0) {
            match = first_named_child(change, XML_DIFF_RESULT);
            if(match) {
                match = match->children;
            }
        }

        if(match) {
            name = (const char *)match->name;
        }

        crm_trace("Handling %s operation for %s %p, %s", op, xpath, match, name);
        if(xpath == NULL) {
            /* Version field, ignore */

        } else if(name == NULL) {
            crm_debug("No result for %s operation to %s", op, xpath);
            CRM_ASSERT(strcmp(op, "delete") == 0 || strcmp(op, "move") == 0);

        } else if(strcmp(name, XML_TAG_CIB) == 0) {
            xmlNode *state = NULL;
            xmlNode *status = first_named_child(match, XML_CIB_TAG_STATUS);

            for (state = pcmk__xe_first_child(status); state != NULL;
                 state = pcmk__xe_next(state)) {

                node = crm_element_value(state, XML_ATTR_UNAME);
                if (node == NULL) {
                    node = ID(state);
                }
                handle_rsc_op(state, node);
            }

        } else if(strcmp(name, XML_CIB_TAG_STATUS) == 0) {
            xmlNode *state = NULL;

            for (state = pcmk__xe_first_child(match); state != NULL;
                 state = pcmk__xe_next(state)) {

                node = crm_element_value(state, XML_ATTR_UNAME);
                if (node == NULL) {
                    node = ID(state);
                }
                handle_rsc_op(state, node);
            }

        } else if(strcmp(name, XML_CIB_TAG_STATE) == 0) {
            node = crm_element_value(match, XML_ATTR_UNAME);
            if (node == NULL) {
                node = ID(match);
            }
            handle_rsc_op(match, node);

        } else if(strcmp(name, XML_CIB_TAG_LRM) == 0) {
            node = ID(match);
            handle_rsc_op(match, node);

        } else if(strcmp(name, XML_LRM_TAG_RESOURCES) == 0) {
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

            handle_rsc_op(match, local_node);
            free(local_node);

        } else if(strcmp(name, XML_LRM_TAG_RESOURCE) == 0) {
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

            handle_rsc_op(match, local_node);
            free(local_node);

        } else if(strcmp(name, XML_LRM_TAG_RSC_OP) == 0) {
            char *local_node = pcmk__xpath_node_id(xpath, "lrm");

            handle_rsc_op(match, local_node);
            free(local_node);

        } else {
            crm_trace("Ignoring %s operation for %s %p, %s", op, xpath, match, name);
        }
    }
}

static void
crm_diff_update_v1(const char *event, xmlNode * msg)
{
    /* Process operation updates */
    xmlXPathObject *xpathObj = xpath_search(msg,
                                            "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED
                                            "//" XML_LRM_TAG_RSC_OP);
    int lpc = 0, max = numXpathResults(xpathObj);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *rsc_op = getXpathResult(xpathObj, lpc);

        handle_rsc_op(rsc_op, NULL);
    }
    freeXpathObject(xpathObj);
}

static void
crm_diff_update(const char *event, xmlNode * msg)
{
    int rc = -1;
    static bool stale = FALSE;
    gboolean cib_updated = FALSE;
    xmlNode *diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    out->progress(out, false);

    if (current_cib != NULL) {
        rc = xml_apply_patchset(current_cib, diff, TRUE);

        switch (rc) {
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
                free_xml(current_cib); current_cib = NULL;
                break;
            case pcmk_ok:
                cib_updated = TRUE;
                break;
            default:
                crm_notice("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc), rc);
                free_xml(current_cib); current_cib = NULL;
        }
    }

    if (current_cib == NULL) {
        crm_trace("Re-requesting the full cib");
        cib->cmds->query(cib, NULL, &current_cib, cib_scope_local | cib_sync_call);
    }

    if (options.external_agent) {
        int format = 0;
        crm_element_value_int(diff, "format", &format);
        switch(format) {
            case 1:
                crm_diff_update_v1(event, msg);
                break;
            case 2:
                crm_diff_update_v2(event, msg);
                break;
            default:
                crm_err("Unknown patch format: %d", format);
        }
    }

    if (current_cib == NULL) {
        if(!stale) {
            print_as(output_format, "--- Stale data ---");
        }
        stale = TRUE;
        return;
    }

    stale = FALSE;
    refresh_after_event(cib_updated, FALSE);
}

static int
get_fencing_history(stonith_history_t **stonith_history)
{
    int rc = 0;

    while (pcmk_is_set(options.mon_ops, mon_op_fence_history)) {
        if (st != NULL) {
            rc = st->cmds->history(st, st_opt_sync_call, NULL, stonith_history, 120);

            if (rc == 0) {
                *stonith_history = stonith__sort_history(*stonith_history);
                if (!pcmk_is_set(options.mon_ops, mon_op_fence_full_history)
                    && (output_format != mon_output_xml)) {

                    *stonith_history = pcmk__reduce_fence_history(*stonith_history);
                }
                break; /* all other cases are errors */
            }
        } else {
            rc = ENOTCONN;
            break;
        }
    }

    return rc;
}

static int
mon_refresh_display(gpointer user_data)
{
    xmlNode *cib_copy = copy_xml(current_cib);
    stonith_history_t *stonith_history = NULL;
    int history_rc = 0;

    last_refresh = time(NULL);

    if (cli_config_update(&cib_copy, NULL, FALSE) == FALSE) {
        clean_up_cib_connection();
        out->err(out, "Upgrade failed: %s", pcmk_strerror(-pcmk_err_schema_validation));
        clean_up(CRM_EX_CONFIG);
        return 0;
    }

    /* get the stonith-history if there is evidence we need it */
    history_rc = get_fencing_history(&stonith_history);

    if (mon_data_set == NULL) {
        mon_data_set = pe_new_working_set();
        CRM_ASSERT(mon_data_set != NULL);
    }
    pe__set_working_set_flags(mon_data_set, pe_flag_no_compat);

    mon_data_set->input = cib_copy;
    cluster_status(mon_data_set);

    /* Unpack constraints if any section will need them
     * (tickets may be referenced in constraints but not granted yet,
     * and bans need negative location constraints) */
    if (pcmk_is_set(show, mon_show_bans) || pcmk_is_set(show, mon_show_tickets)) {
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                   mon_data_set->input);
        unpack_constraints(cib_constraints, mon_data_set);
    }

    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            if (print_html_status(out, mon_data_set, crm_errno2exit(history_rc),
                                  stonith_history, options.mon_ops,
                                  show, options.neg_location_prefix,
                                  options.only_node, options.only_rsc) != 0) {
                g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_CANTCREAT, "Critical: Unable to output html file");
                clean_up(CRM_EX_CANTCREAT);
                return 0;
            }
            break;

        case mon_output_legacy_xml:
        case mon_output_xml:
            print_xml_status(out, mon_data_set, crm_errno2exit(history_rc),
                             stonith_history, options.mon_ops, show,
                             options.neg_location_prefix, options.only_node,
                             options.only_rsc);
            break;

        case mon_output_monitor:
            print_simple_status(out, mon_data_set, options.mon_ops);
            if (pcmk_is_set(options.mon_ops, mon_op_has_warnings)) {
                clean_up(MON_STATUS_WARN);
                return FALSE;
            }
            break;

        case mon_output_console:
            /* If curses is not enabled, this will just fall through to the plain
             * text case.
             */
#if CURSES_ENABLED
            blank_screen();
            print_status(out, mon_data_set, crm_errno2exit(history_rc), stonith_history,
                         options.mon_ops, show, options.neg_location_prefix,
                         options.only_node, options.only_rsc);
            refresh();
            break;
#endif

        case mon_output_plain:
            print_status(out, mon_data_set, crm_errno2exit(history_rc), stonith_history,
                         options.mon_ops, show, options.neg_location_prefix,
                         options.only_node, options.only_rsc);
            break;

        case mon_output_unset:
        case mon_output_none:
            break;
    }

    if (options.daemonize) {
        out->reset(out);
    }

    stonith_history_free(stonith_history);
    stonith_history = NULL;
    pe_reset_working_set(mon_data_set);
    return 1;
}

/* This function is called for fencing events (see fencing_connect for which ones) when
 * --watch-fencing is used on the command line.
 */
static void
mon_st_callback_event(stonith_t * st, stonith_event_t * e)
{
    if (st->state == stonith_disconnected) {
        /* disconnect cib as well and have everything reconnect */
        mon_cib_connection_destroy(NULL);
    } else if (options.external_agent) {
        char *desc = crm_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                    e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                    e->id);
        send_custom_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
        free(desc);
    }
}

/* Cause the screen to be redrawn (via mainloop_set_trigger) when various conditions are met:
 *
 * - If the last update occurred more than reconnect_msec ago (defaults to 5s, but can be
 *   changed via the -i command line option), or
 * - After every 10 CIB updates, or
 * - If it's been 2s since the last update
 *
 * This function sounds like it would be more broadly useful, but it is only called when a
 * fencing event is received or a CIB diff occurrs.
 */
static void
refresh_after_event(gboolean data_updated, gboolean enforce)
{
    static int updates = 0;
    time_t now = time(NULL);

    if (data_updated) {
        updates++;
    }

    if(refresh_timer == NULL) {
        refresh_timer = mainloop_timer_add("refresh", 2000, FALSE, mon_trigger_refresh, NULL);
    }

    if (reconnect_timer > 0) {
        /* we will receive a refresh request after successful reconnect */
        mainloop_timer_stop(refresh_timer);
        return;
    }

    /* as we're not handling initial failure of fencer-connection as
     * fatal give it a retry here
     * not getting here if cib-reconnection is already on the way
     */
    fencing_connect();

    if (enforce ||
        now - last_refresh > options.reconnect_msec / 1000 ||
        updates >= 10) {
        mainloop_set_trigger(refresh_trigger);
        mainloop_timer_stop(refresh_timer);
        updates = 0;

    } else {
        mainloop_timer_start(refresh_timer);
    }
}

/* This function is called for fencing events (see fencing_connect for which ones) when
 * --watch-fencing is NOT used on the command line.
 */
static void
mon_st_callback_display(stonith_t * st, stonith_event_t * e)
{
    if (st->state == stonith_disconnected) {
        /* disconnect cib as well and have everything reconnect */
        mon_cib_connection_destroy(NULL);
    } else {
        out->progress(out, false);
        refresh_after_event(TRUE, FALSE);
    }
}

static void
clean_up_cib_connection(void)
{
    if (cib == NULL) {
        return;
    }

    cib->cmds->signoff(cib);
    cib_delete(cib);
    cib = NULL;
}

static void
clean_up_fencing_connection(void)
{
    if (st == NULL) {
        return;
    }

    if (st->state != stonith_disconnected) {
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_DISCONNECT);
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_FENCE);
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_HISTORY);
        st->cmds->disconnect(st);
    }

    stonith_api_delete(st);
    st = NULL;
}

/*
 * De-init ncurses, disconnect from the CIB manager, disconnect fencing,
 * deallocate memory and show usage-message if requested.
 *
 * We don't actually return, but nominally returning crm_exit_t allows a usage
 * like "return clean_up(exit_code);" which helps static analysis understand the
 * code flow.
 */
static crm_exit_t
clean_up(crm_exit_t exit_code)
{
    /* Quitting crm_mon is much more complicated than it ought to be. */

    /* (1) Close connections, free things, etc. */
    clean_up_cib_connection();
    clean_up_fencing_connection();
    free(options.neg_location_prefix);
    free(options.only_node);
    free(options.only_rsc);
    free(options.pid_file);
    g_slist_free_full(options.includes_excludes, free);

    pe_free_working_set(mon_data_set);
    mon_data_set = NULL;

    g_strfreev(processed_args);

    /* (2) If this is abnormal termination and we're in curses mode, shut down
     * curses first.  Any messages displayed to the screen before curses is shut
     * down will be lost because doing the shut down will also restore the
     * screen to whatever it looked like before crm_mon was started.
     */
    if ((error != NULL || exit_code == CRM_EX_USAGE) && output_format == mon_output_console) {
        out->finish(out, exit_code, false, NULL);
        pcmk__output_free(out);
        out = NULL;
    }

    /* (3) If this is a command line usage related failure, print the usage
     * message.
     */
    if (exit_code == CRM_EX_USAGE && (output_format == mon_output_console || output_format == mon_output_plain)) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        fprintf(stderr, "%s", help);
        g_free(help);
    }

    pcmk__free_arg_context(context);

    /* (4) If this is any kind of error, print the error out and exit.  Make
     * sure to handle situations both before and after formatted output is
     * set up.  We want errors to appear formatted if at all possible.
     */
    if (error != NULL) {
        if (out != NULL) {
            out->err(out, "%s: %s", g_get_prgname(), error->message);
            out->finish(out, exit_code, true, NULL);
            pcmk__output_free(out);
        } else {
            fprintf(stderr, "%s: %s\n", g_get_prgname(), error->message);
        }

        g_clear_error(&error);
        crm_exit(exit_code);
    }

    /* (5) Print formatted output to the screen if we made it far enough in
     * crm_mon to be able to do so.
     */
    if (out != NULL) {
        if (options.daemonize) {
            out->dest = freopen(NULL, "w", out->dest);
            CRM_ASSERT(out->dest != NULL);
        }

        out->finish(out, exit_code, true, NULL);

        pcmk__output_free(out);
        pcmk__unregister_formats();
    }

    crm_exit(exit_code);
}
