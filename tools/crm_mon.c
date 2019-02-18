/*
 * Copyright 2004-2019 the Pacemaker project contributors
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
#include <sys/utsname.h>

#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/lrmd.h>
#include <crm/common/internal.h>  /* crm_ends_with_ext */
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>

#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <crm/pengine/print_ml_status.h>
#include <crm/pengine/internal.h>
#include <../lib/pengine/unpack.h>
#include <pacemaker-internal.h>
#include <crm/stonith-ng.h>

static void clean_up_connections(void);
static crm_exit_t clean_up(crm_exit_t exit_code);
static void crm_diff_update(const char *event, xmlNode * msg);
static gboolean mon_refresh_display(gpointer user_data);
static int cib_connect(gboolean full);
static void mon_st_callback_event(stonith_t * st, stonith_event_t * e);
static void mon_st_callback_display(stonith_t * st, stonith_event_t * e);
static void kick_refresh(gboolean data_updated);

/*
 * Definitions indicating how to output
 */

static char *output_filename = NULL;   /* if sending output to a file, its name */

/* other globals */
static char *pid_file = NULL;

static int reconnect_msec = 5000;
static gboolean daemonize = FALSE;
static GMainLoop *mainloop = NULL;
static guint timer_id = 0;
static mainloop_timer_t *refresh_timer = NULL;
static pe_working_set_t *mon_data_set = NULL;

static const char *external_agent = NULL;
static const char *external_recipient = NULL;

static cib_t *cib = NULL;
static stonith_t *st = NULL;
static xmlNode *current_cib = NULL;

static gboolean one_shot = FALSE;
static gboolean has_warnings = FALSE;
static gboolean watch_fencing = FALSE;
static struct print_params_t pp = { mon_show_default, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, "" };
static gboolean fence_connect = FALSE;
static int fence_history_level = 1;
#if CURSES_ENABLED
static gboolean curses_console_initialized = FALSE;
#endif

long last_refresh = 0;
crm_trigger_t *refresh_trigger = NULL;

/* Define exit codes for monitoring-compatible output
 * For nagios plugins, the possibilities are
 * OK=0, WARN=1, CRIT=2, and UNKNOWN=3
 */
#define MON_STATUS_WARN    CRM_EX_ERROR
#define MON_STATUS_CRIT    CRM_EX_INVALID_PARAM
#define MON_STATUS_UNKNOWN CRM_EX_UNIMPLEMENT_FEATURE

static void
blank_screen(void)
{
#if CURSES_ENABLED
    int lpc = 0;

    for (lpc = 0; lpc < LINES; lpc++) {
        move(lpc, 0);
        clrtoeol();
    }
    move(0, 0);
    refresh();
#endif
}

static gboolean
mon_timer_popped(gpointer data)
{
    int rc = pcmk_ok;

#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        clear();
        refresh();
    }
#endif

    if (timer_id > 0) {
        g_source_remove(timer_id);
        timer_id = 0;
    }

    print_as("Reconnecting...\n");
    rc = cib_connect(TRUE);

    if (rc != pcmk_ok) {
        timer_id = g_timeout_add(reconnect_msec, mon_timer_popped, NULL);
    }
    return FALSE;
}

static void
mon_cib_connection_destroy(gpointer user_data)
{
    print_as("Connection to the cluster-daemons terminated\n");
    if (refresh_timer != NULL) {
        /* we'll trigger a refresh after reconnect */
        mainloop_timer_stop(refresh_timer);
    }
    if (timer_id) {
        /* we'll trigger a new reconnect-timeout at the end */
        g_source_remove(timer_id);
        timer_id = 0;
    }
    if (st) {
        /* the client API won't properly reconnect notifications
         * if they are still in the table - so remove them
         */
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_DISCONNECT);
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_FENCE);
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_HISTORY);
        if (st->state != stonith_disconnected) {
            st->cmds->disconnect(st);
        }
    }
    if (cib) {
        cib->cmds->signoff(cib);
        timer_id = g_timeout_add(reconnect_msec, mon_timer_popped, NULL);
    }
    return;
}

/*
 * Mainloop signal handler.
 */
static void
mon_shutdown(int nsig)
{
    clean_up(CRM_EX_OK);
}

#if ON_DARWIN
#  define sighandler_t sig_t
#endif

#if CURSES_ENABLED
#  ifndef HAVE_SIGHANDLER_T
typedef void (*sighandler_t) (int);
#  endif
static sighandler_t ncurses_winch_handler;
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
        mainloop_set_trigger(refresh_trigger);
    }
    not_done--;
}
#endif

static int
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if ((fence_connect) && (st == NULL)) {
        st = stonith_api_new();
    }

    if ((fence_connect) && (st->state == stonith_disconnected)) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if (rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            if (watch_fencing) {
                st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT,
                                                mon_st_callback_event);
                st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback_event);
            } else {
                st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT,
                                                mon_st_callback_display);
                st->cmds->register_notification(st, T_STONITH_NOTIFY_HISTORY, mon_st_callback_display);
            }
        }
    }

    if (cib->state != cib_connected_query && cib->state != cib_connected_command) {
        crm_trace("Connecting to the CIB");
        if ((output_format == mon_output_console) && need_pass && (cib->variant == cib_remote)) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        rc = cib->cmds->query(cib, NULL, &current_cib, cib_scope_local | cib_sync_call);
        if (rc == pcmk_ok) {
            mon_refresh_display(NULL);
        }

        if (rc == pcmk_ok && full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as
                        ("Notification setup not supported, won't be able to reconnect after failure");
                    if (output_format == mon_output_console) {
                        sleep(2);
                    }
                    rc = pcmk_ok;
                }

            }

            if (rc == pcmk_ok) {
                cib->cmds->del_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
                rc = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, crm_diff_update);
            }

            if (rc != pcmk_ok) {
                print_as("Notification setup failed, could not monitor CIB actions");
                if (output_format == mon_output_console) {
                    sleep(2);
                }
                clean_up_connections();
            }
        }
    }
    return rc;
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",           0, 0, '?', "\tThis text"},
    {"version",        0, 0, '$', "\tVersion information"  },
    {"verbose",        0, 0, 'V', "\tIncrease debug output"},
    {"quiet",          0, 0, 'Q', "\tDisplay only essential output" },

    {"-spacer-",	1, 0, '-', "\nModes (mutually exclusive):"},
    {"as-html",        1, 0, 'h', "\tWrite cluster status to the named html file"},
    {"as-xml",         0, 0, 'X', "\t\tWrite cluster status as xml to stdout. This will enable one-shot mode."},
    {"web-cgi",        0, 0, 'w', "\t\tWeb mode with output suitable for CGI (preselected when run as *.cgi)"},
    {"simple-status",  0, 0, 's', "\tDisplay the cluster status once as a simple one line output (suitable for nagios)"},
    {"-spacer-",	1, 0, '-', "\nDisplay Options:"},
    {"group-by-node",  0, 0, 'n', "\tGroup resources by node"     },
    {"inactive",       0, 0, 'r', "\t\tDisplay inactive resources"  },
    {"failcounts",     0, 0, 'f', "\tDisplay resource fail counts"},
    {"operations",     0, 0, 'o', "\tDisplay resource operation history" },
    {"timing-details", 0, 0, 't', "\tDisplay resource operation history with timing details" },
    {"tickets",        0, 0, 'c', "\t\tDisplay cluster tickets"},
    {"watch-fencing",  0, 0, 'W', "\tListen for fencing events. For use with --external-agent"},
    {"fence-history",  2, 0, 'm', "Show fence history\n"
                                  "\t\t\t\t\t0=off, 1=failures and pending (default without option),\n"
                                  "\t\t\t\t\t2=add successes (default without value for option),\n"
                                  "\t\t\t\t\t3=show full history without reduction to most recent of each flavor"},
    {"neg-locations",  2, 0, 'L', "Display negative location constraints [optionally filtered by id prefix]"},
    {"show-node-attributes", 0, 0, 'A', "Display node attributes" },
    {"hide-headers",   0, 0, 'D', "\tHide all headers" },
    {"show-detail",    0, 0, 'R', "\tShow more details (node IDs, individual clone instances)" },
    {"brief",          0, 0, 'b', "\t\tBrief output" },
    {"pending",        0, 0, 'j', "\t\tDisplay pending state if 'record-pending' is enabled", pcmk_option_hidden},

    {"-spacer-",	1, 0, '-', "\nAdditional Options:"},
    {"interval",       1, 0, 'i', "\tUpdate frequency in seconds" },
    {"one-shot",       0, 0, '1', "\t\tDisplay the cluster status once on the console and exit"},
    {"disable-ncurses",0, 0, 'N', "\tDisable the use of ncurses", !CURSES_ENABLED},
    {"daemonize",      0, 0, 'd', "\tRun in the background as a daemon"},
    {"pid-file",       1, 0, 'p', "\t(Advanced) Daemon pid file location"},
    {"external-agent",    1, 0, 'E', "A program to run when resource operations take place."},
    {"external-recipient",1, 0, 'e', "A recipient for your program (assuming you want the program to send something to someone)."},


    {"xml-file",       1, 0, 'x', NULL, pcmk_option_hidden},

    {"-spacer-",	1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "Display the cluster status on the console with updates as they occur:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_mon", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the cluster status on the console just once then exit:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_mon -1", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display your cluster status, group resources by node, and include inactive resources in the list:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_mon --group-by-node --inactive", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Start crm_mon as a background daemon and have it write the cluster status to an HTML file:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_mon --daemonize --as-html /path/to/docroot/filename.html", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Start crm_mon and export the current cluster status as xml to stdout, then exit.:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_mon --as-xml", pcmk_option_example},

    {NULL, 0, 0, 0}
};
/* *INDENT-ON* */

#if CURSES_ENABLED
static const char *
get_option_desc(char c)
{
    int lpc;

    for (lpc = 0; long_options[lpc].name != NULL; lpc++) {

        if (long_options[lpc].name[0] == '-')
            continue;

        if (long_options[lpc].val == c) {
            static char *buf = NULL;
            const char *rv;
            char *nl;

            /* chop off tabs and cut at newline */
            free(buf); /* free string from last usage */
            buf = strdup(long_options[lpc].desc);
            rv = buf; /* make a copy to keep buf pointer unaltered
                         for freeing when we come by next time.
                         Like this the result stays valid until
                         the next call.
                       */
            while(isspace(rv[0])) {
                rv++;
            }
            nl = strchr(rv, '\n');
            if (nl) {
                *nl = '\0';
            }
            return rv;
        }
    }

    return NULL;
}

#define print_option_help(option, condition) \
    print_as("%c %c: \t%s\n", ((condition)? '*': ' '), option, get_option_desc(option));

static gboolean
detect_user_input(GIOChannel *channel, GIOCondition condition, gpointer unused)
{
    int c;
    gboolean config_mode = FALSE;

    while (1) {

        /* Get user input */
        c = getchar();

        switch (c) {
            case 'm':
                if (!fence_history_level) {
                    pp.fence_history = TRUE;
                    fence_connect = TRUE;
                    if (st == NULL) {
                        mon_cib_connection_destroy(NULL);
                    }
                }
                pp.show ^= mon_show_fence_history;
                break;
            case 'c':
                pp.show ^= mon_show_tickets;
                break;
            case 'f':
                pp.show ^= mon_show_failcounts;
                break;
            case 'n':
                pp.group_by_node = ! pp.group_by_node;
                break;
            case 'o':
                pp.show ^= mon_show_operations;
                if ((pp.show & mon_show_operations) == 0) {
                    pp.print_timing = 0;
                }
                break;
            case 'r':
                pp.inactive_resources = ! pp.inactive_resources;
                break;
            case 'R':
                pp.print_clone_detail = ! pp.print_clone_detail;
                break;
            case 't':
                pp.print_timing = ! pp.print_timing;
                if (pp.print_timing) {
                    pp.show |= mon_show_operations;
                }
                break;
            case 'A':
                pp.show ^= mon_show_attributes;
                break;
            case 'L':
                pp.show ^= mon_show_bans;
                break;
            case 'D':
                /* If any header is shown, clear them all, otherwise set them all */
                if (pp.show & mon_show_headers) {
                    pp.show &= ~mon_show_headers;
                } else {
                    pp.show |= mon_show_headers;
                }
                break;
            case 'b':
                pp.print_brief = ! pp.print_brief;
                break;
            case 'j':
                pp.print_pending = ! pp.print_pending;
                break;
            case '?':
                config_mode = TRUE;
                break;
            default:
                goto refresh;
        }

        if (!config_mode)
            goto refresh;

        blank_screen();

        print_as("Display option change mode\n");
        print_as("\n");
        print_option_help('c', pp.show & mon_show_tickets);
        print_option_help('f', pp.show & mon_show_failcounts);
        print_option_help('n', pp.group_by_node);
        print_option_help('o', pp.show & mon_show_operations);
        print_option_help('r', pp.inactive_resources);
        print_option_help('t', pp.print_timing);
        print_option_help('A', pp.show & mon_show_attributes);
        print_option_help('L', pp.show & mon_show_bans);
        print_option_help('D', (pp.show & mon_show_headers) == 0);
        print_option_help('R', pp.print_clone_detail);
        print_option_help('b', pp.print_brief);
        print_option_help('j', pp.print_pending);
        print_option_help('m', (pp.show & mon_show_fence_history));
        print_as("\n");
        print_as("Toggle fields via field letter, type any other key to return");
    }

refresh:
    mon_refresh_display(NULL);
    return TRUE;
}
#endif

int
main(int argc, char **argv)
{
    int flag;
    int argerr = 0;
    int option_index = 0;
    int rc = pcmk_ok;

    pid_file = strdup("/tmp/ClusterMon.pid");
    crm_log_cli_init("crm_mon");
    crm_set_options(NULL, "mode [options]", long_options,
                    "Provides a summary of cluster's current state."
                    "\n\nOutputs varying levels of detail in a number of different formats.\n");

#if !defined (ON_DARWIN) && !defined (ON_BSD)
    /* prevent zombies */
    signal(SIGCLD, SIG_IGN);
#endif

    if (crm_ends_with_ext(argv[0], ".cgi") == TRUE) {
        output_format = mon_output_cgi;
        one_shot = TRUE;
    }

    /* to enable stonith-connection when called via some application like pcs
     * set environment-variable FENCE_HISTORY to desired level
     * so you don't have to modify this application
     */
    /* fence_history_level = crm_atoi(getenv("FENCE_HISTORY"), "0"); */

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'Q':
                pp.show &= ~mon_show_times;
                break;
            case 'i':
                reconnect_msec = crm_get_msec(optarg);
                break;
            case 'n':
                pp.group_by_node = TRUE;
                break;
            case 'r':
                pp.inactive_resources = TRUE;
                break;
            case 'W':
                watch_fencing = TRUE;
                fence_connect = TRUE;
                break;
            case 'm':
                fence_history_level = crm_atoi(optarg, "2");
                break;
            case 'd':
                daemonize = TRUE;
                break;
            case 't':
                pp.print_timing = TRUE;
                pp.show |= mon_show_operations;
                break;
            case 'o':
                pp.show |= mon_show_operations;
                break;
            case 'f':
                pp.show |= mon_show_failcounts;
                break;
            case 'A':
                pp.show |= mon_show_attributes;
                break;
            case 'L':
                pp.show |= mon_show_bans;
                pp.print_neg_location_prefix = optarg? optarg : "";
                break;
            case 'D':
                pp.show &= ~mon_show_headers;
                break;
            case 'b':
                pp.print_brief = TRUE;
                break;
            case 'j':
                pp.print_pending = TRUE;
                break;
            case 'R':
                pp.print_clone_detail = TRUE;
                break;
            case 'c':
                pp.show |= mon_show_tickets;
                break;
            case 'p':
                free(pid_file);
                if(optarg == NULL) {
                    crm_help(flag, CRM_EX_USAGE);
                }
                pid_file = strdup(optarg);
                break;
            case 'x':
                if(optarg == NULL) {
                    crm_help(flag, CRM_EX_USAGE);
                }
                setenv("CIB_file", optarg, 1);
                one_shot = TRUE;
                break;
            case 'h':
                if(optarg == NULL) {
                    crm_help(flag, CRM_EX_USAGE);
                }
                argerr += (output_format != mon_output_console);
                output_format = mon_output_html;
                output_filename = strdup(optarg);
                umask(S_IWGRP | S_IWOTH);
                break;
            case 'X':
                argerr += (output_format != mon_output_console);
                output_format = mon_output_xml;
                one_shot = TRUE;
                break;
            case 'w':
                /* do not allow argv[0] and argv[1...] redundancy */
                argerr += (output_format != mon_output_console);
                output_format = mon_output_cgi;
                one_shot = TRUE;
                break;
            case 's':
                argerr += (output_format != mon_output_console);
                output_format = mon_output_monitor;
                one_shot = TRUE;
                break;
            case 'E':
                external_agent = optarg;
                break;
            case 'e':
                external_recipient = optarg;
                break;
            case '1':
                one_shot = TRUE;
                break;
            case 'N':
                if (output_format == mon_output_console) {
                    output_format = mon_output_plain;
                }
                break;
            case '$':
            case '?':
                crm_help(flag, CRM_EX_OK);
                break;
            default:
                printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (watch_fencing) {
        /* don't moan as fence_history_level == 1 is default */
        fence_history_level = 0;
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
                break;

            case cib_file:
                /* Don't try to connect to fencing as we
                 * either don't have a running cluster or
                 * the fencing-information would possibly
                 * not match the cib data from a file.
                 * As we don't expect cib-updates coming
                 * in enforce one-shot. */
                fence_history_level = 0;
                one_shot = TRUE;
                break;

            case cib_remote:
                /* updates coming in but no fencing */
                fence_history_level = 0;
                break;

            case cib_undefined:
            case cib_database:
            default:
                /* something is odd */
                rc = -EINVAL;
                crm_err("Invalid cib-source");
                break;
        }
    }

    switch (fence_history_level) {
        case 3:
            pp.fence_full_history = TRUE;
            /* fall through to next lower level */
        case 2:
            pp.show |= mon_show_fence_history;
            /* fall through to next lower level */
        case 1:
            pp.fence_history = TRUE;
            fence_connect = TRUE;
            break;
        default:
            break;
    }

    /* Extra sanity checks when in CGI mode */
    if (output_format == mon_output_cgi) {
        argerr += (optind < argc);
        argerr += (output_filename != NULL);
        argerr += ((cib) && (cib->variant == cib_file));
        argerr += (external_agent != NULL);
        argerr += (daemonize == TRUE);  /* paranoia */

    } else if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }

    if (argerr) {
        return clean_up(CRM_EX_USAGE);
    }

    /* XML output always prints everything */
    if (output_format == mon_output_xml) {
        pp.show = mon_show_all;
        pp.print_timing = TRUE;
    }

    if (one_shot) {
        if (output_format == mon_output_console) {
            output_format = mon_output_plain;
        }

    } else if (daemonize) {
        if ((output_format == mon_output_console) || (output_format == mon_output_plain)) {
            output_format = mon_output_none;
        }
        crm_enable_stderr(FALSE);

        if ((output_format != mon_output_html)
            && !external_agent) {
            printf ("Looks like you forgot to specify one or more of: "
                    "--as-html, --external-agent\n");
            return clean_up(CRM_EX_USAGE);
        }

        if (cib) {
            /* to be on the safe side don't have cib-object around
             * when we are forking
             */
            cib_delete(cib);
            cib = NULL;
            crm_make_daemon(crm_system_name, TRUE, pid_file);
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
        initscr();
        cbreak();
        noecho();
        crm_enable_stderr(FALSE);
        curses_console_initialized = TRUE;
#else
        one_shot = TRUE;
        output_format = mon_output_plain;
        printf("Defaulting to one-shot mode\n");
        printf("You need to have curses available at compile time to enable console mode\n");
#endif
    }

    crm_info("Starting %s", crm_system_name);

    if (cib) {

        do {
            if (!one_shot) {
                print_as("Waiting until cluster is available on this node ...\n");
            }
            rc = cib_connect(!one_shot);

            if (one_shot) {
                break;

            } else if (rc != pcmk_ok) {
                sleep(reconnect_msec / 1000);
#if CURSES_ENABLED
                if (output_format == mon_output_console) {
                    clear();
                    refresh();
                }
#endif
            } else {
                if (output_format == mon_output_html) {
                    print_as("Writing html to %s ...\n", output_filename);
                }
            }

        } while (rc == -ENOTCONN);
    }

    if (rc != pcmk_ok) {
        if (output_format == mon_output_monitor) {
            printf("CLUSTER CRIT: Connection to cluster failed: %s\n",
                    pcmk_strerror(rc));
            return clean_up(MON_STATUS_CRIT);
        } else {
            if (rc == -ENOTCONN) {
                print_as("\nError: cluster is not available on this node\n");
            } else {
                print_as("\nConnection to cluster failed: %s\n",
                            pcmk_strerror(rc));
            }
        }
        if (output_format == mon_output_console) {
            sleep(2);
        }
        return clean_up(crm_errno2exit(rc));
    }

    if (one_shot) {
        return clean_up(CRM_EX_OK);
    }

    mainloop = g_main_loop_new(NULL, FALSE);

    mainloop_add_signal(SIGTERM, mon_shutdown);
    mainloop_add_signal(SIGINT, mon_shutdown);
#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        ncurses_winch_handler = signal(SIGWINCH, mon_winresize);
        if (ncurses_winch_handler == SIG_DFL ||
            ncurses_winch_handler == SIG_IGN || ncurses_winch_handler == SIG_ERR)
            ncurses_winch_handler = NULL;
        g_io_add_watch(g_io_channel_unix_new(STDIN_FILENO), G_IO_IN, detect_user_input, NULL);
    }
#endif
    refresh_trigger = mainloop_add_trigger(G_PRIORITY_LOW, mon_refresh_display, NULL);

    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

    crm_info("Exiting %s", crm_system_name);

    return clean_up(CRM_EX_OK);
}

#define mon_warn(fmt...) do {			\
	if (!has_warnings) {			\
	    print_as("CLUSTER WARN:");		\
	} else {				\
	    print_as(",");			\
	}					\
	print_as(fmt);				\
	has_warnings = TRUE;			\
    } while(0)

/*!
 * \internal
 * \brief Print one-line status suitable for use with monitoring software
 *
 * \param[in] data_set  Working set of CIB state
 * \param[in] history   List of stonith actions
 *
 * \note This function's output (and the return code when the program exits)
 *       should conform to https://www.monitoring-plugins.org/doc/guidelines.html
 */
static void
print_simple_status(pe_working_set_t * data_set,
                    stonith_history_t *history)
{
    GListPtr gIter = NULL;
    int nodes_online = 0;
    int nodes_standby = 0;
    int nodes_maintenance = 0;

    if (data_set->dc_node == NULL) {
        mon_warn(" No DC");
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node->details->standby && node->details->online) {
            nodes_standby++;
        } else if (node->details->maintenance && node->details->online) {
            nodes_maintenance++;
        } else if (node->details->online) {
            nodes_online++;
        } else {
            mon_warn(" offline node: %s", node->details->uname);
        }
    }

    if (!has_warnings) {
        int nresources = count_resources(data_set, NULL);

        print_as("CLUSTER OK: %d node%s online", nodes_online, s_if_plural(nodes_online));
        if (nodes_standby > 0) {
            print_as(", %d standby node%s", nodes_standby, s_if_plural(nodes_standby));
        }
        if (nodes_maintenance > 0) {
            print_as(", %d maintenance node%s", nodes_maintenance, s_if_plural(nodes_maintenance));
        }
        print_as(", %d resource%s configured", nresources, s_if_plural(nresources));
    }

    print_as("\n");
}

/* structure for passing multiple user data to g_list_foreach() */
struct mon_attr_data {
    FILE *stream;
    node_t *node;
};

/*!
 * \internal
 * \brief Reduce the stonith-history
 *        for successful actions we keep the last of every action-type & target
 *        for failed actions we record as well who had failed
 *        for actions in progress we keep full track
 *
 * \param[in] history    List of stonith actions
 *
 */
static stonith_history_t *
reduce_stonith_history(stonith_history_t *history)
{
    stonith_history_t *new = NULL, *hp, *np, *tmp;

    for (hp = history; hp; ) {
        for (np = new; np; np = np->next) {
            if ((hp->state == st_done) || (hp->state == st_failed)) {
                /* action not in progress */
                if (safe_str_eq(hp->target, np->target) &&
                    safe_str_eq(hp->action, np->action) &&
                    (hp->state == np->state)) {
                    if ((hp->state == st_done) ||
                        safe_str_eq(hp->delegate, np->delegate)) {
                        /* replace or purge */
                        if (hp->completed < np->completed) {
                            /* purge older hp */
                            tmp = hp->next;
                            hp->next = NULL;
                            stonith_history_free(hp);
                            hp = tmp;
                            break;
                        }
                        /* damn single linked list */
                        free(hp->target);
                        free(hp->action);
                        free(np->origin);
                        np->origin = hp->origin;
                        free(np->delegate);
                        np->delegate = hp->delegate;
                        free(np->client);
                        np->client = hp->client;
                        np->completed = hp->completed;
                        tmp = hp;
                        hp = hp->next;
                        free(tmp);
                        break;
                    }
                }
                if (np->next) {
                    continue;
                }
            }
            np = 0; /* let outer loop progress hp */
            break;
        }
        /* simply move hp from history to new */
        if (np == NULL) {
            tmp = hp->next;
            hp->next = new;
            new = hp;
            hp = tmp;
        }
    }
    return new;
}

/*!
 * \internal
 * \brief Sort the stonith-history
 *        sort by competed most current on the top
 *        pending actions lacking a completed-stamp are gathered at the top
 *
 * \param[in] history    List of stonith actions
 *
 */
static stonith_history_t *
sort_stonith_history(stonith_history_t *history)
{
    stonith_history_t *new = NULL, *pending = NULL, *hp, *np, *tmp;

    for (hp = history; hp; ) {
        tmp = hp->next;
        if ((hp->state == st_done) || (hp->state == st_failed)) {
            /* sort into new */
            if ((!new) || (hp->completed > new->completed)) {
                hp->next = new;
                new = hp;
            } else {
                np = new;
                do {
                    if ((!np->next) || (hp->completed > np->next->completed)) {
                        hp->next = np->next;
                        np->next = hp;
                        break;
                    }
                    np = np->next;
                } while (1);
            }
        } else {
            /* put into pending */
            hp->next = pending;
            pending = hp;
        }
        hp = tmp;
    }

    /* pending actions don't have a completed-stamp so make them go front */
    if (pending) {
        stonith_history_t *last_pending = pending;

        while (last_pending->next) {
            last_pending = last_pending->next;
        }

        last_pending->next = new;
        new = pending;
    }
    return new;
}

/*!
 * \internal
 * \brief Print a section for failed stonith actions
 *
 * \param[in] stream     File stream to display output to
 * \param[in] history    List of stonith actions
 *
 */
static void
print_failed_stonith_actions(FILE *stream, stonith_history_t *history)
{
    stonith_history_t *hp;

    for (hp = history; hp; hp = hp->next) {
        if (hp->state == st_failed) {
            break;
        }
    }
    if (!hp) {
        return;
    }

    /* Print section heading */
    switch (output_format) {
        /* no need to take care of xml in here as xml gets full
         * history anyway
         */
        case mon_output_plain:
        case mon_output_console:
            print_as("\nFailed Fencing Actions:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Failed Fencing Actions</h2>\n <ul>\n");
            break;

        default:
            break;
    }

    /* Print each failed stonith action */
    for (hp = history; hp; hp = hp->next) {
        if (hp->state == st_failed) {
            print_stonith_action(stream, hp);
        }
    }

    /* End section */
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " </ul>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print pending stonith actions
 *
 * \param[in] stream     File stream to display output to
 * \param[in] history    List of stonith actions
 *
 */
static void
print_stonith_pending(FILE *stream, stonith_history_t *history)
{
    /* xml-output always shows the full history
     * so we'll never have to show pending-actions
     * separately
     */
    if (history && (history->state != st_failed) &&
        (history->state != st_done)) {
        stonith_history_t *hp;

        /* Print section heading */
        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as("\nPending Fencing Actions:\n");
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, " <hr />\n <h2>Pending Fencing Actions</h2>\n <ul>\n");
                break;

            default:
                break;
        }

        for (hp = history; hp; hp = hp->next) {
            if ((hp->state == st_failed) || (hp->state == st_done)) {
                break;
            }
            print_stonith_action(stream, hp);
        }

        /* End section */
        switch (output_format) {
            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, " </ul>\n");
                break;

        default:
            break;
        }
    }
}

/*!
 * \internal
 * \brief Print cluster status to screen
 *
 * This uses the global display preferences set by command-line options
 * to display cluster status in a human-friendly way.
 *
 * \param[in] data_set          Working set of CIB state
 * \param[in] stonith_history   List of stonith actions
 */
static void
print_status(pe_working_set_t * data_set,
             stonith_history_t *stonith_history)
{
    GListPtr gIter = NULL;
    int print_opts = get_resource_display_options();

    /* space-separated lists of node names */
    char *online_nodes = NULL;
    char *online_remote_nodes = NULL;
    char *online_guest_nodes = NULL;
    char *offline_nodes = NULL;
    char *offline_remote_nodes = NULL;

    if (output_format == mon_output_console) {
        blank_screen();
    }
    print_cluster_summary(stdout, data_set);
    print_as("\n");

    /* Gather node information (and print if in bad state or grouping by node) */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *node_mode = NULL;
        char *node_name = get_node_display_name(node);

        /* Get node mode */
        if (node->details->unclean) {
            if (node->details->online) {
                node_mode = "UNCLEAN (online)";

            } else if (node->details->pending) {
                node_mode = "UNCLEAN (pending)";

            } else {
                node_mode = "UNCLEAN (offline)";
            }

        } else if (node->details->pending) {
            node_mode = "pending";

        } else if (node->details->standby_onfail && node->details->online) {
            node_mode = "standby (on-fail)";

        } else if (node->details->standby) {
            if (node->details->online) {
                if (node->details->running_rsc) {
                    node_mode = "standby (with active resources)";
                } else {
                    node_mode = "standby";
                }
            } else {
                node_mode = "OFFLINE (standby)";
            }

        } else if (node->details->maintenance) {
            if (node->details->online) {
                node_mode = "maintenance";
            } else {
                node_mode = "OFFLINE (maintenance)";
            }

        } else if (node->details->online) {
            node_mode = "online";
            if (pp.group_by_node == FALSE) {
                if (is_container_remote_node(node)) {
                    online_guest_nodes = add_list_element(online_guest_nodes, node_name);
                } else if (is_baremetal_remote_node(node)) {
                    online_remote_nodes = add_list_element(online_remote_nodes, node_name);
                } else {
                    online_nodes = add_list_element(online_nodes, node_name);
                }
                free(node_name);
                continue;
            }
        } else {
            node_mode = "OFFLINE";
            if (pp.group_by_node == FALSE) {
                if (is_baremetal_remote_node(node)) {
                    offline_remote_nodes = add_list_element(offline_remote_nodes, node_name);
                } else if (is_container_remote_node(node)) {
                    /* ignore offline guest nodes */
                } else {
                    offline_nodes = add_list_element(offline_nodes, node_name);
                }
                free(node_name);
                continue;
            }
        }

        /* If we get here, node is in bad state, or we're grouping by node */

        /* Print the node name and status */
        if (is_container_remote_node(node)) {
            print_as("Guest");
        } else if (is_baremetal_remote_node(node)) {
            print_as("Remote");
        }
        print_as("Node %s: %s\n", node_name, node_mode);

        /* If we're grouping by node, print its resources */
        if (pp.group_by_node) {
            if (pp.print_brief) {
                print_rscs_brief(node->details->running_rsc, "\t", print_opts | pe_print_rsconly,
                                 stdout, FALSE);
            } else {
                GListPtr gIter2 = NULL;

                for (gIter2 = node->details->running_rsc; gIter2 != NULL; gIter2 = gIter2->next) {
                    resource_t *rsc = (resource_t *) gIter2->data;

                    rsc->fns->print(rsc, "\t", print_opts | pe_print_rsconly, stdout);
                }
            }
        }
        free(node_name);
    }

    /* If we're not grouping by node, summarize nodes by status */
    if (online_nodes) {
        print_as("Online: [%s ]\n", online_nodes);
        free(online_nodes);
    }
    if (offline_nodes) {
        print_as("OFFLINE: [%s ]\n", offline_nodes);
        free(offline_nodes);
    }
    if (online_remote_nodes) {
        print_as("RemoteOnline: [%s ]\n", online_remote_nodes);
        free(online_remote_nodes);
    }
    if (offline_remote_nodes) {
        print_as("RemoteOFFLINE: [%s ]\n", offline_remote_nodes);
        free(offline_remote_nodes);
    }
    if (online_guest_nodes) {
        print_as("GuestOnline: [%s ]\n", online_guest_nodes);
        free(online_guest_nodes);
    }

    /* Print resources section, if needed */
    print_resources(stdout, data_set, print_opts);

    /* print Node Attributes section if requested */
    if (pp.show & mon_show_attributes) {
        print_node_attributes(stdout, data_set);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pp.show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(stdout, data_set,
                           ((pp.show & mon_show_operations)? TRUE : FALSE));
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(stdout, data_set);
    }

    /* Print failed stonith actions */
    if (pp.fence_history) {
        print_failed_stonith_actions(stdout, stonith_history);
    }

    /* Print tickets if requested */
    if (pp.show & mon_show_tickets) {
        print_cluster_tickets(stdout, data_set);
    }

    /* Print negative location constraints if requested */
    if (pp.show & mon_show_bans) {
        print_neg_locations(stdout, data_set);
    }

    /* Print stonith history */
    if (pp.fence_history) {
        if (pp.show & mon_show_fence_history) {
            print_stonith_history(stdout, stonith_history);
        } else {
            print_stonith_pending(stdout, stonith_history);
        }
    }

#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        refresh();
    }
#endif
}

/*!
 * \internal
 * \brief Print cluster status in HTML format (with HTTP headers if CGI)
 *
 * \param[in] data_set   Working set of CIB state
 * \param[in] filename   Name of file to write HTML to (ignored if CGI)
 *
 * \return 0 on success, -1 on error
 */
static int
print_html_status(pe_working_set_t * data_set,
                  const char *filename,
                  stonith_history_t *stonith_history)
{
    FILE *stream;
    GListPtr gIter = NULL;
    char *filename_tmp = NULL;
    int print_opts = get_resource_display_options();

    if (output_format == mon_output_cgi) {
        stream = stdout;
        fprintf(stream, "Content-Type: text/html\n\n");

    } else {
        filename_tmp = crm_concat(filename, "tmp", '.');
        stream = fopen(filename_tmp, "w");
        if (stream == NULL) {
            crm_perror(LOG_ERR, "Cannot open %s for writing", filename_tmp);
            free(filename_tmp);
            return -1;
        }
    }

    fprintf(stream, "<html>\n");
    fprintf(stream, " <head>\n");
    fprintf(stream, "  <title>Cluster status</title>\n");
    fprintf(stream, "  <meta http-equiv=\"refresh\" content=\"%d\">\n", reconnect_msec / 1000);
    fprintf(stream, " </head>\n");
    fprintf(stream, "<body>\n");

    print_cluster_summary(stream, data_set);

    /*** NODE LIST ***/

    fprintf(stream, " <hr />\n <h2>Node List</h2>\n");
    fprintf(stream, "<ul>\n");
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        char *node_name = get_node_display_name(node);

        fprintf(stream, "<li>Node: %s: ", node_name);
        if (node->details->standby_onfail && node->details->online) {
            fprintf(stream, "<font color=\"orange\">standby (on-fail)</font>\n");
        } else if (node->details->standby && node->details->online) {

            fprintf(stream, "<font color=\"orange\">standby%s</font>\n",
                node->details->running_rsc?" (with active resources)":"");
        } else if (node->details->standby) {
            fprintf(stream, "<font color=\"red\">OFFLINE (standby)</font>\n");
        } else if (node->details->maintenance && node->details->online) {
            fprintf(stream, "<font color=\"blue\">maintenance</font>\n");
        } else if (node->details->maintenance) {
            fprintf(stream, "<font color=\"red\">OFFLINE (maintenance)</font>\n");
        } else if (node->details->online) {
            fprintf(stream, "<font color=\"green\">online</font>\n");
        } else {
            fprintf(stream, "<font color=\"red\">OFFLINE</font>\n");
        }
        if (pp.print_brief && pp.group_by_node) {
            fprintf(stream, "<ul>\n");
            print_rscs_brief(node->details->running_rsc, NULL, print_opts | pe_print_rsconly,
                             stream, FALSE);
            fprintf(stream, "</ul>\n");

        } else if (pp.group_by_node) {
            GListPtr lpc2 = NULL;

            fprintf(stream, "<ul>\n");
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                resource_t *rsc = (resource_t *) lpc2->data;

                fprintf(stream, "<li>");
                rsc->fns->print(rsc, NULL, print_opts | pe_print_rsconly, stream);
                fprintf(stream, "</li>\n");
            }
            fprintf(stream, "</ul>\n");
        }
        fprintf(stream, "</li>\n");
        free(node_name);
    }
    fprintf(stream, "</ul>\n");

    /* Print resources section, if needed */
    print_resources(stream, data_set, print_opts);

    /* print Node Attributes section if requested */
    if (pp.show & mon_show_attributes) {
        print_node_attributes(stream, data_set);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pp.show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(stream, data_set,
                           ((pp.show & mon_show_operations)? TRUE : FALSE));
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(stream, data_set);
    }

    /* Print failed stonith actions */
    if (pp.fence_history) {
        print_failed_stonith_actions(stream, stonith_history);
    }

    /* Print stonith history */
    if (pp.fence_history) {
        if (pp.show & mon_show_fence_history) {
            print_stonith_history(stream, stonith_history);
        } else {
            print_stonith_pending(stdout, stonith_history);
        }
    }

    /* Print tickets if requested */
    if (pp.show & mon_show_tickets) {
        print_cluster_tickets(stream, data_set);
    }

    /* Print negative location constraints if requested */
    if (pp.show & mon_show_bans) {
        print_neg_locations(stream, data_set);
    }

    fprintf(stream, "</body>\n");
    fprintf(stream, "</html>\n");
    fflush(stream);
    fclose(stream);

    if (output_format != mon_output_cgi) {
        if (rename(filename_tmp, filename) != 0) {
            crm_perror(LOG_ERR, "Unable to rename %s->%s", filename_tmp, filename);
        }
        free(filename_tmp);
    }
    return 0;
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

    crm_debug("Sending external notification to '%s' via '%s'", external_recipient, external_agent);

    if(rsc) {
        setenv("CRM_notify_rsc", rsc, 1);
    }
    if (external_recipient) {
        setenv("CRM_notify_recipient", external_recipient, 1);
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
        execl(external_agent, external_agent, NULL);
        exit(CRM_EX_ERROR);
    }

    crm_trace("Finished running custom notification program '%s'.", external_agent);
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
    int action = -1;
    int target_rc = -1;
    int transition_num = -1;
    gboolean notify = TRUE;

    char *rsc = NULL;
    char *task = NULL;
    const char *desc = NULL;
    const char *magic = NULL;
    const char *id = NULL;
    char *update_te_uuid = NULL;
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

    if (FALSE == decode_transition_magic(magic, &update_te_uuid, &transition_num, &action,
                                         &status, &rc, &target_rc)) {
        crm_err("Invalid event %s detected for %s", magic, id);
        return;
    }

    if (parse_op_key(id, &rsc, &task, NULL) == FALSE) {
        crm_err("Invalid event detected for %s", id);
        goto bail;
    }

    node = crm_element_value(rsc_op, XML_LRM_ATTR_TARGET);

    while (n != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(n))) {
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

    if (notify && external_agent) {
        send_custom_trap(node, rsc, task, target_rc, rc, status, desc);
    }
  bail:
    free(update_te_uuid);
    free(rsc);
    free(task);
}

static gboolean
mon_trigger_refresh(gpointer user_data)
{
    mainloop_set_trigger(refresh_trigger);
    return FALSE;
}

#define NODE_PATT "/lrm[@id="
static char *
get_node_from_xpath(const char *xpath)
{
    char *nodeid = NULL;
    char *tmp = strstr(xpath, NODE_PATT);

    if(tmp) {
        tmp += strlen(NODE_PATT);
        tmp += 1;

        nodeid = strdup(tmp);
        tmp = strstr(nodeid, "\'");
        CRM_ASSERT(tmp);
        tmp[0] = 0;
    }
    return nodeid;
}

static void
crm_diff_update_v2(const char *event, xmlNode * msg)
{
    xmlNode *change = NULL;
    xmlNode *diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    for (change = __xml_first_child(diff); change != NULL; change = __xml_next(change)) {
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

            for (state = __xml_first_child(status); state != NULL; state = __xml_next(state)) {
                node = crm_element_value(state, XML_ATTR_UNAME);
                if (node == NULL) {
                    node = ID(state);
                }
                handle_rsc_op(state, node);
            }

        } else if(strcmp(name, XML_CIB_TAG_STATUS) == 0) {
            xmlNode *state = NULL;

            for (state = __xml_first_child(match); state != NULL; state = __xml_next(state)) {
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
            char *local_node = get_node_from_xpath(xpath);

            handle_rsc_op(match, local_node);
            free(local_node);

        } else if(strcmp(name, XML_LRM_TAG_RESOURCE) == 0) {
            char *local_node = get_node_from_xpath(xpath);

            handle_rsc_op(match, local_node);
            free(local_node);

        } else if(strcmp(name, XML_LRM_TAG_RSC_OP) == 0) {
            char *local_node = get_node_from_xpath(xpath);

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

    print_dot();

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

    if (external_agent) {
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
            print_as("--- Stale data ---");
        }
        stale = TRUE;
        return;
    }

    stale = FALSE;
    kick_refresh(cib_updated);
}

static gboolean
mon_refresh_display(gpointer user_data)
{
    xmlNode *cib_copy = copy_xml(current_cib);
    stonith_history_t *stonith_history = NULL;

    last_refresh = time(NULL);

    if (cli_config_update(&cib_copy, NULL, FALSE) == FALSE) {
        if (cib) {
            cib->cmds->signoff(cib);
        }
        print_as("Upgrade failed: %s", pcmk_strerror(-pcmk_err_schema_validation));
        if (output_format == mon_output_console) {
            sleep(2);
        }
        clean_up(CRM_EX_CONFIG);
        return FALSE;
    }

    /* get the stonith-history if there is evidence we need it
     */
    while (pp.fence_history) {
        if (st != NULL) {
            if (st->cmds->history(st, st_opt_sync_call, NULL, &stonith_history, 120)) {
                fprintf(stderr, "Critical: Unable to get stonith-history\n");
                mon_cib_connection_destroy(NULL);
            } else {
                if ((!pp.fence_full_history) && (output_format != mon_output_xml)) {
                    stonith_history = reduce_stonith_history(stonith_history);
                }
                stonith_history = sort_stonith_history(stonith_history);
                break; /* all other cases are errors */
            }
        } else {
            fprintf(stderr, "Critical: No stonith-API\n");
        }
        free_xml(cib_copy);
        print_as("Reading stonith-history failed");
        if (output_format == mon_output_console) {
            sleep(2);
        }
        return FALSE;
    }

    if (mon_data_set == NULL) {
        mon_data_set = pe_new_working_set();
        CRM_ASSERT(mon_data_set != NULL);
    }

    mon_data_set->input = cib_copy;
    cluster_status(mon_data_set);

    /* Unpack constraints if any section will need them
     * (tickets may be referenced in constraints but not granted yet,
     * and bans need negative location constraints) */
    if (pp.show & (mon_show_bans | mon_show_tickets)) {
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                   mon_data_set->input);
        unpack_constraints(cib_constraints, mon_data_set);
    }

    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            if (print_html_status(mon_data_set, output_filename, stonith_history) != 0) {
                fprintf(stderr, "Critical: Unable to output html file\n");
                clean_up(CRM_EX_CANTCREAT);
                return FALSE;
            }
            break;

        case mon_output_xml:
            print_xml_status(stdout, mon_data_set, stonith_history, pp);
            break;

        case mon_output_monitor:
            print_simple_status(mon_data_set, stonith_history);
            if (has_warnings) {
                clean_up(MON_STATUS_WARN);
                return FALSE;
            }
            break;

        case mon_output_plain:
        case mon_output_console:
            print_status(mon_data_set, stonith_history);
            break;

        case mon_output_none:
            break;
    }

    stonith_history_free(stonith_history);
    stonith_history = NULL;
    pe_reset_working_set(mon_data_set);
    return TRUE;
}

static void
mon_st_callback_event(stonith_t * st, stonith_event_t * e)
{
    if (st->state == stonith_disconnected) {
        /* disconnect cib as well and have everything reconnect */
        mon_cib_connection_destroy(NULL);
    } else if (external_agent) {
        char *desc = crm_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                    e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                    e->id);
        send_custom_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
        free(desc);
    }
}

static void
kick_refresh(gboolean data_updated)
{
    static int updates = 0;
    long now = time(NULL);

    if (data_updated) {
        updates++;
    }

    if(refresh_timer == NULL) {
        refresh_timer = mainloop_timer_add("refresh", 2000, FALSE, mon_trigger_refresh, NULL);
    }

    /* Refresh
     * - immediately if the last update was more than 5s ago
     * - every 10 cib-updates
     * - at most 2s after the last update
     */
    if ((now - last_refresh) > (reconnect_msec / 1000)) {
        mainloop_set_trigger(refresh_trigger);
        mainloop_timer_stop(refresh_timer);
        updates = 0;

    } else if(updates >= 10) {
        mainloop_set_trigger(refresh_trigger);
        mainloop_timer_stop(refresh_timer);
        updates = 0;

    } else {
        mainloop_timer_start(refresh_timer);
    }
}

static void
mon_st_callback_display(stonith_t * st, stonith_event_t * e)
{
    if (st->state == stonith_disconnected) {
        /* disconnect cib as well and have everything reconnect */
        mon_cib_connection_destroy(NULL);
    } else {
        print_dot();
        kick_refresh(TRUE);
    }
}

static void
clean_up_connections(void)
{
    if (cib != NULL) {
        cib->cmds->signoff(cib);
        cib_delete(cib);
        cib = NULL;
    }

    if (st != NULL) {
        if (st->state != stonith_disconnected) {
            st->cmds->remove_notification(st, T_STONITH_NOTIFY_DISCONNECT);
            st->cmds->remove_notification(st, T_STONITH_NOTIFY_FENCE);
            st->cmds->remove_notification(st, T_STONITH_NOTIFY_HISTORY);
            st->cmds->disconnect(st);
        }
        stonith_api_delete(st);
        st = NULL;
    }
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
#if CURSES_ENABLED
    if (curses_console_initialized) {
        output_format = mon_output_plain;
        echo();
        nocbreak();
        endwin();
        curses_console_initialized = FALSE;
    }
#endif

    clean_up_connections();
    free(output_filename);
    free(pid_file);

    pe_free_working_set(mon_data_set);
    mon_data_set = NULL;

    if (exit_code == CRM_EX_USAGE) {
        if (output_format == mon_output_cgi) {
            fprintf(stdout, "Content-Type: text/plain\n"
                            "Status: 500\n\n");
        } else {
            crm_help('?', CRM_EX_USAGE);
        }
    }
    crm_exit(exit_code);
}
