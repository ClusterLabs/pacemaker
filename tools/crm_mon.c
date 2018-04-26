/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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
#include <crm/pengine/internal.h>
#include <../lib/pengine/unpack.h>
#include <pacemaker-schedulerd.h>
#include <crm/stonith-ng.h>

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

static void clean_up(crm_exit_t exit_code);
void crm_diff_update(const char *event, xmlNode * msg);
gboolean mon_refresh_display(gpointer user_data);
int cib_connect(gboolean full);
void mon_st_callback(stonith_t * st, stonith_event_t * e);
static char *get_node_display_name(node_t *node);

/*
 * Definitions indicating which items to print
 */

#define mon_show_times      (0x0001U)
#define mon_show_stack      (0x0002U)
#define mon_show_dc         (0x0004U)
#define mon_show_count      (0x0008U)
#define mon_show_nodes      (0x0010U)
#define mon_show_resources  (0x0020U)
#define mon_show_attributes (0x0040U)
#define mon_show_failcounts (0x0080U)
#define mon_show_operations (0x0100U)
#define mon_show_tickets    (0x0200U)
#define mon_show_bans       (0x0400U)

#define mon_show_headers    (mon_show_times | mon_show_stack | mon_show_dc | mon_show_count)
#define mon_show_default    (mon_show_headers | mon_show_nodes | mon_show_resources)
#define mon_show_all        (mon_show_default | mon_show_attributes | mon_show_failcounts \
                     | mon_show_operations | mon_show_tickets | mon_show_bans)

unsigned int show = mon_show_default;

/*
 * Definitions indicating how to output
 */

enum mon_output_format_e {
    mon_output_none,
    mon_output_monitor,
    mon_output_plain,
    mon_output_console,
    mon_output_xml,
    mon_output_html,
    mon_output_cgi
} output_format = mon_output_console;

char *output_filename = NULL;   /* if sending output to a file, its name */

/* other globals */
char *xml_file = NULL;
char *pid_file = NULL;

gboolean group_by_node = FALSE;
gboolean inactive_resources = FALSE;
int reconnect_msec = 5000;
gboolean daemonize = FALSE;
GMainLoop *mainloop = NULL;
guint timer_id = 0;
GList *attr_list = NULL;

const char *external_agent = NULL;
const char *external_recipient = NULL;

cib_t *cib = NULL;
stonith_t *st = NULL;
xmlNode *current_cib = NULL;

gboolean one_shot = FALSE;
gboolean has_warnings = FALSE;
gboolean print_timing = FALSE;
gboolean watch_fencing = FALSE;
gboolean print_brief = FALSE;
gboolean print_pending = TRUE;
gboolean print_clone_detail = FALSE;

/* FIXME allow, detect, and correctly interpret glob pattern or regex? */
const char *print_neg_location_prefix = "";

/* Never display node attributes whose name starts with one of these prefixes */
#define FILTER_STR { CRM_FAIL_COUNT_PREFIX, CRM_LAST_FAILURE_PREFIX,       \
                     "shutdown", "terminate", "standby", "probe_complete", \
                     "#", NULL }

long last_refresh = 0;
crm_trigger_t *refresh_trigger = NULL;

/* Define exit codes for monitoring-compatible output */
#define MON_STATUS_WARN CRM_EX_ERROR

/* Convenience macro for prettifying output (e.g. "node" vs "nodes") */
#define s_if_plural(i) (((i) == 1)? "" : "s")

#if CURSES_ENABLED
#  define print_dot() if (output_format == mon_output_console) { \
	printw(".");				\
	clrtoeol();				\
	refresh();				\
    } else {					\
	fprintf(stdout, ".");			\
    }
#else
#  define print_dot() fprintf(stdout, ".");
#endif

#if CURSES_ENABLED
#  define print_as(fmt, args...) if (output_format == mon_output_console) { \
	printw(fmt, ##args);				\
	clrtoeol();					\
	refresh();					\
    } else {						\
	fprintf(stdout, fmt, ##args);			\
    }
#else
#  define print_as(fmt, args...) fprintf(stdout, fmt, ##args);
#endif

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
    print_as("Connection to the CIB terminated\n");
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

int
cib_connect(gboolean full)
{
    int rc = pcmk_ok;
    static gboolean need_pass = TRUE;

    CRM_CHECK(cib != NULL, return -EINVAL);

    if (getenv("CIB_passwd") != NULL) {
        need_pass = FALSE;
    }

    if (watch_fencing && st == NULL) {
        st = stonith_api_new();
    }

    if (watch_fencing && st->state == stonith_disconnected) {
        crm_trace("Connecting to stonith");
        rc = st->cmds->connect(st, crm_system_name, NULL);
        if (rc == pcmk_ok) {
            crm_trace("Setting up stonith callbacks");
            st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, mon_st_callback);
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
                clean_up(crm_errno2exit(rc));
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
            const char * tab = NULL;
            tab = strrchr(long_options[lpc].desc, '\t');
            return tab ? ++tab : long_options[lpc].desc;
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
            case 'c':
                show ^= mon_show_tickets;
                break;
            case 'f':
                show ^= mon_show_failcounts;
                break;
            case 'n':
                group_by_node = ! group_by_node;
                break;
            case 'o':
                show ^= mon_show_operations;
                if ((show & mon_show_operations) == 0) {
                    print_timing = 0;
                }
                break;
            case 'r':
                inactive_resources = ! inactive_resources;
                break;
            case 'R':
                print_clone_detail = ! print_clone_detail;
                break;
            case 't':
                print_timing = ! print_timing;
                if (print_timing) {
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
                if (show & mon_show_headers) {
                    show &= ~mon_show_headers;
                } else {
                    show |= mon_show_headers;
                }
                break;
            case 'b':
                print_brief = ! print_brief;
                break;
            case 'j':
                print_pending = ! print_pending;
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
        print_option_help('c', show & mon_show_tickets);
        print_option_help('f', show & mon_show_failcounts);
        print_option_help('n', group_by_node);
        print_option_help('o', show & mon_show_operations);
        print_option_help('r', inactive_resources);
        print_option_help('t', print_timing);
        print_option_help('A', show & mon_show_attributes);
        print_option_help('L', show & mon_show_bans);
        print_option_help('D', (show & mon_show_headers) == 0);
        print_option_help('R', print_clone_detail);
        print_option_help('b', print_brief);
        print_option_help('j', print_pending);
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

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'Q':
                show &= ~mon_show_times;
                break;
            case 'i':
                reconnect_msec = crm_get_msec(optarg);
                break;
            case 'n':
                group_by_node = TRUE;
                break;
            case 'r':
                inactive_resources = TRUE;
                break;
            case 'W':
                watch_fencing = TRUE;
                break;
            case 'd':
                daemonize = TRUE;
                break;
            case 't':
                print_timing = TRUE;
                show |= mon_show_operations;
                break;
            case 'o':
                show |= mon_show_operations;
                break;
            case 'f':
                show |= mon_show_failcounts;
                break;
            case 'A':
                show |= mon_show_attributes;
                break;
            case 'L':
                show |= mon_show_bans;
                print_neg_location_prefix = optarg? optarg : "";
                break;
            case 'D':
                show &= ~mon_show_headers;
                break;
            case 'b':
                print_brief = TRUE;
                break;
            case 'j':
                print_pending = TRUE;
                break;
            case 'R':
                print_clone_detail = TRUE;
                break;
            case 'c':
                show |= mon_show_tickets;
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
                xml_file = strdup(optarg);
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

    /* Extra sanity checks when in CGI mode */
    if (output_format == mon_output_cgi) {
        argerr += (optind < argc);
        argerr += (output_filename != NULL);
        argerr += (xml_file != NULL);
        argerr += (external_agent != NULL);
        argerr += (daemonize == TRUE);  /* paranoia */

    } else if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }

    if (argerr) {
        if (output_format == mon_output_cgi) {
            fprintf(stdout, "Content-Type: text/plain\n"
                            "Status: 500\n\n");
            return CRM_EX_USAGE;
        }
        crm_help('?', CRM_EX_USAGE);
    }

    /* XML output always prints everything */
    if (output_format == mon_output_xml) {
        show = mon_show_all;
        print_timing = TRUE;
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

        if ((output_format != mon_output_html) && (output_format != mon_output_xml)
            && !external_agent) {
            printf
                ("Looks like you forgot to specify one or more of: --as-html, --as-xml, --external-agent\n");
            crm_help('?', CRM_EX_USAGE);
        }

        crm_make_daemon(crm_system_name, TRUE, pid_file);

    } else if (output_format == mon_output_console) {
#if CURSES_ENABLED
        initscr();
        cbreak();
        noecho();
        crm_enable_stderr(FALSE);
#else
        one_shot = TRUE;
        output_format = mon_output_plain;
        printf("Defaulting to one-shot mode\n");
        printf("You need to have curses available at compile time to enable console mode\n");
#endif
    }

    crm_info("Starting %s", crm_system_name);
    if (xml_file != NULL) {
        current_cib = filename2xml(xml_file);
        mon_refresh_display(NULL);
        return CRM_EX_OK;
    }

    if (current_cib == NULL) {
        int rc = pcmk_ok;

        cib = cib_new();

        do {
            if (!one_shot) {
                print_as("Attempting connection to the cluster...\n");
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
            }

        } while (rc == -ENOTCONN);

        if (rc != pcmk_ok) {
            if (output_format == mon_output_monitor) {
                printf("CLUSTER WARN: Connection to cluster failed: %s\n", pcmk_strerror(rc));
                clean_up(MON_STATUS_WARN);
            } else {
                print_as("\nConnection to cluster failed: %s\n", pcmk_strerror(rc));
            }
            if (output_format == mon_output_console) {
                sleep(2);
            }
            clean_up(crm_errno2exit(rc));
        }
    }

    if (one_shot) {
        return CRM_EX_OK;
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
    g_main_destroy(mainloop);

    crm_info("Exiting %s", crm_system_name);

    clean_up(CRM_EX_OK);
    return CRM_EX_OK; // Should never be reached
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

static int
count_resources(pe_working_set_t * data_set, resource_t * rsc)
{
    int count = 0;
    GListPtr gIter = NULL;

    if (rsc == NULL) {
        gIter = data_set->resources;
    } else if (rsc->children) {
        gIter = rsc->children;
    } else {
        return is_not_set(rsc->flags, pe_rsc_orphan);
    }

    for (; gIter != NULL; gIter = gIter->next) {
        count += count_resources(data_set, gIter->data);
    }
    return count;
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
print_simple_status(pe_working_set_t * data_set)
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

/*!
 * \internal
 * \brief Print a [name]=[value][units] pair, optionally using time string
 *
 * \param[in] stream      File stream to display output to
 * \param[in] name        Name to display
 * \param[in] value       Value to display (or NULL to convert time instead)
 * \param[in] units       Units to display (or NULL for no units)
 * \param[in] epoch_time  Epoch time to convert if value is NULL
 */
static void
print_nvpair(FILE *stream, const char *name, const char *value,
             const char *units, time_t epoch_time)
{
    /* print name= */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(" %s=", name);
            break;

        case mon_output_html:
        case mon_output_cgi:
        case mon_output_xml:
            fprintf(stream, " %s=", name);
            break;

        default:
            break;
    }

    /* If we have a value (and optionally units), print it */
    if (value) {
        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as("%s%s", value, (units? units : ""));
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, "%s%s", value, (units? units : ""));
                break;

            case mon_output_xml:
                fprintf(stream, "\"%s%s\"", value, (units? units : ""));
                break;

            default:
                break;
        }

    /* Otherwise print user-friendly time string */
    } else {
        static char empty_str[] = "";
        char *c, *date_str = asctime(localtime(&epoch_time));

        for (c = (date_str != NULL) ? date_str : empty_str; *c != '\0'; ++c) {
            if (*c == '\n') {
                *c = '\0';
                break;
            }
        }
        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as("'%s'", date_str);
                break;

            case mon_output_html:
            case mon_output_cgi:
            case mon_output_xml:
                fprintf(stream, "\"%s\"", date_str);
                break;

            default:
                break;
        }
    }
}

/*!
 * \internal
 * \brief Print whatever is needed to start a node section
 *
 * \param[in] stream     File stream to display output to
 * \param[in] node       Node to print
 */
static void
print_node_start(FILE *stream, node_t *node)
{
    char *node_name;

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            node_name = get_node_display_name(node);
            print_as("* Node %s:\n", node_name);
            free(node_name);
            break;

        case mon_output_html:
        case mon_output_cgi:
            node_name = get_node_display_name(node);
            fprintf(stream, "  <h3>Node: %s</h3>\n  <ul>\n", node_name);
            free(node_name);
            break;

        case mon_output_xml:
            fprintf(stream, "        <node name=\"%s\">\n", node->details->uname);
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print whatever is needed to end a node section
 *
 * \param[in] stream     File stream to display output to
 */
static void
print_node_end(FILE *stream)
{
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "  </ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "        </node>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print resources section heading appropriate to options
 *
 * \param[in] stream      File stream to display output to
 */
static void
print_resources_heading(FILE *stream)
{
    const char *heading;

    if (group_by_node) {

        /* Active resources have already been printed by node */
        heading = (inactive_resources? "Inactive resources" : NULL);

    } else if (inactive_resources) {
        heading = "Full list of resources";

    } else {
        heading = "Active resources";
    }

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n%s:\n\n", heading);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>%s</h2>\n", heading);
            break;

        case mon_output_xml:
            fprintf(stream, "    <resources>\n");
            break;

        default:
            break;
    }

}

/*!
 * \internal
 * \brief Print whatever resource section closing is appropriate
 *
 * \param[in] stream     File stream to display output to
 */
static void
print_resources_closing(FILE *stream, gboolean printed_heading)
{
    const char *heading;

    /* What type of resources we did or did not display */
    if (group_by_node) {
        heading = "inactive ";
    } else if (inactive_resources) {
        heading = "";
    } else {
        heading = "active ";
    }

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (!printed_heading) {
                print_as("\nNo %sresources\n\n", heading);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            if (!printed_heading) {
                fprintf(stream, " <hr />\n <h2>No %sresources</h2>\n", heading);
            }
            break;

        case mon_output_xml:
            fprintf(stream, "    %s\n",
                    (printed_heading? "</resources>" : "<resources/>"));
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print whatever resource section(s) are appropriate
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Cluster state to display
 * \param[in] print_opts  Bitmask of pe_print_options
 */
static void
print_resources(FILE *stream, pe_working_set_t *data_set, int print_opts)
{
    GListPtr rsc_iter;
    const char *prefix = NULL;
    gboolean printed_heading = FALSE;
    gboolean brief_output = print_brief;

    /* If we already showed active resources by node, and
     * we're not showing inactive resources, we have nothing to do
     */
    if (group_by_node && !inactive_resources) {
        return;
    }

    /* XML uses an indent, and ignores brief option for resources */
    if (output_format == mon_output_xml) {
        prefix = "        ";
        brief_output = FALSE;
    }

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (brief_output && !group_by_node) {
        print_resources_heading(stream);
        printed_heading = TRUE;
        print_rscs_brief(data_set->resources, NULL, print_opts, stream,
                         inactive_resources);
    }

    /* For each resource, display it if appropriate */
    for (rsc_iter = data_set->resources; rsc_iter != NULL; rsc_iter = rsc_iter->next) {
        resource_t *rsc = (resource_t *) rsc_iter->data;

        /* Complex resources may have some sub-resources active and some inactive */
        gboolean is_active = rsc->fns->active(rsc, TRUE);
        gboolean partially_active = rsc->fns->active(rsc, FALSE);

        /* Skip inactive orphans (deleted but still in CIB) */
        if (is_set(rsc->flags, pe_rsc_orphan) && !is_active) {
            continue;

        /* Skip active resources if we already displayed them by node */
        } else if (group_by_node) {
            if (is_active) {
                continue;
            }

        /* Skip primitives already counted in a brief summary */
        } else if (brief_output && (rsc->variant == pe_native)) {
            continue;

        /* Skip resources that aren't at least partially active,
         * unless we're displaying inactive resources
         */
        } else if (!partially_active && !inactive_resources) {
            continue;
        }

        /* Print this resource */
        if (printed_heading == FALSE) {
            print_resources_heading(stream);
            printed_heading = TRUE;
        }
        rsc->fns->print(rsc, prefix, print_opts, stream);
    }

    print_resources_closing(stream, printed_heading);
}

/*!
 * \internal
 * \brief Print heading for resource history
 *
 * \param[in] stream      File stream to display output to
 * \param[in] data_set    Current state of CIB
 * \param[in] node        Node that ran this resource
 * \param[in] rsc         Resource to print
 * \param[in] rsc_id      ID of resource to print
 * \param[in] all         Whether to print every resource or just failed ones
 */
static void
print_rsc_history_start(FILE *stream, pe_working_set_t *data_set, node_t *node,
                        resource_t *rsc, const char *rsc_id, gboolean all)
{
    time_t last_failure = 0;
    int failcount = rsc?
                    pe_get_failcount(node, rsc, &last_failure, pe_fc_default,
                                     NULL, data_set)
                    : 0;

    if (!all && !failcount && (last_failure <= 0)) {
        return;
    }

    /* Print resource ID */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("   %s:", rsc_id);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "   <li>%s:", rsc_id);
            break;

        case mon_output_xml:
            fprintf(stream, "            <resource_history id=\"%s\"", rsc_id);
            break;

        default:
            break;
    }

    /* If resource is an orphan, that's all we can say about it */
    if (rsc == NULL) {
        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(" orphan");
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, " orphan");
                break;

            case mon_output_xml:
                fprintf(stream, " orphan=\"true\"");
                break;

            default:
                break;
        }

    /* If resource is not an orphan, print some details */
    } else if (all || failcount || (last_failure > 0)) {

        /* Print migration threshold */
        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(" migration-threshold=%d", rsc->migration_threshold);
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, " migration-threshold=%d", rsc->migration_threshold);
                break;

            case mon_output_xml:
                fprintf(stream, " orphan=\"false\" migration-threshold=\"%d\"",
                        rsc->migration_threshold);
                break;

            default:
                break;
        }

        /* Print fail count if any */
        if (failcount > 0) {
            switch (output_format) {
                case mon_output_plain:
                case mon_output_console:
                    print_as(" " CRM_FAIL_COUNT_PREFIX "=%d", failcount);
                    break;

                case mon_output_html:
                case mon_output_cgi:
                    fprintf(stream, " " CRM_FAIL_COUNT_PREFIX "=%d", failcount);
                    break;

                case mon_output_xml:
                    fprintf(stream, " " CRM_FAIL_COUNT_PREFIX "=\"%d\"",
                            failcount);
                    break;

                default:
                    break;
            }
        }

        /* Print last failure time if any */
        if (last_failure > 0) {
            print_nvpair(stream, CRM_LAST_FAILURE_PREFIX, NULL, NULL,
                         last_failure);
        }
    }

    /* End the heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "\n    <ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, ">\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print closing for resource history
 *
 * \param[in] stream      File stream to display output to
 */
static void
print_rsc_history_end(FILE *stream)
{
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "    </ul>\n   </li>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "            </resource_history>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print operation history
 *
 * \param[in] stream        File stream to display output to
 * \param[in] data_set      Current state of CIB
 * \param[in] node          Node this operation is for
 * \param[in] xml_op        Root of XML tree describing this operation
 * \param[in] task          Task parsed from this operation's XML
 * \param[in] interval_ms_s Interval parsed from this operation's XML
 * \param[in] rc            Return code parsed from this operation's XML
 */
static void
print_op_history(FILE *stream, pe_working_set_t *data_set, node_t *node,
                 xmlNode *xml_op, const char *task, const char *interval_ms_s,
                 int rc)
{
    const char *value = NULL;
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);

    /* Begin the operation description */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("    + (%s) %s:", call, task);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "     <li>(%s) %s:", call, task);
            break;

        case mon_output_xml:
            fprintf(stream, "                <operation_history call=\"%s\" task=\"%s\"",
                    call, task);
            break;

        default:
            break;
    }

    /* Add name=value pairs as appropriate */
    if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
        print_nvpair(stream, "interval", interval_ms_s, "ms", 0);
    }
    if (print_timing) {
        int int_value;
        const char *attr;

        attr = XML_RSC_OP_LAST_CHANGE;
        value = crm_element_value(xml_op, attr);
        if (value) {
            int_value = crm_parse_int(value, NULL);
            if (int_value > 0) {
                print_nvpair(stream, attr, NULL, NULL, int_value);
            }
        }

        attr = XML_RSC_OP_LAST_RUN;
        value = crm_element_value(xml_op, attr);
        if (value) {
            int_value = crm_parse_int(value, NULL);
            if (int_value > 0) {
                print_nvpair(stream, attr, NULL, NULL, int_value);
            }
        }

        attr = XML_RSC_OP_T_EXEC;
        value = crm_element_value(xml_op, attr);
        if (value) {
            print_nvpair(stream, attr, value, "ms", 0);
        }

        attr = XML_RSC_OP_T_QUEUE;
        value = crm_element_value(xml_op, attr);
        if (value) {
            print_nvpair(stream, attr, value, "ms", 0);
        }
    }

    /* End the operation description */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(" rc=%d (%s)\n", rc, services_ocf_exitcode_str(rc));
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " rc=%d (%s)</li>\n", rc, services_ocf_exitcode_str(rc));
            break;

        case mon_output_xml:
            fprintf(stream, " rc=\"%d\" rc_text=\"%s\" />\n", rc, services_ocf_exitcode_str(rc));
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print resource operation/failure history
 *
 * \param[in] stream      File stream to display output to
 * \param[in] data_set    Current state of CIB
 * \param[in] node        Node that ran this resource
 * \param[in] rsc_entry   Root of XML tree describing resource status
 * \param[in] operations  Whether to print operations or just failcounts
 */
static void
print_rsc_history(FILE *stream, pe_working_set_t *data_set, node_t *node,
                  xmlNode *rsc_entry, gboolean operations)
{
    GListPtr gIter = NULL;
    GListPtr op_list = NULL;
    gboolean printed = FALSE;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);
    xmlNode *rsc_op = NULL;

    /* If we're not showing operations, just print the resource failure summary */
    if (operations == FALSE) {
        print_rsc_history_start(stream, data_set, node, rsc, rsc_id, FALSE);
        print_rsc_history_end(stream);
        return;
    }

    /* Create a list of this resource's operations */
    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next(rsc_op)) {
        if (crm_str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
            op_list = g_list_append(op_list, rsc_op);
        }
    }
    op_list = g_list_sort(op_list, sort_op_by_callid);

    /* Print each operation */
    for (gIter = op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *xml_op = (xmlNode *) gIter->data;
        const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(xml_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
        int rc = crm_parse_int(op_rc, "0");

        /* Display 0-interval monitors as "probe" */
        if (safe_str_eq(task, CRMD_ACTION_STATUS)
            && ((interval_ms_s == NULL) || safe_str_eq(interval_ms_s, "0"))) {
            task = "probe";
        }

        /* Ignore notifies and some probes */
        if (safe_str_eq(task, CRMD_ACTION_NOTIFY) || (safe_str_eq(task, "probe") && (rc == 7))) {
            continue;
        }

        /* If this is the first printed operation, print heading for resource */
        if (printed == FALSE) {
            printed = TRUE;
            print_rsc_history_start(stream, data_set, node, rsc, rsc_id, TRUE);
        }

        /* Print the operation */
        print_op_history(stream, data_set, node, xml_op, task, interval_ms_s,
                         rc);
    }

    /* Free the list we created (no need to free the individual items) */
    g_list_free(op_list);

    /* If we printed anything, close the resource */
    if (printed) {
        print_rsc_history_end(stream);
    }
}

/*!
 * \internal
 * \brief Print node operation/failure history
 *
 * \param[in] stream      File stream to display output to
 * \param[in] data_set    Current state of CIB
 * \param[in] node_state  Root of XML tree describing node status
 * \param[in] operations  Whether to print operations or just failcounts
 */
static void
print_node_history(FILE *stream, pe_working_set_t *data_set,
                   xmlNode *node_state, gboolean operations)
{
    node_t *node = pe_find_node_id(data_set->nodes, ID(node_state));
    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;

    if (node && node->details && node->details->online) {
        print_node_start(stream, node);

        lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
        lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

        /* Print history of each of the node's resources */
        for (rsc_entry = __xml_first_child(lrm_rsc); rsc_entry != NULL;
             rsc_entry = __xml_next(rsc_entry)) {

            if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {
                print_rsc_history(stream, data_set, node, rsc_entry, operations);
            }
        }

        print_node_end(stream);
    }
}

/*!
 * \internal
 * \brief Print extended information about an attribute if appropriate
 *
 * \param[in] data_set  Working set of CIB state
 *
 * \return TRUE if extended information was printed, FALSE otherwise
 * \note Currently, extended information is only supported for ping/pingd
 *       resources, for which a message will be printed if connectivity is lost
 *       or degraded.
 */
static gboolean
print_attr_msg(FILE *stream, node_t * node, GListPtr rsc_list, const char *attrname, const char *attrvalue)
{
    GListPtr gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->meta, "type");

        if (rsc->children != NULL) {
            if (print_attr_msg(stream, node, rsc->children, attrname, attrvalue)) {
                return TRUE;
            }
        }

        if (safe_str_eq(type, "ping") || safe_str_eq(type, "pingd")) {
            const char *name = g_hash_table_lookup(rsc->parameters, "name");

            if (name == NULL) {
                name = "pingd";
            }

            /* To identify the resource with the attribute name. */
            if (safe_str_eq(name, attrname)) {
                int host_list_num = 0;
                int expected_score = 0;
                int value = crm_parse_int(attrvalue, "0");
                const char *hosts = g_hash_table_lookup(rsc->parameters, "host_list");
                const char *multiplier = g_hash_table_lookup(rsc->parameters, "multiplier");

                if(hosts) {
                    char **host_list = g_strsplit(hosts, " ", 0);
                    host_list_num = g_strv_length(host_list);
                    g_strfreev(host_list);
                }

                /* pingd multiplier is the same as the default value. */
                expected_score = host_list_num * crm_parse_int(multiplier, "1");

                switch (output_format) {
                    case mon_output_plain:
                    case mon_output_console:
                        if (value <= 0) {
                            print_as("\t: Connectivity is lost");
                        } else if (value < expected_score) {
                            print_as("\t: Connectivity is degraded (Expected=%d)", expected_score);
                        }
                        break;

                    case mon_output_html:
                    case mon_output_cgi:
                        if (value <= 0) {
                            fprintf(stream, " <b>(connectivity is lost)</b>");
                        } else if (value < expected_score) {
                            fprintf(stream, " <b>(connectivity is degraded -- expected %d)</b>",
                                    expected_score);
                        }
                        break;

                    case mon_output_xml:
                        fprintf(stream, " expected=\"%d\"", expected_score);
                        break;

                    default:
                        break;
                }
                return TRUE;
            }
        }
    }
    return FALSE;
}

static int
compare_attribute(gconstpointer a, gconstpointer b)
{
    int rc;

    rc = strcmp((const char *)a, (const char *)b);

    return rc;
}

static void
create_attr_list(gpointer name, gpointer value, gpointer data)
{
    int i;
    const char *filt_str[] = FILTER_STR;

    CRM_CHECK(name != NULL, return);

    /* filtering automatic attributes */
    for (i = 0; filt_str[i] != NULL; i++) {
        if (g_str_has_prefix(name, filt_str[i])) {
            return;
        }
    }

    attr_list = g_list_insert_sorted(attr_list, name, compare_attribute);
}

/* structure for passing multiple user data to g_list_foreach() */
struct mon_attr_data {
    FILE *stream;
    node_t *node;
};

static void
print_node_attribute(gpointer name, gpointer user_data)
{
    const char *value = NULL;
    struct mon_attr_data *data = (struct mon_attr_data *) user_data;

    value = pe_node_attribute_raw(data->node, name);

    /* Print attribute name and value */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("    + %-32s\t: %-10s", (char *)name, value);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(data->stream, "   <li>%s: %s",
                    (char *)name, value);
            break;

        case mon_output_xml:
            fprintf(data->stream,
                    "            <attribute name=\"%s\" value=\"%s\"",
                    (char *)name, value);
            break;

        default:
            break;
    }

    /* Print extended information if appropriate */
    print_attr_msg(data->stream, data->node, data->node->details->running_rsc,
                   name, value);

    /* Close out the attribute */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(data->stream, "</li>\n");
            break;

        case mon_output_xml:
            fprintf(data->stream, " />\n");
            break;

        default:
            break;
    }
}

static void
print_node_summary(FILE *stream, pe_working_set_t * data_set, gboolean operations)
{
    xmlNode *node_state = NULL;
    xmlNode *cib_status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

    /* Print heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (operations) {
                print_as("\nOperations:\n");
            } else {
                print_as("\nMigration Summary:\n");
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            if (operations) {
                fprintf(stream, " <hr />\n <h2>Operations</h2>\n");
            } else {
                fprintf(stream, " <hr />\n <h2>Migration Summary</h2>\n");
            }
            break;

        case mon_output_xml:
            fprintf(stream, "    <node_history>\n");
            break;

        default:
            break;
    }

    /* Print each node in the CIB status */
    for (node_state = __xml_first_child(cib_status); node_state != NULL;
         node_state = __xml_next(node_state)) {
        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            print_node_history(stream, data_set, node_state, operations);
        }
    }

    /* Close section */
    switch (output_format) {
        case mon_output_xml:
            fprintf(stream, "    </node_history>\n");
            break;

        default:
            break;
    }
}

static void
print_ticket(gpointer name, gpointer value, gpointer data)
{
    ticket_t *ticket = (ticket_t *) value;
    FILE *stream = (FILE *) data;

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("* %s:\t%s%s", ticket->id,
                     (ticket->granted? "granted" : "revoked"),
                     (ticket->standby? " [standby]" : ""));
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "  <li>%s: %s%s", ticket->id,
                    (ticket->granted? "granted" : "revoked"),
                    (ticket->standby? " [standby]" : ""));
            break;

        case mon_output_xml:
            fprintf(stream, "        <ticket id=\"%s\" status=\"%s\" standby=\"%s\"",
                    ticket->id, (ticket->granted? "granted" : "revoked"),
                    (ticket->standby? "true" : "false"));
            break;

        default:
            break;
    }
    if (ticket->last_granted > -1) {
        print_nvpair(stdout, "last-granted", NULL, NULL, ticket->last_granted);
    }
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "</li>\n");
            break;

        case mon_output_xml:
            fprintf(stream, " />\n");
            break;

        default:
            break;
    }
}

static void
print_cluster_tickets(FILE *stream, pe_working_set_t * data_set)
{
    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nTickets:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Tickets</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <tickets>\n");
            break;

        default:
            break;
    }

    /* Print each ticket */
    g_hash_table_foreach(data_set->tickets, print_ticket, stream);

    /* Close section */
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    </tickets>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Return human-friendly string representing node name
 *
 * The returned string will be in the format
 *    uname[@hostUname] [(nodeID)]
 * "@hostUname" will be printed if the node is a guest node.
 * "(nodeID)" will be printed if the node ID is different from the node uname,
 *  and detailed output has been requested.
 *
 * \param[in] node  Node to represent
 * \return Newly allocated string with representation of node name
 * \note It is the caller's responsibility to free the result with free().
 */
static char *
get_node_display_name(node_t *node)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node */
    if (is_container_remote_node(node)) {
        if (node->details->remote_rsc->running_on) {
            /* running_on is a list, but guest nodes will have exactly one entry
             * unless they are in the process of migrating, in which case they
             * will have two; either way, we can use the first item in the list
             */
            node_t *host_node = (node_t *) node->details->remote_rsc->running_on->data;

            if (host_node && host_node->details) {
                node_host = host_node->details->uname;
            }
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (print_clone_detail && safe_str_neq(node->details->uname, node->details->id)) {
        node_id = node->details->id;
    }

    /* Determine name length */
    name_len = strlen(node->details->uname) + 1;
    if (node_host) {
        name_len += strlen(node_host) + 1; /* "@node_host" */
    }
    if (node_id) {
        name_len += strlen(node_id) + 3; /* + " (node_id)" */
    }

    /* Allocate and populate display name */
    node_name = malloc(name_len);
    CRM_ASSERT(node_name != NULL);
    strcpy(node_name, node->details->uname);
    if (node_host) {
        strcat(node_name, "@");
        strcat(node_name, node_host);
    }
    if (node_id) {
        strcat(node_name, " (");
        strcat(node_name, node_id);
        strcat(node_name, ")");
    }
    return node_name;
}

/*!
 * \internal
 * \brief Print a negative location constraint
 *
 * \param[in] stream     File stream to display output to
 * \param[in] node       Node affected by constraint
 * \param[in] location   Constraint to print
 */
static void print_ban(FILE *stream, node_t *node, rsc_to_node_t *location)
{
    char *node_name = NULL;

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            node_name = get_node_display_name(node);
            print_as(" %s\tprevents %s from running %son %s\n",
                     location->id, location->rsc_lh->id,
                     ((location->role_filter == RSC_ROLE_MASTER)? "as Master " : ""),
                     node_name);
            break;

        case mon_output_html:
        case mon_output_cgi:
            node_name = get_node_display_name(node);
            fprintf(stream, "  <li>%s prevents %s from running %son %s</li>\n",
                     location->id, location->rsc_lh->id,
                     ((location->role_filter == RSC_ROLE_MASTER)? "as Master " : ""),
                     node_name);
            break;

        case mon_output_xml:
            fprintf(stream,
                    "        <ban id=\"%s\" resource=\"%s\" node=\"%s\" weight=\"%d\" master_only=\"%s\" />\n",
                    location->id, location->rsc_lh->id, node->details->uname, node->weight,
                    ((location->role_filter == RSC_ROLE_MASTER)? "true" : "false"));
            break;

        default:
            break;
    }
    free(node_name);
}

/*!
 * \internal
 * \brief Print section for negative location constraints
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set corresponding to CIB status to display
 */
static void print_neg_locations(FILE *stream, pe_working_set_t *data_set)
{
    GListPtr gIter, gIter2;

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nNegative Location Constraints:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Negative Location Constraints</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <bans>\n");
            break;

        default:
            break;
    }

    /* Print each ban */
    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        rsc_to_node_t *location = (rsc_to_node_t *) gIter->data;
        if (!g_str_has_prefix(location->id, print_neg_location_prefix))
            continue;
        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            node_t *node = (node_t *) gIter2->data;

            if (node->weight < 0) {
                print_ban(stream, node, location);
            }
        }
    }

    /* Close section */
    switch (output_format) {
        case mon_output_cgi:
        case mon_output_html:
            fprintf(stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    </bans>\n");
            break;

        default:
            break;
    }
}

static void
crm_mon_get_parameters(resource_t *rsc, pe_working_set_t * data_set)
{
    get_rsc_attributes(rsc->parameters, rsc, NULL, data_set);
    crm_trace("Beekhof: unpacked params for %s (%d)", rsc->id, g_hash_table_size(rsc->parameters));
    if(rsc->children) {
        GListPtr gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            crm_mon_get_parameters(gIter->data, data_set);
        }
    }
}

/*!
 * \internal
 * \brief Print node attributes section
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_node_attributes(FILE *stream, pe_working_set_t *data_set)
{
    GListPtr gIter = NULL;

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nNode Attributes:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Node Attributes</h2>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <node_attributes>\n");
            break;

        default:
            break;
    }

    /* Unpack all resource parameters (it would be more efficient to do this
     * only when needed for the first time in print_attr_msg())
     */
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        crm_mon_get_parameters(gIter->data, data_set);
    }

    /* Display each node's attributes */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        struct mon_attr_data data;

        data.stream = stream;
        data.node = (node_t *) gIter->data;

        if (data.node && data.node->details && data.node->details->online) {
            print_node_start(stream, data.node);
            g_hash_table_foreach(data.node->details->attrs, create_attr_list, NULL);
            g_list_foreach(attr_list, print_node_attribute, &data);
            g_list_free(attr_list);
            attr_list = NULL;
            print_node_end(stream);
        }
    }

    /* Print section footer */
    switch (output_format) {
        case mon_output_xml:
            fprintf(stream, "    </node_attributes>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Return resource display options corresponding to command-line choices
 *
 * \return Bitmask of pe_print_options suitable for resource print functions
 */
static int
get_resource_display_options(void)
{
    int print_opts;

    /* Determine basic output format */
    switch (output_format) {
        case mon_output_console:
            print_opts = pe_print_ncurses;
            break;
        case mon_output_html:
        case mon_output_cgi:
            print_opts = pe_print_html;
            break;
        case mon_output_xml:
            print_opts = pe_print_xml;
            break;
        default:
            print_opts = pe_print_printf;
            break;
    }

    /* Add optional display elements */
    if (print_pending) {
        print_opts |= pe_print_pending;
    }
    if (print_clone_detail) {
        print_opts |= pe_print_clone_details|pe_print_implicit;
    }
    if (!inactive_resources) {
        print_opts |= pe_print_clone_active;
    }
    if (print_brief) {
        print_opts |= pe_print_brief;
    }
    return print_opts;
}

/*!
 * \internal
 * \brief Return human-friendly string representing current time
 *
 * \return Current time as string (as by ctime() but without newline) on success
 *         or "Could not determine current time" on error
 * \note The return value points to a statically allocated string which might be
 *       overwritten by subsequent calls to any of the C library date and time functions.
 */
static const char *
crm_now_string(void)
{
    time_t a_time = time(NULL);
    char *since_epoch = ctime(&a_time);

    if ((a_time == (time_t) -1) || (since_epoch == NULL)) {
        return "Could not determine current time";
    }
    since_epoch[strlen(since_epoch) - 1] = EOS; /* trim newline */
    return (since_epoch);
}

/*!
 * \internal
 * \brief Print header for cluster summary if needed
 *
 * \param[in] stream     File stream to display output to
 */
static void
print_cluster_summary_header(FILE *stream)
{
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <h2>Cluster Summary</h2>\n <p>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <summary>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print footer for cluster summary if needed
 *
 * \param[in] stream     File stream to display output to
 */
static void
print_cluster_summary_footer(FILE *stream)
{
    switch (output_format) {
        case mon_output_cgi:
        case mon_output_html:
            fprintf(stream, " </p>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    </summary>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print times the display was last updated and CIB last changed
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_cluster_times(FILE *stream, pe_working_set_t *data_set)
{
    const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
    const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
    const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
    const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("Last updated: %s", crm_now_string());
            print_as((user || client || origin)? "\n" : "\t\t");
            print_as("Last change: %s", last_written ? last_written : "");
            if (user) {
                print_as(" by %s", user);
            }
            if (client) {
                print_as(" via %s", client);
            }
            if (origin) {
                print_as(" on %s", origin);
            }
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <b>Last updated:</b> %s<br/>\n", crm_now_string());
            fprintf(stream, " <b>Last change:</b> %s", last_written ? last_written : "");
            if (user) {
                fprintf(stream, " by %s", user);
            }
            if (client) {
                fprintf(stream, " via %s", client);
            }
            if (origin) {
                fprintf(stream, " on %s", origin);
            }
            fprintf(stream, "<br/>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "        <last_update time=\"%s\" />\n", crm_now_string());
            fprintf(stream, "        <last_change time=\"%s\" user=\"%s\" client=\"%s\" origin=\"%s\" />\n",
                    last_written ? last_written : "", user ? user : "",
                    client ? client : "", origin ? origin : "");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print cluster stack
 *
 * \param[in] stream     File stream to display output to
 * \param[in] stack_s    Stack name
 */
static void
print_cluster_stack(FILE *stream, const char *stack_s)
{
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("Stack: %s\n", stack_s);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <b>Stack:</b> %s<br/>\n", stack_s);
            break;

        case mon_output_xml:
            fprintf(stream, "        <stack type=\"%s\" />\n", stack_s);
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print current DC and its version
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_cluster_dc(FILE *stream, pe_working_set_t *data_set)
{
    node_t *dc = data_set->dc_node;
    xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                           data_set->input, LOG_DEBUG);
    const char *dc_version_s = dc_version?
                               crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                               : NULL;
    const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
    char *dc_name = dc? get_node_display_name(dc) : NULL;

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("Current DC: ");
            if (dc) {
                print_as("%s (version %s) - partition %s quorum\n",
                         dc_name, (dc_version_s? dc_version_s : "unknown"),
                         (crm_is_true(quorum) ? "with" : "WITHOUT"));
            } else {
                print_as("NONE\n");
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <b>Current DC:</b> ");
            if (dc) {
                fprintf(stream, "%s (version %s) - partition %s quorum",
                        dc_name, (dc_version_s? dc_version_s : "unknown"),
                        (crm_is_true(quorum)? "with" : "<font color=\"red\"><b>WITHOUT</b></font>"));
            } else {
                fprintf(stream, "<font color=\"red\"><b>NONE</b></font>");
            }
            fprintf(stream, "<br/>\n");
            break;

        case mon_output_xml:
            fprintf(stream,  "        <current_dc ");
            if (dc) {
                fprintf(stream,
                        "present=\"true\" version=\"%s\" name=\"%s\" id=\"%s\" with_quorum=\"%s\"",
                        (dc_version_s? dc_version_s : ""), dc->details->uname, dc->details->id,
                        (crm_is_true(quorum) ? "true" : "false"));
            } else {
                fprintf(stream, "present=\"false\"");
            }
            fprintf(stream, " />\n");
            break;

        default:
            break;
    }
    free(dc_name);
}

/*!
 * \internal
 * \brief Print counts of configured nodes and resources
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 * \param[in] stack_s    Stack name
 */
static void
print_cluster_counts(FILE *stream, pe_working_set_t *data_set, const char *stack_s)
{
    int nnodes = g_list_length(data_set->nodes);
    int nresources = count_resources(data_set, NULL);

    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:

            print_as("\n%d node%s configured\n", nnodes, s_if_plural(nnodes));

            print_as("%d resource%s configured",
                     nresources, s_if_plural(nresources));
            if(data_set->disabled_resources || data_set->blocked_resources) {
                print_as(" (");
                if (data_set->disabled_resources) {
                    print_as("%d DISABLED", data_set->disabled_resources);
                }
                if (data_set->disabled_resources && data_set->blocked_resources) {
                    print_as(", ");
                }
                if (data_set->blocked_resources) {
                    print_as("%d BLOCKED from starting due to failure",
                             data_set->blocked_resources);
                }
                print_as(")");
            }
            print_as("\n");

            break;

        case mon_output_html:
        case mon_output_cgi:

            fprintf(stream, " %d node%s configured<br/>\n",
                    nnodes, s_if_plural(nnodes));

            fprintf(stream, " %d resource%s configured",
                    nresources, s_if_plural(nresources));
            if (data_set->disabled_resources || data_set->blocked_resources) {
                fprintf(stream, " (");
                if (data_set->disabled_resources) {
                    fprintf(stream, "%d <strong>DISABLED</strong>",
                            data_set->disabled_resources);
                }
                if (data_set->disabled_resources && data_set->blocked_resources) {
                    fprintf(stream, ", ");
                }
                if (data_set->blocked_resources) {
                    fprintf(stream,
                            "%d <strong>BLOCKED</strong> from starting due to failure",
                            data_set->blocked_resources);
                }
                fprintf(stream, ")");
            }
            fprintf(stream, "<br/>\n");
            break;

        case mon_output_xml:
            fprintf(stream,
                    "        <nodes_configured number=\"%d\" />\n",
                    g_list_length(data_set->nodes));
            fprintf(stream,
                    "        <resources_configured number=\"%d\" disabled=\"%d\" blocked=\"%d\" />\n",
                    count_resources(data_set, NULL),
                    data_set->disabled_resources, data_set->blocked_resources);
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print cluster-wide options
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 *
 * \note Currently this is only implemented for HTML and XML output, and
 *       prints only a few options. If there is demand, more could be added.
 */
static void
print_cluster_options(FILE *stream, pe_working_set_t *data_set)
{
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
                print_as("\n              *** Resource management is DISABLED ***");
                print_as("\n  The cluster will not attempt to start, stop or recover services");
                print_as("\n");
            }
            break;

        case mon_output_html:
            fprintf(stream, " </p>\n <h3>Config Options</h3>\n");
            fprintf(stream, " <table>\n");
            fprintf(stream, "  <tr><th>STONITH of failed nodes</th><td>%s</td></tr>\n",
                    is_set(data_set->flags, pe_flag_stonith_enabled)? "enabled" : "disabled");

            fprintf(stream, "  <tr><th>Cluster is</th><td>%ssymmetric</td></tr>\n",
                    is_set(data_set->flags, pe_flag_symmetric_cluster)? "" : "a");

            fprintf(stream, "  <tr><th>No Quorum Policy</th><td>");
            switch (data_set->no_quorum_policy) {
                case no_quorum_freeze:
                    fprintf(stream, "Freeze resources");
                    break;
                case no_quorum_stop:
                    fprintf(stream, "Stop ALL resources");
                    break;
                case no_quorum_ignore:
                    fprintf(stream, "Ignore");
                    break;
                case no_quorum_suicide:
                    fprintf(stream, "Suicide");
                    break;
            }
            fprintf(stream, "</td></tr>\n");

            fprintf(stream, "  <tr><th>Resource management</th><td>");
            if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
                fprintf(stream, "<strong>DISABLED</strong> (the cluster will "
                                "not attempt to start, stop or recover services)");
            } else {
                fprintf(stream, "enabled");
            }
            fprintf(stream, "</td></tr>\n");

            fprintf(stream, "</table>\n <p>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "        <cluster_options");
            fprintf(stream, " stonith-enabled=\"%s\"",
                    is_set(data_set->flags, pe_flag_stonith_enabled)?
                    "true" : "false");
            fprintf(stream, " symmetric-cluster=\"%s\"",
                    is_set(data_set->flags, pe_flag_symmetric_cluster)?
                    "true" : "false");
            fprintf(stream, " no-quorum-policy=\"");
            switch (data_set->no_quorum_policy) {
                case no_quorum_freeze:
                    fprintf(stream, "freeze");
                    break;
                case no_quorum_stop:
                    fprintf(stream, "stop");
                    break;
                case no_quorum_ignore:
                    fprintf(stream, "ignore");
                    break;
                case no_quorum_suicide:
                    fprintf(stream, "suicide");
                    break;
            }
            fprintf(stream, "\"");
            fprintf(stream, " maintenance-mode=\"%s\"",
                    is_set(data_set->flags, pe_flag_maintenance_mode)?
                    "true" : "false");
            fprintf(stream, " />\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Get the name of the stack in use (or "unknown" if not available)
 *
 * \param[in] data_set   Working set of CIB state
 *
 * \return String representing stack name
 */
static const char *
get_cluster_stack(pe_working_set_t *data_set)
{
    xmlNode *stack = get_xpath_object("//nvpair[@name='cluster-infrastructure']",
                                      data_set->input, LOG_DEBUG);
    return stack? crm_element_value(stack, XML_NVPAIR_ATTR_VALUE) : "unknown";
}

/*!
 * \internal
 * \brief Print a summary of cluster-wide information
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_cluster_summary(FILE *stream, pe_working_set_t *data_set)
{
    const char *stack_s = get_cluster_stack(data_set);
    gboolean header_printed = FALSE;

    if (show & mon_show_stack) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_stack(stream, stack_s);
    }

    /* Always print DC if none, even if not requested */
    if ((data_set->dc_node == NULL) || (show & mon_show_dc)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_dc(stream, data_set);
    }

    if (show & mon_show_times) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_times(stream, data_set);
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)
        || data_set->disabled_resources
        || data_set->blocked_resources
        || is_set(show, mon_show_count)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_counts(stream, data_set, stack_s);
    }

    /* There is not a separate option for showing cluster options, so show with
     * stack for now; a separate option could be added if there is demand
     */
    if (show & mon_show_stack) {
        print_cluster_options(stream, data_set);
    }

    if (header_printed) {
        print_cluster_summary_footer(stream);
    }
}

/*!
 * \internal
 * \brief Print a failed action
 *
 * \param[in] stream     File stream to display output to
 * \param[in] xml_op     Root of XML tree describing failed action
 */
static void
print_failed_action(FILE *stream, xmlNode *xml_op)
{
    const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    const char *op_key_attr = "op_key";
    const char *last = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
    const char *node = crm_element_value(xml_op, XML_ATTR_UNAME);
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);
    int rc = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), "0");
    int status = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS), "0");
    char *exit_reason_cleaned;

    /* If no op_key was given, use id instead */
    if (op_key == NULL) {
        op_key = ID(xml_op);
        op_key_attr = "id";
    }

    /* If no exit reason was given, use "none" */
    if (exit_reason == NULL) {
        exit_reason = "none";
    }

    /* Print common action information */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("* %s on %s '%s' (%d): call=%s, status=%s, exitreason='%s'",
                     op_key, node, services_ocf_exitcode_str(rc), rc,
                     call, services_lrm_status_str(status), exit_reason);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "  <li>%s on %s '%s' (%d): call=%s, status=%s, exitreason='%s'",
                     op_key, node, services_ocf_exitcode_str(rc), rc,
                     call, services_lrm_status_str(status), exit_reason);
            break;

        case mon_output_xml:
            exit_reason_cleaned = crm_xml_escape(exit_reason);
            fprintf(stream, "        <failure %s=\"%s\" node=\"%s\"",
                    op_key_attr, op_key, node);
            fprintf(stream, " exitstatus=\"%s\" exitreason=\"%s\" exitcode=\"%d\"",
                    services_ocf_exitcode_str(rc), exit_reason_cleaned, rc);
            fprintf(stream, " call=\"%s\" status=\"%s\"",
                    call, services_lrm_status_str(status));
            free(exit_reason_cleaned);
            break;

        default:
            break;
    }

    /* If last change was given, print timing information as well */
    if (last) {
        time_t run_at = crm_parse_int(last, "0");
        char *run_at_s = ctime(&run_at);

        if (run_at_s) {
            run_at_s[24] = 0; /* Overwrite the newline */
        }

        switch (output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(",\n    last-rc-change='%s', queued=%sms, exec=%sms",
                         run_at_s? run_at_s : "",
                         crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                         crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(stream, " last-rc-change='%s', queued=%sms, exec=%sms",
                        run_at_s? run_at_s : "",
                        crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                        crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
                break;

            case mon_output_xml:
                fprintf(stream,
                        " last-rc-change=\"%s\" queued=\"%s\" exec=\"%s\" interval=\"%u\" task=\"%s\"",
                        run_at_s? run_at_s : "",
                        crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                        crm_element_value(xml_op, XML_RSC_OP_T_EXEC),
                        crm_parse_ms(crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL_MS)),
                        crm_element_value(xml_op, XML_LRM_ATTR_TASK));
                break;

            default:
                break;
        }
    }

    /* End the action listing */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, "</li>\n");
            break;

        case mon_output_xml:
            fprintf(stream, " />\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print a section for failed actions
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_failed_actions(FILE *stream, pe_working_set_t *data_set)
{
    xmlNode *xml_op = NULL;

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nFailed Actions:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Failed Actions</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <failures>\n");
            break;

        default:
            break;
    }

    /* Print each failed action */
    for (xml_op = __xml_first_child(data_set->failed); xml_op != NULL;
         xml_op = __xml_next(xml_op)) {
        print_failed_action(stream, xml_op);
    }

    /* End section */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    </failures>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print cluster status to screen
 *
 * This uses the global display preferences set by command-line options
 * to display cluster status in a human-friendly way.
 *
 * \param[in] data_set   Working set of CIB state
 */
static void
print_status(pe_working_set_t * data_set)
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
                node_mode = "standby";
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
            if (group_by_node == FALSE) {
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
            if (group_by_node == FALSE) {
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
        if (group_by_node) {
            if (print_brief) {
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
    if (show & mon_show_attributes) {
        print_node_attributes(stdout, data_set);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(stdout, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE));
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(stdout, data_set);
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(stdout, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
        print_neg_locations(stdout, data_set);
    }

#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        refresh();
    }
#endif
}

/*!
 * \internal
 * \brief Print cluster status in XML format
 *
 * \param[in] data_set   Working set of CIB state
 */
static void
print_xml_status(pe_working_set_t * data_set)
{
    FILE *stream = stdout;
    GListPtr gIter = NULL;
    int print_opts = get_resource_display_options();

    fprintf(stream, "<?xml version=\"1.0\"?>\n");
    fprintf(stream, "<crm_mon version=\"%s\">\n", VERSION);

    print_cluster_summary(stream, data_set);

    /*** NODES ***/
    fprintf(stream, "    <nodes>\n");
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *node_type = "unknown";

        switch (node->details->type) {
            case node_member:
                node_type = "member";
                break;
            case node_remote:
                node_type = "remote";
                break;
            case node_ping:
                node_type = "ping";
                break;
        }

        fprintf(stream, "        <node name=\"%s\" ", node->details->uname);
        fprintf(stream, "id=\"%s\" ", node->details->id);
        fprintf(stream, "online=\"%s\" ", node->details->online ? "true" : "false");
        fprintf(stream, "standby=\"%s\" ", node->details->standby ? "true" : "false");
        fprintf(stream, "standby_onfail=\"%s\" ", node->details->standby_onfail ? "true" : "false");
        fprintf(stream, "maintenance=\"%s\" ", node->details->maintenance ? "true" : "false");
        fprintf(stream, "pending=\"%s\" ", node->details->pending ? "true" : "false");
        fprintf(stream, "unclean=\"%s\" ", node->details->unclean ? "true" : "false");
        fprintf(stream, "shutdown=\"%s\" ", node->details->shutdown ? "true" : "false");
        fprintf(stream, "expected_up=\"%s\" ", node->details->expected_up ? "true" : "false");
        fprintf(stream, "is_dc=\"%s\" ", node->details->is_dc ? "true" : "false");
        fprintf(stream, "resources_running=\"%d\" ", g_list_length(node->details->running_rsc));
        fprintf(stream, "type=\"%s\" ", node_type);
        if (is_container_remote_node(node)) {
            fprintf(stream, "id_as_resource=\"%s\" ", node->details->remote_rsc->container->id);
        }

        if (group_by_node) {
            GListPtr lpc2 = NULL;

            fprintf(stream, ">\n");
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                resource_t *rsc = (resource_t *) lpc2->data;

                rsc->fns->print(rsc, "            ", print_opts | pe_print_rsconly, stream);
            }
            fprintf(stream, "        </node>\n");
        } else {
            fprintf(stream, "/>\n");
        }
    }
    fprintf(stream, "    </nodes>\n");

    /* Print resources section, if needed */
    print_resources(stream, data_set, print_opts);

    /* print Node Attributes section if requested */
    if (show & mon_show_attributes) {
        print_node_attributes(stream, data_set);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(stream, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE));
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(stream, data_set);
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(stream, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
        print_neg_locations(stream, data_set);
    }

    fprintf(stream, "</crm_mon>\n");
    fflush(stream);
    fclose(stream);
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
print_html_status(pe_working_set_t * data_set, const char *filename)
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
            fprintf(stream, "<font color=\"orange\">standby</font>\n");
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
        if (print_brief && group_by_node) {
            fprintf(stream, "<ul>\n");
            print_rscs_brief(node->details->running_rsc, NULL, print_opts | pe_print_rsconly,
                             stream, FALSE);
            fprintf(stream, "</ul>\n");

        } else if (group_by_node) {
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
    if (show & mon_show_attributes) {
        print_node_attributes(stream, data_set);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(stream, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE));
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(stream, data_set);
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(stream, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
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
    guint interval_ms = 0;
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

    if (parse_op_key(id, &rsc, &task, &interval_ms) == FALSE) {
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
static char *get_node_from_xpath(const char *xpath) 
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

static void crm_diff_update_v2(const char *event, xmlNode * msg) 
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

static void crm_diff_update_v1(const char *event, xmlNode * msg) 
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

void
crm_diff_update(const char *event, xmlNode * msg)
{
    int rc = -1;
    long now = time(NULL);
    static bool stale = FALSE;
    static int updates = 0;
    static mainloop_timer_t *refresh_timer = NULL;
    xmlNode *diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    print_dot();

    if(refresh_timer == NULL) {
        refresh_timer = mainloop_timer_add("refresh", 2000, FALSE, mon_trigger_refresh, NULL);
    }

    if (current_cib != NULL) {
        rc = xml_apply_patchset(current_cib, diff, TRUE);

        switch (rc) {
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
                free_xml(current_cib); current_cib = NULL;
                break;
            case pcmk_ok:
                updates++;
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
    /* Refresh
     * - immediately if the last update was more than 5s ago
     * - every 10 updates
     * - at most 2s after the last update
     */
    if ((now - last_refresh) > (reconnect_msec / 1000)) {
        mainloop_set_trigger(refresh_trigger);
        mainloop_timer_stop(refresh_timer);
        updates = 0;

    } else if(updates > 10) {
        mainloop_set_trigger(refresh_trigger);
        mainloop_timer_stop(refresh_timer);
        updates = 0;

    } else {
        mainloop_timer_start(refresh_timer);
    }
}

gboolean
mon_refresh_display(gpointer user_data)
{
    xmlNode *cib_copy = copy_xml(current_cib);
    pe_working_set_t data_set;

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

    set_working_set_defaults(&data_set);
    data_set.input = cib_copy;
    cluster_status(&data_set);

    /* Unpack constraints if any section will need them
     * (tickets may be referenced in constraints but not granted yet,
     * and bans need negative location constraints) */
    if (show & (mon_show_bans | mon_show_tickets)) {
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);
        unpack_constraints(cib_constraints, &data_set);
    }

    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            if (print_html_status(&data_set, output_filename) != 0) {
                fprintf(stderr, "Critical: Unable to output html file\n");
                clean_up(CRM_EX_CANTCREAT);
            }
            break;

        case mon_output_xml:
            print_xml_status(&data_set);
            break;

        case mon_output_monitor:
            print_simple_status(&data_set);
            if (has_warnings) {
                clean_up(MON_STATUS_WARN);
            }
            break;

        case mon_output_plain:
        case mon_output_console:
            print_status(&data_set);
            break;

        case mon_output_none:
            break;
    }

    cleanup_alloc_calculations(&data_set);
    return TRUE;
}

void
mon_st_callback(stonith_t * st, stonith_event_t * e)
{
    char *desc = crm_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                 e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                 e->id);

    if (external_agent) {
        send_custom_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
    }
    free(desc);
}

/*
 * De-init ncurses, signoff from the CIB and deallocate memory.
 */
static void
clean_up(crm_exit_t exit_code)
{
#if CURSES_ENABLED
    if (output_format == mon_output_console) {
        output_format = mon_output_plain;
        echo();
        nocbreak();
        endwin();
    }
#endif

    if (cib != NULL) {
        cib->cmds->signoff(cib);
        cib_delete(cib);
        cib = NULL;
    }

    free(output_filename);
    free(xml_file);
    free(pid_file);

    crm_exit(exit_code);
}
