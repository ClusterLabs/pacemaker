/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>

#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <../lib/pengine/unpack.h>
#include <../pengine/pengine.h>
#include <crm/stonith-ng.h>

/* GMainLoop *mainloop = NULL; */

void wait_for_refresh(int offset, const char *prefix, int msec);
void clean_up(int rc);
void crm_diff_update(const char *event, xmlNode * msg);
gboolean mon_refresh_display(gpointer user_data);
int cib_connect(gboolean full);
void mon_st_callback(stonith_t * st, stonith_event_t * e);

char *xml_file = NULL;
char *as_html_file = NULL;
int as_xml = 0;
char *pid_file = NULL;
char *snmp_target = NULL;
char *snmp_community = NULL;

gboolean as_console = TRUE;;
gboolean simple_status = FALSE;
gboolean group_by_node = FALSE;
gboolean inactive_resources = FALSE;
gboolean web_cgi = FALSE;
int reconnect_msec = 5000;
gboolean daemonize = FALSE;
GMainLoop *mainloop = NULL;
guint timer_id = 0;
GList *attr_list = NULL;

const char *crm_mail_host = NULL;
const char *crm_mail_prefix = NULL;
const char *crm_mail_from = NULL;
const char *crm_mail_to = NULL;
const char *external_agent = NULL;
const char *external_recipient = NULL;

cib_t *cib = NULL;
stonith_t *st = NULL;
xmlNode *current_cib = NULL;

gboolean one_shot = FALSE;
gboolean has_warnings = FALSE;
gboolean print_failcount = FALSE;
gboolean print_operations = FALSE;
gboolean print_timing = FALSE;
gboolean print_nodes_attr = FALSE;
gboolean print_last_updated = TRUE;
gboolean print_last_change = TRUE;
gboolean print_tickets = FALSE;
gboolean watch_fencing = FALSE;
gboolean hide_headers = FALSE;
gboolean print_brief = FALSE;
gboolean print_pending = FALSE;

/* FIXME allow, detect, and correctly interpret glob pattern or regex? */
const char *print_neg_location_prefix;
const char *print_neg_location_prefix_toggle;

#define FILTER_STR {"shutdown", "terminate", "standby", "fail-count",	\
	    "last-failure", "probe_complete", "#id", "#uname",		\
	    "#is_dc", "#kind", NULL}

gboolean log_diffs = FALSE;
gboolean log_updates = FALSE;

long last_refresh = 0;
crm_trigger_t *refresh_trigger = NULL;

/*
 * 1.3.6.1.4.1.32723 has been assigned to the project by IANA
 * http://www.iana.org/assignments/enterprise-numbers
 */
#define PACEMAKER_PREFIX "1.3.6.1.4.1.32723"
#define PACEMAKER_TRAP_PREFIX PACEMAKER_PREFIX ".1"

#define snmp_crm_trap_oid   PACEMAKER_TRAP_PREFIX
#define snmp_crm_oid_node   PACEMAKER_TRAP_PREFIX ".1"
#define snmp_crm_oid_rsc    PACEMAKER_TRAP_PREFIX ".2"
#define snmp_crm_oid_task   PACEMAKER_TRAP_PREFIX ".3"
#define snmp_crm_oid_desc   PACEMAKER_TRAP_PREFIX ".4"
#define snmp_crm_oid_status PACEMAKER_TRAP_PREFIX ".5"
#define snmp_crm_oid_rc     PACEMAKER_TRAP_PREFIX ".6"
#define snmp_crm_oid_trc    PACEMAKER_TRAP_PREFIX ".7"

#if CURSES_ENABLED
#  define print_dot() if(as_console) {		\
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
#  define print_as(fmt, args...) if(as_console) {	\
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
    if(as_console) {
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
    clean_up(EX_OK);
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
        if (as_console && need_pass && cib->variant == cib_remote) {
            need_pass = FALSE;
            print_as("Password:");
        }

        rc = cib->cmds->signon(cib, crm_system_name, cib_query);

        if (rc != pcmk_ok) {
            return rc;
        }

        current_cib = get_cib_copy(cib);
        mon_refresh_display(NULL);

        if (full) {
            if (rc == pcmk_ok) {
                rc = cib->cmds->set_connection_dnotify(cib, mon_cib_connection_destroy);
                if (rc == -EPROTONOSUPPORT) {
                    print_as
                        ("Notification setup not supported, won't be able to reconnect after failure");
                    if (as_console) {
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
                if (as_console) {
                    sleep(2);
                }
                clean_up(-rc);
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

    {"-spacer-",	1, 0, '-', "\nModes:"},
    {"as-html",        1, 0, 'h', "\tWrite cluster status to the named html file"},
    {"as-xml",         0, 0, 'X', "\t\tWrite cluster status as xml to stdout. This will enable one-shot mode."},
    {"web-cgi",        0, 0, 'w', "\t\tWeb mode with output suitable for cgi"},
    {"simple-status",  0, 0, 's', "\tDisplay the cluster status once as a simple one line output (suitable for nagios)"},
    {"snmp-traps",     1, 0, 'S', "\tSend SNMP traps to this station", !ENABLE_SNMP},
    {"snmp-community", 1, 0, 'C', "Specify community for SNMP traps(default is NULL)", !ENABLE_SNMP},
    {"mail-to",        1, 0, 'T', "\tSend Mail alerts to this user.  See also --mail-from, --mail-host, --mail-prefix", !ENABLE_ESMTP},

    {"-spacer-",	1, 0, '-', "\nDisplay Options:"},
    {"group-by-node",  0, 0, 'n', "\tGroup resources by node"     },
    {"inactive",       0, 0, 'r', "\t\tDisplay inactive resources"  },
    {"failcounts",     0, 0, 'f', "\tDisplay resource fail counts"},
    {"operations",     0, 0, 'o', "\tDisplay resource operation history" },
    {"timing-details", 0, 0, 't', "\tDisplay resource operation history with timing details" },
    {"tickets",        0, 0, 'c', "\t\tDisplay cluster tickets"},
    {"watch-fencing",  0, 0, 'W', "\tListen for fencing events. For use with --external-agent, --mail-to and/or --snmp-traps where supported"},
    {"neg-locations",  2, 0, 'L', "Display negative location constraints [optionally filtered by id prefix]"},
    {"show-node-attributes", 0, 0, 'A', "Display node attributes" },
    {"hide-headers",   0, 0, 'D', "\tHide all headers" },
    {"brief",          0, 0, 'b', "\t\tBrief output" },
    {"pending",        0, 0, 'j', "\t\tDisplay pending state if 'record-pending' is enabled" },

    {"-spacer-",	1, 0, '-', "\nAdditional Options:"},
    {"interval",       1, 0, 'i', "\tUpdate frequency in seconds" },
    {"one-shot",       0, 0, '1', "\t\tDisplay the cluster status once on the console and exit"},
    {"disable-ncurses",0, 0, 'N', "\tDisable the use of ncurses", !CURSES_ENABLED},
    {"daemonize",      0, 0, 'd', "\tRun in the background as a daemon"},
    {"pid-file",       1, 0, 'p', "\t(Advanced) Daemon pid file location"},
    {"mail-from",      1, 0, 'F', "\tMail alerts should come from the named user", !ENABLE_ESMTP},
    {"mail-host",      1, 0, 'H', "\tMail alerts should be sent via the named host", !ENABLE_ESMTP},
    {"mail-prefix",    1, 0, 'P', "Subjects for mail alerts should start with this string", !ENABLE_ESMTP},
    {"external-agent",    1, 0, 'E', "A program to run when resource operations take place."},
    {"external-recipient",1, 0, 'e', "A recipient for your program (assuming you want the program to send something to someone)."},


    {"xml-file",       1, 0, 'x', NULL, 1},

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
    {"-spacer-",	1, 0, '-', "Start crm_mon as a background daemon and have it send email alerts:", pcmk_option_paragraph|!ENABLE_ESMTP},
    {"-spacer-",	1, 0, '-', " crm_mon --daemonize --mail-to user@example.com --mail-host mail.example.com", pcmk_option_example|!ENABLE_ESMTP},
    {"-spacer-",	1, 0, '-', "Start crm_mon as a background daemon and have it send SNMP alerts:", pcmk_option_paragraph|!ENABLE_SNMP},
    {"-spacer-",	1, 0, '-', " crm_mon --daemonize --snmp-traps snmptrapd.example.com", pcmk_option_example|!ENABLE_SNMP},

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
                print_tickets = ! print_tickets;
                break;
            case 'f':
                print_failcount = ! print_failcount;
                break;
            case 'n':
                group_by_node = ! group_by_node;
                break;
            case 'o':
                print_operations = ! print_operations;
                break;
            case 'r':
                inactive_resources = ! inactive_resources;
                break;
            case 't':
                print_timing = ! print_timing;
                if (print_timing)
                    print_operations = TRUE;
                break;
            case 'A':
                print_nodes_attr = ! print_nodes_attr;
                break;
            case 'L':
                if (print_neg_location_prefix) {
                    /* toggle off */
                    print_neg_location_prefix_toggle = print_neg_location_prefix;
                    print_neg_location_prefix = NULL;
                } else if (print_neg_location_prefix_toggle) {
                    /* toggle on */
                    print_neg_location_prefix = print_neg_location_prefix_toggle;
                    print_neg_location_prefix_toggle = NULL;
                } else {
                    /* toggled on for the first time at runtime */
                    print_neg_location_prefix = "";
                }
                break;
            case 'D':
                hide_headers = ! hide_headers;
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
        print_as("%c c: \t%s\n", print_tickets ? '*': ' ', get_option_desc('c'));
        print_as("%c f: \t%s\n", print_failcount ? '*': ' ', get_option_desc('f'));
        print_as("%c n: \t%s\n", group_by_node ? '*': ' ', get_option_desc('n'));
        print_as("%c o: \t%s\n", print_operations ? '*': ' ', get_option_desc('o'));
        print_as("%c r: \t%s\n", inactive_resources ? '*': ' ', get_option_desc('r'));
        print_as("%c t: \t%s\n", print_timing ? '*': ' ', get_option_desc('t'));
        print_as("%c A: \t%s\n", print_nodes_attr ? '*': ' ', get_option_desc('A'));
        print_as("%c L: \t%s\n", print_neg_location_prefix ? '*': ' ', get_option_desc('L'));
        print_as("%c D: \t%s\n", hide_headers ? '*': ' ', get_option_desc('D'));
        print_as("%c b: \t%s\n", print_brief ? '*': ' ', get_option_desc('b'));
        print_as("%c j: \t%s\n", print_pending ? '*': ' ', get_option_desc('j'));
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
    int exit_code = 0;
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

    if (strcmp(crm_system_name, "crm_mon.cgi") == 0) {
        web_cgi = TRUE;
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
                print_last_updated = FALSE;
                print_last_change = FALSE;
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
                print_operations = TRUE;
                break;
            case 'o':
                print_operations = TRUE;
                break;
            case 'f':
                print_failcount = TRUE;
                break;
            case 'A':
                print_nodes_attr = TRUE;
                break;
            case 'L':
                print_neg_location_prefix = optarg ?: "";
                break;
            case 'D':
                hide_headers = TRUE;
                break;
            case 'b':
                print_brief = TRUE;
                break;
            case 'j':
                print_pending = TRUE;
                break;
            case 'c':
                print_tickets = TRUE;
                break;
            case 'p':
                free(pid_file);
                pid_file = strdup(optarg);
                break;
            case 'x':
                xml_file = strdup(optarg);
                one_shot = TRUE;
                break;
            case 'h':
                as_html_file = strdup(optarg);
                umask(S_IWGRP | S_IWOTH);
                break;
            case 'X':
                as_xml = TRUE;
                one_shot = TRUE;
                break;
            case 'w':
                web_cgi = TRUE;
                one_shot = TRUE;
                break;
            case 's':
                simple_status = TRUE;
                one_shot = TRUE;
                break;
            case 'S':
                snmp_target = optarg;
                break;
            case 'T':
                crm_mail_to = optarg;
                break;
            case 'F':
                crm_mail_from = optarg;
                break;
            case 'H':
                crm_mail_host = optarg;
                break;
            case 'P':
                crm_mail_prefix = optarg;
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
                as_console = FALSE;
                break;
            case 'C':
                snmp_community = optarg;
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            default:
                printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }
    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (one_shot) {
        as_console = FALSE;

    } else if (daemonize) {
        as_console = FALSE;
        crm_enable_stderr(FALSE);

        if (!as_html_file && !snmp_target && !crm_mail_to && !external_agent && !as_xml) {
            printf
                ("Looks like you forgot to specify one or more of: --as-html, --as-xml, --mail-to, --snmp-target, --external-agent\n");
            crm_help('?', EX_USAGE);
        }

        crm_make_daemon(crm_system_name, TRUE, pid_file);

    } else if (as_console) {
#if CURSES_ENABLED
        initscr();
        cbreak();
        noecho();
        crm_enable_stderr(FALSE);
#else
        one_shot = TRUE;
        as_console = FALSE;
        printf("Defaulting to one-shot mode\n");
        printf("You need to have curses available at compile time to enable console mode\n");
#endif
    }

    crm_info("Starting %s", crm_system_name);
    if (xml_file != NULL) {
        current_cib = filename2xml(xml_file);
        mon_refresh_display(NULL);
        return exit_code;
    }

    if (current_cib == NULL) {
        cib = cib_new();

        do {
            if (!one_shot) {
                print_as("Attempting connection to the cluster...\n");
            }
            exit_code = cib_connect(!one_shot);

            if (one_shot) {
                break;

            } else if (exit_code != pcmk_ok) {
                sleep(reconnect_msec / 1000);
#if CURSES_ENABLED
                if(as_console) {
                    clear();
                    refresh();
                }
#endif
            }

        } while (exit_code == -ENOTCONN);

        if (exit_code != pcmk_ok) {
            print_as("\nConnection to cluster failed: %s\n", pcmk_strerror(exit_code));
            if (as_console) {
                sleep(2);
            }
            clean_up(-exit_code);
        }
    }

    if (one_shot) {
        return exit_code;
    }

    mainloop = g_main_new(FALSE);

    mainloop_add_signal(SIGTERM, mon_shutdown);
    mainloop_add_signal(SIGINT, mon_shutdown);
#if CURSES_ENABLED
    if (as_console) {
        ncurses_winch_handler = signal(SIGWINCH, mon_winresize);
        if (ncurses_winch_handler == SIG_DFL ||
            ncurses_winch_handler == SIG_IGN || ncurses_winch_handler == SIG_ERR)
            ncurses_winch_handler = NULL;
        g_io_add_watch(g_io_channel_unix_new(STDIN_FILENO), G_IO_IN, detect_user_input, NULL);
    }
#endif
    refresh_trigger = mainloop_add_trigger(G_PRIORITY_LOW, mon_refresh_display, NULL);

    g_main_run(mainloop);
    g_main_destroy(mainloop);

    crm_info("Exiting %s", crm_system_name);

    clean_up(0);
    return 0;                   /* never reached */
}

#define mon_warn(fmt...) do {			\
	if (!has_warnings) {			\
	    print_as("Warning:");		\
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

static int
print_simple_status(pe_working_set_t * data_set)
{
    node_t *dc = NULL;
    GListPtr gIter = NULL;
    int nodes_online = 0;
    int nodes_standby = 0;
    int nodes_maintenance = 0;

    dc = data_set->dc_node;

    if (dc == NULL) {
        mon_warn("No DC ");
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
            mon_warn("offline node: %s", node->details->uname);
        }
    }

    if (!has_warnings) {
        print_as("Ok: %d nodes online", nodes_online);
        if (nodes_standby > 0) {
            print_as(", %d standby nodes", nodes_standby);
        }
        if (nodes_maintenance > 0) {
            print_as(", %d maintenance nodes", nodes_maintenance);
        }
        print_as(", %d resources configured", count_resources(data_set, NULL));
    }

    print_as("\n");
    return 0;
}

static void
print_date(time_t time)
{
    int lpc = 0;
    char date_str[26];

    asctime_r(localtime(&time), date_str);
    for (; lpc < 26; lpc++) {
        if (date_str[lpc] == '\n') {
            date_str[lpc] = 0;
        }
    }
    print_as("'%s'", date_str);
}

#include <crm/pengine/internal.h>
static void
print_rsc_summary(pe_working_set_t * data_set, node_t * node, resource_t * rsc, gboolean all)
{
    gboolean printed = FALSE;

    time_t last_failure = 0;
    int failcount = get_failcount_full(node, rsc, &last_failure, FALSE, data_set);

    if (all || failcount || last_failure > 0) {
        printed = TRUE;
        print_as("   %s: migration-threshold=%d", rsc_printable_id(rsc), rsc->migration_threshold);
    }

    if (failcount > 0) {
        printed = TRUE;
        print_as(" fail-count=%d", failcount);
    }

    if (last_failure > 0) {
        printed = TRUE;
        print_as(" last-failure=");
        print_date(last_failure);
    }

    if (printed) {
        print_as("\n");
    }
}

static void
print_rsc_history(pe_working_set_t * data_set, node_t * node, xmlNode * rsc_entry)
{
    GListPtr gIter = NULL;
    GListPtr op_list = NULL;
    gboolean print_name = TRUE;
    GListPtr sorted_op_list = NULL;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    xmlNode *rsc_op = NULL;

    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next(rsc_op)) {
        if (crm_str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
            op_list = g_list_append(op_list, rsc_op);
        }
    }

    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *xml_op = (xmlNode *) gIter->data;
        const char *value = NULL;
        const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
        const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
        const char *op_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
        const char *interval = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
        int rc = crm_parse_int(op_rc, "0");

        if (safe_str_eq(task, CRMD_ACTION_STATUS)
            && safe_str_eq(interval, "0")) {
            task = "probe";
        }

        if (rc == 7 && safe_str_eq(task, "probe")) {
            continue;

        } else if (safe_str_eq(task, CRMD_ACTION_NOTIFY)) {
            continue;
        }

        if (print_name) {
            print_name = FALSE;
            if (rsc == NULL) {
                print_as("Orphan resource: %s", rsc_id);
            } else {
                print_rsc_summary(data_set, node, rsc, TRUE);
            }
        }

        print_as("    + (%s) %s:", call, task);
        if (safe_str_neq(interval, "0")) {
            print_as(" interval=%sms", interval);
        }

        if (print_timing) {
            int int_value;
            const char *attr = XML_RSC_OP_LAST_CHANGE;

            value = crm_element_value(xml_op, attr);
            if (value) {
                int_value = crm_parse_int(value, NULL);
                if (int_value > 0) {
                    print_as(" %s=", attr);
                    print_date(int_value);
                }
            }

            attr = XML_RSC_OP_LAST_RUN;
            value = crm_element_value(xml_op, attr);
            if (value) {
                int_value = crm_parse_int(value, NULL);
                if (int_value > 0) {
                    print_as(" %s=", attr);
                    print_date(int_value);
                }
            }

            attr = XML_RSC_OP_T_EXEC;
            value = crm_element_value(xml_op, attr);
            if (value) {
                int_value = crm_parse_int(value, NULL);
                print_as(" %s=%dms", attr, int_value);
            }

            attr = XML_RSC_OP_T_QUEUE;
            value = crm_element_value(xml_op, attr);
            if (value) {
                int_value = crm_parse_int(value, NULL);
                print_as(" %s=%dms", attr, int_value);
            }
        }

        print_as(" rc=%s (%s)\n", op_rc, services_ocf_exitcode_str(rc));
    }

    /* no need to free the contents */
    g_list_free(sorted_op_list);
}

static void
print_attr_msg(node_t * node, GListPtr rsc_list, const char *attrname, const char *attrvalue)
{
    GListPtr gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->meta, "type");

        if (rsc->children != NULL) {
            print_attr_msg(node, rsc->children, attrname, attrvalue);
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

                /* pingd is abnormal score. */
                if (value <= 0) {
                    print_as("\t: Connectivity is lost");
                } else if (value < expected_score) {
                    print_as("\t: Connectivity is degraded (Expected=%d)", expected_score);
                }
            }
        }
    }
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

static void
print_node_attribute(gpointer name, gpointer node_data)
{
    const char *value = NULL;
    node_t *node = (node_t *) node_data;

    value = g_hash_table_lookup(node->details->attrs, name);
    print_as("    + %-32s\t: %-10s", (char *)name, value);
    print_attr_msg(node, node->details->running_rsc, name, value);
    print_as("\n");
}

static void
print_node_summary(pe_working_set_t * data_set, gboolean operations)
{
    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;
    xmlNode *node_state = NULL;
    xmlNode *cib_status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

    if (operations) {
        print_as("\nOperations:\n");
    } else {
        print_as("\nMigration summary:\n");
    }

    for (node_state = __xml_first_child(cib_status); node_state != NULL;
         node_state = __xml_next(node_state)) {
        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            node_t *node = pe_find_node_id(data_set->nodes, ID(node_state));

            if (node == NULL || node->details->online == FALSE) {
                continue;
            }

            print_as("* Node %s: ", crm_element_value(node_state, XML_ATTR_UNAME));
            print_as("\n");

            lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
            lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

            for (rsc_entry = __xml_first_child(lrm_rsc); rsc_entry != NULL;
                 rsc_entry = __xml_next(rsc_entry)) {
                if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {
                    if (operations) {
                        print_rsc_history(data_set, node, rsc_entry);

                    } else {
                        const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
                        resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

                        if (rsc) {
                            print_rsc_summary(data_set, node, rsc, FALSE);
                        } else {
                            print_as("   %s: orphan\n", rsc_id);
                        }
                    }
                }
            }
        }
    }
}

static void
print_ticket(gpointer name, gpointer value, gpointer data)
{
    ticket_t *ticket = (ticket_t *) value;

    print_as(" %s\t%s%10s", ticket->id,
             ticket->granted ? "granted" : "revoked", ticket->standby ? " [standby]" : "");
    if (ticket->last_granted > -1) {
        print_as(" last-granted=");
        print_date(ticket->last_granted);
    }
    print_as("\n");

    return;
}

static void
print_cluster_tickets(pe_working_set_t * data_set)
{

    print_as("\nTickets:\n");
    g_hash_table_foreach(data_set->tickets, print_ticket, NULL);

    return;
}

static void print_neg_locations(pe_working_set_t *data_set)
{
    GListPtr gIter, gIter2;

    print_as("\nFencing constraints:\n");
    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        rsc_to_node_t *location = (rsc_to_node_t *) gIter->data;
        if (!g_str_has_prefix(location->id, print_neg_location_prefix))
            continue;
        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            node_t *node = (node_t *) gIter2->data;
            if (node->weight >= 0) /* != -INFINITY ??? */
                continue;
            print_as(" %s\tprevents %s from running %son %s\n",
                    location->id, location->rsc_lh->id,
                    location->role_filter == RSC_ROLE_MASTER ? "as Master " : "",
                    node->details->uname);
        }
    }
}

static int
print_status(pe_working_set_t * data_set)
{
    static int updates = 0;

    GListPtr gIter = NULL;
    node_t *dc = NULL;
    char *since_epoch = NULL;
    char *online_nodes = NULL;
    char *online_remote_nodes = NULL;
    char *online_remote_containers = NULL;
    char *offline_nodes = NULL;
    char *offline_remote_nodes = NULL;
    const char *stack_s = NULL;
    xmlNode *dc_version = NULL;
    xmlNode *quorum_node = NULL;
    xmlNode *stack = NULL;
    time_t a_time = time(NULL);

    int print_opts = pe_print_ncurses;
    const char *quorum_votes = "unknown";

    if (as_console) {
        blank_screen();
    } else {
        print_opts = pe_print_printf;
    }

    if (print_pending) {
        print_opts |= pe_print_pending;
    }

    updates++;
    dc = data_set->dc_node;

    if (a_time == (time_t) - 1) {
        crm_perror(LOG_ERR, "set_node_tstamp(): Invalid time returned");
        return 1;
    }

    since_epoch = ctime(&a_time);
    if (since_epoch != NULL && print_last_updated && !hide_headers) {
        print_as("Last updated: %s", since_epoch);
    }

    if (print_last_change && !hide_headers) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

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
    }

    stack =
        get_xpath_object("//nvpair[@name='cluster-infrastructure']", data_set->input, LOG_DEBUG);
    if (stack) {
        stack_s = crm_element_value(stack, XML_NVPAIR_ATTR_VALUE);
        if (!hide_headers) {
            print_as("Stack: %s\n", stack_s);
        }
    }

    dc_version = get_xpath_object("//nvpair[@name='dc-version']", data_set->input, LOG_DEBUG);
    if (dc == NULL) {
        print_as("Current DC: NONE\n");
    } else if (!hide_headers) {
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);

        if (safe_str_neq(dc->details->uname, dc->details->id)) {
            print_as("Current DC: %s (%s)", dc->details->uname, dc->details->id);
        } else {
            print_as("Current DC: %s", dc->details->uname);
        }
        print_as(" - partition %s quorum\n", crm_is_true(quorum) ? "with" : "WITHOUT");
        if (dc_version) {
            print_as("Version: %s\n", crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE));
        }
    }

    quorum_node =
        get_xpath_object("//nvpair[@name='" XML_ATTR_EXPECTED_VOTES "']", data_set->input,
                         LOG_DEBUG);
    if (quorum_node) {
        quorum_votes = crm_element_value(quorum_node, XML_NVPAIR_ATTR_VALUE);
    }

    if(!hide_headers) {
        if(stack_s && strstr(stack_s, "classic openais") != NULL) {
            print_as("%d Nodes configured, %s expected votes\n", g_list_length(data_set->nodes),
                     quorum_votes);
        } else {
            print_as("%d Nodes configured\n", g_list_length(data_set->nodes));
        }
        print_as("%d Resources configured\n", count_resources(data_set, NULL));
        print_as("\n\n");
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *node_mode = NULL;
        char *node_name = NULL;

        if (is_container_remote_node(node)) {
            node_name = g_strdup_printf("%s:%s", node->details->uname, node->details->remote_rsc->container->id);
        } else {
            node_name = g_strdup_printf("%s", node->details->uname);
        }

        if (node->details->unclean) {
            if (node->details->online && node->details->unclean) {
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
                    online_remote_containers = add_list_element(online_remote_containers, node_name);
                } else if (is_baremetal_remote_node(node)) {
                    online_remote_nodes = add_list_element(online_remote_nodes, node_name);
                } else {
                    online_nodes = add_list_element(online_nodes, node_name);
                }
                continue;
            }
        } else {
            node_mode = "OFFLINE";
            if (group_by_node == FALSE) {
                if (is_baremetal_remote_node(node)) {
                    offline_remote_nodes = add_list_element(offline_remote_nodes, node_name);
                } else if (is_container_remote_node(node)) {
                    /* ignore offline container nodes */
                } else {
                    offline_nodes = add_list_element(offline_nodes, node_name);
                }
                continue;
            }
        }

        if (is_container_remote_node(node)) {
            print_as("ContainerNode %s: %s\n", node_name, node_mode);
        } else if (is_baremetal_remote_node(node)) {
            print_as("RemoteNode %s: %s\n", node_name, node_mode);
        } else if (safe_str_eq(node->details->uname, node->details->id)) {
            print_as("Node %s: %s\n", node_name, node_mode);
        } else {
            print_as("Node %s (%s): %s\n", node_name, node->details->id, node_mode);
        }

        if (print_brief && group_by_node) {
            print_rscs_brief(node->details->running_rsc, "\t", print_opts | pe_print_rsconly,
                             stdout, FALSE);

        } else if (group_by_node) {
            GListPtr gIter2 = NULL;

            for (gIter2 = node->details->running_rsc; gIter2 != NULL; gIter2 = gIter2->next) {
                resource_t *rsc = (resource_t *) gIter2->data;

                rsc->fns->print(rsc, "\t", print_opts | pe_print_rsconly, stdout);
            }
        }
        free(node_name);
    }

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
    if (online_remote_containers) {
        print_as("Containers: [%s ]\n", online_remote_containers);
        free(online_remote_containers);
    }

    if (group_by_node == FALSE && inactive_resources) {
        print_as("\nFull list of resources:\n");

    } else if (inactive_resources) {
        print_as("\nInactive resources:\n");
    }

    if (group_by_node == FALSE || inactive_resources) {
        print_as("\n");

        if (print_brief && group_by_node == FALSE) {
            print_opts |= pe_print_brief;
            print_rscs_brief(data_set->resources, NULL, print_opts, stdout,
                             inactive_resources);
        }

        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            gboolean is_active = rsc->fns->active(rsc, TRUE);
            gboolean partially_active = rsc->fns->active(rsc, FALSE);

            if (print_brief && group_by_node == FALSE
                && rsc->variant == pe_native) {
                continue;
            }

            if (is_set(rsc->flags, pe_rsc_orphan) && is_active == FALSE) {
                continue;

            } else if (group_by_node == FALSE) {
                if (partially_active || inactive_resources) {
                    rsc->fns->print(rsc, NULL, print_opts, stdout);
                }

            } else if (is_active == FALSE && inactive_resources) {
                rsc->fns->print(rsc, NULL, print_opts, stdout);
            }
        }
    }

    if (print_nodes_attr) {
        print_as("\nNode Attributes:\n");
        for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            if (node == NULL || node->details->online == FALSE) {
                continue;
            }
            print_as("* Node %s:\n", node->details->uname);
            g_hash_table_foreach(node->details->attrs, create_attr_list, NULL);
            g_list_foreach(attr_list, print_node_attribute, node);
            g_list_free(attr_list);
            attr_list = NULL;
        }
    }

    if (print_operations || print_failcount) {
        print_node_summary(data_set, print_operations);
    }

    if (xml_has_children(data_set->failed)) {
        xmlNode *xml_op = NULL;

        print_as("\nFailed actions:\n");
        for (xml_op = __xml_first_child(data_set->failed); xml_op != NULL;
             xml_op = __xml_next(xml_op)) {
            int status = 0;
            int rc = 0;
            const char *id = ID(xml_op);
            const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
            const char *last = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
            const char *node = crm_element_value(xml_op, XML_ATTR_UNAME);
            const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
            const char *rc_s = crm_element_value(xml_op, XML_LRM_ATTR_RC);
            const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);

            rc = crm_parse_int(rc_s, "0");
            status = crm_parse_int(status_s, "0");

            if (last) {
                time_t run_at = crm_parse_int(last, "0");
                char *run_at_s = ctime(&run_at);
                if(run_at_s) {
                    run_at_s[24] = 0; /* Overwrite the newline */
                }

                print_as("    %s on %s '%s' (%d): call=%s, status=%s, last-rc-change='%s', queued=%sms, exec=%sms\n",
                         op_key ? op_key : id, node, services_ocf_exitcode_str(rc), rc, call, services_lrm_status_str(status),
                         run_at_s, crm_element_value(xml_op, XML_RSC_OP_T_QUEUE), crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
            } else {
                print_as("    %s on %s '%s' (%d): call=%s, status=%s\n",
                         op_key ? op_key : id, node, services_ocf_exitcode_str(rc), rc, call, services_lrm_status_str(status));
            }
        }
        print_as("\n");
    }

    if (print_tickets || print_neg_location_prefix) {
        /* For recording the tickets that are referenced in rsc_ticket constraints
         * but have never been granted yet.
         * To be able to print negative location constraint summary,
         * we also need them to be unpacked. */
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);
        unpack_constraints(cib_constraints, data_set);
    }
    if (print_tickets) {
        print_cluster_tickets(data_set);
    }
    if (print_neg_location_prefix) {
        print_neg_locations(data_set);
    }
#if CURSES_ENABLED
    if (as_console) {
        refresh();
    }
#endif
    return 0;
}

static int
print_xml_status(pe_working_set_t * data_set)
{
    FILE *stream = stdout;
    GListPtr gIter = NULL;
    node_t *dc = NULL;
    xmlNode *stack = NULL;
    xmlNode *quorum_node = NULL;
    const char *quorum_votes = "unknown";
    int print_opts = pe_print_xml;

    dc = data_set->dc_node;

    if (print_pending) {
        print_opts |= pe_print_pending;
    }

    fprintf(stream, "<?xml version=\"1.0\"?>\n");
    fprintf(stream, "<crm_mon version=\"%s\">\n", VERSION);

    /*** SUMMARY ***/
    fprintf(stream, "    <summary>\n");

    if (print_last_updated) {
        time_t now = time(NULL);
        char *now_str = ctime(&now);

        now_str[24] = EOS;      /* replace the newline */
        fprintf(stream, "        <last_update time=\"%s\" />\n", now_str);
    }

    if (print_last_change) {
        const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
        const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
        const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
        const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

        fprintf(stream,
                "        <last_change time=\"%s\" user=\"%s\" client=\"%s\" origin=\"%s\" />\n",
                last_written ? last_written : "", user ? user : "", client ? client : "",
                origin ? origin : "");
    }

    stack = get_xpath_object("//nvpair[@name='cluster-infrastructure']",
                             data_set->input, LOG_DEBUG);
    if (stack) {
        fprintf(stream, "        <stack type=\"%s\" />\n",
                crm_element_value(stack, XML_NVPAIR_ATTR_VALUE));
    }

    if (!dc) {
        fprintf(stream, "        <current_dc present=\"false\" />\n");
    } else {
        const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
        const char *uname = dc->details->uname;
        const char *id = dc->details->id;
        xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                               data_set->input,
                                               LOG_DEBUG);

        fprintf(stream,
                "        <current_dc present=\"true\" version=\"%s\" name=\"%s\" id=\"%s\" with_quorum=\"%s\" />\n",
                dc_version ? crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE) : "", uname, id,
                quorum ? (crm_is_true(quorum) ? "true" : "false") : "false");
    }

    quorum_node = get_xpath_object("//nvpair[@name='" XML_ATTR_EXPECTED_VOTES "']",
                                   data_set->input, LOG_DEBUG);
    if (quorum_node) {
        quorum_votes = crm_element_value(quorum_node, XML_NVPAIR_ATTR_VALUE);
    }
    fprintf(stream, "        <nodes_configured number=\"%d\" expected_votes=\"%s\" />\n",
            g_list_length(data_set->nodes), quorum_votes);

    fprintf(stream, "        <resources_configured number=\"%d\" />\n",
            count_resources(data_set, NULL));

    fprintf(stream, "    </summary>\n");

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

    /*** RESOURCES ***/
    if (group_by_node == FALSE || inactive_resources) {
        fprintf(stream, "    <resources>\n");
        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;
            gboolean is_active = rsc->fns->active(rsc, TRUE);
            gboolean partially_active = rsc->fns->active(rsc, FALSE);

            if (is_set(rsc->flags, pe_rsc_orphan) && is_active == FALSE) {
                continue;

            } else if (group_by_node == FALSE) {
                if (partially_active || inactive_resources) {
                    rsc->fns->print(rsc, "        ", print_opts, stream);
                }

            } else if (is_active == FALSE && inactive_resources) {
                rsc->fns->print(rsc, "        ", print_opts, stream);
            }
        }
        fprintf(stream, "    </resources>\n");
    }

    fprintf(stream, "</crm_mon>\n");
    fflush(stream);
    fclose(stream);

    return 0;
}

static int
print_html_status(pe_working_set_t * data_set, const char *filename, gboolean web_cgi)
{
    FILE *stream;
    GListPtr gIter = NULL;
    node_t *dc = NULL;
    static int updates = 0;
    char *filename_tmp = NULL;
    int print_opts = pe_print_html;

    if (print_pending) {
        print_opts |= pe_print_pending;
    }

    if (web_cgi) {
        stream = stdout;
        fprintf(stream, "Content-type: text/html\n\n");

    } else {
        filename_tmp = crm_concat(filename, "tmp", '.');
        stream = fopen(filename_tmp, "w");
        if (stream == NULL) {
            crm_perror(LOG_ERR, "Cannot open %s for writing", filename_tmp);
            free(filename_tmp);
            return -1;
        }
    }

    updates++;
    dc = data_set->dc_node;

    fprintf(stream, "<html>");
    fprintf(stream, "<head>");
    fprintf(stream, "<title>Cluster status</title>");
/* content="%d;url=http://webdesign.about.com" */
    fprintf(stream, "<meta http-equiv=\"refresh\" content=\"%d\">", reconnect_msec / 1000);
    fprintf(stream, "</head>");

    /*** SUMMARY ***/

    fprintf(stream, "<h2>Cluster summary</h2>");
    {
        char *now_str = NULL;
        time_t now = time(NULL);

        now_str = ctime(&now);
        now_str[24] = EOS;      /* replace the newline */
        fprintf(stream, "Last updated: <b>%s</b><br/>\n", now_str);
    }

    if (dc == NULL) {
        fprintf(stream, "Current DC: <font color=\"red\"><b>NONE</b></font><br/>");
    } else {
        fprintf(stream, "Current DC: %s (%s)<br/>", dc->details->uname, dc->details->id);
    }
    fprintf(stream, "%d Nodes configured.<br/>", g_list_length(data_set->nodes));
    fprintf(stream, "%d Resources configured.<br/>", count_resources(data_set, NULL));

    /*** CONFIG ***/

    fprintf(stream, "<h3>Config Options</h3>\n");

    fprintf(stream, "<table>\n");
    fprintf(stream, "<tr><td>STONITH of failed nodes</td><td>:</td><td>%s</td></tr>\n",
            is_set(data_set->flags, pe_flag_stonith_enabled) ? "enabled" : "disabled");

    fprintf(stream, "<tr><td>Cluster is</td><td>:</td><td>%ssymmetric</td></tr>\n",
            is_set(data_set->flags, pe_flag_symmetric_cluster) ? "" : "a-");

    fprintf(stream, "<tr><td>No Quorum Policy</td><td>:</td><td>");
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
    fprintf(stream, "\n</td></tr>\n</table>\n");

    /*** NODE LIST ***/

    fprintf(stream, "<h2>Node List</h2>\n");
    fprintf(stream, "<ul>\n");
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        fprintf(stream, "<li>");
        if (node->details->standby_onfail && node->details->online) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"orange\">standby (on-fail)</font>\n");
        } else if (node->details->standby && node->details->online) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"orange\">standby</font>\n");
        } else if (node->details->standby) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"red\">OFFLINE (standby)</font>\n");
        } else if (node->details->maintenance && node->details->online) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"blue\">maintenance</font>\n");
        } else if (node->details->maintenance) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"red\">OFFLINE (maintenance)</font>\n");
        } else if (node->details->online) {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"green\">online</font>\n");
        } else {
            fprintf(stream, "Node: %s (%s): %s", node->details->uname, node->details->id,
                    "<font color=\"red\">OFFLINE</font>\n");
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
    }
    fprintf(stream, "</ul>\n");

    if (group_by_node && inactive_resources) {
        fprintf(stream, "<h2>Inactive Resources</h2>\n");

    } else if (group_by_node == FALSE) {
        fprintf(stream, "<h2>Resource List</h2>\n");
    }

    if (group_by_node == FALSE || inactive_resources) {
        if (print_brief && group_by_node == FALSE) {
            print_opts |= pe_print_brief;
            print_rscs_brief(data_set->resources, NULL, print_opts, stream,
                             inactive_resources);
        }

        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;
            gboolean is_active = rsc->fns->active(rsc, TRUE);
            gboolean partially_active = rsc->fns->active(rsc, FALSE);

            if (print_brief && group_by_node == FALSE
                && rsc->variant == pe_native) {
                continue;
            }

            if (is_set(rsc->flags, pe_rsc_orphan) && is_active == FALSE) {
                continue;

            } else if (group_by_node == FALSE) {
                if (partially_active || inactive_resources) {
                    rsc->fns->print(rsc, NULL, print_opts, stream);
                }

            } else if (is_active == FALSE && inactive_resources) {
                rsc->fns->print(rsc, NULL, print_opts, stream);
            }
        }
    }

    fprintf(stream, "</html>");
    fflush(stream);
    fclose(stream);

    if (!web_cgi) {
        if (rename(filename_tmp, filename) != 0) {
            crm_perror(LOG_ERR, "Unable to rename %s->%s", filename_tmp, filename);
        }
        free(filename_tmp);
    }
    return 0;
}

#if ENABLE_SNMP
#  include <net-snmp/net-snmp-config.h>
#  include <net-snmp/snmpv3_api.h>
#  include <net-snmp/agent/agent_trap.h>
#  include <net-snmp/library/snmp_client.h>
#  include <net-snmp/library/mib.h>
#  include <net-snmp/library/snmp_debug.h>

#  define add_snmp_field(list, oid_string, value) do {			\
	oid name[MAX_OID_LEN];						\
        size_t name_length = MAX_OID_LEN;				\
	if (snmp_parse_oid(oid_string, name, &name_length)) {		\
	    int s_rc = snmp_add_var(list, name, name_length, 's', (value)); \
	    if(s_rc != 0) {						\
		crm_err("Could not add %s=%s rc=%d", oid_string, value, s_rc); \
	    } else {							\
		crm_trace("Added %s=%s", oid_string, value);		\
	    }								\
	} else {							\
	    crm_err("Could not parse OID: %s", oid_string);		\
	}								\
    } while(0)								\

#  define add_snmp_field_int(list, oid_string, value) do {		\
	oid name[MAX_OID_LEN];						\
        size_t name_length = MAX_OID_LEN;				\
	if (snmp_parse_oid(oid_string, name, &name_length)) {		\
	    if(NULL == snmp_pdu_add_variable(				\
		   list, name, name_length, ASN_INTEGER,		\
		   (u_char *) & value, sizeof(value))) {		\
		crm_err("Could not add %s=%d", oid_string, value);	\
	    } else {							\
		crm_trace("Added %s=%d", oid_string, value);		\
	    }								\
	} else {							\
	    crm_err("Could not parse OID: %s", oid_string);		\
	}								\
    } while(0)								\

static int
snmp_input(int operation, netsnmp_session * session, int reqid, netsnmp_pdu * pdu, void *magic)
{
    return 1;
}

static netsnmp_session *
crm_snmp_init(const char *target, char *community)
{
    static netsnmp_session *session = NULL;

#  ifdef NETSNMPV53
    char target53[128];

    snprintf(target53, sizeof(target53), "%s:162", target);
#  endif

    if (session) {
        return session;
    }

    if (target == NULL) {
        return NULL;
    }

    if (get_crm_log_level() > LOG_INFO) {
        char *debug_tokens = strdup("run:shell,snmptrap,tdomain");

        debug_register_tokens(debug_tokens);
        snmp_set_do_debugging(1);
    }

    session = calloc(1, sizeof(netsnmp_session));
    snmp_sess_init(session);
    session->version = SNMP_VERSION_2c;
    session->callback = snmp_input;
    session->callback_magic = NULL;

    if (community) {
        session->community_len = strlen(community);
        session->community = (unsigned char *)community;
    }

    session = snmp_add(session,
#  ifdef NETSNMPV53
                       netsnmp_tdomain_transport(target53, 0, "udp"),
#  else
                       netsnmp_transport_open_client("snmptrap", target),
#  endif
                       NULL, NULL);

    if (session == NULL) {
        snmp_sess_perror("Could not create snmp transport", session);
    }
    return session;
}

#endif

static int
send_snmp_trap(const char *node, const char *rsc, const char *task, int target_rc, int rc,
               int status, const char *desc)
{
    int ret = 1;

#if ENABLE_SNMP
    static oid snmptrap_oid[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
    static oid sysuptime_oid[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };

    netsnmp_pdu *trap_pdu;
    netsnmp_session *session = crm_snmp_init(snmp_target, snmp_community);

    trap_pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!trap_pdu) {
        crm_err("Failed to create SNMP notification");
        return SNMPERR_GENERR;
    }

    if (1) {
        /* send uptime */
        char csysuptime[20];
        time_t now = time(NULL);

        sprintf(csysuptime, "%ld", now);
        snmp_add_var(trap_pdu, sysuptime_oid, sizeof(sysuptime_oid) / sizeof(oid), 't', csysuptime);
    }

    /* Indicate what the trap is by setting snmpTrapOid.0 */
    ret =
        snmp_add_var(trap_pdu, snmptrap_oid, sizeof(snmptrap_oid) / sizeof(oid), 'o',
                     snmp_crm_trap_oid);
    if (ret != 0) {
        crm_err("Failed set snmpTrapOid.0=%s", snmp_crm_trap_oid);
        return ret;
    }

    /* Add extries to the trap */
    if (rsc) {
        add_snmp_field(trap_pdu, snmp_crm_oid_rsc, rsc);
    }
    add_snmp_field(trap_pdu, snmp_crm_oid_node, node);
    add_snmp_field(trap_pdu, snmp_crm_oid_task, task);
    add_snmp_field(trap_pdu, snmp_crm_oid_desc, desc);

    add_snmp_field_int(trap_pdu, snmp_crm_oid_rc, rc);
    add_snmp_field_int(trap_pdu, snmp_crm_oid_trc, target_rc);
    add_snmp_field_int(trap_pdu, snmp_crm_oid_status, status);

    /* Send and cleanup */
    ret = snmp_send(session, trap_pdu);
    if (ret == 0) {
        /* error */
        snmp_sess_perror("Could not send SNMP trap", session);
        snmp_free_pdu(trap_pdu);
        ret = SNMPERR_GENERR;
    } else {
        ret = SNMPERR_SUCCESS;
    }
#else
    crm_err("Sending SNMP traps is not supported by this installation");
#endif
    return ret;
}

#if ENABLE_ESMTP
#  include <auth-client.h>
#  include <libesmtp.h>

static void
print_recipient_status(smtp_recipient_t recipient, const char *mailbox, void *arg)
{
    const smtp_status_t *status;

    status = smtp_recipient_status(recipient);
    printf("%s: %d %s", mailbox, status->code, status->text);
}

static void
event_cb(smtp_session_t session, int event_no, void *arg, ...)
{
    int *ok;
    va_list alist;

    va_start(alist, arg);
    switch (event_no) {
        case SMTP_EV_CONNECT:
        case SMTP_EV_MAILSTATUS:
        case SMTP_EV_RCPTSTATUS:
        case SMTP_EV_MESSAGEDATA:
        case SMTP_EV_MESSAGESENT:
        case SMTP_EV_DISCONNECT:
            break;

        case SMTP_EV_WEAK_CIPHER:{
                int bits = va_arg(alist, long);
                ok = va_arg(alist, int *);

                crm_debug("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.", bits);
                *ok = 1;
                break;
            }
        case SMTP_EV_STARTTLS_OK:
            crm_debug("SMTP_EV_STARTTLS_OK - TLS started here.");
            break;

        case SMTP_EV_INVALID_PEER_CERTIFICATE:{
                long vfy_result = va_arg(alist, long);
                ok = va_arg(alist, int *);

                /* There is a table in handle_invalid_peer_certificate() of mail-file.c */
                crm_err("SMTP_EV_INVALID_PEER_CERTIFICATE: %ld", vfy_result);
                *ok = 1;
                break;
            }
        case SMTP_EV_NO_PEER_CERTIFICATE:
            ok = va_arg(alist, int *);

            crm_debug("SMTP_EV_NO_PEER_CERTIFICATE - accepted.");
            *ok = 1;
            break;
        case SMTP_EV_WRONG_PEER_CERTIFICATE:
            ok = va_arg(alist, int *);

            crm_debug("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted.");
            *ok = 1;
            break;
        case SMTP_EV_NO_CLIENT_CERTIFICATE:
            ok = va_arg(alist, int *);

            crm_debug("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted.");
            *ok = 1;
            break;
        default:
            crm_debug("Got event: %d - ignored.\n", event_no);
    }
    va_end(alist);
}
#endif

#define BODY_MAX 2048

#if ENABLE_ESMTP
static void
crm_smtp_debug(const char *buf, int buflen, int writing, void *arg)
{
    char type = 0;
    int lpc = 0, last = 0, level = *(int *)arg;

    if (writing == SMTP_CB_HEADERS) {
        type = 'H';
    } else if (writing) {
        type = 'C';
    } else {
        type = 'S';
    }

    for (; lpc < buflen; lpc++) {
        switch (buf[lpc]) {
            case 0:
            case '\n':
                if (last > 0) {
                    do_crm_log(level, "   %.*s", lpc - last, buf + last);
                } else {
                    do_crm_log(level, "%c: %.*s", type, lpc - last, buf + last);
                }
                last = lpc + 1;
                break;
        }
    }
}
#endif

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

    setenv("CRM_notify_recipient", external_recipient, 1);
    setenv("CRM_notify_node", node, 1);
    setenv("CRM_notify_rsc", rsc, 1);
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
    }

    crm_trace("Finished running custom notification program '%s'.", external_agent);
    free(target_rc_s);
    free(status_s);
    free(rc_s);
    return 0;
}

static int
send_smtp_trap(const char *node, const char *rsc, const char *task, int target_rc, int rc,
               int status, const char *desc)
{
#if ENABLE_ESMTP
    smtp_session_t session;
    smtp_message_t message;
    auth_context_t authctx;
    struct sigaction sa;

    int len = 25; /* Note: Check extra padding on the Subject line below */
    int noauth = 1;
    int smtp_debug = LOG_DEBUG;
    char crm_mail_body[BODY_MAX];
    char *crm_mail_subject = NULL;

    memset(&sa, 0, sizeof(struct sigaction));

    if (node == NULL) {
        node = "-";
    }
    if (rsc == NULL) {
        rsc = "-";
    }
    if (desc == NULL) {
        desc = "-";
    }

    if (crm_mail_to == NULL) {
        return 1;
    }

    if (crm_mail_host == NULL) {
        crm_mail_host = "localhost:25";
    }

    if (crm_mail_prefix == NULL) {
        crm_mail_prefix = "Cluster notification";
    }

    crm_debug("Sending '%s' mail to %s via %s", crm_mail_prefix, crm_mail_to, crm_mail_host);

    len += strlen(crm_mail_prefix);
    len += strlen(task);
    len += strlen(rsc);
    len += strlen(node);
    len += strlen(desc);
    len++;

    crm_mail_subject = calloc(1, len);
    /* If you edit this line, ensure you allocate enough memory for it by altering 'len' above */
    snprintf(crm_mail_subject, len, "%s - %s event for %s on %s: %s\r\n", crm_mail_prefix, task,
             rsc, node, desc);

    len = 0;
    len += snprintf(crm_mail_body + len, BODY_MAX - len, "\r\n%s\r\n", crm_mail_prefix);
    len += snprintf(crm_mail_body + len, BODY_MAX - len, "====\r\n\r\n");
    if (rc == target_rc) {
        len += snprintf(crm_mail_body + len, BODY_MAX - len,
                        "Completed operation %s for resource %s on %s\r\n", task, rsc, node);
    } else {
        len += snprintf(crm_mail_body + len, BODY_MAX - len,
                        "Operation %s for resource %s on %s failed: %s\r\n", task, rsc, node, desc);
    }

    len += snprintf(crm_mail_body + len, BODY_MAX - len, "\r\nDetails:\r\n");
    len += snprintf(crm_mail_body + len, BODY_MAX - len,
                    "\toperation status: (%d) %s\r\n", status, services_lrm_status_str(status));
    if (status == PCMK_LRM_OP_DONE) {
        len += snprintf(crm_mail_body + len, BODY_MAX - len,
                        "\tscript returned: (%d) %s\r\n", rc, services_ocf_exitcode_str(rc));
        len += snprintf(crm_mail_body + len, BODY_MAX - len,
                        "\texpected return value: (%d) %s\r\n", target_rc,
                        services_ocf_exitcode_str(target_rc));
    }

    auth_client_init();
    session = smtp_create_session();
    message = smtp_add_message(session);

    smtp_starttls_enable(session, Starttls_ENABLED);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    smtp_set_server(session, crm_mail_host);

    authctx = auth_create_context();
    auth_set_mechanism_flags(authctx, AUTH_PLUGIN_PLAIN, 0);

    smtp_set_eventcb(session, event_cb, NULL);

    /* Now tell libESMTP it can use the SMTP AUTH extension.
     */
    if (!noauth) {
        crm_debug("Adding authentication context");
        smtp_auth_set_context(session, authctx);
    }

    if (crm_mail_from == NULL) {
        struct utsname us;
        char auto_from[BODY_MAX];

        CRM_ASSERT(uname(&us) == 0);
        snprintf(auto_from, BODY_MAX, "crm_mon@%s", us.nodename);
        smtp_set_reverse_path(message, auto_from);

    } else {
        /* NULL is ok */
        smtp_set_reverse_path(message, crm_mail_from);
    }

    smtp_set_header(message, "To", NULL /*phrase */ , NULL /*addr */ ); /* "Phrase" <addr> */
    smtp_add_recipient(message, crm_mail_to);

    /* Set the Subject: header and override any subject line in the message headers. */
    smtp_set_header(message, "Subject", crm_mail_subject);
    smtp_set_header_option(message, "Subject", Hdr_OVERRIDE, 1);

    smtp_set_message_str(message, crm_mail_body);
    smtp_set_monitorcb(session, crm_smtp_debug, &smtp_debug, 1);

    if (smtp_start_session(session)) {
        char buf[128];
        int rc = smtp_errno();

        crm_err("SMTP server problem: %s (%d)", smtp_strerror(rc, buf, sizeof buf), rc);

    } else {
        char buf[128];
        int rc = smtp_errno();
        const smtp_status_t *smtp_status = smtp_message_transfer_status(message);

        if (rc != 0) {
            crm_err("SMTP server problem: %s (%d)", smtp_strerror(rc, buf, sizeof buf), rc);
        }
        crm_info("Send status: %d %s", smtp_status->code, crm_str(smtp_status->text));
        smtp_enumerate_recipients(message, print_recipient_status, NULL);
    }

    smtp_destroy_session(session);
    auth_destroy_context(authctx);
    auth_client_exit();
#endif
    return 0;
}

static void
handle_rsc_op(xmlNode * rsc_op)
{
    int rc = -1;
    int status = -1;
    int action = -1;
    int interval = 0;
    int target_rc = -1;
    int transition_num = -1;
    gboolean notify = TRUE;

    char *rsc = NULL;
    char *task = NULL;
    const char *desc = NULL;
    const char *node = NULL;
    const char *magic = NULL;
    const char *id = crm_element_value(rsc_op, XML_LRM_ATTR_TASK_KEY);
    char *update_te_uuid = NULL;

    xmlNode *n = rsc_op;

    if (id == NULL) {
        /* Compatability with <= 1.1.5 */
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

    if (parse_op_key(id, &rsc, &task, &interval) == FALSE) {
        crm_err("Invalid event detected for %s", id);
        goto bail;
    }

    while (n != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(n))) {
        n = n->parent;
    }

    node = crm_element_value(n, XML_ATTR_UNAME);
    if (node == NULL) {
        node = ID(n);
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

    if (notify && snmp_target) {
        send_snmp_trap(node, rsc, task, target_rc, rc, status, desc);
    }
    if (notify && crm_mail_to) {
        send_smtp_trap(node, rsc, task, target_rc, rc, status, desc);
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

void
crm_diff_update(const char *event, xmlNode * msg)
{
    int rc = -1;
    long now = time(NULL);
    static bool stale = FALSE;
    static int updates = 0;
    static mainloop_timer_t *refresh_timer = NULL;

    print_dot();

    if(refresh_timer == NULL) {
        refresh_timer = mainloop_timer_add("refresh", 2000, FALSE, mon_trigger_refresh, NULL);
    }

    if (current_cib != NULL) {
        xmlNode *cib_last = current_cib;

        current_cib = NULL;

        rc = cib_apply_patch_event(msg, cib_last, &current_cib, LOG_DEBUG);
        free_xml(cib_last);

        switch (rc) {
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
                break;
            case pcmk_ok:
                updates++;
                break;
            default:
                crm_notice("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc), rc);
        }
    }

    if (current_cib == NULL) {
        current_cib = get_cib_copy(cib);
    }

    if (crm_mail_to || snmp_target || external_agent) {
        /* Process operation updates */
        xmlXPathObject *xpathObj = xpath_search(msg,
                                                "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED
                                                "//" XML_LRM_TAG_RSC_OP);
        int lpc = 0, max = numXpathResults(xpathObj);

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *rsc_op = getXpathResult(xpathObj, lpc);

            handle_rsc_op(rsc_op);
        }
        freeXpathObject(xpathObj);
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
        print_as("Upgrade failed: %s", pcmk_strerror(-pcmk_err_dtd_validation));
        if (as_console) {
            sleep(2);
        }
        clean_up(EX_USAGE);
        return FALSE;
    }

    set_working_set_defaults(&data_set);
    data_set.input = cib_copy;
    cluster_status(&data_set);

    if (as_html_file || web_cgi) {
        if (print_html_status(&data_set, as_html_file, web_cgi) != 0) {
            fprintf(stderr, "Critical: Unable to output html file\n");
            clean_up(EX_USAGE);
        }
    } else if (as_xml) {
        if (print_xml_status(&data_set) != 0) {
            fprintf(stderr, "Critical: Unable to output xml file\n");
            clean_up(EX_USAGE);
        }
    } else if (daemonize) {
        /* do nothing */

    } else if (simple_status) {
        print_simple_status(&data_set);
        if (has_warnings) {
            clean_up(EX_USAGE);
        }

    } else {
        print_status(&data_set);
    }

    cleanup_calculations(&data_set);
    return TRUE;
}

void
mon_st_callback(stonith_t * st, stonith_event_t * e)
{
    char *desc = g_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                 e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                 e->id);

    if (snmp_target) {
        send_snmp_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
    }
    if (crm_mail_to) {
        send_smtp_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
    }
    if (external_agent) {
        send_custom_trap(e->target, NULL, e->operation, pcmk_ok, e->result, 0, desc);
    }
    g_free(desc);
}

/*
 * De-init ncurses, signoff from the CIB and deallocate memory.
 */
void
clean_up(int rc)
{
#if ENABLE_SNMP
    netsnmp_session *session = crm_snmp_init(NULL, NULL);

    if (session) {
        snmp_close(session);
        snmp_shutdown("snmpapp");
    }
#endif

#if CURSES_ENABLED
    if (as_console) {
        as_console = FALSE;
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

    free(as_html_file);
    free(xml_file);
    free(pid_file);

    if (rc >= 0) {
        crm_exit(rc);
    }
    return;
}
