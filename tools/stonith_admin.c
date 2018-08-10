/*
 * Copyright 2009-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>

#include <crm/stonith-ng.h>
#include <crm/cib.h>
#include <crm/pengine/status.h>

#include <crm/common/xml.h>


/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {   "help", no_argument, NULL, '?',
        "\tDisplay this text and exit."
    },
    {   "version", no_argument, NULL, '$',
        "\tDisplay version information and exit."
    },
    {   "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output (may be specified multiple times)."
    },
    {   "quiet", no_argument, NULL, 'q',
        "\tBe less descriptive in output."
    },
    {   "cleanup", no_argument, NULL, 'c',
        "\tCleanup wherever appropriate."
    },
    {   "broadcast", no_argument, NULL, 'b',
        "Broadcast wherever appropriate."
    },
    {   "-spacer-", no_argument, NULL, '-', "\nDevice definition commands:" },

    {   "register", required_argument, NULL, 'R',
        "Register the named stonith device. Requires: --agent.\n"
        "\t\t\tOptional: --option, --env-option."
    },
    {   "deregister", required_argument, NULL, 'D',
        "De-register the named stonith device."
    },
    {   "register-level", required_argument, NULL, 'r',
        "Register a stonith level for the named target,\n"
        "\t\t\tspecified as one of NAME, @PATTERN, or ATTR=VALUE.\n"
        "\t\t\tRequires: --index and one or more --device entries."
    },
    {   "deregister-level", required_argument, NULL, 'd',
        "Unregister a stonith level for the named target,\n"
        "\t\t\tspecified as for --register-level. Requires: --index."
    },

    {   "-spacer-", no_argument, NULL, '-', "\nQueries:" },

    {   "list", required_argument, NULL, 'l',
        "List devices that can terminate the specified host.\n"
        "\t\t\tOptional: --timeout."
    },
    {   "list-registered", no_argument, NULL, 'L',
        "List all registered devices. Optional: --timeout."
    },
    {   "list-installed", no_argument, NULL, 'I',
        "List all installed devices. Optional: --timeout."
    },
    {   "list-targets", required_argument, NULL, 's',
        "List the targets that can be fenced by the\n"
        "\t\t\tnamed device. Optional: --timeout."
    },
    {   "metadata", no_argument, NULL, 'M',
        "\tShow agent metadata. Requires: --agent.\n"
        "\t\t\tOptional: --timeout."
    },
    {   "query", required_argument, NULL, 'Q',
        "Check the named device's status. Optional: --timeout."
    },
    {   "history", required_argument, NULL, 'H',
        "Show last successful fencing operation for named node\n"
        "\t\t\t(or '*' for all nodes). Optional: --timeout, --cleanup,\n"
        "\t\t\t--quiet (show only the operation's epoch timestamp),\n"
        "\t\t\t--verbose (show all recorded and pending operations),\n"
        "\t\t\t--broadcast (update history from all nodes available)."
    },
    {   "last", required_argument, NULL, 'h',
        "Indicate when the named node was last fenced.\n"
        "\t\t\tOptional: --as-node-id."
    },
    {   "validate", no_argument, NULL, 'K',
        "\tValidate a fence device configuration.\n"
        "\t\t\tRequires: --agent. Optional: --option, --env-option,\n"
        "\t\t\t--quiet (print no output, only return status).\n"
    },

    {   "-spacer-", no_argument, NULL, '-', "\nFencing Commands:" },

    {   "fence", required_argument, NULL, 'F',
        "Fence named host. Optional: --timeout, --tolerance."
    },
    {   "unfence", required_argument, NULL, 'U',
        "Unfence named host. Optional: --timeout, --tolerance."
    },
    {   "reboot", required_argument, NULL, 'B',
        "Reboot named host. Optional: --timeout, --tolerance."
    },
    {   "confirm", required_argument, NULL, 'C',
        "Tell cluster that named host is now safely down."
    },

    {   "-spacer-", no_argument, NULL, '-', "\nAdditional Options:" },

    {   "agent", required_argument, NULL, 'a',
        "The agent to use (for example, fence_xvm;\n"
        "\t\t\twith --register, --metadata, --validate)."
    },
    {   "option", required_argument, NULL, 'o',
        "Specify a device configuration parameter as NAME=VALUE\n"
        "\t\t\t(may be specified multiple times; with --register,\n"
        "\t\t\t--validate)."
    },
    {   "env-option", required_argument, NULL, 'e',
        "Specify a device configuration parameter with the\n"
        "\t\t\tspecified name, using the value of the\n"
        "\t\t\tenvironment variable of the same name prefixed with\n"
        "\t\t\tOCF_RESKEY_ (may be specified multiple times;\n"
        "\t\t\twith --register, --validate)."
    },
    {   "tag", required_argument, NULL, 'T',
        "Identify fencing operations in logs with the specified\n"
        "\t\t\ttag; useful when multiple entities might invoke\n"
        "\t\t\tstonith_admin (used with most commands)."
    },
    {   "device", required_argument, NULL, 'v',
        "Device ID (with --register-level, device to associate with\n"
        "\t\t\ta given host and level; may be specified multiple times)"
#if SUPPORT_CIBSECRETS
        "\n\t\t\t(with --validate, name to use to load CIB secrets)"
#endif
        "."
    },
    {   "index", required_argument, NULL, 'i',
        "The stonith level (1-9) (with --register-level,\n"
        "\t\t\t--deregister-level)."
    },
    {   "timeout", required_argument, NULL, 't',
        "Operation timeout in seconds (default 120;\n"
        "\t\t\tused with most commands)."
    },
    {   "as-node-id", no_argument, NULL, 'n',
        "(Advanced) The supplied node is the corosync node ID\n"
        "\t\t\t(with --last)."
    },
    {   "tolerance", required_argument, NULL,   0,
        "(Advanced) Do nothing if an equivalent --fence request\n"
        "\t\t\tsucceeded less than this many seconds earlier\n"
        "\t\t\t(with --fence, --unfence, --reboot)."
    },

    { 0, 0, 0, 0 }
};
/* *INDENT-ON* */

static int st_opts = st_opt_sync_call | st_opt_allow_suicide;

static GMainLoop *mainloop = NULL;
struct {
    stonith_t *st;
    const char *target;
    const char *action;
    char *name;
    int timeout;
    int tolerance;
    int rc;
} async_fence_data;

static int
try_mainloop_connect(void)
{
    stonith_t *st = async_fence_data.st;
    int tries = 10;
    int i = 0;
    int rc = 0;

    for (i = 0; i < tries; i++) {
        crm_debug("Connecting as %s", async_fence_data.name);
        rc = st->cmds->connect(st, async_fence_data.name, NULL);

        if (!rc) {
            crm_debug("stonith client connection established");
            return 0;
        } else {
            crm_debug("stonith client connection failed");
        }
        sleep(1);
    }

    crm_err("Could not connect to the fencer");
    return -1;
}

static void
notify_callback(stonith_t * st, stonith_event_t * e)
{
    if (e->result != pcmk_ok) {
        return;
    }

    if (safe_str_eq(async_fence_data.target, e->target) &&
        safe_str_eq(async_fence_data.action, e->action)) {

        async_fence_data.rc = e->result;
        g_main_loop_quit(mainloop);
    }
}

static void
fence_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    async_fence_data.rc = data->rc;

    g_main_loop_quit(mainloop);
}

static gboolean
async_fence_helper(gpointer user_data)
{
    stonith_t *st = async_fence_data.st;
    int call_id = 0;

    if (try_mainloop_connect()) {
        g_main_loop_quit(mainloop);
        return TRUE;
    }

    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, notify_callback);

    call_id = st->cmds->fence(st,
                              st_opt_allow_suicide,
                              async_fence_data.target,
                              async_fence_data.action,
                              async_fence_data.timeout, async_fence_data.tolerance);

    if (call_id < 0) {
        g_main_loop_quit(mainloop);
        return TRUE;
    }

    st->cmds->register_callback(st,
                                call_id,
                                async_fence_data.timeout,
                                st_opt_timeout_updates, NULL, "callback", fence_callback);

    return TRUE;
}

static int
mainloop_fencing(stonith_t * st, const char *target, const char *action, int timeout, int tolerance)
{
    crm_trigger_t *trig;

    async_fence_data.st = st;
    async_fence_data.target = target;
    async_fence_data.action = action;
    async_fence_data.timeout = timeout;
    async_fence_data.tolerance = tolerance;
    async_fence_data.rc = -1;

    trig = mainloop_add_trigger(G_PRIORITY_HIGH, async_fence_helper, NULL);
    mainloop_set_trigger(trig);

    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);

    return async_fence_data.rc;
}

static int
handle_level(stonith_t *st, char *target, int fence_level,
             stonith_key_value_t *devices, bool added)
{
    char *node = NULL;
    char *pattern = NULL;
    char *name = NULL;
    char *value = strchr(target, '=');

    /* Determine if targeting by attribute, node name pattern or node name */
    if (value != NULL)  {
        name = target;
        *value++ = '\0';
    } else if (*target == '@') {
        pattern = target + 1;
    } else {
        node = target;
    }

    /* Register or unregister level as appropriate */
    if (added) {
        return st->cmds->register_level_full(st, st_opts, node, pattern,
                                             name, value, fence_level,
                                             devices);
    }
    return st->cmds->remove_level_full(st, st_opts, node, pattern,
                                       name, value, fence_level);
}

static char *
fence_action_str(const char *action)
{
    char *str = NULL;

    if (action == NULL) {
        str = strdup("unknown");
    } else if (action[0] == 'o') { // on, off
        str = crm_concat("turn", action, ' ');
    } else {
        str = strdup(action);
    }
    return str;
}

static void
print_fence_event(stonith_history_t *event)
{
    char *action_s = fence_action_str(event->action);
    time_t complete = event->completed;

    printf("%s was able to %s node %s on behalf of %s from %s at %s\n",
           (event->delegate? event->delegate : "This node"), action_s,
           event->target, event->client, event->origin, ctime(&complete));
    free(action_s);
}

static int
handle_history(stonith_t *st, const char *target, int timeout, int quiet,
             int verbose, int cleanup, int broadcast)
{
    stonith_history_t *history = NULL, *hp, *latest = NULL;
    int rc = 0;

    if (!quiet) {
        if (cleanup) {
            printf("cleaning up fencing-history%s%s\n",
                   target?" for node ":"", target?target:"");
        }
        if (broadcast) {
            printf("gather fencing-history from all nodes\n");
        }
    }
    rc = st->cmds->history(st, st_opts | (cleanup?st_opt_cleanup:0) |
                           (broadcast?st_opt_broadcast:0),
                           (safe_str_eq(target, "*")? NULL : target),
                           &history, timeout);
    for (hp = history; hp; hp = hp->next) {
        char *action_s = NULL;
        time_t complete = hp->completed;

        if (hp->state == st_done) {
            latest = hp;
        }

        if (quiet || !verbose) {
            continue;
        }

        if (hp->state == st_failed) {
            action_s = fence_action_str(hp->action);
            printf("%s failed to %s node %s on behalf of %s from %s at %s\n",
                   hp->delegate ? hp->delegate : "We", action_s, hp->target,
                   hp->client, hp->origin, ctime(&complete));

        } else if (hp->state == st_done) {
            print_fence_event(latest);

        } else {
            /* ocf:pacemaker:controld depends on "wishes to" being
             * in this output, when used with older versions of DLM
             * that don't report stateful_merge_wait
             */
            action_s = fence_action_str(hp->action);
            printf("%s at %s wishes to %s node %s - %d %lld\n",
                   hp->client, hp->origin, action_s, hp->target, hp->state,
                   (long long) complete);
        }

        free(action_s);
    }

    if (latest) {
        if (quiet) {
            printf("%lld\n", (long long) latest->completed);
        } else if (!verbose) { // already printed if verbose
            print_fence_event(latest);
        }
    }

    stonith_history_free(history);
    return rc;
}

static int
validate(stonith_t *st, const char *agent, const char *id,
         stonith_key_value_t *params, int timeout, int quiet)
{
    int rc = 1;
    char *output = NULL;
    char *error_output = NULL;

    rc = st->cmds->validate(st, st_opt_sync_call, id, NULL, agent, params,
                            timeout, &output, &error_output);

    if (!quiet) {
        printf("Validation of %s %s\n", agent, (rc? "failed" : "succeeded"));
        if (output && *output) {
            puts(output);
            free(output);
        }
        if (error_output && *error_output) {
            puts(error_output);
            free(error_output);
        }
    }
    return rc;
}

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int quiet = 0;
    int cleanup = 0;
    int broadcast = 0;
    int verbose = 0;
    int argerr = 0;
    int timeout = 120;
    int option_index = 0;
    int fence_level = 0;
    int no_connect = 0;
    int tolerance = 0;
    int as_nodeid = FALSE;

    char *name = NULL;
    char *value = NULL;
    char *target = NULL;
    char *lists = NULL;
    const char *agent = NULL;
    const char *device = NULL;
    const char *longname = NULL;

    char action = 0;
    crm_exit_t exit_code = CRM_EX_OK;
    stonith_t *st = NULL;
    stonith_key_value_t *params = NULL;
    stonith_key_value_t *devices = NULL;
    stonith_key_value_t *dIter = NULL;

    crm_log_cli_init("stonith_admin");
    crm_set_options(NULL, "<command> [<options>]", long_options,
                    "access the Pacemaker fencing API");

    async_fence_data.name = strdup(crm_system_name);

    while (1) {
        flag = crm_get_option_long(argc, argv, &option_index, &longname);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                verbose = 1;
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, CRM_EX_OK);
                break;
            case 'I':
            case 'K':
                no_connect = 1;
                /* fall through */
            case 'L':
                action = flag;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'c':
                cleanup = 1;
                break;
            case 'b':
                broadcast = 1;
                break;
            case 'Q':
            case 'R':
            case 'D':
            case 's':
                action = flag;
                device = optarg;
                break;
            case 'T':
                free(async_fence_data.name);
                async_fence_data.name = crm_strdup_printf("%s.%s", crm_system_name, optarg);
                break;
            case 'a':
                agent = optarg;
                break;
            case 'l':
                target = optarg;
                action = 'L';
                break;
            case 'M':
                no_connect = 1;
                action = flag;
                break;
            case 't':
                timeout = crm_atoi(optarg, NULL);
                break;
            case 'B':
            case 'F':
            case 'U':
                /* using mainloop here */
                no_connect = 1;
                /* fall through */
            case 'C':
                /* Always log the input arguments */
                crm_log_args(argc, argv);
                target = optarg;
                action = flag;
                break;
            case 'n':
                as_nodeid = TRUE;
                break;
            case 'h':
            case 'H':
            case 'r':
            case 'd':
                target = optarg;
                action = flag;
                break;
            case 'i':
                fence_level = crm_atoi(optarg, NULL);
                break;
            case 'v':
                devices = stonith_key_value_add(devices, NULL, optarg);
                break;
            case 'o':
                crm_info("Scanning: -o %s", optarg);
                rc = sscanf(optarg, "%m[^=]=%m[^=]", &name, &value);
                if (rc != 2) {
                    crm_err("Invalid option: -o %s", optarg);
                    ++argerr;
                } else {
                    crm_info("Got: '%s'='%s'", name, value);
                    params = stonith_key_value_add(params, name, value);
                }
                free(value); value = NULL;
                free(name); name = NULL;
                break;
            case 'e':
                {
                    char *key = crm_concat("OCF_RESKEY", optarg, '_');
                    const char *env = getenv(key);

                    if (env == NULL) {
                        crm_err("Invalid option: -e %s", optarg);
                        ++argerr;
                    } else {
                        crm_info("Got: '%s'='%s'", optarg, env);
                        params = stonith_key_value_add(params, optarg, env);
                    }
                    free(key);
                }
                break;
            case 0:
                if (safe_str_eq("tolerance", longname)) {
                    tolerance = crm_get_msec(optarg) / 1000;    /* Send in seconds */
                }
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (action == 0) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    st = stonith_api_new();

    if (!no_connect) {
        rc = st->cmds->connect(st, async_fence_data.name, NULL);
        if (rc < 0) {
            fprintf(stderr, "Could not connect to fencer: %s\n",
                    pcmk_strerror(rc));
            exit_code = CRM_EX_DISCONNECT;
            goto done;
        }
    }

    switch (action) {
        case 'I':
            rc = st->cmds->list_agents(st, st_opt_sync_call, NULL, &devices, timeout);
            for (dIter = devices; dIter; dIter = dIter->next) {
                fprintf(stdout, " %s\n", dIter->value);
            }
            if (rc == 0) {
                fprintf(stderr, "No devices found\n");
            } else if (rc > 0) {
                fprintf(stderr, "%d devices found\n", rc);
                rc = 0;
            }
            stonith_key_value_freeall(devices, 1, 1);
            break;
        case 'L':
            rc = st->cmds->query(st, st_opts, target, &devices, timeout);
            for (dIter = devices; dIter; dIter = dIter->next) {
                fprintf(stdout, " %s\n", dIter->value);
            }
            if (rc == 0) {
                fprintf(stderr, "No devices found\n");
            } else if (rc > 0) {
                fprintf(stderr, "%d devices found\n", rc);
                rc = 0;
            }
            stonith_key_value_freeall(devices, 1, 1);
            break;
        case 'Q':
            rc = st->cmds->monitor(st, st_opts, device, timeout);
            if (rc < 0) {
                rc = st->cmds->list(st, st_opts, device, NULL, timeout);
            }
            break;
        case 's':
            rc = st->cmds->list(st, st_opts, device, &lists, timeout);
            if (rc == 0) {
                if (lists) {
                    char *source = lists, *dest = lists; 

                    while (*dest) {
                        if ((*dest == '\\') && (*(dest+1) == 'n')) {
                            *source = '\n';
                            dest++;
                            dest++;
                            source++;
                        } else if ((*dest == ',') || (*dest == ';')) {
                            dest++;
                        } else {
                            *source = *dest;
                            dest++;
                            source++;
                        }

                        if (!(*dest)) {
                            *source = 0;
                        }
                    }
                    fprintf(stdout, "%s", lists);
                    free(lists);
                }
            } else {
                fprintf(stderr, "List command returned error. rc : %d\n", rc);
            }
            break;
        case 'R':
            rc = st->cmds->register_device(st, st_opts, device, NULL, agent,
                                           params);
            break;
        case 'D':
            rc = st->cmds->remove_device(st, st_opts, device);
            break;
        case 'd':
        case 'r':
            rc = handle_level(st, target, fence_level, devices, action == 'r');
            break;
        case 'M':
            if (agent == NULL) {
                printf("Please specify an agent to query using -a,--agent [value]\n");
                exit_code = CRM_EX_USAGE;
                goto done;
            } else {
                char *buffer = NULL;

                rc = st->cmds->metadata(st, st_opt_sync_call, agent, NULL, &buffer, timeout);
                if (rc == pcmk_ok) {
                    printf("%s\n", buffer);
                }
                free(buffer);
            }
            break;
        case 'C':
            rc = st->cmds->confirm(st, st_opts, target);
            break;
        case 'B':
            rc = mainloop_fencing(st, target, "reboot", timeout, tolerance);
            break;
        case 'F':
            rc = mainloop_fencing(st, target, "off", timeout, tolerance);
            break;
        case 'U':
            rc = mainloop_fencing(st, target, "on", timeout, tolerance);
            break;
        case 'h':
            {
                time_t when = 0;

                if(as_nodeid) {
                    uint32_t nodeid = atol(target);
                    when = stonith_api_time(nodeid, NULL, FALSE);
                } else {
                    when = stonith_api_time(0, target, FALSE);
                }
                if(when) {
                    printf("Node %s last kicked at: %s\n", target, ctime(&when));
                } else {
                    printf("Node %s has never been kicked\n", target);
                }
            }
            break;
        case 'H':
            rc = handle_history(st, target, timeout, quiet,
                                verbose, cleanup, broadcast);
            break;
        case 'K':
            if (agent == NULL) {
                printf("Please specify an agent to validate with --agent\n");
                exit_code = CRM_EX_USAGE;
                goto done;
            }
            device = (devices? devices->key : NULL);
            rc = validate(st, agent, device, params, timeout, quiet);
            break;
    }

    crm_info("Command returned: %s (%d)", pcmk_strerror(rc), rc);
    exit_code = crm_errno2exit(rc);

  done:
    free(async_fence_data.name);
    stonith_key_value_freeall(params, 1, 1);
    st->cmds->disconnect(st);
    stonith_api_delete(st);
    return exit_code;
}
