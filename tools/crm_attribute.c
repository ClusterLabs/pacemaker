/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/util.h>
#include <crm/cluster.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/attrd_internal.h>
#include <sys/utsname.h>

crm_exit_t exit_code = CRM_EX_OK;

struct {
    char command;
    char *attr_id;
    char *attr_name;
    char *attr_pattern;
    char *dest_node;
    char *set_name;
    const char *attr_default;
    const char *attr_value;
    const char *dest_uname;
    const char *set_type;
    const char *type;
} options = {
    .command = 'G'
};

gboolean BE_QUIET = FALSE;

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "quiet", no_argument, NULL, 'q',
        "\tPrint only the value on stdout\n", pcmk__option_default
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nOptions for selecting attribute:", pcmk__option_default
    },
    {
        "name", required_argument, NULL, 'n',
        "Operate on attribute or option with this name",
        pcmk__option_default
    },
    {
        "pattern", required_argument, NULL, 'P',
        "Operate on all attributes matching this pattern "
            "(with -v/-D and -l reboot)",
        pcmk__option_default
    },
    {
        "promotion", optional_argument, NULL, 'p',
        "Operate on node attribute used as promotion score for specified "
            "resource, or resource given in OCF_RESOURCE_INSTANCE environment "
            "variable if none is specified; this also defaults -l/--lifetime "
            "to reboot (normally invoked from an OCF resource agent)",
        pcmk__option_default
    },
    {
        "set-name", required_argument, NULL, 's',
        "(Advanced) Operate on instance of specified attribute that is "
            "within set with this XML ID",
        pcmk__option_default
    },
    {
        "id", required_argument, NULL, 'i',
        "\t(Advanced) Operate on instance of specified attribute with this "
            "XML ID",
        pcmk__option_default
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    {
        "query", no_argument, NULL, 'G',
        "\tQuery the current value of the attribute/option",
        pcmk__option_default
    },
    {
        "update", required_argument, NULL, 'v',
        "Update the value of the attribute/option", pcmk__option_default
    },
    {
        "delete", no_argument, NULL, 'D',
        "\tDelete the attribute/option", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional Options:", pcmk__option_default
    },
    {
        "node", required_argument, NULL, 'N',
        "Set a node attribute for named node (instead of a cluster option). "
            "See also: -l",
        pcmk__option_default
    },
    {
        "type", required_argument, NULL, 't',
        "Which part of the configuration to update/delete/query the option in",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\t\tValid values: crm_config, rsc_defaults, op_defaults, tickets",
        pcmk__option_default
    },
    {
        "lifetime", required_argument, NULL, 'l',
        "Lifetime of the node attribute", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\t\tValid values: reboot, forever", pcmk__option_default
    },
    {
        "utilization", no_argument, NULL, 'z',
        "Set an utilization attribute for the node.", pcmk__option_default
    },
    {
        "default", required_argument, NULL, 'd',
        "(Advanced) Default value to display if none is found in configuration",
        pcmk__option_default
    },
    {
        "inhibit-policy-engine", no_argument, NULL, '!',
        NULL, pcmk__option_hidden
    },

    /* legacy */
    {
        "quiet", no_argument, NULL, 'Q',
        NULL, pcmk__option_hidden
    },
    {
        "node-uname", required_argument, NULL, 'U',
        NULL, pcmk__option_hidden
    },
    {
        "get-value", no_argument, NULL, 'G',
        NULL, pcmk__option_hidden
    },
    {
        "delete-attr", no_argument, NULL, 'D',
        NULL, pcmk__option_hidden
    },
    {
        "attr-value", required_argument, NULL, 'v',
        NULL, pcmk__option_hidden
    },
    {
        "attr-name", required_argument, NULL, 'n',
        NULL, pcmk__option_hidden
    },
    {
        "attr-id", required_argument, NULL, 'i',
        NULL, pcmk__option_hidden
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nExamples:", pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Add new node attribute called 'location' with the value of 'office' "
            "for host 'myhost':",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --node myhost --name location --update office",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Query the value of the 'location' node attribute for host 'myhost':",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --node myhost --name location --query",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Change the value of the 'location' node attribute for host 'myhost':",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --node myhost --name location --update backoffice",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Delete the 'location' node attribute for host 'myhost':",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --node myhost --name location --delete",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Query the value of the cluster-delay cluster option:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --type crm_config --name cluster-delay --query",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Query value of the \"cluster-delay\" cluster option and print only "
            "the value:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_attribute --type crm_config --name cluster-delay --query --quiet",
        pcmk__option_example
    },
    { 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
    cib_t *the_cib = NULL;
    int rc = pcmk_ok;

    int cib_opts = cib_sync_call;
    int argerr = 0;
    int flag;

    int option_index = 0;
    int is_remote_node = 0;

    bool try_attrd = true;
    bool promotion_score = false;
    int attrd_opts = pcmk__node_attr_none;

    pcmk__cli_init_logging("crm_attribute", 0);
    pcmk__set_cli_options(NULL, "-n <attribute> <command> [options]",
                          long_options,
                          "query and update Pacemaker cluster options "
                          "and node attributes");

    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'G':
                options.command = flag;
                options.attr_value = optarg;
                break;
            case 'D':
            case 'v':
                options.command = flag;
                options.attr_value = optarg;
                crm_log_args(argc, argv);
                break;
            case 'q':
            case 'Q':
                BE_QUIET = TRUE;
                break;
            case 'U':
            case 'N':
                options.dest_uname = strdup(optarg);
                break;
            case 's':
                options.set_name = strdup(optarg);
                break;
            case 'l':
            case 't':
                options.type = optarg;
                break;
            case 'z':
                options.type = XML_CIB_TAG_NODES;
                options.set_type = XML_TAG_UTILIZATION;
                break;
            case 'n':
                options.attr_name = strdup(optarg);
                break;
            case 'p':
                promotion_score = true;
                options.attr_name = pcmk_promotion_score_name(optarg);
                if (options.attr_name == NULL) {
                    fprintf(stderr, "-p/--promotion must be called from an "
                                    " OCF resource agent or with a resource ID "
                                    " specified\n\n");
                    ++argerr;
                }
                break;
            case 'P':
                options.attr_pattern = strdup(optarg);
                break;
            case 'i':
                options.attr_id = strdup(optarg);
                break;
            case 'd':
                options.attr_default = optarg;
                break;
            case '!':
                crm_warn("Inhibiting notifications for this update");
                cib__set_call_options(cib_opts, crm_system_name,
                                      cib_inhibit_notify);
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

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);

    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not connect to the CIB: %s\n",
                pcmk_strerror(rc));
        exit_code = crm_errno2exit(rc);
        goto done;
    }

    // Use default CIB location if not given
    if (options.type == NULL) {
        if (promotion_score) {
            // Updating a promotion score node attribute
            options.type = "reboot";

        } else if (options.dest_uname != NULL) {
            // Updating some other node attribute
            options.type = "forever";

        } else {
            // Updating cluster options
            options.type = XML_CIB_TAG_CRMCONFIG;
        }
    }

    if (pcmk__str_eq(options.type, "reboot", pcmk__str_casei)) {
        options.type = XML_CIB_TAG_STATUS;

    } else if (pcmk__str_eq(options.type, "forever", pcmk__str_casei)) {
        options.type = XML_CIB_TAG_NODES;
    }

    // Use default node if not given (except for cluster options and tickets)
    if (!pcmk__strcase_any_of(options.type, XML_CIB_TAG_CRMCONFIG, XML_CIB_TAG_TICKETS,
                              NULL)) {
        /* If we are being called from a resource agent via the cluster,
         * the correct local node name will be passed as an environment
         * variable. Otherwise, we have to ask the cluster.
         */
        options.dest_uname = pcmk__node_attr_target(options.dest_uname);
        if (options.dest_uname == NULL) {
            options.dest_uname = get_local_node_name();
        }

        rc = query_node_uuid(the_cib, options.dest_uname, &options.dest_node, &is_remote_node);
        if (pcmk_ok != rc) {
            fprintf(stderr, "Could not map name=%s to a UUID\n", options.dest_uname);
            exit_code = crm_errno2exit(rc);
            goto done;
        }
    }

    if ((options.command == 'D') && (options.attr_name == NULL) && (options.attr_pattern == NULL)) {
        fprintf(stderr, "Error: must specify attribute name or pattern to delete\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.attr_pattern) {
        if (((options.command != 'v') && (options.command != 'D'))
            || !pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei)) {

            fprintf(stderr, "Error: pattern can only be used with till-reboot update or delete\n");
            exit_code = CRM_EX_USAGE;
            goto done;
        }
        options.command = 'u';
        free(options.attr_name);
        options.attr_name = options.attr_pattern;
    }

    // Only go through attribute manager for transient attributes
    try_attrd = pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei);

    // Don't try to contact attribute manager if we're using a file as CIB
    if (getenv("CIB_file") || getenv("CIB_shadow")) {
        try_attrd = FALSE;
    }

    if (is_remote_node) {
        attrd_opts = pcmk__node_attr_remote;
    }
    if (((options.command == 'v') || (options.command == 'D') || (options.command == 'u')) && try_attrd
        && (pcmk__node_attr_request(NULL, options.command, options.dest_uname, options.attr_name,
                                    options.attr_value, options.type, options.set_name, NULL, NULL,
                                    attrd_opts) == pcmk_rc_ok)) {
        crm_info("Update %s=%s sent via pacemaker-attrd",
                 options.attr_name, ((options.command == 'D')? "<none>" : options.attr_value));

    } else if (options.command == 'D') {
        rc = delete_attr_delegate(the_cib, cib_opts, options.type, options.dest_node, options.set_type, options.set_name,
                                  options.attr_id, options.attr_name, options.attr_value, TRUE, NULL);

        if (rc == -ENXIO) {
            /* Nothing to delete...
             * which means it's not there...
             * which is what the admin wanted
             */
            rc = pcmk_ok;
        }

    } else if (options.command == 'v') {
        CRM_LOG_ASSERT(options.type != NULL);
        CRM_LOG_ASSERT(options.attr_name != NULL);
        CRM_LOG_ASSERT(options.attr_value != NULL);

        rc = update_attr_delegate(the_cib, cib_opts, options.type, options.dest_node, options.set_type, options.set_name,
                                  options.attr_id, options.attr_name, options.attr_value, TRUE, NULL, is_remote_node ? "remote" : NULL);

    } else {                    /* query */

        char *read_value = NULL;

        rc = read_attr_delegate(the_cib, options.type, options.dest_node, options.set_type, options.set_name,
                                options.attr_id, options.attr_name, &read_value, TRUE, NULL);

        if (rc == -ENXIO && options.attr_default) {
            read_value = strdup(options.attr_default);
            rc = pcmk_ok;
        }

        crm_info("Read %s=%s %s%s",
                 options.attr_name, crm_str(read_value), options.set_name ? "in " : "", options.set_name ? options.set_name : "");

        if (rc == -ENOTUNIQ) {
            // Multiple matches (already displayed) are not error for queries
            rc = pcmk_ok;

        } else if (BE_QUIET == FALSE) {
            fprintf(stdout, "%s%s %s%s %s%s value=%s\n",
                    options.type ? "scope=" : "", options.type ? options.type : "",
                    options.attr_id ? "id=" : "", options.attr_id ? options.attr_id : "",
                    options.attr_name ? "name=" : "", options.attr_name ? options.attr_name : "",
                    read_value ? read_value : "(null)");

        } else if (read_value != NULL) {
            fprintf(stdout, "%s\n", read_value);
        }
        free(read_value);
    }

    if (rc == -ENOTUNIQ) {
        printf("Please choose from one of the matches above and supply the 'id' with --attr-id\n");
        exit_code = crm_errno2exit(rc);

    } else if (rc != pcmk_ok) {
        fprintf(stderr, "Error performing operation: %s\n", pcmk_strerror(rc));
        exit_code = crm_errno2exit(rc);
    }

done:
    free(options.attr_id);
    free(options.attr_name);
    free(options.attr_value);
    free(options.dest_node);
    free(options.set_name);

    if (the_cib) {
        the_cib->cmds->signoff(the_cib);
        cib_delete(the_cib);
    }

    return crm_exit(exit_code);
}
