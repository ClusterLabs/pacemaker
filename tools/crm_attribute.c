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
#include <crm/common/attrd_internal.h>
#include <sys/utsname.h>

gboolean BE_QUIET = FALSE;
char command = 'G';

const char *dest_uname = NULL;
char *dest_node = NULL;
char *set_name = NULL;
char *attr_id = NULL;
char *attr_name = NULL;
char *attr_pattern = NULL;
const char *type = NULL;
const char *rsc_id = NULL;
const char *attr_value = NULL;
const char *attr_default = NULL;
const char *set_type = NULL;

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
        "name", required_argument, NULL, 'n',
        "Name of the attribute/option to operate on", pcmk__option_default
    },
    {
        "pattern", required_argument, NULL, 'P',
        "Pattern matching names of attributes (only with -v/-D and -l reboot)",
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
        "set-name", required_argument, NULL, 's',
        "(Advanced) The attribute set in which to place the value",
        pcmk__option_default
    },
    {
        "id", required_argument, NULL, 'i',
        "\t(Advanced) The ID used to identify the attribute",
        pcmk__option_default
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
    int attrd_opts = pcmk__node_attr_none;

    crm_log_cli_init("crm_attribute");
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
                command = flag;
                attr_value = optarg;
                break;
            case 'D':
            case 'v':
                command = flag;
                attr_value = optarg;
                crm_log_args(argc, argv);
                break;
            case 'q':
            case 'Q':
                BE_QUIET = TRUE;
                break;
            case 'U':
            case 'N':
                dest_uname = strdup(optarg);
                break;
            case 's':
                set_name = strdup(optarg);
                break;
            case 'l':
            case 't':
                type = optarg;
                break;
            case 'z':
                type = XML_CIB_TAG_NODES;
                set_type = XML_TAG_UTILIZATION;
                break;
            case 'n':
                attr_name = strdup(optarg);
                break;
            case 'P':
                attr_pattern = strdup(optarg);
                break;
            case 'i':
                attr_id = strdup(optarg);
                break;
            case 'r':
                rsc_id = optarg;
                break;
            case 'd':
                attr_default = optarg;
                break;
            case '!':
                crm_warn("Inhibiting notifications for this update");
                cib_opts |= cib_inhibit_notify;
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
        fprintf(stderr, "Error connecting to the CIB manager: %s\n",
                pcmk_strerror(rc));
        crm_exit(crm_errno2exit(rc));
    }

    if (type == NULL && dest_uname != NULL) {
	    type = "forever";
    }

    if (safe_str_eq(type, "reboot")) {
        type = XML_CIB_TAG_STATUS;

    } else if (safe_str_eq(type, "forever")) {
        type = XML_CIB_TAG_NODES;
    }

    if (type == NULL && dest_uname == NULL) {
        /* we're updating cluster options - don't populate dest_node */
        type = XML_CIB_TAG_CRMCONFIG;

    } else if (safe_str_eq(type, XML_CIB_TAG_CRMCONFIG)) {
    } else if (safe_str_neq(type, XML_CIB_TAG_TICKETS)) {
        /* If we are being called from a resource agent via the cluster,
         * the correct local node name will be passed as an environment
         * variable. Otherwise, we have to ask the cluster.
         */
        dest_uname = pcmk__node_attr_target(dest_uname);
        if (dest_uname == NULL) {
            dest_uname = get_local_node_name();
        }

        rc = query_node_uuid(the_cib, dest_uname, &dest_node, &is_remote_node);
        if (pcmk_ok != rc) {
            fprintf(stderr, "Could not map name=%s to a UUID\n", dest_uname);
            the_cib->cmds->signoff(the_cib);
            cib_delete(the_cib);
            crm_exit(crm_errno2exit(rc));
        }
    }

    if ((command == 'D') && (attr_name == NULL) && (attr_pattern == NULL)) {
        fprintf(stderr, "Error: must specify attribute name or pattern to delete\n");
        crm_exit(CRM_EX_USAGE);
    }

    if (attr_pattern) {
        if (((command != 'v') && (command != 'D'))
            || safe_str_neq(type, XML_CIB_TAG_STATUS)) {

            fprintf(stderr, "Error: pattern can only be used with till-reboot update or delete\n");
            crm_exit(CRM_EX_USAGE);
        }
        command = 'u';
        free(attr_name);
        attr_name = attr_pattern;
    }

    // Only go through attribute manager for transient attributes
    try_attrd = safe_str_eq(type, XML_CIB_TAG_STATUS);

    // Don't try to contact attribute manager if we're using a file as CIB
    if (getenv("CIB_file") || getenv("CIB_shadow")) {
        try_attrd = FALSE;
    }

    if (is_remote_node) {
        attrd_opts = pcmk__node_attr_remote;
    }
    if (((command == 'v') || (command == 'D') || (command == 'u')) && try_attrd
        && (pcmk__node_attr_request(NULL, command, dest_uname, attr_name,
                                    attr_value, type, set_name, NULL, NULL,
                                    attrd_opts) == pcmk_rc_ok)) {
        crm_info("Update %s=%s sent via pacemaker-attrd",
                 attr_name, ((command == 'D')? "<none>" : attr_value));

    } else if (command == 'D') {
        rc = delete_attr_delegate(the_cib, cib_opts, type, dest_node, set_type, set_name,
                                  attr_id, attr_name, attr_value, TRUE, NULL);

        if (rc == -ENXIO) {
            /* Nothing to delete...
             * which means it's not there...
             * which is what the admin wanted
             */
            rc = pcmk_ok;
        }

    } else if (command == 'v') {
        CRM_LOG_ASSERT(type != NULL);
        CRM_LOG_ASSERT(attr_name != NULL);
        CRM_LOG_ASSERT(attr_value != NULL);

        rc = update_attr_delegate(the_cib, cib_opts, type, dest_node, set_type, set_name,
                                  attr_id, attr_name, attr_value, TRUE, NULL, is_remote_node ? "remote" : NULL);

    } else {                    /* query */

        char *read_value = NULL;

        rc = read_attr_delegate(the_cib, type, dest_node, set_type, set_name,
                                attr_id, attr_name, &read_value, TRUE, NULL);

        if (rc == -ENXIO && attr_default) {
            read_value = strdup(attr_default);
            rc = pcmk_ok;
        }

        crm_info("Read %s=%s %s%s",
                 attr_name, crm_str(read_value), set_name ? "in " : "", set_name ? set_name : "");

        if (rc == -ENOTUNIQ) {
            // Multiple matches (already displayed) are not error for queries
            rc = pcmk_ok;

        } else if (BE_QUIET == FALSE) {
            fprintf(stdout, "%s%s %s%s %s%s value=%s\n",
                    type ? "scope=" : "", type ? type : "",
                    attr_id ? "id=" : "", attr_id ? attr_id : "",
                    attr_name ? "name=" : "", attr_name ? attr_name : "",
                    read_value ? read_value : "(null)");

        } else if (read_value != NULL) {
            fprintf(stdout, "%s\n", read_value);
        }
        free(read_value);
    }

    if (rc == -ENOTUNIQ) {
        printf("Please choose from one of the matches above and supply the 'id' with --attr-id\n");

    } else if (rc != pcmk_ok) {
        fprintf(stderr, "Error performing operation: %s\n", pcmk_strerror(rc));
    }

    the_cib->cmds->signoff(the_cib);
    cib_delete(the_cib);
    crm_exit(crm_errno2exit(rc));
}
