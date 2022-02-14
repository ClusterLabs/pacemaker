/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
#include <libgen.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/ipc.h>

#include <crm/common/attrd_internal.h>

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
        "\tIncrease debug output\n", pcmk__option_default
    },
    {
        "name", required_argument, NULL, 'n',
        "The attribute's name", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    {
        "update", required_argument, NULL, 'U',
        "Update attribute's value in pacemaker-attrd. If this causes the value "
            "to change, it will also be updated in the cluster configuration.",
        pcmk__option_default
    },
    {
        "update-both", required_argument, NULL, 'B',
        "Update attribute's value and time to wait (dampening) in "
            "pacemaker-attrd. If this causes the value or dampening to change, "
            "the attribute will also be written to the cluster configuration, "
            "so be aware that repeatedly changing the dampening reduces its "
            "effectiveness.",
        pcmk__option_default
    },
    {
        "update-delay", no_argument, NULL, 'Y',
        "Update attribute's dampening in pacemaker-attrd (requires "
            "-d/--delay). If this causes the dampening to change, the "
            "attribute will also be written to the cluster configuration, so "
            "be aware that repeatedly changing the dampening reduces its "
            "effectiveness.",
        pcmk__option_default
    },
    {
        "query", no_argument, NULL, 'Q',
        "\tQuery the attribute's value from pacemaker-attrd",
        pcmk__option_default
    },
    {
        "delete", no_argument, NULL, 'D',
        "\tDelete attribute from pacemaker-attrd. If a value was previously "
            "set, it will also be removed from the cluster configuration",
        pcmk__option_default
    },
    {
        "refresh", no_argument, NULL, 'R',
        "\t(Advanced) Force the pacemaker-attrd daemon to resend all current "
            "values to the CIB",
        pcmk__option_default
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional options:", pcmk__option_default
    },
    {
        "delay", required_argument, NULL, 'd',
        "The time to wait (dampening) in seconds for further changes "
            "before writing",
        pcmk__option_default
    },
    {
        "set", required_argument, NULL, 's',
        "(Advanced) The attribute set in which to place the value",
        pcmk__option_default
    },
    {
        "node", required_argument, NULL, 'N',
        "Set the attribute for the named node (instead of the local one)",
        pcmk__option_default
    },
    {
        "all", no_argument, NULL, 'A',
        "Show values of the attribute for all nodes (query only)",
        pcmk__option_default
    },

    // @TODO Implement --lifetime
    {
        "lifetime", required_argument, NULL, 'l',
        "(Not yet implemented) Lifetime of the node attribute (silently "
            "ignored by cluster)",
        pcmk__option_default
    },
    {
        "private", no_argument, NULL, 'p',
        "\tIf this creates a new attribute, never write the attribute to CIB",
        pcmk__option_default
    },

    /* Legacy options */
    {
        "quiet", no_argument, NULL, 'q',
        NULL, pcmk__option_hidden
    },
    {
        "update", required_argument, NULL, 'v',
        NULL, pcmk__option_hidden
    },
    {
        "section", required_argument, NULL, 'S',
        NULL, pcmk__option_hidden
    },
    { 0, 0, 0, 0 }
};

static int do_query(const char *attr_name, const char *attr_node, gboolean query_all);
static int do_update(char command, const char *attr_node, const char *attr_name,
                     const char *attr_value, const char *attr_section,
                     const char *attr_set, const char *attr_dampen, int attr_options);

// Free memory at exit to make analyzers happy
#define cleanup_memory() \
    free(attr_dampen); \
    free(attr_name); \
    free(attr_node); \
    free(attr_section); \
    free(attr_set);

int
main(int argc, char **argv)
{
    int index = 0;
    int argerr = 0;
    int attr_options = pcmk__node_attr_none;
    int flag;
    crm_exit_t exit_code = CRM_EX_OK;
    char *attr_node = NULL;
    char *attr_name = NULL;
    char *attr_set = NULL;
    char *attr_section = NULL;
    char *attr_dampen = NULL;
    const char *attr_value = NULL;
    char command = 'Q';

    gboolean query_all = FALSE;

    pcmk__cli_init_logging("attrd_updater", 0);
    pcmk__set_cli_options(NULL, "-n <attribute> <command> [options]",
                          long_options,
                          "query and update Pacemaker node attributes");

    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                cleanup_memory();
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'n':
                pcmk__str_update(&attr_name, optarg);
                break;
            case 's':
                pcmk__str_update(&attr_set, optarg);
                break;
            case 'd':
                pcmk__str_update(&attr_dampen, optarg);
                break;
            case 'l':
            case 'S':
                pcmk__str_update(&attr_section, optarg);
                break;
            case 'N':
                pcmk__str_update(&attr_node, optarg);
                break;
            case 'A':
                query_all = TRUE;
                break;
            case 'p':
                pcmk__set_node_attr_flags(attr_options, pcmk__node_attr_private);
                break;
            case 'q':
                break;
            case 'Y':
                command = flag;
                crm_log_args(argc, argv); /* Too much? */
                break;
            case 'Q':
            case 'B':
            case 'R':
            case 'D':
            case 'U':
            case 'v':
                command = flag;
                attr_value = optarg;
                crm_log_args(argc, argv); /* Too much? */
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (command != 'R' && attr_name == NULL) {
        ++argerr;
    }

    if (argerr) {
        cleanup_memory();
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    if (command == 'Q') {
        exit_code = crm_errno2exit(do_query(attr_name, attr_node, query_all));
    } else {
        /* @TODO We don't know whether the specified node is a Pacemaker Remote
         * node or not, so we can't set pcmk__node_attr_remote when appropriate.
         * However, it's not a big problem, because pacemaker-attrd will learn
         * and remember a node's "remoteness".
         */
        const char *target = pcmk__node_attr_target(attr_node);

        exit_code = pcmk_rc2exitc(do_update(command,
                                            target == NULL ? attr_node : target,
                                            attr_name, attr_value,
                                            attr_section, attr_set,
                                            attr_dampen, attr_options));
    }

    cleanup_memory();
    crm_exit(exit_code);
}

/*!
 * \internal
 * \brief Submit a query request to pacemaker-attrd and wait for reply
 *
 * \param[in] name    Name of attribute to query
 * \param[in] host    Query applies to this host only (or all hosts if NULL)
 * \param[out] reply  On success, will be set to new XML tree with reply
 *
 * \return pcmk_ok on success, -errno on error
 * \note On success, caller is responsible for freeing result via free_xml(*reply)
 */
static int
send_attrd_query(const char *name, const char *host, xmlNode **reply)
{
    int rc;
    crm_ipc_t *ipc;
    xmlNode *query;

    /* Build the query XML */
    query = create_xml_node(NULL, __func__);
    if (query == NULL) {
        return -ENOMEM;
    }
    crm_xml_add(query, F_TYPE, T_ATTRD);
    crm_xml_add(query, F_ORIG, crm_system_name);
    crm_xml_add(query, PCMK__XA_ATTR_NODE_NAME, host);
    crm_xml_add(query, PCMK__XA_TASK, PCMK__ATTRD_CMD_QUERY);
    crm_xml_add(query, PCMK__XA_ATTR_NAME, name);

    /* Connect to pacemaker-attrd, send query XML and get reply */
    crm_debug("Sending query for value of %s on %s", name, (host? host : "all nodes"));
    ipc = crm_ipc_new(T_ATTRD, 0);
    if (crm_ipc_connect(ipc) == FALSE) {
        crm_perror(LOG_ERR, "Connection to cluster attribute manager failed");
        rc = -ENOTCONN;
    } else {
        rc = crm_ipc_send(ipc, query, crm_ipc_client_response, 0, reply);
        if (rc > 0) {
            rc = pcmk_ok;
        }
        crm_ipc_close(ipc);
    }
    crm_ipc_destroy(ipc);

    free_xml(query);
    return(rc);
}

/*!
 * \brief Validate pacemaker-attrd's XML reply to an query
 *
 * param[in] reply      Root of reply XML tree to validate
 * param[in] attr_name  Name of attribute that was queried
 *
 * \return pcmk_ok on success,
 *         -errno on error (-ENXIO = requested attribute does not exist)
 */
static int
validate_attrd_reply(xmlNode *reply, const char *attr_name)
{
    const char *reply_attr;

    if (reply == NULL) {
        fprintf(stderr, "Could not query value of %s: reply did not contain valid XML\n",
                attr_name);
        return -pcmk_err_schema_validation;
    }
    crm_log_xml_trace(reply, "Reply");

    reply_attr = crm_element_value(reply, PCMK__XA_ATTR_NAME);
    if (reply_attr == NULL) {
        fprintf(stderr, "Could not query value of %s: attribute does not exist\n",
                attr_name);
        return -ENXIO;
    }

    if (!pcmk__str_eq(crm_element_value(reply, F_TYPE), T_ATTRD, pcmk__str_casei)
        || (crm_element_value(reply, PCMK__XA_ATTR_VERSION) == NULL)
        || strcmp(reply_attr, attr_name)) {
            fprintf(stderr,
                    "Could not query value of %s: reply did not contain expected identification\n",
                    attr_name);
            return -pcmk_err_schema_validation;
    }
    return pcmk_ok;
}

/*!
 * \brief Print the attribute values in a pacemaker-attrd XML query reply
 *
 * \param[in] reply     Root of XML tree with query reply
 * \param[in] attr_name Name of attribute that was queried
 *
 * \return TRUE if any values were printed
 */
static gboolean
print_attrd_values(xmlNode *reply, const char *attr_name)
{
    xmlNode *child;
    const char *reply_host, *reply_value;
    gboolean have_values = FALSE;

    /* Iterate through reply's XML tags (a node tag for each host-value pair) */
    for (child = pcmk__xml_first_child(reply); child != NULL;
         child = pcmk__xml_next(child)) {

        if (!pcmk__str_eq((const char *)child->name, XML_CIB_TAG_NODE,
                          pcmk__str_casei)) {
            crm_warn("Ignoring unexpected %s tag in query reply", child->name);
        } else {
            reply_host = crm_element_value(child, PCMK__XA_ATTR_NODE_NAME);
            reply_value = crm_element_value(child, PCMK__XA_ATTR_VALUE);

            if (reply_host == NULL) {
                crm_warn("Ignoring %s tag without %s attribute in query reply",
                         XML_CIB_TAG_NODE, PCMK__XA_ATTR_NODE_NAME);
            } else {
                printf("name=\"%s\" host=\"%s\" value=\"%s\"\n",
                       attr_name, reply_host, (reply_value? reply_value : ""));
                have_values = TRUE;
            }
        }
    }
    return have_values;
}

/*!
 * \brief Submit a query to pacemaker-attrd and print reply
 *
 * \param[in] attr_name  Name of attribute to be affected by request
 * \param[in] attr_node  Name of host to query for (or NULL for localhost)
 * \param[in] query_all  If TRUE, ignore attr_node and query all nodes instead
 *
 * \return pcmk_ok on success, -errno on error
 */
static int
do_query(const char *attr_name, const char *attr_node, gboolean query_all)
{
    xmlNode *reply = NULL;
    int rc;

    /* Decide which node(s) to query */
    if (query_all == TRUE) {
        attr_node = NULL;
    } else {
        const char *target = pcmk__node_attr_target(attr_node);
        if (target != NULL) {
            attr_node = target;
        }
    }

    /* Build and send pacemaker-attrd request, and get XML reply */
    rc = send_attrd_query(attr_name, attr_node, &reply);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not query value of %s: %s (%d)\n", attr_name, pcmk_strerror(rc), rc);
        return rc;
    }

    /* Validate the XML reply */
    rc = validate_attrd_reply(reply, attr_name);
    if (rc != pcmk_ok) {
        if (reply != NULL) {
            free_xml(reply);
        }
        return rc;
    }

    /* Print the values from the reply */
    if (print_attrd_values(reply, attr_name) == FALSE) {
        fprintf(stderr,
                "Could not query value of %s: reply had attribute name but no host values\n",
                attr_name);
        free_xml(reply);
        return -pcmk_err_schema_validation;
    }

    return pcmk_ok;
}

static int
do_update(char command, const char *attr_node, const char *attr_name,
          const char *attr_value, const char *attr_section,
          const char *attr_set, const char *attr_dampen, int attr_options)
{
    int rc = pcmk__node_attr_request(NULL, command, attr_node, attr_name,
                                     attr_value, attr_section, attr_set,
                                     attr_dampen, NULL, attr_options);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Could not update %s=%s: %s (%d)\n",
                attr_name, attr_value, pcmk_rc_str(rc), rc);
    }
    return rc;
}
