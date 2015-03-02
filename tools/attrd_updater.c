
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>

#include <crm/attrd.h>

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output\n"},

    {"name",    1, 0, 'n', "The attribute's name"},

    {"-spacer-",1, 0, '-', "\nCommands:"},
    {"update",  1, 0, 'U', "Update the attribute's value in attrd.  If this causes the value to change, it will also be updated in the cluster configuration"},
#ifdef HAVE_ATOMIC_ATTRD
    {"query",   0, 0, 'Q', "\tQuery the attribute's value from attrd"},
#endif
    {"delete",  0, 0, 'D', "\tDelete the attribute in attrd.  If a value was previously set, it will also be removed from the cluster configuration"},
    {"refresh", 0, 0, 'R', "\t(Advanced) Force the attrd daemon to resend all current values to the CIB\n"},    
    
    {"-spacer-",1, 0, '-', "\nAdditional options:"},
    {"delay",   1, 0, 'd', "The time to wait (dampening) in seconds for further changes before writing"},
    {"set",     1, 0, 's', "(Advanced) The attribute set in which to place the value"},
    {"node",    1, 0, 'N', "Set the attribute for the named node (instead of the local one)"},
#ifdef HAVE_ATOMIC_ATTRD
    {"all",     0, 0, 'A', "Show values of the attribute for all nodes (query only)"},
    /* lifetime could be implemented for atomic attrd if there is sufficient user demand */
    {"lifetime",1, 0, 'l', "(Deprecated) Lifetime of the node attribute (silently ignored by cluster)"},
    {"private", 0, 0, 'p', "\tIf this creates a new attribute, never write the attribute to the CIB"},
#else
    {"lifetime",1, 0, 'l', "Lifetime of the node attribute.  Allowed values: forever, reboot"},
#endif

    /* Legacy options */
    {"quiet",   0, 0, 'q', NULL, pcmk_option_hidden},
    {"update",  1, 0, 'v', NULL, pcmk_option_hidden},
    {"section", 1, 0, 'S', NULL, pcmk_option_hidden},
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static int do_query(const char *attr_name, const char *attr_node, gboolean query_all);
static int do_update(char command, const char *attr_node, const char *attr_name,
                     const char *attr_value, const char *attr_section,
                     const char *attr_set, const char *attr_dampen, int attr_options);

int
main(int argc, char **argv)
{
    int index = 0;
    int argerr = 0;
    int attr_options = attrd_opt_none;
    int flag;
    const char *attr_node = NULL;
    const char *attr_name = NULL;
    const char *attr_value = NULL;
    const char *attr_set = NULL;
    const char *attr_section = NULL;
    const char *attr_dampen = NULL;
    char command = 'Q';

#ifdef HAVE_ATOMIC_ATTRD
    gboolean query_all = FALSE;
#endif

    crm_log_cli_init("attrd_updater");
    crm_set_options(NULL, "command -n attribute [options]", long_options,
                    "Tool for updating cluster node attributes");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                crm_help(flag, EX_OK);
                break;
            case 'n':
                attr_name = strdup(optarg);
                break;
            case 's':
                attr_set = strdup(optarg);
                break;
            case 'd':
                attr_dampen = strdup(optarg);
                break;
            case 'l':
            case 'S':
                attr_section = strdup(optarg);
                break;
            case 'N':
                attr_node = strdup(optarg);
                break;
#ifdef HAVE_ATOMIC_ATTRD
            case 'A':
                query_all = TRUE;
            case 'p':
                set_bit(attr_options, attrd_opt_private);
                break;
#endif
            case 'q':
                break;
#ifdef HAVE_ATOMIC_ATTRD
            case 'Q':
#endif
            case 'R':
            case 'D':
            case 'U':
            case 'v':
                command = flag;
                attr_value = optarg;
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
        crm_help('?', EX_USAGE);
    }

    if (command == 'Q') {
#ifdef HAVE_ATOMIC_ATTRD
        crm_exit(do_query(attr_name, attr_node, query_all));
#else
        crm_help('?', EX_USAGE);
#endif
    } else {
        crm_exit(do_update(command, attr_node, attr_name, attr_value,
                           attr_section, attr_set, attr_dampen, attr_options));
    }
    return crm_exit(pcmk_ok);
}

/*!
 * \internal
 * \brief Submit a query request to attrd and wait for reply
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
    query = create_xml_node(NULL, __FUNCTION__);
    if (query == NULL) {
        return -ENOMEM;
    }
    crm_xml_add(query, F_TYPE, T_ATTRD);
    crm_xml_add(query, F_ORIG, crm_system_name);
    crm_xml_add(query, F_ATTRD_HOST, host);
    crm_xml_add(query, F_ATTRD_TASK, ATTRD_OP_QUERY);
    crm_xml_add(query, F_ATTRD_ATTRIBUTE, name);

    /* Connect to attrd, send query XML and get reply */
    crm_debug("Sending query for value of %s on %s", name, (host? host : "all nodes"));
    ipc = crm_ipc_new(T_ATTRD, 0);
    if (crm_ipc_connect(ipc) == FALSE) {
        rc = -ENOTCONN;
    } else {
        rc = crm_ipc_send(ipc, query, crm_ipc_flags_none|crm_ipc_client_response, 0, reply);
        if (rc > 0) {
            rc = pcmk_ok;
        }
        crm_ipc_close(ipc);
    }

    free_xml(query);
    return(rc);
}

/*!
 * \brief Validate attrd's XML reply to an query
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

    reply_attr = crm_element_value(reply, F_ATTRD_ATTRIBUTE);
    if (reply_attr == NULL) {
        fprintf(stderr, "Could not query value of %s: attribute does not exist\n",
                attr_name);
        return -ENXIO;
    }

    if (safe_str_neq(crm_element_value(reply, F_TYPE), T_ATTRD)
        || (crm_element_value(reply, F_ATTRD_VERSION) == NULL)
        || strcmp(reply_attr, attr_name)) {
            fprintf(stderr,
                    "Could not query value of %s: reply did not contain expected identification\n",
                    attr_name);
            return -pcmk_err_schema_validation;
    }
    return pcmk_ok;
}

/*!
 * \brief Print the attribute values in an attrd XML query reply
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
    for (child = __xml_first_child(reply); child != NULL; child = __xml_next(child)) {
        if (safe_str_neq((const char*)child->name, XML_CIB_TAG_NODE)) {
            crm_warn("Ignoring unexpected %s tag in query reply", child->name);
        } else {
            reply_host = crm_element_value(child, F_ATTRD_HOST);
            reply_value = crm_element_value(child, F_ATTRD_VALUE);

            if (reply_host == NULL) {
                crm_warn("Ignoring %s tag without %s attribute in query reply",
                         XML_CIB_TAG_NODE, F_ATTRD_HOST);
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
 * \brief Submit a query to attrd and print reply
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
    } else if (attr_node == NULL) {
        crm_debug("User did not specify node for query, using localhost");
        attr_node = "localhost";
    }

    /* Build and send attrd request, and get XML reply */
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
    int rc = attrd_update_delegate(NULL, command, attr_node, attr_name,
                                   attr_value, attr_section, attr_set,
                                   attr_dampen, NULL, attr_options);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not update %s=%s: %s (%d)\n", attr_name, attr_value, pcmk_strerror(rc), rc);
    }
    return rc;
}
