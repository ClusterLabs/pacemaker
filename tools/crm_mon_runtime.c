/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/curses_internal.h>
#include <crm/pengine/common.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>
#include <crm/common/internal.h>
#include <crm/common/util.h>

#include "crm_mon.h"

void
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

static int
compare_attribute(gconstpointer a, gconstpointer b)
{
    int rc;

    rc = strcmp((const char *)a, (const char *)b);

    return rc;
}

GList *
append_attr_list(GList *attr_list, char *name)
{
    int i;
    const char *filt_str[] = FILTER_STR;

    CRM_CHECK(name != NULL, return attr_list);

    /* filtering automatic attributes */
    for (i = 0; filt_str[i] != NULL; i++) {
        if (g_str_has_prefix(name, filt_str[i])) {
            return attr_list;
        }
    }

    return g_list_insert_sorted(attr_list, name, compare_attribute);
}

void
crm_mon_get_parameters(resource_t *rsc, pe_working_set_t * data_set)
{
    get_rsc_attributes(rsc->parameters, rsc, NULL, data_set);
    if(rsc->children) {
        GListPtr gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            crm_mon_get_parameters(gIter->data, data_set);
        }
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
const char *
get_cluster_stack(pe_working_set_t *data_set)
{
    xmlNode *stack = get_xpath_object("//nvpair[@name='cluster-infrastructure']",
                                      data_set->input, LOG_DEBUG);
    return stack? crm_element_value(stack, XML_NVPAIR_ATTR_VALUE) : "unknown";
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
char *
get_node_display_name(node_t *node, unsigned int mon_ops)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node */
    if (pe__is_guest_node(node)) {
        node_t *host_node = pe__current_node(node->details->remote_rsc);

        if (host_node && host_node->details) {
            node_host = host_node->details->uname;
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (is_set(mon_ops, mon_op_print_clone_detail) && safe_str_neq(node->details->uname, node->details->id)) {
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
 * \brief Return resource display options corresponding to command-line choices
 *
 * \return Bitmask of pe_print_options suitable for resource print functions
 */
int
get_resource_display_options(unsigned int mon_ops, mon_output_format_t output_format)
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
    if (is_set(mon_ops, mon_op_print_pending)) {
        print_opts |= pe_print_pending;
    }
    if (is_set(mon_ops, mon_op_print_clone_detail)) {
        print_opts |= pe_print_clone_details|pe_print_implicit;
    }
    if (is_not_set(mon_ops, mon_op_inactive_resources)) {
        print_opts |= pe_print_clone_active;
    }
    if (is_set(mon_ops, mon_op_print_brief)) {
        print_opts |= pe_print_brief;
    }
    return print_opts;
}
