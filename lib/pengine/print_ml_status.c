/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#include <crm/pengine/print_ml_status.h>

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <crm/pengine/internal.h>
#include <unpack.h>

/* Never display node attributes whose name starts with one of these prefixes */
#define FILTER_STR { CRM_FAIL_COUNT_PREFIX, CRM_LAST_FAILURE_PREFIX,       \
                     "shutdown", "terminate", "standby", "probe_complete", \
                     "#", NULL }

static GList *attr_list;
static struct print_params_t pp;

/*!
 * \internal
 * \brief Print cluster status in XML format
 *
 * \param[in] data_set   Working set of CIB state
 */
void print_xml_status(FILE *stream, pe_working_set_t * data_set, stonith_history_t *stonith_history
                      , struct print_params_t print_params)
{
    GListPtr gIter = NULL;
    int print_opts = get_resource_display_options();

    pp = print_params;
    fprintf(stream, "<?xml version=\"1.0\"?>\n");
    fprintf(stream, "<crm_mon version=\"%s\">\n", VERSION);

    print_cluster_summary(stream, data_set);

    /*** NODES ***/
    fprintf(stream, "    <nodes>\n");
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;
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

        if (pp.group_by_node) {
            GListPtr lpc2 = NULL;

            fprintf(stream, ">\n");
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                pe_resource_t *rsc = (pe_resource_t *) lpc2->data;

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

    /* Print stonith history */
    if (pp.fence_history) {
        print_stonith_history(stdout, stonith_history);
    }

    /* Print tickets if requested */
    if (pp.show & mon_show_tickets) {
        print_cluster_tickets(stream, data_set);
    }

    /* Print negative location constraints if requested */
    if (pp.show & mon_show_bans) {
        print_neg_locations(stream, data_set);
    }

    fprintf(stream, "</crm_mon>\n");
    fflush(stream);
    fclose(stream);
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
print_rsc_history_start(FILE *stream, pe_working_set_t *data_set, pe_node_t *node,
                             pe_resource_t *rsc, const char *rsc_id, gboolean all)
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
print_op_history(FILE *stream, pe_working_set_t *data_set, pe_node_t *node,
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
    if (pp.print_timing) {
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
print_rsc_history(FILE *stream, pe_working_set_t *data_set, pe_node_t *node,
                  xmlNode *rsc_entry, gboolean operations)
{
    GListPtr gIter = NULL;
    GListPtr op_list = NULL;
    gboolean printed = FALSE;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
    pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);
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
char* get_node_display_name(pe_node_t *node)
{
    char *node_name;
    const char *node_host = NULL;
    const char *node_id = NULL;
    int name_len;

    CRM_ASSERT((node != NULL) && (node->details != NULL) && (node->details->uname != NULL));

    /* Host is displayed only if this is a guest node */
    if (is_container_remote_node(node)) {
        pe_node_t *host_node = pe__current_node(node->details->remote_rsc);

        if (host_node && host_node->details) {
            node_host = host_node->details->uname;
        }
        if (node_host == NULL) {
            node_host = ""; /* so we at least get "uname@" to indicate guest */
        }
    }

    /* Node ID is displayed if different from uname and detail is requested */
    if (pp.print_clone_detail && safe_str_neq(node->details->uname, node->details->id)) {
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
 * \brief Print whatever is needed to start a node section
 *
 * \param[in] stream     File stream to display output to
 * \param[in] node       Node to print
 */
static void
print_node_start(FILE *stream, pe_node_t *node)
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

    if (pp.group_by_node) {

        /* Active resources have already been printed by node */
        heading = (pp.inactive_resources? "Inactive resources" : NULL);

    } else if (pp.inactive_resources) {
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
    if (pp.group_by_node) {
        heading = "inactive ";
    } else if (pp.inactive_resources) {
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
void print_resources(FILE *stream, pe_working_set_t *data_set, int print_opts)
{
    GListPtr rsc_iter;
    const char *prefix = NULL;
    gboolean printed_heading = FALSE;
    gboolean brief_output = pp.print_brief;

    /* If we already showed active resources by node, and
     * we're not showing inactive resources, we have nothing to do
     */
    if (pp.group_by_node && !pp.inactive_resources) {
        return;
    }

    /* XML uses an indent, and ignores brief option for resources */
    if (output_format == mon_output_xml) {
        prefix = "        ";
        brief_output = FALSE;
    }

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (brief_output && !pp.group_by_node) {
        print_resources_heading(stream);
        printed_heading = TRUE;
        print_rscs_brief(data_set->resources, NULL, print_opts, stream,
                         pp.inactive_resources);
    }

    /* For each resource, display it if appropriate */
    for (rsc_iter = data_set->resources; rsc_iter != NULL; rsc_iter = rsc_iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) rsc_iter->data;

        /* Complex resources may have some sub-resources active and some inactive */
        gboolean is_active = rsc->fns->active(rsc, TRUE);
        gboolean partially_active = rsc->fns->active(rsc, FALSE);

        /* Skip inactive orphans (deleted but still in CIB) */
        if (is_set(rsc->flags, pe_rsc_orphan) && !is_active) {
            continue;

        /* Skip active resources if we already displayed them by node */
        } else if (pp.group_by_node) {
            if (is_active) {
                continue;
            }

        /* Skip primitives already counted in a brief summary */
        } else if (brief_output && (rsc->variant == pe_native)) {
            continue;

        /* Skip resources that aren't at least partially active,
         * unless we're displaying inactive resources
         */
        } else if (!partially_active && !pp.inactive_resources) {
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
    pe_node_t *node = pe_find_node_id(data_set->nodes, ID(node_state));
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

void print_node_summary(FILE *stream, pe_working_set_t * data_set, gboolean operations)
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

int count_resources(pe_working_set_t * data_set, pe_resource_t * rsc)
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
    pe_node_t *dc = data_set->dc_node;
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
void print_cluster_summary(FILE *stream, pe_working_set_t *data_set)
{
    const char *stack_s = get_cluster_stack(data_set);
    gboolean header_printed = FALSE;

    if (pp.show & mon_show_stack) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_stack(stream, stack_s);
    }

    /* Always print DC if none, even if not requested */
    if ((data_set->dc_node == NULL) || (pp.show & mon_show_dc)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_dc(stream, data_set);
    }

    if (pp.show & mon_show_times) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_times(stream, data_set);
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)
        || data_set->disabled_resources
        || data_set->blocked_resources
        || is_set(pp.show, mon_show_count)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(stream);
            header_printed = TRUE;
        }
        print_cluster_counts(stream, data_set, stack_s);
    }

    /* There is not a separate option for showing cluster options, so show with
     * stack for now; a separate option could be added if there is demand
     */
    if (pp.show & mon_show_stack) {
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
void print_failed_actions(FILE *stream, pe_working_set_t *data_set)
{
    xmlNode *xml_op = NULL;

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nFailed Resource Actions:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream,
                    " <hr />\n <h2>Failed Resource Actions</h2>\n <ul>\n");
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
 * \brief Return resource display options corresponding to command-line choices
 *
 * \return Bitmask of pe_print_options suitable for resource print functions
 */
int get_resource_display_options(void)
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
    if (pp.print_pending) {
        print_opts |= pe_print_pending;
    }
    if (pp.print_clone_detail) {
        print_opts |= pe_print_clone_details|pe_print_implicit;
    }
    if (!pp.inactive_resources) {
        print_opts |= pe_print_clone_active;
    }
    if (pp.print_brief) {
        print_opts |= pe_print_brief;
    }
    return print_opts;
}

static void
crm_mon_get_parameters(pe_resource_t *rsc, pe_working_set_t * data_set)
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

static int
compare_attribute(gconstpointer a, gconstpointer b)
{
    int rc;

    rc = strcmp((const char *)a, (const char *)b);

    return rc;
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
print_attr_msg(FILE *stream, pe_node_t * node, GListPtr rsc_list, const char *attrname, const char *attrvalue)
{
    GListPtr gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;
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

/* structure for passing multiple user data to g_list_foreach() */
struct mon_attr_data {
    FILE *stream;
    pe_node_t *node;
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

/*!
 * \internal
 * \brief Print node attributes section
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
void print_node_attributes(FILE *stream, pe_working_set_t *data_set)
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
        data.node = (pe_node_t *) gIter->data;

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
 * \brief Turn stonith action into a better readable string
 *
 * \param[in] action     Stonith action
 */
static char *
fence_action_str(const char *action)
{
    char *str = NULL;

    if (action == NULL) {
        str = strdup("fencing");
    } else if (!strcmp(action, "on")) {
        str = strdup("unfencing");
    } else if (!strcmp(action, "off")) {
        str = strdup("turning off");
    } else {
        str = strdup(action);
    }
    return str;
}

/*!
 * \internal
 * \brief Print a stonith action
 *
 * \param[in] stream     File stream to display output to
 * \param[in] event      stonith event
 */
void print_stonith_action(FILE *stream, stonith_history_t *event)
{
    char *action_s = fence_action_str(event->action);
    char *run_at_s = ctime(&event->completed);

    if ((run_at_s) && (run_at_s[0] != 0)) {
        run_at_s[strlen(run_at_s)-1] = 0; /* Overwrite the newline */
    }

    switch(output_format) {
        case mon_output_xml:
            fprintf(stream, "        <fence_event target=\"%s\" action=\"%s\"",
                    event->target, event->action);
            switch(event->state) {
                case st_done:
                    fprintf(stream, " state=\"success\"");
                    break;
                case st_failed:
                    fprintf(stream, " state=\"failed\"");
                    break;
                default:
                    fprintf(stream, " state=\"pending\"");
            }
            fprintf(stream, " origin=\"%s\" client=\"%s\"",
                    event->origin, event->client);
            if (event->delegate) {
                fprintf(stream, " delegate=\"%s\"", event->delegate);
            }
            switch(event->state) {
                case st_done:
                case st_failed:
                    fprintf(stream, " completed=\"%s\"", run_at_s?run_at_s:"");
                    break;
                default:
                    break;
            }
            fprintf(stream, " />\n");
            break;

        case mon_output_plain:
        case mon_output_console:
            switch(event->state) {
                case st_done:
                    print_as("* %s of %s successful: delegate=%s, client=%s, origin=%s,\n"
                             "    %s='%s'\n",
                             action_s, event->target,
                             event->delegate ? event->delegate : "",
                             event->client, event->origin,
                             pp.fence_full_history?"completed":"last-successful",
                             run_at_s?run_at_s:"");
                    break;
                case st_failed:
                    print_as("* %s of %s failed: delegate=%s, client=%s, origin=%s,\n"
                             "    %s='%s'\n",
                             action_s, event->target,
                             event->delegate ? event->delegate : "",
                             event->client, event->origin,
                             pp.fence_full_history?"completed":"last-failed",
                             run_at_s?run_at_s:"");
                    break;
                default:
                    print_as("* %s of %s pending: client=%s, origin=%s\n",
                             action_s, event->target,
                             event->client, event->origin);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            switch(event->state) {
                case st_done:
                    fprintf(stream, "  <li>%s of %s successful: delegate=%s, "
                                    "client=%s, origin=%s, %s='%s'</li>\n",
                                    action_s, event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    pp.fence_full_history?"completed":"last-successful",
                                    run_at_s?run_at_s:"");
                    break;
                case st_failed:
                    fprintf(stream, "  <li>%s of %s failed: delegate=%s, "
                                    "client=%s, origin=%s, %s='%s'</li>\n",
                                    action_s, event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    pp.fence_full_history?"completed":"last-failed",
                                    run_at_s?run_at_s:"");
                    break;
                default:
                    fprintf(stream, "  <li>%s of %s pending: client=%s, "
                                    "origin=%s</li>\n",
                                    action_s, event->target,
                                    event->client, event->origin);
            }
            break;

        default:
            /* no support for fence history for other formats so far */
            break;
    }

    free(action_s);
}

/*!
 * \internal
 * \brief Print a section for stonith-history
 *
 * \param[in] stream     File stream to display output to
 * \param[in] history    List of stonith actions
 *
 */
void print_stonith_history(FILE *stream, stonith_history_t *history)
{
    stonith_history_t *hp;

    /* Print section heading */
    switch (output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as("\nFencing History:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " <hr />\n <h2>Fencing History</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    <fence_history>\n");
            break;

        default:
            break;
    }

    for (hp = history; hp; hp = hp->next) {
        if ((hp->state != st_failed) || (output_format == mon_output_xml)) {
            print_stonith_action(stream, hp);
        }
    }

    /* End section */
    switch (output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(stream, "    </fence_history>\n");
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

void print_cluster_tickets(FILE *stream, pe_working_set_t * data_set)
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
 * \brief Print a negative location constraint
 *
 * \param[in] stream     File stream to display output to
 * \param[in] node       Node affected by constraint
 * \param[in] location   Constraint to print
 */
static void
print_ban(FILE *stream, pe_node_t *node, pe__location_t *location)
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
void print_neg_locations(FILE *stream, pe_working_set_t *data_set)
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
        pe__location_t *location = gIter->data;
        if (!g_str_has_prefix(location->id, pp.print_neg_location_prefix))
            continue;
        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_node_t *node = (pe_node_t *) gIter2->data;

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
