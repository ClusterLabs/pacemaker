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
#include <time.h>

#include <config.h>
#include <crm/cib/util.h>
#include <crm/common/curses_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>
#include <crm/common/internal.h>
#include <crm/common/util.h>
#include <crm/fencing/internal.h>

#include "crm_mon.h"

static void print_node_start(mon_state_t *state, node_t *node, unsigned int mon_ops);
static void print_node_end(mon_state_t *state);
static void print_resources_heading(mon_state_t *state, unsigned int mon_ops);
static void print_resources_closing(mon_state_t *state, gboolean printed_heading,
                                    unsigned int mon_ops);
static void print_resources(mon_state_t *state, pe_working_set_t *data_set,
                            int print_opts, unsigned int mon_ops);
static void print_rsc_history_start(mon_state_t *state, pe_working_set_t *data_set,
                                    node_t *node, resource_t *rsc, const char *rsc_id,
                                    gboolean all);
static void print_rsc_history_end(mon_state_t *state);
static void print_op_history(mon_state_t *state, pe_working_set_t *data_set,
                             node_t *node, xmlNode *xml_op, const char *task,
                             const char *interval_ms_s, int rc, unsigned int mon_ops);
static void print_rsc_history(mon_state_t *state, pe_working_set_t *data_set,
                              node_t *node, xmlNode *rsc_entry, gboolean operations,
                              unsigned int mon_ops);
static void print_node_history(mon_state_t *state, pe_working_set_t *data_set,
                               xmlNode *node_state, gboolean operations,
                               unsigned int mon_ops);
static gboolean print_attr_msg(mon_state_t *state, node_t * node, GListPtr rsc_list,
                               const char *attrname, const char *attrvalue);
static void print_node_attribute(gpointer name, gpointer user_data);
static void print_node_summary(mon_state_t *state, pe_working_set_t * data_set,
                               gboolean operations, unsigned int mon_ops);
static void print_ticket(gpointer name, gpointer value, gpointer user_data);
static void print_cluster_tickets(mon_state_t *state, pe_working_set_t * data_set);
static void print_ban(mon_state_t *state, pe_node_t *node, pe__location_t *location,
                      unsigned int mon_ops);
static void print_neg_locations(mon_state_t *state, pe_working_set_t *data_set,
                                unsigned int mon_ops, const char *prefix);
static void print_node_attributes(mon_state_t *state, pe_working_set_t *data_set,
                                  unsigned int mon_ops);
static void print_cluster_summary_header(mon_state_t *state);
static void print_cluster_summary_footer(mon_state_t *state);
static void print_cluster_times(mon_state_t *state, pe_working_set_t *data_set);
static void print_cluster_stack(mon_state_t *state, const char *stack_s);
static void print_cluster_dc(mon_state_t *state, pe_working_set_t *data_set,
                             unsigned int mon_ops);
static void print_cluster_counts(mon_state_t *state, pe_working_set_t *data_set,
                                 const char *stack_s);
static void print_cluster_options(mon_state_t *state, pe_working_set_t *data_set);
static void print_cluster_summary(mon_state_t *state, pe_working_set_t *data_set,
                                  unsigned int mon_ops, unsigned int show);
static void print_failed_action(mon_state_t *state, xmlNode *xml_op);
static void print_failed_actions(mon_state_t *state, pe_working_set_t *data_set);
static void print_stonith_action(mon_state_t *state, stonith_history_t *event, unsigned int mon_ops, stonith_history_t *top_history);
static void print_failed_stonith_actions(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops);
static void print_stonith_pending(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops);
static void print_stonith_history(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops);

/*!
 * \internal
 * \brief Print whatever is needed to start a node section
 *
 * \param[in] stream     File stream to display output to
 * \param[in] node       Node to print
 */
static void
print_node_start(mon_state_t *state, node_t *node, unsigned int mon_ops)
{
    char *node_name;

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            node_name = get_node_display_name(node, mon_ops);
            print_as(state->output_format, "* Node %s:\n", node_name);
            free(node_name);
            break;

        case mon_output_html:
        case mon_output_cgi:
            node_name = get_node_display_name(node, mon_ops);
            fprintf(state->stream, "  <h3>Node: %s</h3>\n  <ul>\n", node_name);
            free(node_name);
            break;

        case mon_output_xml:
            fprintf(state->stream, "        <node name=\"%s\">\n", node->details->uname);
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
print_node_end(mon_state_t *state)
{
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "  </ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "        </node>\n");
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
print_resources_heading(mon_state_t *state, unsigned int mon_ops)
{
    const char *heading;

    if (is_set(mon_ops, mon_op_group_by_node)) {

        /* Active resources have already been printed by node */
        heading = is_set(mon_ops, mon_op_inactive_resources) ? "Inactive resources" : NULL;

    } else if (is_set(mon_ops, mon_op_inactive_resources)) {
        heading = "Full list of resources";

    } else {
        heading = "Active resources";
    }

    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\n%s:\n\n", heading);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>%s</h2>\n", heading);
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <resources>\n");
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
print_resources_closing(mon_state_t *state, gboolean printed_heading,
                        unsigned int mon_ops)
{
    const char *heading;

    /* What type of resources we did or did not display */
    if (is_set(mon_ops, mon_op_group_by_node)) {
        heading = "inactive ";
    } else if (is_set(mon_ops, mon_op_inactive_resources)) {
        heading = "";
    } else {
        heading = "active ";
    }

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (!printed_heading) {
                print_as(state->output_format, "\nNo %sresources\n\n", heading);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            if (!printed_heading) {
                fprintf(state->stream, " <hr />\n <h2>No %sresources</h2>\n", heading);
            }
            break;

        case mon_output_xml:
            fprintf(state->stream, "    %s\n",
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
print_resources(mon_state_t *state, pe_working_set_t *data_set,
                int print_opts, unsigned int mon_ops)
{
    GListPtr rsc_iter;
    const char *prefix = NULL;
    gboolean printed_heading = FALSE;
    gboolean brief_output = is_set(mon_ops, mon_op_print_brief);

    /* If we already showed active resources by node, and
     * we're not showing inactive resources, we have nothing to do
     */
    if (is_set(mon_ops, mon_op_group_by_node) && is_not_set(mon_ops, mon_op_inactive_resources)) {
        return;
    }

    /* XML uses an indent, and ignores brief option for resources */
    if (state->output_format == mon_output_xml) {
        prefix = "        ";
        brief_output = FALSE;
    }

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (brief_output && is_not_set(mon_ops, mon_op_group_by_node)) {
        print_resources_heading(state, mon_ops);
        printed_heading = TRUE;
        print_rscs_brief(data_set->resources, NULL, print_opts, state->stream,
                         is_set(mon_ops, mon_op_inactive_resources));
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
        } else if (is_set(mon_ops, mon_op_group_by_node)) {
            if (is_active) {
                continue;
            }

        /* Skip primitives already counted in a brief summary */
        } else if (brief_output && (rsc->variant == pe_native)) {
            continue;

        /* Skip resources that aren't at least partially active,
         * unless we're displaying inactive resources
         */
        } else if (!partially_active && is_not_set(mon_ops, mon_op_inactive_resources)) {
            continue;
        }

        /* Print this resource */
        if (printed_heading == FALSE) {
            print_resources_heading(state, mon_ops);
            printed_heading = TRUE;
        }
        rsc->fns->print(rsc, prefix, print_opts, state->stream);
    }

    print_resources_closing(state, printed_heading, mon_ops);
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
print_rsc_history_start(mon_state_t *state, pe_working_set_t *data_set,
                        node_t *node, resource_t *rsc, const char *rsc_id,
                        gboolean all)
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
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "   %s:", rsc_id);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "   <li>%s:", rsc_id);
            break;

        case mon_output_xml:
            fprintf(state->stream, "            <resource_history id=\"%s\"", rsc_id);
            break;

        default:
            break;
    }

    /* If resource is an orphan, that's all we can say about it */
    if (rsc == NULL) {
        switch (state->output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(state->output_format, " orphan");
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(state->stream, " orphan");
                break;

            case mon_output_xml:
                fprintf(state->stream, " orphan=\"true\"");
                break;

            default:
                break;
        }

    /* If resource is not an orphan, print some details */
    } else if (all || failcount || (last_failure > 0)) {

        /* Print migration threshold */
        switch (state->output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(state->output_format, " migration-threshold=%d", rsc->migration_threshold);
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(state->stream, " migration-threshold=%d", rsc->migration_threshold);
                break;

            case mon_output_xml:
                fprintf(state->stream, " orphan=\"false\" migration-threshold=\"%d\"",
                        rsc->migration_threshold);
                break;

            default:
                break;
        }

        /* Print fail count if any */
        if (failcount > 0) {
            switch (state->output_format) {
                case mon_output_plain:
                case mon_output_console:
                    print_as(state->output_format, " " CRM_FAIL_COUNT_PREFIX "=%d", failcount);
                    break;

                case mon_output_html:
                case mon_output_cgi:
                    fprintf(state->stream, " " CRM_FAIL_COUNT_PREFIX "=%d", failcount);
                    break;

                case mon_output_xml:
                    fprintf(state->stream, " " CRM_FAIL_COUNT_PREFIX "=\"%d\"",
                            failcount);
                    break;

                default:
                    break;
            }
        }

        /* Print last failure time if any */
        if (last_failure > 0) {
            switch (state->output_format) {
                case mon_output_console:
                case mon_output_plain: {
                    char *time = pcmk_format_named_time(CRM_LAST_FAILURE_PREFIX, last_failure);
                    print_as(state->output_format, " %s", time);
                    free(time);
                    break;
                }

                case mon_output_cgi:
                case mon_output_html:
                case mon_output_xml: {
                    char *time = pcmk_format_named_time(CRM_LAST_FAILURE_PREFIX, last_failure);
                    fprintf(state->stream, " %s", time);
                    free(time);
                    break;
                }

                default:
                    break;
            }
        }
    }

    /* End the heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "\n    <ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, ">\n");
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
print_rsc_history_end(mon_state_t *state)
{
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "    </ul>\n   </li>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "            </resource_history>\n");
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
print_op_history(mon_state_t *state, pe_working_set_t *data_set, node_t *node,
                 xmlNode *xml_op, const char *task, const char *interval_ms_s,
                 int rc, unsigned int mon_ops)
{
    const char *value = NULL;
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);

    /* Begin the operation description */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "    + (%s) %s:", call, task);
            if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
                char *pair = pcmk_format_nvpair("interval", interval_ms_s, "ms");
                print_as(state->output_format, " %s", pair);
                free(pair);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "     <li>(%s) %s:", call, task);
            if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
                char *pair = pcmk_format_nvpair("interval", interval_ms_s, "ms");
                fprintf(state->stream, " %s", pair);
                free(pair);
            }
            break;

        case mon_output_xml:
            fprintf(state->stream, "                <operation_history call=\"%s\" task=\"%s\"",
                    call, task);
            if (interval_ms_s && safe_str_neq(interval_ms_s, "0")) {
                char *pair = pcmk_format_nvpair("interval", interval_ms_s, "ms");
                fprintf(state->stream, " %s", pair);
                free(pair);
            }
            break;

        default:
            break;
    }

    if (is_set(mon_ops, mon_op_print_timing)) {
        time_t epoch = 0;
        const char *attr;

        attr = XML_RSC_OP_LAST_CHANGE;
        if ((crm_element_value_epoch(xml_op, attr, &epoch) == pcmk_ok)
            && (epoch > 0)) {
            switch (state->output_format) {
                case mon_output_console:
                case mon_output_plain: {
                    char *time = pcmk_format_named_time(attr, epoch);
                    print_as(state->output_format, " %s", time);
                    free(time);
                    break;
                }

                case mon_output_cgi:
                case mon_output_html:
                case mon_output_xml: {
                    char *time = pcmk_format_named_time(attr, epoch);
                    fprintf(state->stream, " %s", time);
                    free(time);
                    break;
                }

                default:
                    break;
            }
        }

        // last-run is deprecated
        attr = XML_RSC_OP_LAST_RUN;
        if ((crm_element_value_epoch(xml_op, attr, &epoch) == pcmk_ok)
            && (epoch > 0)) {
            switch (state->output_format) {
                case mon_output_console:
                case mon_output_plain: {
                    char *time = pcmk_format_named_time(attr, epoch);
                    print_as(state->output_format, " %s", time);
                    free(time);
                    break;
                }

                case mon_output_cgi:
                case mon_output_html:
                case mon_output_xml: {
                    char *time = pcmk_format_named_time(attr, epoch);
                    fprintf(state->stream, " %s", time);
                    free(time);
                    break;
                }

                default:
                    break;
            }
        }

        attr = XML_RSC_OP_T_EXEC;
        value = crm_element_value(xml_op, attr);
        if (value) {
            switch (state->output_format) {
                case mon_output_console:
                case mon_output_plain: {
                    char *pair = pcmk_format_nvpair(attr, value, "ms");
                    print_as(state->output_format, " %s", pair);
                    free(pair);
                    break;
                }

                case mon_output_cgi:
                case mon_output_html:
                case mon_output_xml: {
                    char *pair = pcmk_format_nvpair(attr, value, "ms");
                    fprintf(state->stream, " %s", pair);
                    free(pair);
                    break;
                }

                default:
                    break;
            }
        }

        attr = XML_RSC_OP_T_QUEUE;
        value = crm_element_value(xml_op, attr);
        if (value) {
            switch (state->output_format) {
                case mon_output_console:
                case mon_output_plain: {
                    char *pair = pcmk_format_nvpair(attr, value, "ms");
                    print_as(state->output_format, " %s", pair);
                    free(pair);
                    break;
                }

                case mon_output_cgi:
                case mon_output_html:
                case mon_output_xml: {
                    char *pair = pcmk_format_nvpair(attr, value, "ms");
                    fprintf(state->stream, " %s", pair);
                    free(pair);
                    break;
                }

                default:
                    break;
            }
        }
    }

    /* End the operation description */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, " rc=%d (%s)\n", rc, services_ocf_exitcode_str(rc));
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " rc=%d (%s)</li>\n", rc, services_ocf_exitcode_str(rc));
            break;

        case mon_output_xml:
            fprintf(state->stream, " rc=\"%d\" rc_text=\"%s\" />\n", rc, services_ocf_exitcode_str(rc));
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
print_rsc_history(mon_state_t *state, pe_working_set_t *data_set, node_t *node,
                  xmlNode *rsc_entry, gboolean operations, unsigned int mon_ops)
{
    GListPtr gIter = NULL;
    GListPtr op_list = NULL;
    gboolean printed = FALSE;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);
    xmlNode *rsc_op = NULL;

    /* If we're not showing operations, just print the resource failure summary */
    if (operations == FALSE) {
        print_rsc_history_start(state, data_set, node, rsc, rsc_id, FALSE);
        print_rsc_history_end(state);
        return;
    }

    /* Create a list of this resource's operations */
    for (rsc_op = __xml_first_child_element(rsc_entry); rsc_op != NULL;
         rsc_op = __xml_next_element(rsc_op)) {
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
            print_rsc_history_start(state, data_set, node, rsc, rsc_id, TRUE);
        }

        /* Print the operation */
        print_op_history(state, data_set, node, xml_op, task, interval_ms_s, rc, mon_ops);
    }

    /* Free the list we created (no need to free the individual items) */
    g_list_free(op_list);

    /* If we printed anything, close the resource */
    if (printed) {
        print_rsc_history_end(state);
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
print_node_history(mon_state_t *state, pe_working_set_t *data_set,
                   xmlNode *node_state, gboolean operations,
                   unsigned int mon_ops)
{
    node_t *node = pe_find_node_id(data_set->nodes, ID(node_state));
    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;

    if (node && node->details && node->details->online) {
        print_node_start(state, node, mon_ops);

        lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
        lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

        /* Print history of each of the node's resources */
        for (rsc_entry = __xml_first_child_element(lrm_rsc); rsc_entry != NULL;
             rsc_entry = __xml_next_element(rsc_entry)) {

            if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {
                print_rsc_history(state, data_set, node, rsc_entry, operations, mon_ops);
            }
        }

        print_node_end(state);
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
print_attr_msg(mon_state_t *state, node_t * node, GListPtr rsc_list,
               const char *attrname, const char *attrvalue)
{
    GListPtr gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->meta, "type");

        if (rsc->children != NULL) {
            if (print_attr_msg(state, node, rsc->children, attrname, attrvalue)) {
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

                switch (state->output_format) {
                    case mon_output_plain:
                    case mon_output_console:
                        if (value <= 0) {
                            print_as(state->output_format, "\t: Connectivity is lost");
                        } else if (value < expected_score) {
                            print_as(state->output_format, "\t: Connectivity is degraded (Expected=%d)", expected_score);
                        }
                        break;

                    case mon_output_html:
                    case mon_output_cgi:
                        if (value <= 0) {
                            fprintf(state->stream, " <b>(connectivity is lost)</b>");
                        } else if (value < expected_score) {
                            fprintf(state->stream, " <b>(connectivity is degraded -- expected %d)</b>",
                                    expected_score);
                        }
                        break;

                    case mon_output_xml:
                        fprintf(state->stream, " expected=\"%d\"", expected_score);
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
    mon_state_t *state;
    node_t *node;
};

static void
print_node_attribute(gpointer name, gpointer user_data)
{
    const char *value = NULL;
    struct mon_attr_data *data = (struct mon_attr_data *) user_data;

    value = pe_node_attribute_raw(data->node, name);

    /* Print attribute name and value */
    switch (data->state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(data->state->output_format, "    + %-32s\t: %-10s", (char *)name, value);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(data->state->stream, "   <li>%s: %s",
                    (char *)name, value);
            break;

        case mon_output_xml:
            fprintf(data->state->stream,
                    "            <attribute name=\"%s\" value=\"%s\"",
                    (char *)name, value);
            break;

        default:
            break;
    }

    /* Print extended information if appropriate */
    print_attr_msg(data->state, data->node, data->node->details->running_rsc,
                   name, value);

    /* Close out the attribute */
    switch (data->state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(data->state->output_format, "\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(data->state->stream, "</li>\n");
            break;

        case mon_output_xml:
            fprintf(data->state->stream, " />\n");
            break;

        default:
            break;
    }
}

static void
print_node_summary(mon_state_t *state, pe_working_set_t * data_set,
                   gboolean operations, unsigned int mon_ops)
{
    xmlNode *node_state = NULL;
    xmlNode *cib_status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

    /* Print heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (operations) {
                print_as(state->output_format, "\nOperations:\n");
            } else {
                print_as(state->output_format, "\nMigration Summary:\n");
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            if (operations) {
                fprintf(state->stream, " <hr />\n <h2>Operations</h2>\n");
            } else {
                fprintf(state->stream, " <hr />\n <h2>Migration Summary</h2>\n");
            }
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <node_history>\n");
            break;

        default:
            break;
    }

    /* Print each node in the CIB status */
    for (node_state = __xml_first_child_element(cib_status); node_state != NULL;
         node_state = __xml_next_element(node_state)) {
        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            print_node_history(state, data_set, node_state, operations, mon_ops);
        }
    }

    /* Close section */
    switch (state->output_format) {
        case mon_output_xml:
            fprintf(state->stream, "    </node_history>\n");
            break;

        default:
            break;
    }
}

static void
print_ticket(gpointer name, gpointer value, gpointer user_data)
{
    mon_state_t *data = (mon_state_t *) user_data;
    ticket_t *ticket = (ticket_t *) value;

    switch (data->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(data->output_format, "* %s:\t%s%s", ticket->id,
                     (ticket->granted? "granted" : "revoked"),
                     (ticket->standby? " [standby]" : ""));
            if (ticket->last_granted > -1) {
                char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
                print_as(data->output_format, " %s\n", time);
                free(time);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(data->stream, "  <li>%s: %s%s", ticket->id,
                    (ticket->granted? "granted" : "revoked"),
                    (ticket->standby? " [standby]" : ""));
            if (ticket->last_granted > -1) {
                char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
                fprintf(data->stream, " %s</li>\n", time);
                free(time);
            }
            break;

        case mon_output_xml:
            fprintf(data->stream, "        <ticket id=\"%s\" status=\"%s\" standby=\"%s\"",
                    ticket->id, (ticket->granted? "granted" : "revoked"),
                    (ticket->standby? "true" : "false"));
            if (ticket->last_granted > -1) {
                char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
                fprintf(data->stream, " %s />\n", time);
                free(time);
            }
            break;

        default:
            break;
    }
}

static void
print_cluster_tickets(mon_state_t *state, pe_working_set_t * data_set)
{
    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nTickets:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>Tickets</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <tickets>\n");
            break;

        default:
            break;
    }

    /* Print each ticket */
    g_hash_table_foreach(data_set->tickets, print_ticket, state);

    /* Close section */
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    </tickets>\n");
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
print_ban(mon_state_t *state, pe_node_t *node, pe__location_t *location,
          unsigned int mon_ops)
{
    char *node_name = NULL;

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            node_name = get_node_display_name(node, mon_ops);
            print_as(state->output_format, " %s\tprevents %s from running %son %s\n",
                     location->id, location->rsc_lh->id,
                     ((location->role_filter == RSC_ROLE_MASTER)? "as Master " : ""),
                     node_name);
            break;

        case mon_output_html:
        case mon_output_cgi:
            node_name = get_node_display_name(node, mon_ops);
            fprintf(state->stream, "  <li>%s prevents %s from running %son %s</li>\n",
                     location->id, location->rsc_lh->id,
                     ((location->role_filter == RSC_ROLE_MASTER)? "as Master " : ""),
                     node_name);
            break;

        case mon_output_xml:
            fprintf(state->stream,
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
static void
print_neg_locations(mon_state_t *state, pe_working_set_t *data_set, unsigned int mon_ops,
                    const char *prefix)
{
    GListPtr gIter, gIter2;

    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nNegative Location Constraints:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>Negative Location Constraints</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <bans>\n");
            break;

        default:
            break;
    }

    /* Print each ban */
    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        pe__location_t *location = gIter->data;
        if (!g_str_has_prefix(location->id, prefix))
            continue;
        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            node_t *node = (node_t *) gIter2->data;

            if (node->weight < 0) {
                print_ban(state, node, location, mon_ops);
            }
        }
    }

    /* Close section */
    switch (state->output_format) {
        case mon_output_cgi:
        case mon_output_html:
            fprintf(state->stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    </bans>\n");
            break;

        default:
            break;
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
print_node_attributes(mon_state_t *state, pe_working_set_t *data_set, unsigned int mon_ops)
{
    GListPtr gIter = NULL;

    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nNode Attributes:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>Node Attributes</h2>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <node_attributes>\n");
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

        data.state = state;
        data.node = (node_t *) gIter->data;

        if (data.node && data.node->details && data.node->details->online) {
            GList *attr_list = NULL;
            GHashTableIter iter;
            gpointer key, value;

            print_node_start(state, data.node, mon_ops);

            g_hash_table_iter_init(&iter, data.node->details->attrs);
            while (g_hash_table_iter_next (&iter, &key, &value)) {
                attr_list = append_attr_list(attr_list, key);
            }

            g_list_foreach(attr_list, print_node_attribute, &data);
            g_list_free(attr_list);
            print_node_end(state);
        }
    }

    /* Print section footer */
    switch (state->output_format) {
        case mon_output_xml:
            fprintf(state->stream, "    </node_attributes>\n");
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
print_cluster_summary_header(mon_state_t *state)
{
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <h2>Cluster Summary</h2>\n <p>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <summary>\n");
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
print_cluster_summary_footer(mon_state_t *state)
{
    switch (state->output_format) {
        case mon_output_cgi:
        case mon_output_html:
            fprintf(state->stream, " </p>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    </summary>\n");
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
print_cluster_times(mon_state_t *state, pe_working_set_t *data_set)
{
    const char *last_written = crm_element_value(data_set->input, XML_CIB_ATTR_WRITTEN);
    const char *user = crm_element_value(data_set->input, XML_ATTR_UPDATE_USER);
    const char *client = crm_element_value(data_set->input, XML_ATTR_UPDATE_CLIENT);
    const char *origin = crm_element_value(data_set->input, XML_ATTR_UPDATE_ORIG);

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console: {
            const char *now_str = crm_now_string(NULL);

            print_as(state->output_format, "Last updated: %s", now_str ? now_str : "Could not determine current time");
            print_as(state->output_format, (user || client || origin)? "\n" : "\t\t");
            print_as(state->output_format, "Last change: %s", last_written ? last_written : "");
            if (user) {
                print_as(state->output_format, " by %s", user);
            }
            if (client) {
                print_as(state->output_format, " via %s", client);
            }
            if (origin) {
                print_as(state->output_format, " on %s", origin);
            }
            print_as(state->output_format, "\n");
            break;
        }

        case mon_output_html:
        case mon_output_cgi: {
            const char *now_str = crm_now_string(NULL);

            fprintf(state->stream, " <b>Last updated:</b> %s<br/>\n",
                    now_str ? now_str : "Could not determine current time");
            fprintf(state->stream, " <b>Last change:</b> %s", last_written ? last_written : "");
            if (user) {
                fprintf(state->stream, " by %s", user);
            }
            if (client) {
                fprintf(state->stream, " via %s", client);
            }
            if (origin) {
                fprintf(state->stream, " on %s", origin);
            }
            fprintf(state->stream, "<br/>\n");
            break;
        }

        case mon_output_xml: {
            const char *now_str = crm_now_string(NULL);

            fprintf(state->stream, "        <last_update time=\"%s\" />\n",
                    now_str ? now_str : "Could not determine current time");
            fprintf(state->stream, "        <last_change time=\"%s\" user=\"%s\" client=\"%s\" origin=\"%s\" />\n",
                    last_written ? last_written : "", user ? user : "",
                    client ? client : "", origin ? origin : "");
            break;
        }

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
print_cluster_stack(mon_state_t *state, const char *stack_s)
{
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "Stack: %s\n", stack_s);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <b>Stack:</b> %s<br/>\n", stack_s);
            break;

        case mon_output_xml:
            fprintf(state->stream, "        <stack type=\"%s\" />\n", stack_s);
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
print_cluster_dc(mon_state_t *state, pe_working_set_t *data_set, unsigned int mon_ops)
{
    node_t *dc = data_set->dc_node;
    xmlNode *dc_version = get_xpath_object("//nvpair[@name='dc-version']",
                                           data_set->input, LOG_DEBUG);
    const char *dc_version_s = dc_version?
                               crm_element_value(dc_version, XML_NVPAIR_ATTR_VALUE)
                               : NULL;
    const char *quorum = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);
    char *dc_name = dc? get_node_display_name(dc, mon_ops) : NULL;

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "Current DC: ");
            if (dc) {
                print_as(state->output_format, "%s (version %s) - partition %s quorum\n",
                         dc_name, (dc_version_s? dc_version_s : "unknown"),
                         (crm_is_true(quorum) ? "with" : "WITHOUT"));
            } else {
                print_as(state->output_format, "NONE\n");
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <b>Current DC:</b> ");
            if (dc) {
                fprintf(state->stream, "%s (version %s) - partition %s quorum",
                        dc_name, (dc_version_s? dc_version_s : "unknown"),
                        (crm_is_true(quorum)? "with" : "<font color=\"red\"><b>WITHOUT</b></font>"));
            } else {
                fprintf(state->stream, "<font color=\"red\"><b>NONE</b></font>");
            }
            fprintf(state->stream, "<br/>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream,  "        <current_dc ");
            if (dc) {
                fprintf(state->stream,
                        "present=\"true\" version=\"%s\" name=\"%s\" id=\"%s\" with_quorum=\"%s\"",
                        (dc_version_s? dc_version_s : ""), dc->details->uname, dc->details->id,
                        (crm_is_true(quorum) ? "true" : "false"));
            } else {
                fprintf(state->stream, "present=\"false\"");
            }
            fprintf(state->stream, " />\n");
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
print_cluster_counts(mon_state_t *state, pe_working_set_t *data_set, const char *stack_s)
{
    int nnodes = g_list_length(data_set->nodes);
    int nresources = count_resources(data_set, NULL);

    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:

            print_as(state->output_format, "\n%d node%s configured\n", nnodes, s_if_plural(nnodes));

            print_as(state->output_format, "%d resource%s configured",
                     nresources, s_if_plural(nresources));
            if(data_set->disabled_resources || data_set->blocked_resources) {
                print_as(state->output_format, " (");
                if (data_set->disabled_resources) {
                    print_as(state->output_format, "%d DISABLED", data_set->disabled_resources);
                }
                if (data_set->disabled_resources && data_set->blocked_resources) {
                    print_as(state->output_format, ", ");
                }
                if (data_set->blocked_resources) {
                    print_as(state->output_format, "%d BLOCKED from starting due to failure",
                             data_set->blocked_resources);
                }
                print_as(state->output_format, ")");
            }
            print_as(state->output_format, "\n");

            break;

        case mon_output_html:
        case mon_output_cgi:

            fprintf(state->stream, " %d node%s configured<br/>\n",
                    nnodes, s_if_plural(nnodes));

            fprintf(state->stream, " %d resource%s configured",
                    nresources, s_if_plural(nresources));
            if (data_set->disabled_resources || data_set->blocked_resources) {
                fprintf(state->stream, " (");
                if (data_set->disabled_resources) {
                    fprintf(state->stream, "%d <strong>DISABLED</strong>",
                            data_set->disabled_resources);
                }
                if (data_set->disabled_resources && data_set->blocked_resources) {
                    fprintf(state->stream, ", ");
                }
                if (data_set->blocked_resources) {
                    fprintf(state->stream,
                            "%d <strong>BLOCKED</strong> from starting due to failure",
                            data_set->blocked_resources);
                }
                fprintf(state->stream, ")");
            }
            fprintf(state->stream, "<br/>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream,
                    "        <nodes_configured number=\"%d\" />\n",
                    g_list_length(data_set->nodes));
            fprintf(state->stream,
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
print_cluster_options(mon_state_t *state, pe_working_set_t *data_set)
{
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
                print_as(state->output_format, "\n              *** Resource management is DISABLED ***");
                print_as(state->output_format, "\n  The cluster will not attempt to start, stop or recover services");
                print_as(state->output_format, "\n");
            }
            break;

        case mon_output_html:
            fprintf(state->stream, " </p>\n <h3>Config Options</h3>\n");
            fprintf(state->stream, " <table>\n");
            fprintf(state->stream, "  <tr><th>STONITH of failed nodes</th><td>%s</td></tr>\n",
                    is_set(data_set->flags, pe_flag_stonith_enabled)? "enabled" : "disabled");

            fprintf(state->stream, "  <tr><th>Cluster is</th><td>%ssymmetric</td></tr>\n",
                    is_set(data_set->flags, pe_flag_symmetric_cluster)? "" : "a");

            fprintf(state->stream, "  <tr><th>No Quorum Policy</th><td>");
            switch (data_set->no_quorum_policy) {
                case no_quorum_freeze:
                    fprintf(state->stream, "Freeze resources");
                    break;
                case no_quorum_stop:
                    fprintf(state->stream, "Stop ALL resources");
                    break;
                case no_quorum_ignore:
                    fprintf(state->stream, "Ignore");
                    break;
                case no_quorum_suicide:
                    fprintf(state->stream, "Suicide");
                    break;
            }
            fprintf(state->stream, "</td></tr>\n");

            fprintf(state->stream, "  <tr><th>Resource management</th><td>");
            if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
                fprintf(state->stream, "<strong>DISABLED</strong> (the cluster will "
                                "not attempt to start, stop or recover services)");
            } else {
                fprintf(state->stream, "enabled");
            }
            fprintf(state->stream, "</td></tr>\n");

            fprintf(state->stream, "</table>\n <p>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "        <cluster_options");
            fprintf(state->stream, " stonith-enabled=\"%s\"",
                    is_set(data_set->flags, pe_flag_stonith_enabled)?
                    "true" : "false");
            fprintf(state->stream, " symmetric-cluster=\"%s\"",
                    is_set(data_set->flags, pe_flag_symmetric_cluster)?
                    "true" : "false");
            fprintf(state->stream, " no-quorum-policy=\"");
            switch (data_set->no_quorum_policy) {
                case no_quorum_freeze:
                    fprintf(state->stream, "freeze");
                    break;
                case no_quorum_stop:
                    fprintf(state->stream, "stop");
                    break;
                case no_quorum_ignore:
                    fprintf(state->stream, "ignore");
                    break;
                case no_quorum_suicide:
                    fprintf(state->stream, "suicide");
                    break;
            }
            fprintf(state->stream, "\"");
            fprintf(state->stream, " maintenance-mode=\"%s\"",
                    is_set(data_set->flags, pe_flag_maintenance_mode)?
                    "true" : "false");
            fprintf(state->stream, " />\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print a summary of cluster-wide information
 *
 * \param[in] stream     File stream to display output to
 * \param[in] data_set   Working set of CIB state
 */
static void
print_cluster_summary(mon_state_t *state, pe_working_set_t *data_set,
                      unsigned int mon_ops, unsigned int show)
{
    const char *stack_s = get_cluster_stack(data_set);
    gboolean header_printed = FALSE;

    if (show & mon_show_stack) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(state);
            header_printed = TRUE;
        }
        print_cluster_stack(state, stack_s);
    }

    /* Always print DC if none, even if not requested */
    if ((data_set->dc_node == NULL) || (show & mon_show_dc)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(state);
            header_printed = TRUE;
        }
        print_cluster_dc(state, data_set, mon_ops);
    }

    if (show & mon_show_times) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(state);
            header_printed = TRUE;
        }
        print_cluster_times(state, data_set);
    }

    if (is_set(data_set->flags, pe_flag_maintenance_mode)
        || data_set->disabled_resources
        || data_set->blocked_resources
        || is_set(show, mon_show_count)) {
        if (header_printed == FALSE) {
            print_cluster_summary_header(state);
            header_printed = TRUE;
        }
        print_cluster_counts(state, data_set, stack_s);
    }

    /* There is not a separate option for showing cluster options, so show with
     * stack for now; a separate option could be added if there is demand
     */
    if (show & mon_show_stack) {
        print_cluster_options(state, data_set);
    }

    if (header_printed) {
        print_cluster_summary_footer(state);
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
print_failed_action(mon_state_t *state, xmlNode *xml_op)
{
    const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
    const char *op_key_attr = "op_key";
    const char *node = crm_element_value(xml_op, XML_ATTR_UNAME);
    const char *call = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    const char *exit_reason = crm_element_value(xml_op, XML_LRM_ATTR_EXIT_REASON);
    int rc = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_RC), "0");
    int status = crm_parse_int(crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS), "0");
    time_t last_change = 0;
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
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "* %s on %s '%s' (%d): call=%s, status=%s, exitreason='%s'",
                     op_key, node, services_ocf_exitcode_str(rc), rc,
                     call, services_lrm_status_str(status), exit_reason);
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "  <li>%s on %s '%s' (%d): call=%s, status=%s, exitreason='%s'",
                     op_key, node, services_ocf_exitcode_str(rc), rc,
                     call, services_lrm_status_str(status), exit_reason);
            break;

        case mon_output_xml:
            exit_reason_cleaned = crm_xml_escape(exit_reason);
            fprintf(state->stream, "        <failure %s=\"%s\" node=\"%s\"",
                    op_key_attr, op_key, node);
            fprintf(state->stream, " exitstatus=\"%s\" exitreason=\"%s\" exitcode=\"%d\"",
                    services_ocf_exitcode_str(rc), exit_reason_cleaned, rc);
            fprintf(state->stream, " call=\"%s\" status=\"%s\"",
                    call, services_lrm_status_str(status));
            free(exit_reason_cleaned);
            break;

        default:
            break;
    }

    /* If last change was given, print timing information as well */
    if (crm_element_value_epoch(xml_op, XML_RSC_OP_LAST_CHANGE,
                                &last_change) == pcmk_ok) {
        char *run_at_s = ctime(&last_change);

        if (run_at_s) {
            run_at_s[24] = 0; /* Overwrite the newline */
        }

        switch (state->output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(state->output_format, ",\n    last-rc-change='%s', queued=%sms, exec=%sms",
                         run_at_s? run_at_s : "",
                         crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                         crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(state->stream, " last-rc-change='%s', queued=%sms, exec=%sms",
                        run_at_s? run_at_s : "",
                        crm_element_value(xml_op, XML_RSC_OP_T_QUEUE),
                        crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
                break;

            case mon_output_xml:
                fprintf(state->stream,
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
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, "</li>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, " />\n");
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
print_failed_actions(mon_state_t *state, pe_working_set_t *data_set)
{
    xmlNode *xml_op = NULL;

    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nFailed Resource Actions:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream,
                    " <hr />\n <h2>Failed Resource Actions</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <failures>\n");
            break;

        default:
            break;
    }

    /* Print each failed action */
    for (xml_op = __xml_first_child(data_set->failed); xml_op != NULL;
         xml_op = __xml_next(xml_op)) {
        print_failed_action(state, xml_op);
    }

    /* End section */
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    </failures>\n");
            break;

        default:
            break;
    }
}

/*!
 * \internal
 * \brief Print a stonith action
 *
 * \param[in] stream     File stream to display output to
 * \param[in] event      stonith event
 */
static void
print_stonith_action(mon_state_t *state, stonith_history_t *event, unsigned int mon_ops, stonith_history_t *top_history)
{
    const char *action_s = stonith_action_str(event->action);
    char *run_at_s = ctime(&event->completed);

    if ((run_at_s) && (run_at_s[0] != 0)) {
        run_at_s[strlen(run_at_s)-1] = 0; /* Overwrite the newline */
    }

    switch(state->output_format) {
        case mon_output_xml:
            fprintf(state->stream, "        <fence_event target=\"%s\" action=\"%s\"",
                    event->target, event->action);
            switch(event->state) {
                case st_done:
                    fprintf(state->stream, " state=\"success\"");
                    break;
                case st_failed:
                    fprintf(state->stream, " state=\"failed\"");
                    break;
                default:
                    fprintf(state->stream, " state=\"pending\"");
            }
            fprintf(state->stream, " origin=\"%s\" client=\"%s\"",
                    event->origin, event->client);
            if (event->delegate) {
                fprintf(state->stream, " delegate=\"%s\"", event->delegate);
            }
            switch(event->state) {
                case st_done:
                case st_failed:
                    fprintf(state->stream, " completed=\"%s\"", run_at_s?run_at_s:"");
                    break;
                default:
                    break;
            }
            fprintf(state->stream, " />\n");
            break;

        case mon_output_plain:
        case mon_output_console:
            switch(event->state) {
                case st_done:
                    print_as(state->output_format, "* %s of %s successful: delegate=%s, client=%s, origin=%s,\n"
                             "    %s='%s'\n",
                             action_s, event->target,
                             event->delegate ? event->delegate : "",
                             event->client, event->origin,
                             is_set(mon_ops, mon_op_fence_full_history) ? "completed" : "last-successful",
                             run_at_s?run_at_s:"");
                    break;
                case st_failed:
                    print_as(state->output_format, "* %s of %s failed: delegate=%s, client=%s, origin=%s,\n"
                             "    %s='%s' %s\n",
                             action_s, event->target,
                             event->delegate ? event->delegate : "",
                             event->client, event->origin,
                             is_set(mon_ops, mon_op_fence_full_history) ? "completed" : "last-failed",
                             run_at_s?run_at_s:"",
                             stonith__later_succeeded(event, top_history) ? "(a later attempt succeeded)" : "");
                    break;
                default:
                    print_as(state->output_format, "* %s of %s pending: client=%s, origin=%s\n",
                             action_s, event->target,
                             event->client, event->origin);
            }
            break;

        case mon_output_html:
        case mon_output_cgi:
            switch(event->state) {
                case st_done:
                    fprintf(state->stream, "  <li>%s of %s successful: delegate=%s, "
                                    "client=%s, origin=%s, %s='%s'</li>\n",
                                    action_s, event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    is_set(mon_ops, mon_op_fence_full_history) ? "completed" : "last-successful",
                                    run_at_s?run_at_s:"");
                    break;
                case st_failed:
                    fprintf(state->stream, "  <li>%s of %s failed: delegate=%s, "
                                    "client=%s, origin=%s, %s='%s' %s</li>\n",
                                    action_s, event->target,
                                    event->delegate ? event->delegate : "",
                                    event->client, event->origin,
                                    is_set(mon_ops, mon_op_fence_full_history) ? "completed" : "last-failed",
                                    run_at_s?run_at_s:"",
                                    stonith__later_succeeded(event, top_history) ? "(a later attempt succeeded)" : "");
                    break;
                default:
                    fprintf(state->stream, "  <li>%s of %s pending: client=%s, "
                                    "origin=%s</li>\n",
                                    action_s, event->target,
                                    event->client, event->origin);
            }
            break;

        default:
            /* no support for fence history for other formats so far */
            break;
    }
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
print_failed_stonith_actions(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops)
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
    switch (state->output_format) {
        /* no need to take care of xml in here as xml gets full
         * history anyway
         */
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nFailed Fencing Actions:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>Failed Fencing Actions</h2>\n <ul>\n");
            break;

        default:
            break;
    }

    /* Print each failed stonith action */
    for (hp = history; hp; hp = hp->next) {
        if (hp->state == st_failed) {
            print_stonith_action(state, hp, mon_ops, history);
        }
    }

    /* End section */
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " </ul>\n");
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
print_stonith_pending(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops)
{
    /* xml-output always shows the full history
     * so we'll never have to show pending-actions
     * separately
     */
    if (history && (history->state != st_failed) &&
        (history->state != st_done)) {
        stonith_history_t *hp;

        /* Print section heading */
        switch (state->output_format) {
            case mon_output_plain:
            case mon_output_console:
                print_as(state->output_format, "\nPending Fencing Actions:\n");
                break;

            case mon_output_html:
            case mon_output_cgi:
                fprintf(state->stream, " <hr />\n <h2>Pending Fencing Actions</h2>\n <ul>\n");
                break;

            default:
                break;
        }

        history = stonith__sort_history(history);
        for (hp = history; hp; hp = hp->next) {
            if ((hp->state == st_failed) || (hp->state == st_done)) {
                break;
            }
            print_stonith_action(state, hp, mon_ops, history);
        }

        /* End section */
        switch (state->output_format) {
            case mon_output_html:
            case mon_output_cgi:
                fprintf(state->stream, " </ul>\n");
                break;

        default:
            break;
        }
    }
}

/*!
 * \internal
 * \brief Print a section for stonith-history
 *
 * \param[in] stream     File stream to display output to
 * \param[in] history    List of stonith actions
 *
 */
static void
print_stonith_history(mon_state_t *state, stonith_history_t *history, unsigned int mon_ops)
{
    stonith_history_t *hp;

    /* Print section heading */
    switch (state->output_format) {
        case mon_output_plain:
        case mon_output_console:
            print_as(state->output_format, "\nFencing History:\n");
            break;

        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " <hr />\n <h2>Fencing History</h2>\n <ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    <fence_history>\n");
            break;

        default:
            break;
    }

    stonith__sort_history(history);
    for (hp = history; hp; hp = hp->next) {
        if ((hp->state != st_failed) || (state->output_format == mon_output_xml)) {
            print_stonith_action(state, hp, mon_ops, history);
        }
    }

    /* End section */
    switch (state->output_format) {
        case mon_output_html:
        case mon_output_cgi:
            fprintf(state->stream, " </ul>\n");
            break;

        case mon_output_xml:
            fprintf(state->stream, "    </fence_history>\n");
            break;

        default:
            break;
    }
}

void
print_status(mon_state_t *state, pe_working_set_t *data_set,
             stonith_history_t *stonith_history, unsigned int mon_ops,
             unsigned int show, const char *prefix)
{
    GListPtr gIter = NULL;
    int print_opts = get_resource_display_options(mon_ops, state->output_format);

    /* space-separated lists of node names */
    char *online_nodes = NULL;
    char *online_remote_nodes = NULL;
    char *online_guest_nodes = NULL;
    char *offline_nodes = NULL;
    char *offline_remote_nodes = NULL;

    if (state->output_format == mon_output_console) {
        blank_screen();
    }
    print_cluster_summary(state, data_set, mon_ops, show);
    print_as(state->output_format, "\n");

    /* Gather node information (and print if in bad state or grouping by node) */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *node_mode = NULL;
        char *node_name = get_node_display_name(node, mon_ops);

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
            if (is_not_set(mon_ops, mon_op_group_by_node)) {
                if (pe__is_guest_node(node)) {
                    online_guest_nodes = add_list_element(online_guest_nodes, node_name);
                } else if (pe__is_remote_node(node)) {
                    online_remote_nodes = add_list_element(online_remote_nodes, node_name);
                } else {
                    online_nodes = add_list_element(online_nodes, node_name);
                }
                free(node_name);
                continue;
            }
        } else {
            node_mode = "OFFLINE";
            if (is_not_set(mon_ops, mon_op_group_by_node)) {
                if (pe__is_remote_node(node)) {
                    offline_remote_nodes = add_list_element(offline_remote_nodes, node_name);
                } else if (pe__is_guest_node(node)) {
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
        if (pe__is_guest_node(node)) {
            print_as(state->output_format, "Guest");
        } else if (pe__is_remote_node(node)) {
            print_as(state->output_format, "Remote");
        }
        print_as(state->output_format, "Node %s: %s\n", node_name, node_mode);

        /* If we're grouping by node, print its resources */
        if (is_set(mon_ops, mon_op_group_by_node)) {
            if (is_set(mon_ops, mon_op_print_brief)) {
                print_rscs_brief(node->details->running_rsc, "\t", print_opts | pe_print_rsconly,
                                 state->stream, FALSE);
            } else {
                GListPtr gIter2 = NULL;

                for (gIter2 = node->details->running_rsc; gIter2 != NULL; gIter2 = gIter2->next) {
                    resource_t *rsc = (resource_t *) gIter2->data;

                    rsc->fns->print(rsc, "\t", print_opts | pe_print_rsconly, state->stream);
                }
            }
        }
        free(node_name);
    }

    /* If we're not grouping by node, summarize nodes by status */
    if (online_nodes) {
        print_as(state->output_format, "Online: [%s ]\n", online_nodes);
        free(online_nodes);
    }
    if (offline_nodes) {
        print_as(state->output_format, "OFFLINE: [%s ]\n", offline_nodes);
        free(offline_nodes);
    }
    if (online_remote_nodes) {
        print_as(state->output_format, "RemoteOnline: [%s ]\n", online_remote_nodes);
        free(online_remote_nodes);
    }
    if (offline_remote_nodes) {
        print_as(state->output_format, "RemoteOFFLINE: [%s ]\n", offline_remote_nodes);
        free(offline_remote_nodes);
    }
    if (online_guest_nodes) {
        print_as(state->output_format, "GuestOnline: [%s ]\n", online_guest_nodes);
        free(online_guest_nodes);
    }

    /* Print resources section, if needed */
    print_resources(state, data_set, print_opts, mon_ops);

    /* print Node Attributes section if requested */
    if (show & mon_show_attributes) {
        print_node_attributes(state, data_set, mon_ops);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(state, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE), mon_ops);
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(state, data_set);
    }

    /* Print failed stonith actions */
    if (is_set(mon_ops, mon_op_fence_history)) {
        print_failed_stonith_actions(state, stonith_history, mon_ops);
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(state, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
        print_neg_locations(state, data_set, mon_ops, prefix);
    }

    /* Print stonith history */
    if (is_set(mon_ops, mon_op_fence_history)) {
        if (show & mon_show_fence_history) {
            print_stonith_history(state, stonith_history, mon_ops);
        } else {
            print_stonith_pending(state, stonith_history, mon_ops);
        }
    }

#if CURSES_ENABLED
    if (state->output_format == mon_output_console) {
        refresh();
    }
#endif
}

void
print_xml_status(mon_state_t *state, pe_working_set_t *data_set,
                 stonith_history_t *stonith_history, unsigned int mon_ops,
                 unsigned int show, const char *prefix)
{
    GListPtr gIter = NULL;
    int print_opts = get_resource_display_options(mon_ops, state->output_format);

    fprintf(state->stream, "<?xml version=\"1.0\"?>\n");
    fprintf(state->stream, "<crm_mon version=\"%s\">\n", VERSION);

    print_cluster_summary(state, data_set, mon_ops, show);

    /*** NODES ***/
    fprintf(state->stream, "    <nodes>\n");
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

        fprintf(state->stream, "        <node name=\"%s\" ", node->details->uname);
        fprintf(state->stream, "id=\"%s\" ", node->details->id);
        fprintf(state->stream, "online=\"%s\" ", node->details->online ? "true" : "false");
        fprintf(state->stream, "standby=\"%s\" ", node->details->standby ? "true" : "false");
        fprintf(state->stream, "standby_onfail=\"%s\" ", node->details->standby_onfail ? "true" : "false");
        fprintf(state->stream, "maintenance=\"%s\" ", node->details->maintenance ? "true" : "false");
        fprintf(state->stream, "pending=\"%s\" ", node->details->pending ? "true" : "false");
        fprintf(state->stream, "unclean=\"%s\" ", node->details->unclean ? "true" : "false");
        fprintf(state->stream, "shutdown=\"%s\" ", node->details->shutdown ? "true" : "false");
        fprintf(state->stream, "expected_up=\"%s\" ", node->details->expected_up ? "true" : "false");
        fprintf(state->stream, "is_dc=\"%s\" ", node->details->is_dc ? "true" : "false");
        fprintf(state->stream, "resources_running=\"%d\" ", g_list_length(node->details->running_rsc));
        fprintf(state->stream, "type=\"%s\" ", node_type);
        if (pe__is_guest_node(node)) {
            fprintf(state->stream, "id_as_resource=\"%s\" ", node->details->remote_rsc->container->id);
        }

        if (is_set(mon_ops, mon_op_group_by_node)) {
            GListPtr lpc2 = NULL;

            fprintf(state->stream, ">\n");
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                resource_t *rsc = (resource_t *) lpc2->data;

                rsc->fns->print(rsc, "            ", print_opts | pe_print_rsconly, state->stream);
            }
            fprintf(state->stream, "        </node>\n");
        } else {
            fprintf(state->stream, "/>\n");
        }
    }
    fprintf(state->stream, "    </nodes>\n");

    /* Print resources section, if needed */
    print_resources(state, data_set, print_opts, mon_ops);

    /* print Node Attributes section if requested */
    if (show & mon_show_attributes) {
        print_node_attributes(state, data_set, mon_ops);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(state, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE), mon_ops);
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(state, data_set);
    }

    /* Print stonith history */
    if (is_set(mon_ops, mon_op_fence_history)) {
        print_stonith_history(state, stonith_history, mon_ops);
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(state, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
        print_neg_locations(state, data_set, mon_ops, prefix);
    }

    fprintf(state->stream, "</crm_mon>\n");
    fflush(state->stream);
}

int
print_html_status(mon_state_t *state, pe_working_set_t *data_set,
                  const char *filename, stonith_history_t *stonith_history,
                  unsigned int mon_ops, unsigned int show, const char *prefix,
                  unsigned int reconnect_msec)
{
    GListPtr gIter = NULL;
    char *filename_tmp = NULL;
    int print_opts = get_resource_display_options(mon_ops, state->output_format);

    if (state->output_format == mon_output_cgi) {
        fprintf(state->stream, "Content-Type: text/html\n\n");

    } else {
        filename_tmp = crm_concat(filename, "tmp", '.');
        state->stream = fopen(filename_tmp, "w");
        if (state->stream == NULL) {
            crm_perror(LOG_ERR, "Cannot open %s for writing", filename_tmp);
            free(filename_tmp);
            return -1;
        }
    }

    fprintf(state->stream, "<html>\n");
    fprintf(state->stream, " <head>\n");
    fprintf(state->stream, "  <title>Cluster status</title>\n");
    fprintf(state->stream, "  <meta http-equiv=\"refresh\" content=\"%d\">\n", reconnect_msec / 1000);
    fprintf(state->stream, " </head>\n");
    fprintf(state->stream, "<body>\n");

    print_cluster_summary(state, data_set, mon_ops, show);

    /*** NODE LIST ***/

    fprintf(state->stream, " <hr />\n <h2>Node List</h2>\n");
    fprintf(state->stream, "<ul>\n");
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        char *node_name = get_node_display_name(node, mon_ops);

        fprintf(state->stream, "<li>Node: %s: ", node_name);
        if (node->details->standby_onfail && node->details->online) {
            fprintf(state->stream, "<font color=\"orange\">standby (on-fail)</font>\n");
        } else if (node->details->standby && node->details->online) {

            fprintf(state->stream, "<font color=\"orange\">standby%s</font>\n",
                node->details->running_rsc?" (with active resources)":"");
        } else if (node->details->standby) {
            fprintf(state->stream, "<font color=\"red\">OFFLINE (standby)</font>\n");
        } else if (node->details->maintenance && node->details->online) {
            fprintf(state->stream, "<font color=\"blue\">maintenance</font>\n");
        } else if (node->details->maintenance) {
            fprintf(state->stream, "<font color=\"red\">OFFLINE (maintenance)</font>\n");
        } else if (node->details->online) {
            fprintf(state->stream, "<font color=\"green\">online</font>\n");
        } else {
            fprintf(state->stream, "<font color=\"red\">OFFLINE</font>\n");
        }
        if (is_set(mon_ops, mon_op_print_brief) && is_set(mon_ops, mon_op_group_by_node)) {
            fprintf(state->stream, "<ul>\n");
            print_rscs_brief(node->details->running_rsc, NULL, print_opts | pe_print_rsconly,
                             state->stream, FALSE);
            fprintf(state->stream, "</ul>\n");

        } else if (is_set(mon_ops, mon_op_group_by_node)) {
            GListPtr lpc2 = NULL;

            fprintf(state->stream, "<ul>\n");
            for (lpc2 = node->details->running_rsc; lpc2 != NULL; lpc2 = lpc2->next) {
                resource_t *rsc = (resource_t *) lpc2->data;

                fprintf(state->stream, "<li>");
                rsc->fns->print(rsc, NULL, print_opts | pe_print_rsconly, state->stream);
                fprintf(state->stream, "</li>\n");
            }
            fprintf(state->stream, "</ul>\n");
        }
        fprintf(state->stream, "</li>\n");
        free(node_name);
    }
    fprintf(state->stream, "</ul>\n");

    /* Print resources section, if needed */
    print_resources(state, data_set, print_opts, mon_ops);

    /* print Node Attributes section if requested */
    if (show & mon_show_attributes) {
        print_node_attributes(state, data_set, mon_ops);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (show & (mon_show_operations | mon_show_failcounts)) {
        print_node_summary(state, data_set,
                           ((show & mon_show_operations)? TRUE : FALSE), mon_ops);
    }

    /* If there were any failed actions, print them */
    if (xml_has_children(data_set->failed)) {
        print_failed_actions(state, data_set);
    }

    /* Print failed stonith actions */
    if (is_set(mon_ops, mon_op_fence_history)) {
        print_failed_stonith_actions(state, stonith_history, mon_ops);
    }

    /* Print stonith history */
    if (is_set(mon_ops, mon_op_fence_history)) {
        if (show & mon_show_fence_history) {
            print_stonith_history(state, stonith_history, mon_ops);
        } else {
            print_stonith_pending(state, stonith_history, mon_ops);
        }
    }

    /* Print tickets if requested */
    if (show & mon_show_tickets) {
        print_cluster_tickets(state, data_set);
    }

    /* Print negative location constraints if requested */
    if (show & mon_show_bans) {
        print_neg_locations(state, data_set, mon_ops, prefix);
    }

    fprintf(state->stream, "</body>\n");
    fprintf(state->stream, "</html>\n");
    fflush(state->stream);

    if (state->output_format != mon_output_cgi) {
        if (rename(filename_tmp, filename) != 0) {
            crm_perror(LOG_ERR, "Unable to rename %s->%s", filename_tmp, filename);
        }
        free(filename_tmp);
    }
    return 0;
}
