/*
 * Copyright 2019-2020 the Pacemaker project contributors
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

static void print_resources_heading(pcmk__output_t *out, unsigned int mon_ops);
static void print_resources_closing(pcmk__output_t *out, unsigned int mon_ops);
static int print_resources(pcmk__output_t *out, pe_working_set_t *data_set,
                           unsigned int print_opts, unsigned int mon_ops, gboolean brief_output,
                           gboolean print_summary, GListPtr only_node, GListPtr only_rsc,
                           gboolean print_spacer);
static int print_rsc_history(pcmk__output_t *out, pe_working_set_t *data_set,
                             pe_node_t *node, xmlNode *rsc_entry, unsigned int mon_ops,
                             GListPtr op_list);
static int print_node_history(pcmk__output_t *out, pe_working_set_t *data_set,
                              pe_node_t *node, xmlNode *node_state, gboolean operations,
                              unsigned int mon_ops, GListPtr only_node, GListPtr only_rsc);
static gboolean add_extra_info(pcmk__output_t *out, pe_node_t * node, GListPtr rsc_list,
                               const char *attrname, int *expected_score);
static void print_node_attribute(gpointer name, gpointer user_data);
static int print_node_summary(pcmk__output_t *out, pe_working_set_t * data_set,
                              gboolean operations, unsigned int mon_ops,
                              GListPtr only_node, GListPtr only_rsc, gboolean print_spacer);
static int print_cluster_tickets(pcmk__output_t *out, pe_working_set_t * data_set,
                                 gboolean print_spacer);
static int print_neg_locations(pcmk__output_t *out, pe_working_set_t *data_set,
                               unsigned int mon_ops, const char *prefix,
                               GListPtr only_rsc, gboolean print_spacer);
static int print_node_attributes(pcmk__output_t *out, pe_working_set_t *data_set,
                                 unsigned int mon_ops, GListPtr only_node,
                                 GListPtr only_rsc, gboolean print_spacer);
static int print_failed_actions(pcmk__output_t *out, pe_working_set_t *data_set,
                                GListPtr only_node, gboolean print_spacer);

static GListPtr
build_uname_list(pe_working_set_t *data_set, const char *s) {
    GListPtr unames = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        /* Nothing was given so return a list of all node names.  Or, '*' was
         * given.  This would normally fall into the pe__unames_with_tag branch
         * where it will return an empty list.  Catch it here instead.
         */
        unames = g_list_prepend(unames, strdup("*"));
    } else {
        pe_node_t *node = pe_find_node(data_set->nodes, s);

        if (node) {
            /* The given string was a valid uname for a node.  Return a
             * singleton list containing just that uname.
             */
            unames = g_list_prepend(unames, strdup(s));
        } else {
            /* The given string was not a valid uname.  It's either a tag or
             * it's a typo or something.  In the first case, we'll return a
             * list of all the unames of the nodes with the given tag.  In the
             * second case, we'll return a NULL pointer and nothing will
             * get displayed.
             */
            unames = pe__unames_with_tag(data_set, s);
        }
    }

    return unames;
}

static GListPtr
build_rsc_list(pe_working_set_t *data_set, const char *s) {
    GListPtr resources = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        resources = g_list_prepend(resources, strdup("*"));
    } else {
        pe_resource_t *rsc = pe_find_resource_with_flags(data_set->resources, s,
                                                         pe_find_renamed|pe_find_any);

        if (rsc) {
            /* A colon in the name we were given means we're being asked to filter
             * on a specific instance of a cloned resource.  Put that exact string
             * into the filter list.  Otherwise, use the printable ID of whatever
             * resource was found that matches what was asked for.
             */
            if (strstr(s, ":") != NULL) {
                resources = g_list_prepend(resources, strdup(rsc->id));
            } else {
                resources = g_list_prepend(resources, strdup(rsc_printable_id(rsc)));
            }
        } else {
            /* The given string was not a valid resource name.  It's either
             * a tag or it's a typo or something.  See build_uname_list for
             * more detail.
             */
            resources = pe__rscs_with_tag(data_set, s);
        }
    }

    return resources;
}

/*!
 * \internal
 * \brief Print resources section heading appropriate to options
 *
 * \param[in] out     The output functions structure.
 * \param[in] mon_ops Bitmask of mon_op_*.
 */
static void
print_resources_heading(pcmk__output_t *out, unsigned int mon_ops)
{
    const char *heading;

    if (is_set(mon_ops, mon_op_group_by_node)) {

        /* Active resources have already been printed by node */
        heading = is_set(mon_ops, mon_op_inactive_resources) ? "Inactive Resources" : NULL;

    } else if (is_set(mon_ops, mon_op_inactive_resources)) {
        heading = "Full List of Resources";

    } else {
        heading = "Active Resources";
    }

    /* Print section heading */
    out->begin_list(out, NULL, NULL, "%s", heading);
}

/*!
 * \internal
 * \brief Print whatever resource section closing is appropriate
 *
 * \param[in] out     The output functions structure.
 * \param[in] mon_ops Bitmask of mon_op_*.
 */
static void
print_resources_closing(pcmk__output_t *out, unsigned int mon_ops)
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

    out->list_item(out, NULL, "No %sresources", heading);
}

/*!
 * \internal
 * \brief Print whatever resource section(s) are appropriate
 *
 * \param[in] out           The output functions structure.
 * \param[in] data_set      Cluster state to display.
 * \param[in] print_opts    Bitmask of pe_print_*.
 * \param[in] mon_ops       Bitmask of mon_op_*.
 * \param[in] brief_output  Whether to display full or brief output.
 * \param[in] print_summary Whether to display a failure summary.
 */
static int
print_resources(pcmk__output_t *out, pe_working_set_t *data_set,
                unsigned int print_opts, unsigned int mon_ops, gboolean brief_output,
                gboolean print_summary, GListPtr only_node, GListPtr only_rsc,
                gboolean print_spacer)
{
    GListPtr rsc_iter;
    int rc = pcmk_rc_no_output;

    /* If we already showed active resources by node, and
     * we're not showing inactive resources, we have nothing to do
     */
    if (is_set(mon_ops, mon_op_group_by_node) && is_not_set(mon_ops, mon_op_inactive_resources)) {
        return rc;
    }

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);

    print_resources_heading(out, mon_ops);

    /* If we haven't already printed resources grouped by node,
     * and brief output was requested, print resource summary */
    if (brief_output && is_not_set(mon_ops, mon_op_group_by_node)) {
        GListPtr rscs = pe__filter_rsc_list(data_set->resources, only_rsc);

        pe__rscs_brief_output(out, rscs, print_opts,
                              is_set(mon_ops, mon_op_inactive_resources));
        g_list_free(rscs);
    }

    /* For each resource, display it if appropriate */
    for (rsc_iter = data_set->resources; rsc_iter != NULL; rsc_iter = rsc_iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) rsc_iter->data;
        int x;

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

        } else if (partially_active && !pe__rsc_running_on_any_node_in_list(rsc, only_node)) {
            continue;
        }

        /* Print this resource */
        x = out->message(out, crm_map_element_name(rsc->xml), print_opts, rsc,
                         only_node, only_rsc);
        if (x == pcmk_rc_ok) {
            rc = pcmk_rc_ok;
        }
    }

    if (print_summary && rc != pcmk_rc_ok) {
        print_resources_closing(out, mon_ops);
    }

    out->end_list(out);
    return pcmk_rc_ok;
}

static int
failure_count(pe_working_set_t *data_set, pe_node_t *node, pe_resource_t *rsc, time_t *last_failure) {
    return rsc ? pe_get_failcount(node, rsc, last_failure, pe_fc_default,
                                  NULL, data_set)
               : 0;
}

static GListPtr
get_operation_list(xmlNode *rsc_entry) {
    GListPtr op_list = NULL;
    xmlNode *rsc_op = NULL;

    for (rsc_op = __xml_first_child_element(rsc_entry); rsc_op != NULL;
         rsc_op = __xml_next_element(rsc_op)) {
        const char *task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(rsc_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);
        int op_rc_i = crm_parse_int(op_rc, "0");

        /* Display 0-interval monitors as "probe" */
        if (safe_str_eq(task, CRMD_ACTION_STATUS)
            && pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
            task = "probe";
        }

        /* Ignore notifies and some probes */
        if (safe_str_eq(task, CRMD_ACTION_NOTIFY) || (safe_str_eq(task, "probe") && (op_rc_i == 7))) {
            continue;
        }

        if (crm_str_eq((const char *) rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
            op_list = g_list_append(op_list, rsc_op);
        }
    }

    op_list = g_list_sort(op_list, sort_op_by_callid);
    return op_list;
}

/*!
 * \internal
 * \brief Print resource operation/failure history
 *
 * \param[in] out       The output functions structure.
 * \param[in] data_set  Cluster state to display.
 * \param[in] node      Node that ran this resource.
 * \param[in] rsc_entry Root of XML tree describing resource status.
 * \param[in] mon_ops   Bitmask of mon_op_*.
 * \param[in] op_list   A list of operations to print.
 */
static int
print_rsc_history(pcmk__output_t *out, pe_working_set_t *data_set, pe_node_t *node,
                  xmlNode *rsc_entry, unsigned int mon_ops, GListPtr op_list)
{
    GListPtr gIter = NULL;
    int rc = pcmk_rc_no_output;
    const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
    pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    /* Print each operation */
    for (gIter = op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *xml_op = (xmlNode *) gIter->data;
        const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(xml_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(xml_op, XML_LRM_ATTR_RC);
        int op_rc_i = crm_parse_int(op_rc, "0");

        /* Display 0-interval monitors as "probe" */
        if (safe_str_eq(task, CRMD_ACTION_STATUS)
            && pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
            task = "probe";
        }

        /* If this is the first printed operation, print heading for resource */
        if (rc == pcmk_rc_no_output) {
            time_t last_failure = 0;
            int failcount = failure_count(data_set, node, rsc, &last_failure);

            out->message(out, "resource-history", rsc, rsc_id, TRUE, failcount, last_failure, TRUE);
            rc = pcmk_rc_ok;
        }

        /* Print the operation */
        out->message(out, "op-history", xml_op, task, interval_ms_s,
                     op_rc_i, is_set(mon_ops, mon_op_print_timing));
    }

    /* Free the list we created (no need to free the individual items) */
    g_list_free(op_list);

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print node operation/failure history
 *
 * \param[in] out        The output functions structure.
 * \param[in] data_set   Cluster state to display.
 * \param[in] node_state Root of XML tree describing node status.
 * \param[in] operations Whether to print operations or just failcounts.
 * \param[in] mon_ops    Bitmask of mon_op_*.
 */
static int
print_node_history(pcmk__output_t *out, pe_working_set_t *data_set,
                   pe_node_t *node, xmlNode *node_state, gboolean operations,
                   unsigned int mon_ops, GListPtr only_node, GListPtr only_rsc)
{
    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;
    int rc = pcmk_rc_no_output;

    lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
    lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

    /* Print history of each of the node's resources */
    for (rsc_entry = __xml_first_child_element(lrm_rsc); rsc_entry != NULL;
         rsc_entry = __xml_next_element(rsc_entry)) {
        const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
        pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

        if (!crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {
            continue;
        }

        /* We can't use is_filtered here to filter group resources.  For is_filtered,
         * we have to decide whether to check the parent or not.  If we check the
         * parent, all elements of a group will always be printed because that's how
         * is_filtered works for groups.  If we do not check the parent, sometimes
         * this will filter everything out.
         *
         * For other resource types, is_filtered is okay.
         */
        if (uber_parent(rsc)->variant == pe_group) {
            if (!pcmk__str_in_list(only_rsc, rsc_printable_id(rsc)) &&
                !pcmk__str_in_list(only_rsc, rsc_printable_id(uber_parent(rsc)))) {
                continue;
            }
        } else {
            if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
                continue;
            }
        }

        if (operations == FALSE) {
            time_t last_failure = 0;
            int failcount = failure_count(data_set, node, rsc, &last_failure);

            if (failcount <= 0) {
                continue;
            }

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, get_resource_display_options(mon_ops),
                             FALSE, NULL, is_set(mon_ops, mon_op_print_clone_detail),
                             is_set(mon_ops, mon_op_print_brief), is_set(mon_ops, mon_op_group_by_node),
                             only_node, only_rsc);
            }

            out->message(out, "resource-history", rsc, rsc_id, FALSE,
                         failcount, last_failure, FALSE);
        } else {
            GListPtr op_list = get_operation_list(rsc_entry);

            if (op_list == NULL) {
                continue;
            }

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, get_resource_display_options(mon_ops),
                             FALSE, NULL, is_set(mon_ops, mon_op_print_clone_detail),
                             is_set(mon_ops, mon_op_print_brief), is_set(mon_ops, mon_op_group_by_node),
                             only_node, only_rsc);
            }

            print_rsc_history(out, data_set, node, rsc_entry, mon_ops, op_list);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Determine whether extended information about an attribute should be added.
 *
 * \param[in]  out            The output functions structure.
 * \param[in]  node           Node that ran this resource.
 * \param[in]  rsc_list       The list of resources for this node.
 * \param[in]  attrname       The attribute to find.
 * \param[out] expected_score The expected value for this attribute.
 *
 * \return TRUE if extended information should be printed, FALSE otherwise
 * \note Currently, extended information is only supported for ping/pingd
 *       resources, for which a message will be printed if connectivity is lost
 *       or degraded.
 */
static gboolean
add_extra_info(pcmk__output_t *out, pe_node_t *node, GListPtr rsc_list,
               const char *attrname, int *expected_score)
{
    GListPtr gIter = NULL;

    for (gIter = rsc_list; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;
        const char *type = g_hash_table_lookup(rsc->meta, "type");
        const char *name = NULL;

        if (rsc->children != NULL) {
            if (add_extra_info(out, node, rsc->children, attrname, expected_score)) {
                return TRUE;
            }
        }

        if (!pcmk__str_eq(type, "ping", pcmk__str_casei) && !pcmk__str_eq(type, "pingd", pcmk__str_casei)) {
            return FALSE;
        }

        name = g_hash_table_lookup(rsc->parameters, "name");

        if (name == NULL) {
            name = "pingd";
        }

        /* To identify the resource with the attribute name. */
        if (safe_str_eq(name, attrname)) {
            int host_list_num = 0;
            /* int value = crm_parse_int(attrvalue, "0"); */
            const char *hosts = g_hash_table_lookup(rsc->parameters, "host_list");
            const char *multiplier = g_hash_table_lookup(rsc->parameters, "multiplier");

            if (hosts) {
                char **host_list = g_strsplit(hosts, " ", 0);
                host_list_num = g_strv_length(host_list);
                g_strfreev(host_list);
            }

            /* pingd multiplier is the same as the default value. */
            *expected_score = host_list_num * crm_parse_int(multiplier, "1");

            return TRUE;
        }
    }
    return FALSE;
}

/* structure for passing multiple user data to g_list_foreach() */
struct mon_attr_data {
    pcmk__output_t *out;
    pe_node_t *node;
};

static void
print_node_attribute(gpointer name, gpointer user_data)
{
    const char *value = NULL;
    int expected_score = 0;
    gboolean add_extra = FALSE;
    struct mon_attr_data *data = (struct mon_attr_data *) user_data;

    value = pe_node_attribute_raw(data->node, name);

    add_extra = add_extra_info(data->out, data->node, data->node->details->running_rsc,
                               name, &expected_score);

    /* Print attribute name and value */
    data->out->message(data->out, "node-attribute", name, value, add_extra,
                       expected_score);
}

/*!
 * \internal
 * \brief Print history for all nodes.
 *
 * \param[in] out        The output functions structure.
 * \param[in] data_set   Cluster state to display.
 * \param[in] operations Whether to print operations or just failcounts.
 * \param[in] mon_ops    Bitmask of mon_op_*.
 */
static int
print_node_summary(pcmk__output_t *out, pe_working_set_t * data_set,
                   gboolean operations, unsigned int mon_ops, GListPtr only_node,
                   GListPtr only_rsc, gboolean print_spacer)
{
    xmlNode *node_state = NULL;
    xmlNode *cib_status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(cib_status) == 0) {
        return rc;
    }

    /* Print each node in the CIB status */
    for (node_state = __xml_first_child_element(cib_status); node_state != NULL;
         node_state = __xml_next_element(node_state)) {
        pe_node_t *node;

        if (!crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            continue;
        }

        node = pe_find_node_id(data_set->nodes, ID(node_state));

        if (!node || !node->details || !node->details->online) {
            continue;
        }

        if (!pcmk__str_in_list(only_node, node->details->uname)) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, operations ? "Operations" : "Migration Summary");

        print_node_history(out, data_set, node, node_state, operations, mon_ops,
                           only_node, only_rsc);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print all tickets.
 *
 * \param[in] out      The output functions structure.
 * \param[in] data_set Cluster state to display.
 */
static int
print_cluster_tickets(pcmk__output_t *out, pe_working_set_t * data_set,
                      gboolean print_spacer)
{
    GHashTableIter iter;
    gpointer key, value;

    if (g_hash_table_size(data_set->tickets) == 0) {
        return pcmk_rc_no_output;
    }

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);

    /* Print section heading */
    out->begin_list(out, NULL, NULL, "Tickets");

    /* Print each ticket */
    g_hash_table_iter_init(&iter, data_set->tickets);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        pe_ticket_t *ticket = (pe_ticket_t *) value;
        out->message(out, "ticket", ticket);
    }

    /* Close section */
    out->end_list(out);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Print section for negative location constraints
 *
 * \param[in] out      The output functions structure.
 * \param[in] data_set Cluster state to display.
 * \param[in] mon_ops  Bitmask of mon_op_*.
 * \param[in] prefix   ID prefix to filter results by.
 */
static int
print_neg_locations(pcmk__output_t *out, pe_working_set_t *data_set,
                    unsigned int mon_ops, const char *prefix, GListPtr only_rsc,
                    gboolean print_spacer)
{
    GListPtr gIter, gIter2;
    int rc = pcmk_rc_no_output;

    /* Print each ban */
    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        pe__location_t *location = gIter->data;

        if (prefix != NULL && !g_str_has_prefix(location->id, prefix))
            continue;

        if (!pcmk__str_in_list(only_rsc, rsc_printable_id(location->rsc_lh)) &&
            !pcmk__str_in_list(only_rsc, rsc_printable_id(uber_parent(location->rsc_lh)))) {
            continue;
        }

        for (gIter2 = location->node_list_rh; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_node_t *node = (pe_node_t *) gIter2->data;

            if (node->weight < 0) {
                PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Negative Location Constraints");
                out->message(out, "ban", node, location, is_set(mon_ops, mon_op_print_clone_detail));
            }
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print node attributes section
 *
 * \param[in] out      The output functions structure.
 * \param[in] data_set Cluster state to display.
 * \param[in] mon_ops  Bitmask of mon_op_*.
 */
static int
print_node_attributes(pcmk__output_t *out, pe_working_set_t *data_set,
                      unsigned int mon_ops, GListPtr only_node,
                      GListPtr only_rsc, gboolean print_spacer)
{
    GListPtr gIter = NULL;
    int rc = pcmk_rc_no_output;

    /* Unpack all resource parameters (it would be more efficient to do this
     * only when needed for the first time in add_extra_info())
     */
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        crm_mon_get_parameters(gIter->data, data_set);
    }

    /* Display each node's attributes */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        struct mon_attr_data data;

        data.out = out;
        data.node = (pe_node_t *) gIter->data;

        if (data.node && data.node->details && data.node->details->online) {
            GList *attr_list = NULL;
            GHashTableIter iter;
            gpointer key, value;

            g_hash_table_iter_init(&iter, data.node->details->attrs);
            while (g_hash_table_iter_next (&iter, &key, &value)) {
                attr_list = append_attr_list(attr_list, key);
            }

            if (attr_list == NULL) {
                continue;
            }

            if (!pcmk__str_in_list(only_node, data.node->details->uname)) {
                continue;
            }

            PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Node Attributes");

            out->message(out, "node", data.node, get_resource_display_options(mon_ops),
                         FALSE, NULL, is_set(mon_ops, mon_op_print_clone_detail),
                         is_set(mon_ops, mon_op_print_brief), is_set(mon_ops, mon_op_group_by_node),
                         only_node, only_rsc);
            g_list_foreach(attr_list, print_node_attribute, &data);
            g_list_free(attr_list);
            out->end_list(out);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print a section for failed actions
 *
 * \param[in] out      The output functions structure.
 * \param[in] data_set Cluster state to display.
 */
static int
print_failed_actions(pcmk__output_t *out, pe_working_set_t *data_set,
                     GListPtr only_node, gboolean print_spacer)
{
    xmlNode *xml_op = NULL;
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(data_set->failed) == 0) {
        return rc;
    }

    for (xml_op = __xml_first_child(data_set->failed); xml_op != NULL;
         xml_op = __xml_next(xml_op)) {
        if (!pcmk__str_in_list(only_node, crm_element_value(xml_op, XML_ATTR_UNAME))) {
            continue;
        }

        PCMK__OUTPUT_LIST_HEADER(out, print_spacer, rc, "Failed Resource Actions");
        out->message(out, "failed-action", xml_op);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

#define CHECK_RC(retcode, retval)   \
    if (retval == pcmk_rc_ok) {     \
        retcode = pcmk_rc_ok;       \
    }

/*!
 * \internal
 * \brief Top-level printing function for text/curses output.
 *
 * \param[in] out             The output functions structure.
 * \param[in] data_set        Cluster state to display.
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
void
print_status(pcmk__output_t *out, pe_working_set_t *data_set,
             stonith_history_t *stonith_history, unsigned int mon_ops,
             unsigned int show, char *prefix, char *only_node, char *only_rsc)
{
    GListPtr unames = NULL;
    GListPtr resources = NULL;

    unsigned int print_opts = get_resource_display_options(mon_ops);
    int rc = pcmk_rc_no_output;

    CHECK_RC(rc, out->message(out, "cluster-summary", data_set,
                              is_set(mon_ops, mon_op_print_clone_detail),
                              is_set(show, mon_show_stack),
                              is_set(show, mon_show_dc),
                              is_set(show, mon_show_times),
                              is_set(show, mon_show_counts),
                              is_set(show, mon_show_options)));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    if (is_set(show, mon_show_nodes) && unames) {
        PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
        CHECK_RC(rc, out->message(out, "node-list", data_set->nodes, unames,
                                  resources, print_opts,
                                  is_set(mon_ops, mon_op_print_clone_detail),
                                  is_set(mon_ops, mon_op_print_brief),
                                  is_set(mon_ops, mon_op_group_by_node)));
    }

    /* Print resources section, if needed */
    if (is_set(show, mon_show_resources)) {
        CHECK_RC(rc, print_resources(out, data_set, print_opts, mon_ops,
                                     is_set(mon_ops, mon_op_print_brief), TRUE,
                                     unames, resources, rc == pcmk_rc_ok));
    }

    /* print Node Attributes section if requested */
    if (is_set(show, mon_show_attributes)) {
        CHECK_RC(rc, print_node_attributes(out, data_set, mon_ops, unames, resources,
                                           rc == pcmk_rc_ok));
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (is_set(show, mon_show_operations) || is_set(show, mon_show_failcounts)) {
        CHECK_RC(rc, print_node_summary(out, data_set, is_set(show, mon_show_operations),
                                        mon_ops, unames, resources, rc == pcmk_rc_ok));
    }

    /* If there were any failed actions, print them */
    if (is_set(show, mon_show_failures) && xml_has_children(data_set->failed)) {
        CHECK_RC(rc, print_failed_actions(out, data_set, unames, rc == pcmk_rc_ok));
    }

    /* Print failed stonith actions */
    if (is_set(show, mon_show_fence_failed) && is_set(mon_ops, mon_op_fence_history)) {
        stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                              GINT_TO_POINTER(st_failed));

        if (hp) {
            CHECK_RC(rc, out->message(out, "failed-fencing-history", hp, unames,
                                      is_set(mon_ops, mon_op_fence_full_history),
                                      rc == pcmk_rc_ok));
        }
    }

    /* Print tickets if requested */
    if (is_set(show, mon_show_tickets)) {
        CHECK_RC(rc, print_cluster_tickets(out, data_set, rc == pcmk_rc_ok));
    }

    /* Print negative location constraints if requested */
    if (is_set(show, mon_show_bans)) {
        CHECK_RC(rc, print_neg_locations(out, data_set, mon_ops, prefix, resources,
                                         rc == pcmk_rc_ok));
    }

    /* Print stonith history */
    if (is_set(mon_ops, mon_op_fence_history)) {
        if (is_set(show, mon_show_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                CHECK_RC(rc, out->message(out, "fencing-history", hp, unames,
                                          is_set(mon_ops, mon_op_fence_full_history),
                                          rc == pcmk_rc_ok));
            }
        } else if (is_set(show, mon_show_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                CHECK_RC(rc, out->message(out, "pending-fencing-actions", hp, unames,
                                          is_set(mon_ops, mon_op_fence_full_history),
                                          rc == pcmk_rc_ok));
            }
        }
    }

    g_list_free_full(unames, free);
}

/*!
 * \internal
 * \brief Top-level printing function for XML output.
 *
 * \param[in] out             The output functions structure.
 * \param[in] data_set        Cluster state to display.
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
void
print_xml_status(pcmk__output_t *out, pe_working_set_t *data_set,
                 crm_exit_t history_rc, stonith_history_t *stonith_history,
                 unsigned int mon_ops, unsigned int show, char *prefix,
                 char *only_node, char *only_rsc)
{
    GListPtr unames = NULL;
    GListPtr resources = NULL;
    unsigned int print_opts = get_resource_display_options(mon_ops);

    out->message(out, "cluster-summary", data_set,
                 is_set(mon_ops, mon_op_print_clone_detail),
                 is_set(show, mon_show_stack),
                 is_set(show, mon_show_dc),
                 is_set(show, mon_show_times),
                 is_set(show, mon_show_counts),
                 is_set(show, mon_show_options));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    /*** NODES ***/
    if (is_set(show, mon_show_nodes)) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, print_opts,
                     is_set(mon_ops, mon_op_print_clone_detail),
                     is_set(mon_ops, mon_op_print_brief),
                     is_set(mon_ops, mon_op_group_by_node));
    }

    /* Print resources section, if needed */
    if (is_set(show, mon_show_resources)) {
        print_resources(out, data_set, print_opts, mon_ops, FALSE, FALSE,
                        unames, resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (is_set(show, mon_show_attributes)) {
        print_node_attributes(out, data_set, mon_ops, unames, resources, FALSE);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (is_set(show, mon_show_operations) || is_set(show, mon_show_failcounts)) {
        print_node_summary(out, data_set, is_set(show, mon_show_operations),
                           mon_ops, unames, resources, FALSE);
    }

    /* If there were any failed actions, print them */
    if (is_set(show, mon_show_failures) && xml_has_children(data_set->failed)) {
        print_failed_actions(out, data_set, unames, FALSE);
    }

    /* Print stonith history */
    if (is_set(show, mon_show_fencing_all) && is_set(mon_ops, mon_op_fence_history)) {
        out->message(out, "full-fencing-history", history_rc, stonith_history,
                     unames, is_set(mon_ops, mon_op_fence_full_history), FALSE);
    }

    /* Print tickets if requested */
    if (is_set(show, mon_show_tickets)) {
        print_cluster_tickets(out, data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (is_set(show, mon_show_bans)) {
        print_neg_locations(out, data_set, mon_ops, prefix, resources, FALSE);
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
}

/*!
 * \internal
 * \brief Top-level printing function for HTML output.
 *
 * \param[in] out             The output functions structure.
 * \param[in] data_set        Cluster state to display.
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
int
print_html_status(pcmk__output_t *out, pe_working_set_t *data_set,
                  stonith_history_t *stonith_history, unsigned int mon_ops,
                  unsigned int show, char *prefix, char *only_node,
                  char *only_rsc)
{
    GListPtr unames = NULL;
    GListPtr resources = NULL;

    unsigned int print_opts = get_resource_display_options(mon_ops);

    out->message(out, "cluster-summary", data_set,
                 is_set(mon_ops, mon_op_print_clone_detail),
                 is_set(show, mon_show_stack),
                 is_set(show, mon_show_dc),
                 is_set(show, mon_show_times),
                 is_set(show, mon_show_counts),
                 is_set(show, mon_show_options));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    /*** NODE LIST ***/
    if (is_set(show, mon_show_nodes) && unames) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, print_opts,
                     is_set(mon_ops, mon_op_print_clone_detail),
                     is_set(mon_ops, mon_op_print_brief),
                     is_set(mon_ops, mon_op_group_by_node));
    }

    /* Print resources section, if needed */
    if (is_set(show, mon_show_resources)) {
        print_resources(out, data_set, print_opts, mon_ops,
                        is_set(mon_ops, mon_op_print_brief), TRUE, unames,
                        resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (is_set(show, mon_show_attributes)) {
        print_node_attributes(out, data_set, mon_ops, unames, resources, FALSE);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (is_set(show, mon_show_operations) || is_set(show, mon_show_failcounts)) {
        print_node_summary(out, data_set, is_set(show, mon_show_operations),
                           mon_ops, unames, resources, FALSE);
    }

    /* If there were any failed actions, print them */
    if (is_set(show, mon_show_failures) && xml_has_children(data_set->failed)) {
        print_failed_actions(out, data_set, unames, FALSE);
    }

    /* Print failed stonith actions */
    if (is_set(show, mon_show_fence_failed) && is_set(mon_ops, mon_op_fence_history)) {
        stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                              GINT_TO_POINTER(st_failed));

        if (hp) {
            out->message(out, "failed-fencing-history", hp, unames,
                         is_set(mon_ops, mon_op_fence_full_history), FALSE);
        }
    }

    /* Print stonith history */
    if (is_set(mon_ops, mon_op_fence_history)) {
        if (is_set(show, mon_show_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                out->message(out, "fencing-history", hp, unames,
                             is_set(mon_ops, mon_op_fence_full_history),
                             FALSE);
            }
        } else if (is_set(show, mon_show_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                out->message(out, "pending-fencing-actions", hp, unames,
                             is_set(mon_ops, mon_op_fence_full_history),
                             FALSE);
            }
        }
    }

    /* Print tickets if requested */
    if (is_set(show, mon_show_tickets)) {
        print_cluster_tickets(out, data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (is_set(show, mon_show_bans)) {
        print_neg_locations(out, data_set, mon_ops, prefix, resources, FALSE);
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
    return 0;
}
