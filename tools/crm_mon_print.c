/*
 * Copyright 2019-2021 the Pacemaker project contributors
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

#ifndef PCMK__CONFIG_H
#  define PCMK__CONFIG_H
#  include <config.h>
#endif

#include <crm/cib/util.h>
#include <crm/common/curses_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>
#include <crm/common/internal.h>
#include <crm/common/xml_internal.h>
#include <crm/common/util.h>
#include <crm/fencing/internal.h>

#include "crm_mon.h"

static int print_rsc_history(pe_working_set_t *data_set, pe_node_t *node,
                             xmlNode *rsc_entry, unsigned int mon_ops,
                             GList *op_list);
static int print_node_history(pe_working_set_t *data_set, pe_node_t *node,
                              xmlNode *node_state, gboolean operations,
                              unsigned int mon_ops, GList *only_node,
                              GList *only_rsc);
static int print_node_summary(pe_working_set_t * data_set, gboolean operations,
                              unsigned int mon_ops, GList *only_node,
                              GList *only_rsc, gboolean print_spacer);
static int print_cluster_tickets(pe_working_set_t * data_set, gboolean print_spacer);
static int print_neg_locations(pe_working_set_t *data_set, unsigned int mon_ops,
                               const char *prefix, GList *only_rsc,
                               gboolean print_spacer);

static GList *
build_uname_list(pe_working_set_t *data_set, const char *s) {
    GList *unames = NULL;

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

static GList *
build_rsc_list(pe_working_set_t *data_set, const char *s) {
    GList *resources = NULL;

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

static int
failure_count(pe_working_set_t *data_set, pe_node_t *node, pe_resource_t *rsc, time_t *last_failure) {
    return rsc ? pe_get_failcount(node, rsc, last_failure, pe_fc_default,
                                  NULL, data_set)
               : 0;
}

static GList *
get_operation_list(xmlNode *rsc_entry) {
    GList *op_list = NULL;
    xmlNode *rsc_op = NULL;

    for (rsc_op = pcmk__xe_first_child(rsc_entry); rsc_op != NULL;
         rsc_op = pcmk__xe_next(rsc_op)) {
        const char *task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        const char *interval_ms_s = crm_element_value(rsc_op,
                                                      XML_LRM_ATTR_INTERVAL_MS);
        const char *op_rc = crm_element_value(rsc_op, XML_LRM_ATTR_RC);
        int op_rc_i = crm_parse_int(op_rc, "0");

        /* Display 0-interval monitors as "probe" */
        if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)
            && pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
            task = "probe";
        }

        /* Ignore notifies and some probes */
        if (pcmk__str_eq(task, CRMD_ACTION_NOTIFY, pcmk__str_casei) || (pcmk__str_eq(task, "probe", pcmk__str_casei) && (op_rc_i == 7))) {
            continue;
        }

        if (pcmk__str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, pcmk__str_none)) {
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
 * \param[in] data_set  Cluster state to display.
 * \param[in] node      Node that ran this resource.
 * \param[in] rsc_entry Root of XML tree describing resource status.
 * \param[in] mon_ops   Bitmask of mon_op_*.
 * \param[in] op_list   A list of operations to print.
 */
static int
print_rsc_history(pe_working_set_t *data_set, pe_node_t *node, xmlNode *rsc_entry,
                  unsigned int mon_ops, GList *op_list)
{
    pcmk__output_t *out = data_set->priv;
    GList *gIter = NULL;
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
        if (pcmk__str_eq(task, CRMD_ACTION_STATUS, pcmk__str_casei)
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
                     op_rc_i, pcmk_is_set(mon_ops, mon_op_print_timing));
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
 * \param[in] data_set   Cluster state to display.
 * \param[in] node_state Root of XML tree describing node status.
 * \param[in] operations Whether to print operations or just failcounts.
 * \param[in] mon_ops    Bitmask of mon_op_*.
 */
static int
print_node_history(pe_working_set_t *data_set, pe_node_t *node, xmlNode *node_state,
                   gboolean operations, unsigned int mon_ops,
                   GList *only_node, GList *only_rsc)
{
    pcmk__output_t *out = data_set->priv;
    xmlNode *lrm_rsc = NULL;
    xmlNode *rsc_entry = NULL;
    int rc = pcmk_rc_no_output;

    lrm_rsc = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
    lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

    /* Print history of each of the node's resources */
    for (rsc_entry = pcmk__xe_first_child(lrm_rsc); rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry)) {

        const char *rsc_id = crm_element_value(rsc_entry, XML_ATTR_ID);
        pe_resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

        if (!pcmk__str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, pcmk__str_none)) {
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
                             FALSE, NULL,
                             pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                             pcmk_is_set(mon_ops, mon_op_print_brief),
                             pcmk_is_set(mon_ops, mon_op_group_by_node),
                             only_node, only_rsc);
            }

            out->message(out, "resource-history", rsc, rsc_id, FALSE,
                         failcount, last_failure, FALSE);
        } else {
            GList *op_list = get_operation_list(rsc_entry);

            if (op_list == NULL) {
                continue;
            }

            if (rc == pcmk_rc_no_output) {
                rc = pcmk_rc_ok;
                out->message(out, "node", node, get_resource_display_options(mon_ops),
                             FALSE, NULL,
                             pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                             pcmk_is_set(mon_ops, mon_op_print_brief),
                             pcmk_is_set(mon_ops, mon_op_group_by_node),
                             only_node, only_rsc);
            }

            print_rsc_history(data_set, node, rsc_entry, mon_ops, op_list);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print history for all nodes.
 *
 * \param[in] data_set   Cluster state to display.
 * \param[in] operations Whether to print operations or just failcounts.
 * \param[in] mon_ops    Bitmask of mon_op_*.
 */
static int
print_node_summary(pe_working_set_t * data_set, gboolean operations,
                   unsigned int mon_ops, GList *only_node,
                   GList *only_rsc, gboolean print_spacer)
{
    pcmk__output_t *out = data_set->priv;
    xmlNode *node_state = NULL;
    xmlNode *cib_status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);
    int rc = pcmk_rc_no_output;

    if (xmlChildElementCount(cib_status) == 0) {
        return rc;
    }

    /* Print each node in the CIB status */
    for (node_state = pcmk__xe_first_child(cib_status); node_state != NULL;
         node_state = pcmk__xe_next(node_state)) {
        pe_node_t *node;

        if (!pcmk__str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, pcmk__str_none)) {
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

        print_node_history(data_set, node, node_state, operations, mon_ops,
                           only_node, only_rsc);
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \brief Print all tickets.
 *
 * \param[in] data_set Cluster state to display.
 */
static int
print_cluster_tickets(pe_working_set_t * data_set, gboolean print_spacer)
{
    pcmk__output_t *out = data_set->priv;
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
 * \param[in] data_set Cluster state to display.
 * \param[in] mon_ops  Bitmask of mon_op_*.
 * \param[in] prefix   ID prefix to filter results by.
 */
static int
print_neg_locations(pe_working_set_t *data_set, unsigned int mon_ops,
                    const char *prefix, GList *only_rsc,
                    gboolean print_spacer)
{
    pcmk__output_t *out = data_set->priv;
    GList *gIter, *gIter2;
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
                out->message(out, "ban", node, location,
                             pcmk_is_set(mon_ops, mon_op_print_clone_detail));
            }
        }
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
 * \param[in] data_set        Cluster state to display.
 * \param[in] history_rc      Result of getting stonith history
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
void
print_status(pe_working_set_t *data_set, crm_exit_t history_rc,
             stonith_history_t *stonith_history, unsigned int mon_ops,
             unsigned int show, char *prefix, char *only_node, char *only_rsc)
{
    pcmk__output_t *out = data_set->priv;
    GList *unames = NULL;
    GList *resources = NULL;

    unsigned int print_opts = get_resource_display_options(mon_ops);
    int rc = pcmk_rc_no_output;
    bool already_printed_failure = false;

    CHECK_RC(rc, out->message(out, "cluster-summary", data_set,
                              pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                              pcmk_is_set(show, mon_show_stack),
                              pcmk_is_set(show, mon_show_dc),
                              pcmk_is_set(show, mon_show_times),
                              pcmk_is_set(show, mon_show_counts),
                              pcmk_is_set(show, mon_show_options)));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    if (pcmk_is_set(show, mon_show_nodes) && unames) {
        PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
        CHECK_RC(rc, out->message(out, "node-list", data_set->nodes, unames,
                                  resources, print_opts,
                                  pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                                  pcmk_is_set(mon_ops, mon_op_print_brief),
                                  pcmk_is_set(mon_ops, mon_op_group_by_node)));
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(show, mon_show_resources)) {
        CHECK_RC(rc, out->message(out, "resource-list", data_set, print_opts,
                                  pcmk_is_set(mon_ops, mon_op_group_by_node),
                                  pcmk_is_set(mon_ops, mon_op_inactive_resources),
                                  pcmk_is_set(mon_ops, mon_op_print_brief), TRUE, unames,
                                  resources, rc == pcmk_rc_ok));
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(show, mon_show_attributes)) {
        CHECK_RC(rc, out->message(out, "node-attribute-list", data_set,
                                  get_resource_display_options(mon_ops),
                                  rc == pcmk_rc_ok,
                                  pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                                  pcmk_is_set(mon_ops, mon_op_print_brief),
                                  pcmk_is_set(mon_ops, mon_op_group_by_node),
                                  unames, resources));
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_is_set(show, mon_show_operations)
        || pcmk_is_set(show, mon_show_failcounts)) {

        CHECK_RC(rc, print_node_summary(data_set,
                                        pcmk_is_set(show, mon_show_operations),
                                        mon_ops, unames, resources,
                                        (rc == pcmk_rc_ok)));
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(show, mon_show_failures)
        && xml_has_children(data_set->failed)) {

        CHECK_RC(rc, out->message(out, "failed-action-list", data_set, unames,
                                  resources, rc == pcmk_rc_ok));
    }

    /* Print failed stonith actions */
    if (pcmk_is_set(show, mon_show_fence_failed)
        && pcmk_is_set(mon_ops, mon_op_fence_history)) {

        if (history_rc == 0) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                CHECK_RC(rc, out->message(out, "failed-fencing-list", stonith_history, unames,
                                          pcmk_is_set(mon_ops, mon_op_fence_full_history),
                                          rc == pcmk_rc_ok));
            }
        } else {
            PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
            out->list_item(out, NULL, "Failed to get fencing history: %s",
                           crm_exit_str(history_rc));
            out->end_list(out);

            already_printed_failure = true;
        }
    }

    /* Print tickets if requested */
    if (pcmk_is_set(show, mon_show_tickets)) {
        CHECK_RC(rc, print_cluster_tickets(data_set, rc == pcmk_rc_ok));
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        CHECK_RC(rc, print_neg_locations(data_set, mon_ops, prefix, resources,
                                         rc == pcmk_rc_ok));
    }

    /* Print stonith history */
    if (pcmk_is_set(mon_ops, mon_op_fence_history)) {
        if (history_rc != 0) {
            if (!already_printed_failure) {
                PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk_is_set(show, mon_show_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                CHECK_RC(rc, out->message(out, "fencing-list", hp, unames,
                                          pcmk_is_set(mon_ops, mon_op_fence_full_history),
                                          rc == pcmk_rc_ok));
            }
        } else if (pcmk_is_set(show, mon_show_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                CHECK_RC(rc, out->message(out, "pending-fencing-list", hp, unames,
                                          pcmk_is_set(mon_ops, mon_op_fence_full_history),
                                          rc == pcmk_rc_ok));
            }
        }
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
}

/*!
 * \internal
 * \brief Top-level printing function for XML output.
 *
 * \param[in] data_set        Cluster state to display.
 * \param[in] history_rc      Result of getting stonith history
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
void
print_xml_status(pe_working_set_t *data_set, crm_exit_t history_rc,
                 stonith_history_t *stonith_history, unsigned int mon_ops,
                 unsigned int show, char *prefix, char *only_node, char *only_rsc)
{
    pcmk__output_t *out = data_set->priv;
    GList *unames = NULL;
    GList *resources = NULL;
    unsigned int print_opts = get_resource_display_options(mon_ops);

    out->message(out, "cluster-summary", data_set,
                 pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                 pcmk_is_set(show, mon_show_stack),
                 pcmk_is_set(show, mon_show_dc),
                 pcmk_is_set(show, mon_show_times),
                 pcmk_is_set(show, mon_show_counts),
                 pcmk_is_set(show, mon_show_options));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    /*** NODES ***/
    if (pcmk_is_set(show, mon_show_nodes)) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, print_opts,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node));
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(show, mon_show_resources)) {
        out->message(out, "resource-list", data_set, print_opts,
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     pcmk_is_set(mon_ops, mon_op_inactive_resources),
                     FALSE, FALSE, unames, resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(show, mon_show_attributes)) {
        out->message(out, "node-attribute-list", data_set,
                     get_resource_display_options(mon_ops), FALSE,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_is_set(show, mon_show_operations)
        || pcmk_is_set(show, mon_show_failcounts)) {

        print_node_summary(data_set,
                           pcmk_is_set(show, mon_show_operations),
                           mon_ops, unames, resources, FALSE);
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(show, mon_show_failures)
        && xml_has_children(data_set->failed)) {

        out->message(out, "failed-action-list", data_set, unames, resources,
                     FALSE);
    }

    /* Print stonith history */
    if (pcmk_is_set(show, mon_show_fencing_all)
        && pcmk_is_set(mon_ops, mon_op_fence_history)) {

        out->message(out, "full-fencing-list", history_rc, stonith_history,
                     unames, pcmk_is_set(mon_ops, mon_op_fence_full_history),
                     FALSE);
    }

    /* Print tickets if requested */
    if (pcmk_is_set(show, mon_show_tickets)) {
        print_cluster_tickets(data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        print_neg_locations(data_set, mon_ops, prefix, resources, FALSE);
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
}

/*!
 * \internal
 * \brief Top-level printing function for HTML output.
 *
 * \param[in] data_set        Cluster state to display.
 * \param[in] history_rc      Result of getting stonith history
 * \param[in] stonith_history List of stonith actions.
 * \param[in] mon_ops         Bitmask of mon_op_*.
 * \param[in] show            Bitmask of mon_show_*.
 * \param[in] prefix          ID prefix to filter results by.
 */
int
print_html_status(pe_working_set_t *data_set, crm_exit_t history_rc,
                  stonith_history_t *stonith_history, unsigned int mon_ops,
                  unsigned int show, char *prefix, char *only_node, char *only_rsc)
{
    pcmk__output_t *out = data_set->priv;
    GList *unames = NULL;
    GList *resources = NULL;

    unsigned int print_opts = get_resource_display_options(mon_ops);
    bool already_printed_failure = false;

    out->message(out, "cluster-summary", data_set,
                 pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                 pcmk_is_set(show, mon_show_stack),
                 pcmk_is_set(show, mon_show_dc),
                 pcmk_is_set(show, mon_show_times),
                 pcmk_is_set(show, mon_show_counts),
                 pcmk_is_set(show, mon_show_options));

    unames = build_uname_list(data_set, only_node);
    resources = build_rsc_list(data_set, only_rsc);

    /*** NODE LIST ***/
    if (pcmk_is_set(show, mon_show_nodes) && unames) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, print_opts,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node));
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(show, mon_show_resources)) {
        out->message(out, "resource-list", data_set, print_opts,
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     pcmk_is_set(mon_ops, mon_op_inactive_resources),
                     pcmk_is_set(mon_ops, mon_op_print_brief), TRUE, unames,
                     resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(show, mon_show_attributes)) {
        out->message(out, "node-attribute-list", data_set,
                     get_resource_display_options(mon_ops), FALSE,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_is_set(show, mon_show_operations)
        || pcmk_is_set(show, mon_show_failcounts)) {

        print_node_summary(data_set,
                           pcmk_is_set(show, mon_show_operations),
                           mon_ops, unames, resources, FALSE);
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(show, mon_show_failures)
        && xml_has_children(data_set->failed)) {

        out->message(out, "failed-action-list", data_set, unames, resources,
                     FALSE);
    }

    /* Print failed stonith actions */
    if (pcmk_is_set(show, mon_show_fence_failed)
        && pcmk_is_set(mon_ops, mon_op_fence_history)) {

        if (history_rc == 0) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                out->message(out, "failed-fencing-list", stonith_history, unames,
                             pcmk_is_set(mon_ops, mon_op_fence_full_history), FALSE);
            }
        } else {
            out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
            out->list_item(out, NULL, "Failed to get fencing history: %s",
                           crm_exit_str(history_rc));
            out->end_list(out);
        }
    }

    /* Print stonith history */
    if (pcmk_is_set(mon_ops, mon_op_fence_history)) {
        if (history_rc != 0) {
            if (!already_printed_failure) {
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk_is_set(show, mon_show_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                out->message(out, "fencing-list", hp, unames,
                             pcmk_is_set(mon_ops, mon_op_fence_full_history),
                             FALSE);
            }
        } else if (pcmk_is_set(show, mon_show_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                out->message(out, "pending-fencing-list", hp, unames,
                             pcmk_is_set(mon_ops, mon_op_fence_full_history),
                             FALSE);
            }
        }
    }

    /* Print tickets if requested */
    if (pcmk_is_set(show, mon_show_tickets)) {
        print_cluster_tickets(data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        print_neg_locations(data_set, mon_ops, prefix, resources, FALSE);
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
    return 0;
}
