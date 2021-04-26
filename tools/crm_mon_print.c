/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

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

/*!
 * \internal
 * \brief Return resource display options corresponding to command-line choices
 *
 * \return Bitmask of pe_print_options suitable for resource print functions
 */
static unsigned int
get_resource_display_options(unsigned int mon_ops)
{
    int print_opts = 0;

    if (pcmk_is_set(mon_ops, mon_op_print_pending)) {
        print_opts |= pe_print_pending;
    }
    if (pcmk_is_set(mon_ops, mon_op_print_clone_detail)) {
        print_opts |= pe_print_clone_details|pe_print_implicit;
    }
    if (!pcmk_is_set(mon_ops, mon_op_inactive_resources)) {
        print_opts |= pe_print_clone_active;
    }
    if (pcmk_is_set(mon_ops, mon_op_print_brief)) {
        print_opts |= pe_print_brief;
    }
    return print_opts;
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
             unsigned int show, const char *prefix, char *only_node, char *only_rsc)
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

    unames = pe__build_node_name_list(data_set, only_node);
    resources = pe__build_rsc_list(data_set, only_rsc);

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

        CHECK_RC(rc, out->message(out, "node-summary", data_set, unames,
                                  resources, pcmk_is_set(show, mon_show_operations),
                                  get_resource_display_options(mon_ops),
                                  pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                                  pcmk_is_set(mon_ops, mon_op_print_brief),
                                  pcmk_is_set(mon_ops, mon_op_group_by_node),
                                  pcmk_is_set(mon_ops, mon_op_print_timing),
                                  rc == pcmk_rc_ok));
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
        CHECK_RC(rc, out->message(out, "ticket-list", data_set, rc == pcmk_rc_ok));
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        CHECK_RC(rc, out->message(out, "ban-list", data_set, prefix, resources,
                                  pcmk_is_set(mon_ops, mon_op_print_clone_detail),
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
                 unsigned int show, const char *prefix, char *only_node, char *only_rsc)
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

    unames = pe__build_node_name_list(data_set, only_node);
    resources = pe__build_rsc_list(data_set, only_rsc);

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

        out->message(out, "node-summary", data_set, unames,
                     resources, pcmk_is_set(show, mon_show_operations),
                     get_resource_display_options(mon_ops),
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     pcmk_is_set(mon_ops, mon_op_print_timing),
                     FALSE);
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
        out->message(out, "ticket-list", data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        out->message(out, "ban-list", data_set, prefix, resources,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail), FALSE);
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
                  unsigned int show, const char *prefix, char *only_node, char *only_rsc)
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

    unames = pe__build_node_name_list(data_set, only_node);
    resources = pe__build_rsc_list(data_set, only_rsc);

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

        out->message(out, "node-summary", data_set, unames,
                     resources, pcmk_is_set(show, mon_show_operations),
                     get_resource_display_options(mon_ops),
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail),
                     pcmk_is_set(mon_ops, mon_op_print_brief),
                     pcmk_is_set(mon_ops, mon_op_group_by_node),
                     pcmk_is_set(mon_ops, mon_op_print_timing),
                     FALSE);
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
        out->message(out, "ticket-list", data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(show, mon_show_bans)) {
        out->message(out, "ban-list", data_set, prefix, resources,
                     pcmk_is_set(mon_ops, mon_op_print_clone_detail), FALSE);
    }

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);
    return 0;
}
