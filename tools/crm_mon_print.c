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
#include <crm/common/output.h>
#include <crm/fencing/internal.h>
#include <pacemaker.h>

#include "crm_mon.h"

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
             stonith_history_t *stonith_history, gboolean fence_history,
             unsigned int mon_ops, unsigned int print_opts,
             unsigned int section_opts, unsigned int show_opts,
             const char *prefix, GList *unames, GList *resources)
{
    pcmk__output_t *out = data_set->priv;

    int rc = pcmk_rc_no_output;
    bool already_printed_failure = false;

    CHECK_RC(rc, out->message(out, "cluster-summary", data_set,
                              section_opts, show_opts));

    if (pcmk_is_set(section_opts, pcmk_section_nodes) && unames) {
        PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
        CHECK_RC(rc, out->message(out, "node-list", data_set->nodes, unames,
                                  resources, show_opts, print_opts));
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(section_opts, pcmk_section_resources)) {
        CHECK_RC(rc, out->message(out, "resource-list", data_set, show_opts, print_opts,
                                  TRUE, unames, resources, rc == pcmk_rc_ok));
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(section_opts, pcmk_section_attributes)) {
        CHECK_RC(rc, out->message(out, "node-attribute-list", data_set,
                                  show_opts, print_opts, rc == pcmk_rc_ok,
                                  unames, resources));
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_any_flags_set(section_opts, pcmk_section_operations | pcmk_section_failcounts)) {
        CHECK_RC(rc, out->message(out, "node-summary", data_set, unames,
                                  resources, section_opts, show_opts, print_opts,
                                  rc == pcmk_rc_ok));
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(section_opts, pcmk_section_failures)
        && xml_has_children(data_set->failed)) {

        CHECK_RC(rc, out->message(out, "failed-action-list", data_set, unames,
                                  resources, rc == pcmk_rc_ok));
    }

    /* Print failed stonith actions */
    if (pcmk_is_set(section_opts, pcmk_section_fence_failed) && fence_history) {
        if (history_rc == 0) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                CHECK_RC(rc, out->message(out, "failed-fencing-list", stonith_history, unames,
                                          section_opts, rc == pcmk_rc_ok));
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
    if (pcmk_is_set(section_opts, pcmk_section_tickets)) {
        CHECK_RC(rc, out->message(out, "ticket-list", data_set, rc == pcmk_rc_ok));
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(section_opts, pcmk_section_bans)) {
        CHECK_RC(rc, out->message(out, "ban-list", data_set, prefix, resources,
                                  show_opts, rc == pcmk_rc_ok));
    }

    /* Print stonith history */
    if (fence_history && pcmk_any_flags_set(section_opts, pcmk_section_fencing_all)) {
        if (history_rc != 0) {
            if (!already_printed_failure) {
                PCMK__OUTPUT_SPACER_IF(out, rc == pcmk_rc_ok);
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk_is_set(section_opts, pcmk_section_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                CHECK_RC(rc, out->message(out, "fencing-list", hp, unames,
                                          section_opts, rc == pcmk_rc_ok));
            }
        } else if (pcmk_is_set(section_opts, pcmk_section_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                CHECK_RC(rc, out->message(out, "pending-fencing-list", hp, unames,
                                          section_opts, rc == pcmk_rc_ok));
            }
        }
    }
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
                 stonith_history_t *stonith_history, gboolean fence_history,
                 unsigned int mon_ops, unsigned int print_opts,
                 unsigned int section_opts, unsigned int show_opts,
                 const char *prefix, GList *unames, GList *resources)
{
    pcmk__output_t *out = data_set->priv;

    out->message(out, "cluster-summary", data_set, section_opts, show_opts);

    /*** NODES ***/
    if (pcmk_is_set(section_opts, pcmk_section_nodes)) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, show_opts, print_opts);
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(section_opts, pcmk_section_resources)) {
        /* XML output always displays full details. */
        unsigned int full_show_opts = show_opts & ~pcmk_show_brief;

        out->message(out, "resource-list", data_set, full_show_opts, print_opts,
                     FALSE, unames, resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(section_opts, pcmk_section_attributes)) {
        out->message(out, "node-attribute-list", data_set,
                     show_opts, print_opts, FALSE,
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_any_flags_set(section_opts, pcmk_section_operations | pcmk_section_failcounts)) {
        out->message(out, "node-summary", data_set, unames,
                     resources, section_opts, show_opts, print_opts,
                     FALSE);
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(section_opts, pcmk_section_failures)
        && xml_has_children(data_set->failed)) {

        out->message(out, "failed-action-list", data_set, unames, resources,
                     FALSE);
    }

    /* Print stonith history */
    if (pcmk_is_set(section_opts, pcmk_section_fencing_all) && fence_history) {
        out->message(out, "full-fencing-list", history_rc, stonith_history,
                     unames, section_opts, FALSE);
    }

    /* Print tickets if requested */
    if (pcmk_is_set(section_opts, pcmk_section_tickets)) {
        out->message(out, "ticket-list", data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(section_opts, pcmk_section_bans)) {
        out->message(out, "ban-list", data_set, prefix, resources, show_opts,
                     FALSE);
    }
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
                  stonith_history_t *stonith_history, gboolean fence_history,
                  unsigned int mon_ops, unsigned int print_opts,
                  unsigned int section_opts, unsigned int show_opts,
                  const char *prefix, GList *unames, GList *resources)
{
    pcmk__output_t *out = data_set->priv;

    bool already_printed_failure = false;

    out->message(out, "cluster-summary", data_set, section_opts, show_opts);

    /*** NODE LIST ***/
    if (pcmk_is_set(section_opts, pcmk_section_nodes) && unames) {
        out->message(out, "node-list", data_set->nodes, unames,
                     resources, show_opts, print_opts);
    }

    /* Print resources section, if needed */
    if (pcmk_is_set(section_opts, pcmk_section_resources)) {
        out->message(out, "resource-list", data_set, show_opts, print_opts,
                     TRUE, unames, resources, FALSE);
    }

    /* print Node Attributes section if requested */
    if (pcmk_is_set(section_opts, pcmk_section_attributes)) {
        out->message(out, "node-attribute-list", data_set,
                     show_opts, print_opts, FALSE,
                     unames, resources);
    }

    /* If requested, print resource operations (which includes failcounts)
     * or just failcounts
     */
    if (pcmk_any_flags_set(section_opts, pcmk_section_operations | pcmk_section_failcounts)) {
        out->message(out, "node-summary", data_set, unames,
                     resources, section_opts, show_opts, print_opts,
                     FALSE);
    }

    /* If there were any failed actions, print them */
    if (pcmk_is_set(section_opts, pcmk_section_failures)
        && xml_has_children(data_set->failed)) {

        out->message(out, "failed-action-list", data_set, unames, resources,
                     FALSE);
    }

    /* Print failed stonith actions */
    if (pcmk_is_set(section_opts, pcmk_section_fence_failed) && fence_history) {
        if (history_rc == 0) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_eq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                out->message(out, "failed-fencing-list", stonith_history, unames,
                             section_opts, FALSE);
            }
        } else {
            out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
            out->list_item(out, NULL, "Failed to get fencing history: %s",
                           crm_exit_str(history_rc));
            out->end_list(out);
        }
    }

    /* Print stonith history */
    if (fence_history && pcmk_any_flags_set(section_opts, pcmk_section_fencing_all)) {
        if (history_rc != 0) {
            if (!already_printed_failure) {
                out->begin_list(out, NULL, NULL, "Failed Fencing Actions");
                out->list_item(out, NULL, "Failed to get fencing history: %s",
                               crm_exit_str(history_rc));
                out->end_list(out);
            }
        } else if (pcmk_is_set(section_opts, pcmk_section_fence_worked)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_neq,
                                                                  GINT_TO_POINTER(st_failed));

            if (hp) {
                out->message(out, "fencing-list", hp, unames, section_opts, FALSE);
            }
        } else if (pcmk_is_set(section_opts, pcmk_section_fence_pending)) {
            stonith_history_t *hp = stonith__first_matching_event(stonith_history, stonith__event_state_pending, NULL);

            if (hp) {
                out->message(out, "pending-fencing-list", hp, unames,
                             section_opts, FALSE);
            }
        }
    }

    /* Print tickets if requested */
    if (pcmk_is_set(section_opts, pcmk_section_tickets)) {
        out->message(out, "ticket-list", data_set, FALSE);
    }

    /* Print negative location constraints if requested */
    if (pcmk_is_set(section_opts, pcmk_section_bans)) {
        out->message(out, "ban-list", data_set, prefix, resources, show_opts,
                     FALSE);
    }

    return 0;
}
