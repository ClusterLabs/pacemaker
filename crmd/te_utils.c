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

#include <sys/param.h>
#include <crm/crm.h>

#include <crm/msg_xml.h>

#include <crm/common/xml.h>
#include <tengine.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crm/fencing/internal.h>

crm_trigger_t *stonith_reconnect = NULL;
GListPtr stonith_cleanup_list = NULL;

static gboolean
fail_incompletable_stonith(crm_graph_t * graph)
{
    GListPtr lpc = NULL;
    const char *task = NULL;
    xmlNode *last_action = NULL;

    if (graph == NULL) {
        return FALSE;
    }

    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        GListPtr lpc2 = NULL;
        synapse_t *synapse = (synapse_t *) lpc->data;

        if (synapse->confirmed) {
            continue;
        }

        for (lpc2 = synapse->actions; lpc2 != NULL; lpc2 = lpc2->next) {
            crm_action_t *action = (crm_action_t *) lpc2->data;

            if (action->type != action_type_crm || action->confirmed) {
                continue;
            }

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
            if (task && safe_str_eq(task, CRM_OP_FENCE)) {
                action->failed = TRUE;
                last_action = action->xml;
                update_graph(graph, action);
                crm_notice("Failing action %d (%s): STONITHd terminated",
                           action->id, ID(action->xml));
            }
        }
    }

    if (last_action != NULL) {
        crm_warn("STONITHd failure resulted in un-runnable actions");
        abort_transition(INFINITY, tg_restart, "Stonith failure", last_action);
        return TRUE;
    }

    return FALSE;
}

static void
tengine_stonith_connection_destroy(stonith_t * st, stonith_event_t * e)
{
    if (is_set(fsa_input_register, R_ST_REQUIRED)) {
        crm_crit("Fencing daemon connection failed");
        mainloop_set_trigger(stonith_reconnect);

    } else {
        crm_info("Fencing daemon disconnected");
    }

    /* cbchan will be garbage at this point, arrange for it to be reset */
    stonith_api->state = stonith_disconnected;

    if (AM_I_DC) {
        fail_incompletable_stonith(transition_graph);
        trigger_graph();
    }
}

#if SUPPORT_CMAN
#  include <libfenced.h>
#endif

static void
tengine_stonith_notify(stonith_t * st, stonith_event_t * st_event)
{
    if (st_event == NULL) {
        crm_err("Notify data not found");
        return;
    }

    if (st_event->result == pcmk_ok && crm_str_eq(st_event->target, fsa_our_uname, TRUE)) {
        crm_err("We were alegedly just fenced by %s for %s!", st_event->executioner,
                st_event->origin);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
        return;
    }

    crm_notice("Peer %s was%s terminated (%s) by %s for %s: %s (ref=%s) by client %s",
               st_event->target, st_event->result == pcmk_ok ? "" : " not",
               st_event->operation,
               st_event->executioner ? st_event->executioner : "<anyone>",
               st_event->origin, pcmk_strerror(st_event->result), st_event->id,
               st_event->client_origin ? st_event->client_origin : "<unknown>");

#if SUPPORT_CMAN
    if (st_event->result == pcmk_ok && is_cman_cluster()) {
        int local_rc = 0;
        char *target_copy = strdup(st_event->target);

        /* In case fenced hasn't noticed yet
         *
         * Any fencing that has been inititated will be completed by way of the fence_pcmk redirect
         */
        local_rc = fenced_external(target_copy);
        if (local_rc != 0) {
            crm_err("Could not notify CMAN that '%s' is now fenced: %d", st_event->target,
                    local_rc);
        } else {
            crm_notice("Notified CMAN that '%s' is now fenced", st_event->target);
        }
        free(target_copy);
    }
#endif

    if (st_event->result == pcmk_ok) {
        gboolean we_are_executioner = safe_str_eq(st_event->executioner, fsa_our_uname);

        crm_trace("target=%s dc=%s", st_event->target, fsa_our_dc);
        if (fsa_our_dc == NULL || safe_str_eq(fsa_our_dc, st_event->target)) {
            crm_notice("Target %s our leader %s (recorded: %s)",
                       fsa_our_dc ? "was" : "may have been", st_event->target,
                       fsa_our_dc ? fsa_our_dc : "<unset>");

            /* Given the CIB resyncing that occurs around elections,
             * have one node update the CIB now and, if the new DC is different,
             * have them do so too after the election
             */
            if (we_are_executioner) {
                const char *uuid = get_uuid(st_event->target);

                send_stonith_update(NULL, st_event->target, uuid);
            }
            stonith_cleanup_list = g_list_append(stonith_cleanup_list, strdup(st_event->target));

        } else if (AM_I_DC &&
                   st_event->client_origin &&
                   safe_str_neq(st_event->client_origin, crm_system_name)) {
            const char *uuid = get_uuid(st_event->target);

            /* If a remote process outside of pacemaker invoked stonith to
             * fence someone, report the fencing result to the cib
             * and abort the transition graph. */
            crm_info("External fencing operation from %s fenced %s", st_event->client_origin,
                     st_event->target);
            send_stonith_update(NULL, st_event->target, uuid);
            abort_transition(INFINITY, tg_restart, "External Fencing Operation", NULL);
        }
    }
}

gboolean
te_connect_stonith(gpointer user_data)
{
    int lpc = 0;
    int rc = pcmk_ok;

    if (stonith_api == NULL) {
        stonith_api = stonith_api_new();
    }

    if (stonith_api->state != stonith_disconnected) {
        crm_trace("Still connected");
        return TRUE;
    }

    for (lpc = 0; lpc < 30; lpc++) {
        crm_debug("Attempting connection to fencing daemon...");

        sleep(1);
        rc = stonith_api->cmds->connect(stonith_api, crm_system_name, NULL);

        if (rc == pcmk_ok) {
            break;
        }

        if (user_data != NULL) {
            crm_err("Sign-in failed: triggered a retry");
            mainloop_set_trigger(stonith_reconnect);
            return TRUE;
        }

        crm_err("Sign-in failed: pausing and trying again in 2s...");
        sleep(1);
    }

    CRM_CHECK(rc == pcmk_ok, return TRUE);      /* If not, we failed 30 times... just get out */
    stonith_api->cmds->register_notification(stonith_api, T_STONITH_NOTIFY_DISCONNECT,
                                             tengine_stonith_connection_destroy);

    stonith_api->cmds->register_notification(stonith_api, T_STONITH_NOTIFY_FENCE,
                                             tengine_stonith_notify);

    crm_trace("Connected");
    return TRUE;
}

gboolean
stop_te_timer(crm_action_timer_t * timer)
{
    const char *timer_desc = "action timer";

    if (timer == NULL) {
        return FALSE;
    }
    if (timer->reason == timeout_abort) {
        timer_desc = "global timer";
        crm_trace("Stopping %s", timer_desc);
    }

    if (timer->source_id != 0) {
        crm_trace("Stopping %s", timer_desc);
        g_source_remove(timer->source_id);
        timer->source_id = 0;

    } else {
        crm_trace("%s was already stopped", timer_desc);
        return FALSE;
    }

    return TRUE;
}

gboolean
te_graph_trigger(gpointer user_data)
{
    enum transition_status graph_rc = -1;

    if (transition_graph == NULL) {
        crm_debug("Nothing to do");
        return TRUE;
    }

    crm_trace("Invoking graph %d in state %s", transition_graph->id, fsa_state2string(fsa_state));

    switch (fsa_state) {
        case S_STARTING:
        case S_PENDING:
        case S_NOT_DC:
        case S_HALT:
        case S_ILLEGAL:
        case S_STOPPING:
        case S_TERMINATE:
            return TRUE;
            break;
        default:
            break;
    }

    if (transition_graph->complete == FALSE) {
        graph_rc = run_graph(transition_graph);
        print_graph(LOG_DEBUG_3, transition_graph);

        if (graph_rc == transition_active) {
            crm_trace("Transition not yet complete");
            return TRUE;

        } else if (graph_rc == transition_pending) {
            crm_trace("Transition not yet complete - no actions fired");
            return TRUE;
        }

        if (graph_rc != transition_complete) {
            crm_warn("Transition failed: %s", transition_status(graph_rc));
            print_graph(LOG_NOTICE, transition_graph);
        }
    }

    crm_debug("Transition %d is now complete", transition_graph->id);
    transition_graph->complete = TRUE;
    notify_crmd(transition_graph);

    return TRUE;
}

void
trigger_graph_processing(const char *fn, int line)
{
    mainloop_set_trigger(transition_trigger);
    crm_trace("%s:%d - Triggered graph processing", fn, line);
}

void
abort_transition_graph(int abort_priority, enum transition_action abort_action,
                       const char *abort_text, xmlNode * reason, const char *fn, int line)
{
    const char *magic = NULL;

    CRM_CHECK(transition_graph != NULL, return);

    if (reason) {
        int diff_add_updates = 0;
        int diff_add_epoch = 0;
        int diff_add_admin_epoch = 0;

        int diff_del_updates = 0;
        int diff_del_epoch = 0;
        int diff_del_admin_epoch = 0;
        xmlNode *diff = get_xpath_object("//" F_CIB_UPDATE_RESULT "//diff", reason, LOG_DEBUG_2);

        magic = crm_element_value(reason, XML_ATTR_TRANSITION_MAGIC);

        if (diff) {
            cib_diff_version_details(diff,
                                     &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                                     &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);
            if (crm_str_eq(TYPE(reason), XML_CIB_TAG_NVPAIR, TRUE)) {
                crm_info
                    ("%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, name=%s, value=%s, magic=%s, cib=%d.%d.%d) : %s",
                     fn, line, transition_graph->complete, TYPE(reason), ID(reason), NAME(reason),
                     VALUE(reason), magic ? magic : "NA", diff_add_admin_epoch, diff_add_epoch,
                     diff_add_updates, abort_text);
            } else {
                crm_info
                    ("%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, magic=%s, cib=%d.%d.%d) : %s",
                     fn, line, transition_graph->complete, TYPE(reason), ID(reason),
                     magic ? magic : "NA", diff_add_admin_epoch, diff_add_epoch, diff_add_updates,
                     abort_text);
            }

        } else {
            crm_info
                ("%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, magic=%s) : %s",
                 fn, line, transition_graph->complete, TYPE(reason), ID(reason),
                 magic ? magic : "NA", abort_text);
        }

    } else {
        crm_info("%s:%d - Triggered transition abort (complete=%d) : %s",
                 fn, line, transition_graph->complete, abort_text);
    }

    switch (fsa_state) {
        case S_STARTING:
        case S_PENDING:
        case S_NOT_DC:
        case S_HALT:
        case S_ILLEGAL:
        case S_STOPPING:
        case S_TERMINATE:
            crm_info("Abort suppressed: state=%s (complete=%d)",
                     fsa_state2string(fsa_state), transition_graph->complete);
            return;
        default:
            break;
    }

    if (magic == NULL && reason != NULL) {
        crm_log_xml_debug(reason, "Cause");
    }

    /* Make sure any queued calculations are discarded ASAP */
    free(fsa_pe_ref);
    fsa_pe_ref = NULL;

    if (transition_graph->complete) {
        if (transition_timer->period_ms > 0) {
            crm_timer_stop(transition_timer);
            crm_timer_start(transition_timer);
        } else if (too_many_st_failures() == FALSE) {
            register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);
        }
        return;
    }

    update_abort_priority(transition_graph, abort_priority, abort_action, abort_text);

    mainloop_set_trigger(transition_trigger);
}
