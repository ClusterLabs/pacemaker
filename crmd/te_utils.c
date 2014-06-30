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
#include <throttle.h>
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
    if(stonith_api) {
        stonith_api->state = stonith_disconnected;
    }

    if (AM_I_DC) {
        fail_incompletable_stonith(transition_graph);
        trigger_graph();
    }
}

#if SUPPORT_CMAN
#  include <libfenced.h>
#endif

char *te_client_id = NULL;

#ifdef HAVE_SYS_REBOOT_H
#  include <unistd.h>
#  include <sys/reboot.h>
#endif

static void
tengine_stonith_notify(stonith_t * st, stonith_event_t * st_event)
{
    if(te_client_id == NULL) {
        te_client_id = g_strdup_printf("%s.%d", crm_system_name, getpid());
    }

    if (st_event == NULL) {
        crm_err("Notify data not found");
        return;
    }

    if (st_event->result == pcmk_ok && safe_str_eq("on", st_event->action)) {
        crm_notice("%s was successfully unfenced by %s (at the request of %s)",
                   st_event->target, st_event->executioner, st_event->origin);
                /* TODO: Hook up st_event->device */
        return;

    } else if (safe_str_eq("on", st_event->action)) {
        crm_err("Unfencing of %s by %s failed: %s (%d)",
                st_event->target, st_event->executioner,
                pcmk_strerror(st_event->result), st_event->result);
        return;

    } else if (st_event->result == pcmk_ok && crm_str_eq(st_event->target, fsa_our_uname, TRUE)) {
        crm_crit("We were allegedly just fenced by %s for %s!",
                 st_event->executioner, st_event->origin); /* Dumps blackbox if enabled */

        qb_log_fini(); /* Try to get the above log message to disk - somehow */

        /* Get out ASAP and do not come back up.
         *
         * Triggering a reboot is also not the worst idea either since
         * the rest of the cluster thinks we're safely down
         */

#ifdef RB_HALT_SYSTEM
        reboot(RB_HALT_SYSTEM);
#endif

        /*
         * If reboot() fails or is not supported, coming back up will
         * probably lead to a situation where the other nodes set our
         * status to 'lost' because of the fencing callback and will
         * discard subsequent election votes with:
         *
         * Election 87 (current: 5171, owner: 103): Processed vote from east-03 (Peer is not part of our cluster)
         *
         * So just stay dead, something is seriously messed up anyway.
         *
         */
        exit(100); /* None of our wrappers since we already called qb_log_fini() */
        return;
    }

    if (st_event->result == pcmk_ok &&
        safe_str_eq(st_event->operation, T_STONITH_NOTIFY_FENCE)) {
        st_fail_count_reset(st_event->target);
    }

    crm_notice("Peer %s was%s terminated (%s) by %s for %s: %s (ref=%s) by client %s",
               st_event->target, st_event->result == pcmk_ok ? "" : " not",
               st_event->action,
               st_event->executioner ? st_event->executioner : "<anyone>",
               st_event->origin, pcmk_strerror(st_event->result), st_event->id,
               st_event->client_origin ? st_event->client_origin : "<unknown>");

#if SUPPORT_CMAN
    if (st_event->result == pcmk_ok && is_cman_cluster()) {
        int local_rc = 0;
        int confirm = 0;
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

        /* In case fenced is already trying to shoot it */
        confirm = open("/var/run/cluster/fenced_override", O_NONBLOCK|O_WRONLY);
        if (confirm) {
            int ignore = 0;
            int len = strlen(target_copy);

            errno = 0;
            local_rc = write(confirm, target_copy, len);
            ignore = write(confirm, "\n", 1);

            if(ignore < 0 && errno == EBADF) {
                crm_trace("CMAN not expecting %s to be fenced (yet)", st_event->target);

            } else if (local_rc < len) {
                crm_perror(LOG_ERR, "Confirmation of CMAN fencing event for '%s' failed: %d", st_event->target, local_rc);

            } else {
                fsync(confirm);
                crm_notice("Confirmed CMAN fencing event for '%s'", st_event->target);
            }
            close(confirm);
        }
        free(target_copy);
    }
#endif

    if (st_event->result == pcmk_ok) {
        crm_node_t *peer = crm_find_peer_full(0, st_event->target, CRM_GET_PEER_REMOTE | CRM_GET_PEER_CLUSTER);
        const char *uuid = NULL;
        gboolean we_are_executioner = safe_str_eq(st_event->executioner, fsa_our_uname);

        if (peer == NULL) {
            return;
        }

        uuid = crm_peer_uuid(peer);

        crm_trace("target=%s dc=%s", st_event->target, fsa_our_dc);
        if(AM_I_DC) {
            /* The DC always sends updates */
            send_stonith_update(NULL, st_event->target, uuid);

            if (st_event->client_origin && safe_str_neq(st_event->client_origin, te_client_id)) {

                /* Abort the current transition graph if it wasn't us
                 * that invoked stonith to fence someone
                 */
                crm_info("External fencing operation from %s fenced %s", st_event->client_origin, st_event->target);
                abort_transition(INFINITY, tg_restart, "External Fencing Operation", NULL);
            }

            /* Assume it was our leader if we dont currently have one */
        } else if (fsa_our_dc == NULL || safe_str_eq(fsa_our_dc, st_event->target)) {
            crm_notice("Target %s our leader %s (recorded: %s)",
                       fsa_our_dc ? "was" : "may have been", st_event->target,
                       fsa_our_dc ? fsa_our_dc : "<unset>");

            /* Given the CIB resyncing that occurs around elections,
             * have one node update the CIB now and, if the new DC is different,
             * have them do so too after the election
             */
            if (we_are_executioner) {
                send_stonith_update(NULL, st_event->target, uuid);
            }
            stonith_cleanup_list = g_list_append(stonith_cleanup_list, strdup(st_event->target));

        }

        crmd_peer_down(peer, TRUE);
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
        int limit = transition_graph->batch_limit;

        transition_graph->batch_limit = throttle_get_total_job_limit(limit);
        graph_rc = run_graph(transition_graph);
        transition_graph->batch_limit = limit; /* Restore the configured value */

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
    crm_trace("%s:%d - Triggered graph processing", fn, line);
    mainloop_set_trigger(transition_trigger);
}

void
abort_transition_graph(int abort_priority, enum transition_action abort_action,
                       const char *abort_text, xmlNode * reason, const char *fn, int line)
{
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };
    int level = LOG_INFO;
    xmlNode *diff = NULL;
    xmlNode *change = NULL;

    CRM_CHECK(transition_graph != NULL, return);

    switch (fsa_state) {
        case S_STARTING:
        case S_PENDING:
        case S_NOT_DC:
        case S_HALT:
        case S_ILLEGAL:
        case S_STOPPING:
        case S_TERMINATE:
            crm_info("Abort %s suppressed: state=%s (complete=%d)",
                     abort_text, fsa_state2string(fsa_state), transition_graph->complete);
            return;
        default:
            break;
    }

    /* Make sure any queued calculations are discarded ASAP */
    free(fsa_pe_ref);
    fsa_pe_ref = NULL;

    if (transition_graph->complete == FALSE) {
        if(update_abort_priority(transition_graph, abort_priority, abort_action, abort_text)) {
            level = LOG_NOTICE;
        }
    }

    if(reason) {
        xmlNode *search = NULL;

        for(search = reason; search; search = search->parent) {
            if (safe_str_eq(XML_TAG_DIFF, TYPE(search))) {
                diff = search;
                break;
            }
        }

        if(diff) {
            xml_patch_versions(diff, add, del);
            for(search = reason; search; search = search->parent) {
                if (safe_str_eq(XML_DIFF_CHANGE, TYPE(search))) {
                    change = search;
                    break;
                }
            }
        }
    }

    if(reason == NULL) {
        do_crm_log(level, "Transition aborted: %s (source=%s:%d, %d)",
                   abort_text, fn, line, transition_graph->complete);

    } else if(change == NULL) {
        char *local_path = xml_get_path(reason);

        do_crm_log(level, "Transition aborted by %s.%s: %s (cib=%d.%d.%d, source=%s:%d, path=%s, %d)",
                   TYPE(reason), ID(reason), abort_text, add[0], add[1], add[2], fn, line, local_path, transition_graph->complete);
        free(local_path);

    } else {
        const char *kind = NULL;
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *path = crm_element_value(change, XML_DIFF_PATH);

        if(change == reason) {
            if(strcmp(op, "create") == 0) {
                reason = reason->children;

            } else if(strcmp(op, "modify") == 0) {
                reason = first_named_child(reason, XML_DIFF_RESULT);
                if(reason) {
                    reason = reason->children;
                }
            }
        }

        kind = TYPE(reason);
        if(strcmp(op, "delete") == 0) {
            const char *shortpath = strrchr(path, '/');

            do_crm_log(level, "Transition aborted by deletion of %s: %s (cib=%d.%d.%d, source=%s:%d, path=%s, %d)",
                       shortpath?shortpath+1:path, abort_text, add[0], add[1], add[2], fn, line, path, transition_graph->complete);

        } else if (safe_str_eq(XML_CIB_TAG_NVPAIR, kind)) { 
            do_crm_log(level, "Transition aborted by %s, %s=%s: %s (%s cib=%d.%d.%d, source=%s:%d, path=%s, %d)",
                       crm_element_value(reason, XML_ATTR_ID),
                       crm_element_value(reason, XML_NVPAIR_ATTR_NAME),
                       crm_element_value(reason, XML_NVPAIR_ATTR_VALUE),
                       abort_text, op, add[0], add[1], add[2], fn, line, path, transition_graph->complete);

        } else if (safe_str_eq(XML_LRM_TAG_RSC_OP, kind)) {
            const char *magic = crm_element_value(reason, XML_ATTR_TRANSITION_MAGIC);

            do_crm_log(level, "Transition aborted by %s '%s' on %s: %s (magic=%s, cib=%d.%d.%d, source=%s:%d, %d)",
                       crm_element_value(reason, XML_LRM_ATTR_TASK_KEY), op,
                       crm_element_value(reason, XML_LRM_ATTR_TARGET), abort_text,
                       magic, add[0], add[1], add[2], fn, line, transition_graph->complete);

        } else if (safe_str_eq(XML_CIB_TAG_STATE, kind)
                   || safe_str_eq(XML_CIB_TAG_NODE, kind)) {
            const char *uname = crm_peer_uname(ID(reason));

            do_crm_log(level, "Transition aborted by %s '%s' on %s: %s (cib=%d.%d.%d, source=%s:%d, %d)",
                       kind, op, uname ? uname : ID(reason), abort_text,
                       add[0], add[1], add[2], fn, line, transition_graph->complete);

        } else {
            do_crm_log(level, "Transition aborted by %s.%s '%s': %s (cib=%d.%d.%d, source=%s:%d, path=%s, %d)",
                       TYPE(reason), ID(reason), op?op:"change", abort_text, add[0], add[1], add[2], fn, line, path, transition_graph->complete);
        }
    }

    if (transition_graph->complete) {
        if (transition_timer->period_ms > 0) {
            crm_timer_stop(transition_timer);
            crm_timer_start(transition_timer);
        } else {
            register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);
        }
        return;
    }

    mainloop_set_trigger(transition_trigger);
}
