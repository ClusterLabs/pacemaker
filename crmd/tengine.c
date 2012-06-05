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
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>             /* for access */

#include <sys/types.h>          /* for calls to open */
#include <sys/stat.h>           /* for calls to open */
#include <fcntl.h>              /* for calls to open */
#include <pwd.h>                /* for getpwuid */
#include <grp.h>                /* for initgroups */

#include <sys/time.h>           /* for getrlimit */
#include <sys/resource.h>       /* for getrlimit */

#include <errno.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>
#include <tengine.h>
#include <te_callbacks.h>

extern crm_graph_functions_t te_graph_fns;
struct crm_subsystem_s *te_subsystem = NULL;
stonith_t *stonith_api = NULL;

static void
global_cib_callback(const xmlNode * msg, int callid, int rc, xmlNode * output)
{
}

static crm_graph_t *
create_blank_graph(void)
{
    crm_graph_t *a_graph = unpack_graph(NULL, NULL);

    a_graph->complete = TRUE;
    a_graph->abort_reason = "DC Takeover";
    a_graph->completion_action = tg_restart;
    return a_graph;
}

/*	 A_TE_START, A_TE_STOP, A_TE_RESTART	*/
void
do_te_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean init_ok = TRUE;

    if (action & A_TE_STOP) {
        if (transition_graph) {
            destroy_graph(transition_graph);
            transition_graph = NULL;
        }

        if (fsa_cib_conn) {
            fsa_cib_conn->cmds->del_notify_callback(
                fsa_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff);
        }

        clear_bit_inplace(fsa_input_register, te_subsystem->flag_connected);
        crm_info("Transitioner is now inactive");
    }

    if ((action & A_TE_START) == 0) {
        return;

    } else if (is_set(fsa_input_register, te_subsystem->flag_connected)) {
        crm_debug("The transitioner is already active");
        return;

    } else if ((action & A_TE_START) && cur_state == S_STOPPING) {
        crm_info("Ignoring request to start %s while shutting down", te_subsystem->name);
        return;
    }

    te_uuid = crm_generate_uuid();
    crm_info("Registering TE UUID: %s", te_uuid);

    if (transition_trigger == NULL) {
        transition_trigger = mainloop_add_trigger(G_PRIORITY_LOW, te_graph_trigger, NULL);
    }

    if (cib_ok !=
        fsa_cib_conn->cmds->add_notify_callback(fsa_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff)) {
        crm_err("Could not set CIB notification callback");
        init_ok = FALSE;
    }

    if (cib_ok != fsa_cib_conn->cmds->set_op_callback(fsa_cib_conn, global_cib_callback)) {
        crm_err("Could not set CIB global callback");
        init_ok = FALSE;
    }

    if (init_ok) {
        set_graph_functions(&te_graph_fns);

        if (transition_graph) {
            destroy_graph(transition_graph);
        }

        /* create a blank one */
        crm_debug("Transitioner is now active");
        transition_graph = create_blank_graph();
        set_bit_inplace(fsa_input_register, te_subsystem->flag_connected);
    }
}

/*	 A_TE_INVOKE, A_TE_CANCEL	*/
void
do_te_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{

    if (AM_I_DC == FALSE || (fsa_state != S_TRANSITION_ENGINE && (action & A_TE_INVOKE))) {
        crm_notice("No need to invoke the TE (%s) in state %s",
                   fsa_action2string(action), fsa_state2string(fsa_state));
        return;
    }

    if (action & A_TE_CANCEL) {
        crm_debug("Cancelling the transition: %s",
                  transition_graph->complete ? "inactive" : "active");
        abort_transition(INFINITY, tg_restart, "Peer Cancelled", NULL);
        if (transition_graph->complete == FALSE) {
            crmd_fsa_stall(NULL);
        }

    } else if (action & A_TE_HALT) {
        crm_debug("Halting the transition: %s", transition_graph->complete ? "inactive" : "active");
        abort_transition(INFINITY, tg_stop, "Peer Halt", NULL);
        if (transition_graph->complete == FALSE) {
            crmd_fsa_stall(NULL);
        }

    } else if (action & A_TE_INVOKE) {
        const char *value = NULL;
        xmlNode *graph_data = NULL;
        ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
        const char *ref = crm_element_value(input->msg, XML_ATTR_REFERENCE);
        const char *graph_file = crm_element_value(input->msg, F_CRM_TGRAPH);
        const char *graph_input = crm_element_value(input->msg, F_CRM_TGRAPH_INPUT);

        if (graph_file == NULL && input->xml == NULL) {
            crm_log_xml_err(input->msg, "Bad command");
            register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
            return;
        }

        if (transition_graph->complete == FALSE) {
            crm_info("Another transition is already active");
            abort_transition(INFINITY, tg_restart, "Transition Active", NULL);
            return;
        }

        if (fsa_pe_ref == NULL || safe_str_neq(fsa_pe_ref, ref)) {
            crm_info("Transition is redundant: %s vs. %s", crm_str(fsa_pe_ref), crm_str(ref));
            abort_transition(INFINITY, tg_restart, "Transition Redundant", NULL);
        }

        graph_data = input->xml;

        if (graph_data == NULL && graph_file != NULL) {
            graph_data = filename2xml(graph_file);
        }

        if (is_timer_started(transition_timer)) {
            crm_debug("The transitioner wait for a transition timer");
            return;
        }

        CRM_CHECK(graph_data != NULL,
                  crm_err("Input raised by %s is invalid", msg_data->origin);
                  crm_log_xml_err(input->msg, "Bad command");
                  return);

        destroy_graph(transition_graph);
        transition_graph = unpack_graph(graph_data, graph_input);
        CRM_CHECK(transition_graph != NULL, transition_graph = create_blank_graph(); return);
        crm_info("Processing graph %d (ref=%s) derived from %s", transition_graph->id, ref,
                 graph_input);

        value = crm_element_value(graph_data, "failed-stop-offset");
        if (value) {
            crm_free(failed_stop_offset);
            failed_stop_offset = crm_strdup(value);
        }

        value = crm_element_value(graph_data, "failed-start-offset");
        if (value) {
            crm_free(failed_start_offset);
            failed_start_offset = crm_strdup(value);
        }

        trigger_graph();
        print_graph(LOG_DEBUG_2, transition_graph);

        if (graph_data != input->xml) {
            free_xml(graph_data);
        }
    }
}
