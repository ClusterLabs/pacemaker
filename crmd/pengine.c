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
#include <crm/common/cluster.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>

static GCHSource *pe_source = NULL;
struct crm_subsystem_s *pe_subsystem = NULL;
void do_pe_invoke_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

static void
save_cib_contents(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *id = user_data;

    register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
    CRM_CHECK(id != NULL, return);

    if (rc == cib_ok) {
        int len = 15;
        char *filename = NULL;

        len += strlen(id);
        len += strlen(PE_STATE_DIR);

        crm_malloc0(filename, len);
        CRM_CHECK(filename != NULL, return);

        sprintf(filename, PE_STATE_DIR "/pe-core-%s.bz2", id);
        if (write_xml_file(output, filename, TRUE) < 0) {
            crm_err("Could not save CIB contents after PE crash to %s", filename);
        } else {
            crm_notice("Saved CIB contents after PE crash to %s", filename);
        }

        crm_free(filename);
    }

    crm_free(id);
}

static void
pe_connection_destroy(gpointer user_data)
{
    pe_source = NULL;
    clear_bit_inplace(fsa_input_register, pe_subsystem->flag_connected);
    if (is_set(fsa_input_register, pe_subsystem->flag_required)) {
        int rc = cib_ok;
        cl_uuid_t new_uuid;
        char uuid_str[UU_UNPARSE_SIZEOF];

        cl_uuid_generate(&new_uuid);
        cl_uuid_unparse(&new_uuid, uuid_str);

        crm_crit("Connection to the Policy Engine failed (pid=%d, uuid=%s)",
                 pe_subsystem->pid, uuid_str);

        /*
         *The PE died...
         *
         * Save the current CIB so that we have a chance of
         * figuring out what killed it.
         *
         * Delay raising the I_ERROR until the query below completes or
         * 5s is up, whichever comes first.
         *
         */
        rc = fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local);
        fsa_cib_conn->cmds->register_callback(fsa_cib_conn, rc, 5, FALSE, crm_strdup(uuid_str),
                                              "save_cib_contents", save_cib_contents);

    } else {
        crm_info("Connection to the Policy Engine released");
    }

    pe_subsystem->pid = -1;
    pe_subsystem->ipc = NULL;
    pe_subsystem->client = NULL;

    mainloop_set_trigger(fsa_source);
    return;
}

static gboolean
pe_msg_dispatch(IPC_Channel * client, gpointer user_data)
{
    xmlNode *msg = NULL;
    gboolean stay_connected = TRUE;

    while (IPC_ISRCONN(client)
           && client->ops->is_message_pending(client)) {

        msg = xmlfromIPC(client, MAX_IPC_DELAY);
        if (msg != NULL) {
            route_message(C_IPC_MESSAGE, msg);
            free_xml(msg);
        }
    }

    if (client->ch_status != IPC_CONNECT) {
        crm_info("Received HUP from %s:[%d]", pe_subsystem->name, pe_subsystem->pid);
        stay_connected = FALSE;
    }

    mainloop_set_trigger(fsa_source);
    return stay_connected;
}

/*	 A_PE_START, A_PE_STOP, A_TE_RESTART	*/
void
do_pe_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    struct crm_subsystem_s *this_subsys = pe_subsystem;

    long long stop_actions = A_PE_STOP;
    long long start_actions = A_PE_START;

    if (action & stop_actions) {
        clear_bit_inplace(fsa_input_register, pe_subsystem->flag_required);

        if (is_heartbeat_cluster()) {
            stop_subsystem(this_subsys, FALSE);

        } else {
            if (pe_source) {
                G_main_del_IPC_Channel(pe_source);
                pe_source = NULL;
            }

            if (pe_subsystem->ipc) {
                pe_subsystem->ipc->ops->destroy(pe_subsystem->ipc);
                pe_subsystem->ipc = NULL;
            }
            clear_bit_inplace(fsa_input_register, pe_subsystem->flag_connected);
        }
    }

    if ((action & start_actions) && (is_set(fsa_input_register, R_PE_CONNECTED) == FALSE)) {
        if (cur_state != S_STOPPING) {
            if (is_openais_cluster()) {
                set_bit_inplace(fsa_input_register, pe_subsystem->flag_required);

            } else if (is_heartbeat_cluster()) {
                if (start_subsystem(this_subsys) == FALSE) {
                    register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
                    return;
                }
                sleep(4);
            }

            pe_subsystem->ipc = init_client_ipc_comms_nodispatch(CRM_SYSTEM_PENGINE);
            if (pe_subsystem->ipc == NULL) {
                crm_warn("Setup of client connection failed," " not adding channel to mainloop");
                register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
                return;
            }

            if (is_openais_cluster()) {
                pe_subsystem->pid = pe_subsystem->ipc->farside_pid;;
            }

            set_bit_inplace(fsa_input_register, pe_subsystem->flag_connected);
            pe_source =
                G_main_add_IPC_Channel(G_PRIORITY_HIGH, pe_subsystem->ipc, FALSE, pe_msg_dispatch,
                                       NULL, pe_connection_destroy);

        } else {
            crm_info("Ignoring request to start %s while shutting down", this_subsys->name);
        }
    }
}

int fsa_pe_query = 0;
char *fsa_pe_ref = NULL;

/*	 A_PE_INVOKE	*/
void
do_pe_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (AM_I_DC == FALSE) {
        crm_err("Not DC: No need to invoke the PE (anymore): %s", fsa_action2string(action));
        return;
    }

    if (is_set(fsa_input_register, R_PE_CONNECTED) == FALSE) {
        if (is_set(fsa_input_register, R_SHUTDOWN)) {
            crm_err("Cannot shut down gracefully without the PE");
            register_fsa_input_before(C_FSA_INTERNAL, I_TERMINATE, NULL);

        } else {
            crm_info("Waiting for the PE to connect");
            crmd_fsa_stall(NULL);
            register_fsa_action(A_PE_START);
        }
        return;
    }

    if (is_set(fsa_input_register, R_HAVE_CIB) == FALSE) {
        crm_err("Attempted to invoke the PE without a consistent" " copy of the CIB!");

        /* start the join from scratch */
        register_fsa_input_before(C_FSA_INTERNAL, I_ELECTION, NULL);
        return;
    }

    fsa_pe_query = fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local);

    crm_debug("Query %d: Requesting the current CIB: %s", fsa_pe_query, fsa_state2string(fsa_state));

    /* Make sure any queued calculations are discarded */
    crm_free(fsa_pe_ref);
    fsa_pe_ref = NULL;

    fsa_cib_conn->cmds->register_callback(fsa_cib_conn, fsa_pe_query, 60, FALSE, NULL,
                                          "do_pe_invoke_callback", do_pe_invoke_callback);
}

void
do_pe_invoke_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    xmlNode *cmd = NULL;

    if (rc != cib_ok) {
        crm_err("Cant retrieve the CIB: %s", cib_error2string(rc));
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
        return;

    } else if (call_id != fsa_pe_query) {
        crm_trace("Skipping superceeded CIB query: %d (current=%d)", call_id, fsa_pe_query);
        return;

    } else if (AM_I_DC == FALSE || is_set(fsa_input_register, R_PE_CONNECTED) == FALSE) {
        crm_debug("No need to invoke the PE anymore");
        return;

    } else if (fsa_state != S_POLICY_ENGINE) {
        crm_debug("Discarding PE request in state: %s", fsa_state2string(fsa_state));
        return;

    } else if (last_peer_update != 0) {
        crm_debug("Re-asking for the CIB: peer update %d still pending", last_peer_update);

        sleep(1);
        register_fsa_action(A_PE_INVOKE);
        return;

    } else if (fsa_state != S_POLICY_ENGINE) {
        crm_err("Invoking PE in state: %s", fsa_state2string(fsa_state));
        return;
    }

    CRM_LOG_ASSERT(output != NULL);

    crm_xml_add(output, XML_ATTR_DC_UUID, fsa_our_uuid);
    crm_xml_add_int(output, XML_ATTR_HAVE_QUORUM, fsa_has_quorum);

    if (ever_had_quorum && crm_have_quorum == FALSE) {
        crm_xml_add_int(output, XML_ATTR_QUORUM_PANIC, 1);
    }

    cmd = create_request(CRM_OP_PECALC, output, NULL, CRM_SYSTEM_PENGINE, CRM_SYSTEM_DC, NULL);

    crm_free(fsa_pe_ref);
    fsa_pe_ref = crm_element_value_copy(cmd, XML_ATTR_REFERENCE);

    if (send_ipc_message(pe_subsystem->ipc, cmd) == FALSE) {
        crm_err("Could not contact the pengine");
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
    }

    crm_debug("Invoking the PE: query=%d, ref=%s, seq=%llu, quorate=%d",
             fsa_pe_query, fsa_pe_ref, crm_peer_seq, fsa_has_quorum);
    free_xml(cmd);
}
