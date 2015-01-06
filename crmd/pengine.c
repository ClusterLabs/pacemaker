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
#include <crm/cluster.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>

struct crm_subsystem_s *pe_subsystem = NULL;
void do_pe_invoke_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

static void
save_cib_contents(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *id = user_data;

    register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
    CRM_CHECK(id != NULL, return);

    if (rc == pcmk_ok) {
        int len = 15;
        char *filename = NULL;

        len += strlen(id);
        len += strlen(PE_STATE_DIR);

        filename = calloc(1, len);
        CRM_CHECK(filename != NULL, return);

        sprintf(filename, PE_STATE_DIR "/pe-core-%s.bz2", id);
        if (write_xml_file(output, filename, TRUE) < 0) {
            crm_err("Could not save CIB contents after PE crash to %s", filename);
        } else {
            crm_notice("Saved CIB contents after PE crash to %s", filename);
        }

        free(filename);
    }

    free(id);
}

static void
pe_ipc_destroy(gpointer user_data)
{
    if (is_set(fsa_input_register, pe_subsystem->flag_required)) {
        int rc = pcmk_ok;
        char *uuid_str = crm_generate_uuid();

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
        fsa_register_cib_callback(rc, FALSE, uuid_str, save_cib_contents);

    } else {
        if (is_heartbeat_cluster()) {
            stop_subsystem(pe_subsystem, FALSE);
        }
        crm_info("Connection to the Policy Engine released");
    }

    clear_bit(fsa_input_register, pe_subsystem->flag_connected);
    pe_subsystem->pid = -1;
    pe_subsystem->source = NULL;
    pe_subsystem->client = NULL;

    mainloop_set_trigger(fsa_source);
    return;
}

static int
pe_ipc_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *msg = string2xml(buffer);

    if (msg) {
        route_message(C_IPC_MESSAGE, msg);
    }

    free_xml(msg);
    return 0;
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

    static struct ipc_client_callbacks pe_callbacks = {
        .dispatch = pe_ipc_dispatch,
        .destroy = pe_ipc_destroy
    };

    if (action & stop_actions) {
        clear_bit(fsa_input_register, pe_subsystem->flag_required);

        mainloop_del_ipc_client(pe_subsystem->source);
        pe_subsystem->source = NULL;

        clear_bit(fsa_input_register, pe_subsystem->flag_connected);
    }

    if ((action & start_actions) && (is_set(fsa_input_register, R_PE_CONNECTED) == FALSE)) {
        if (cur_state != S_STOPPING) {
            set_bit(fsa_input_register, pe_subsystem->flag_required);

            pe_subsystem->source =
                mainloop_add_ipc_client(CRM_SYSTEM_PENGINE, G_PRIORITY_DEFAULT,
                                        5 * 1024 * 1024 /* 5Mb */ , NULL, &pe_callbacks);

            if (pe_subsystem->source == NULL) {
                crm_warn("Setup of client connection failed, not adding channel to mainloop");
                register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
                return;
            }

            /* if (is_openais_cluster()) { */
            /*     pe_subsystem->pid = pe_subsystem->ipc->farside_pid; */
            /* } */

            set_bit(fsa_input_register, pe_subsystem->flag_connected);

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
            crmd_fsa_stall(FALSE);
            register_fsa_action(A_PE_START);
        }
        return;
    }

    if (cur_state != S_POLICY_ENGINE) {
        crm_notice("No need to invoke the PE in state %s", fsa_state2string(cur_state));
        return;
    }
    if (is_set(fsa_input_register, R_HAVE_CIB) == FALSE) {
        crm_err("Attempted to invoke the PE without a consistent copy of the CIB!");

        /* start the join from scratch */
        register_fsa_input_before(C_FSA_INTERNAL, I_ELECTION, NULL);
        return;
    }

    fsa_pe_query = fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local);

    crm_debug("Query %d: Requesting the current CIB: %s", fsa_pe_query,
              fsa_state2string(fsa_state));

    /* Make sure any queued calculations are discarded */
    free(fsa_pe_ref);
    fsa_pe_ref = NULL;

    fsa_register_cib_callback(fsa_pe_query, FALSE, NULL, do_pe_invoke_callback);
}

static void
force_local_option(xmlNode *xml, const char *attr_name, const char *attr_value)
{
    int max = 0;
    int lpc = 0;
    int xpath_max = 1024;
    char *xpath_string = NULL;
    xmlXPathObjectPtr xpathObj = NULL;

    xpath_string = calloc(1, xpath_max);
    lpc = snprintf(xpath_string, xpath_max, "%.128s//%s//nvpair[@name='%.128s']",
                       get_object_path(XML_CIB_TAG_CRMCONFIG), XML_CIB_TAG_PROPSET, attr_name);
    CRM_LOG_ASSERT(lpc > 0);

    xpathObj = xpath_search(xml, xpath_string);
    max = numXpathResults(xpathObj);
    free(xpath_string);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *match = getXpathResult(xpathObj, lpc);
        crm_trace("Forcing %s/%s = %s", ID(match), attr_name, attr_value);
        crm_xml_add(match, XML_NVPAIR_ATTR_VALUE, attr_value);
    }

    if(max == 0) {
        char *attr_id = crm_concat(CIB_OPTIONS_FIRST, attr_name, '-');

        crm_trace("Creating %s/%s = %s", attr_id, attr_name, attr_value);
        xml = create_xml_node(xml, XML_CIB_TAG_CRMCONFIG);
        xml = create_xml_node(xml, XML_CIB_TAG_PROPSET);
        crm_xml_add(xml, XML_ATTR_ID, CIB_OPTIONS_FIRST);

        xml = create_xml_node(xml, XML_CIB_TAG_NVPAIR);

        crm_xml_add(xml, XML_ATTR_ID, attr_id);
        crm_xml_add(xml, XML_NVPAIR_ATTR_NAME, attr_name);
        crm_xml_add(xml, XML_NVPAIR_ATTR_VALUE, attr_value);

        free(attr_id);
    }
    freeXpathObject(xpathObj);
}

void
do_pe_invoke_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    int sent;
    xmlNode *cmd = NULL;

    if (rc != pcmk_ok) {
        crm_err("Cant retrieve the CIB: %s (call %d)", pcmk_strerror(rc), call_id);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
        return;

    } else if (call_id != fsa_pe_query) {
        crm_trace("Skipping superseded CIB query: %d (current=%d)", call_id, fsa_pe_query);
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

    /* refresh our remote-node cache when the pengine is invoked */
    crm_remote_peer_cache_refresh(output);

    crm_xml_add(output, XML_ATTR_DC_UUID, fsa_our_uuid);
    crm_xml_add_int(output, XML_ATTR_HAVE_QUORUM, fsa_has_quorum);
    force_local_option(output, XML_ATTR_HAVE_WATCHDOG, daemon_option("watchdog"));

    if (ever_had_quorum && crm_have_quorum == FALSE) {
        crm_xml_add_int(output, XML_ATTR_QUORUM_PANIC, 1);
    }

    cmd = create_request(CRM_OP_PECALC, output, NULL, CRM_SYSTEM_PENGINE, CRM_SYSTEM_DC, NULL);

    free(fsa_pe_ref);
    fsa_pe_ref = crm_element_value_copy(cmd, XML_ATTR_REFERENCE);

    sent = crm_ipc_send(mainloop_get_ipc_client(pe_subsystem->source), cmd, 0, 0, NULL);
    if (sent <= 0) {
        crm_err("Could not contact the pengine: %d", sent);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
    }

    crm_debug("Invoking the PE: query=%d, ref=%s, seq=%llu, quorate=%d",
              fsa_pe_query, fsa_pe_ref, crm_peer_seq, fsa_has_quorum);
    free_xml(cmd);
}
