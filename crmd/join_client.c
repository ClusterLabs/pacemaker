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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd_fsa.h>
#include <crmd_messages.h>

int reannounce_count = 0;
void join_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t * orig);

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
void
do_cl_join_query(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *req = create_request(CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
                                  CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

    sleep(1);                   /* give the CCM time to propogate to the DC */
    update_dc(NULL);            /* Unset any existing value so that the result is not discarded */
    crm_debug("Querying for a DC");
    send_cluster_message(NULL, crm_msg_crmd, req, FALSE);
    free_xml(req);
}

/*	 A_CL_JOIN_ANNOUNCE	*/

/* this is kind of a workaround for the fact that we may not be around or
 * are otherwise unable to reply when the DC sends out A_DC_JOIN_OFFER_ALL
 */
void
do_cl_join_announce(long long action,
                    enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    /* Once we hear from the DC, we can stop the timer
     *
     * This timer was started either on startup or when a node
     * left the CCM list
     */

    /* don't announce if we're in one of these states */
    if (cur_state != S_PENDING) {
        crm_warn("Not announcing cluster join because in state %s",
                 fsa_state2string(cur_state));
        return;
    }

    if (AM_I_OPERATIONAL) {
        /* send as a broadcast */
        xmlNode *req = create_request(CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
                                      CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

        crm_debug("Announcing availability");
        update_dc(NULL);
        send_cluster_message(NULL, crm_msg_crmd, req, FALSE);
        free_xml(req);

    } else {
        /* Delay announce until we have finished local startup */
        crm_warn("Delaying announce of cluster join until local startup is complete");
        return;
    }
}

static int query_call_id = 0;

/*	 A_CL_JOIN_REQUEST	*/
/* aka. accept the welcome offer */
void
do_cl_join_offer_respond(long long action,
                         enum crmd_fsa_cause cause,
                         enum crmd_fsa_state cur_state,
                         enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
    const char *welcome_from = crm_element_value(input->msg, F_CRM_HOST_FROM);
    const char *join_id = crm_element_value(input->msg, F_CRM_JOIN_ID);

#if 0
    if (we are sick) {
        log error;

        /* save the request for later? */
        return;
    }
#endif

    crm_trace("Accepting cluster join offer from node %s "CRM_XS" join-%s",
              welcome_from, crm_element_value(input->msg, F_CRM_JOIN_ID));

    /* we only ever want the last one */
    if (query_call_id > 0) {
        crm_trace("Cancelling previous join query: %d", query_call_id);
        remove_cib_op_callback(query_call_id, FALSE);
        query_call_id = 0;
    }

    if (update_dc(input->msg) == FALSE) {
        crm_warn("Discarding cluster join offer from node %s (expected %s)",
                 welcome_from, fsa_our_dc);
        return;
    }

    CRM_LOG_ASSERT(input != NULL);
    query_call_id =
        fsa_cib_conn->cmds->query(fsa_cib_conn, NULL, NULL, cib_scope_local | cib_no_children);
    fsa_register_cib_callback(query_call_id, FALSE, strdup(join_id), join_query_callback);
    crm_trace("Registered join query callback: %d", query_call_id);

    register_fsa_action(A_DC_TIMER_STOP);
}

void
join_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *join_id = user_data;
    xmlNode *generation = create_xml_node(NULL, XML_CIB_TAG_GENERATION_TUPPLE);

    CRM_LOG_ASSERT(join_id != NULL);

    if (query_call_id != call_id) {
        crm_trace("Query %d superseded", call_id);
        goto done;
    }

    query_call_id = 0;
    if(rc != pcmk_ok || output == NULL) {
        crm_err("Could not retrieve version details for join-%s: %s (%d)",
                join_id, pcmk_strerror(rc), rc);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);

    } else if (fsa_our_dc == NULL) {
        crm_debug("Membership is in flux, not continuing join-%s", join_id);

    } else {
        xmlNode *reply = NULL;

        crm_debug("Respond to join offer join-%s from %s", join_id, fsa_our_dc);
        copy_in_properties(generation, output);

        reply = create_request(CRM_OP_JOIN_REQUEST, generation, fsa_our_dc,
                               CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

        crm_xml_add(reply, F_CRM_JOIN_ID, join_id);
        send_cluster_message(crm_get_peer(0, fsa_our_dc), crm_msg_crmd, reply, TRUE);
        free_xml(reply);
    }

  done:
    free_xml(generation);
}

/*	A_CL_JOIN_RESULT	*/
/* aka. this is notification that we have (or have not) been accepted */
void
do_cl_join_finalize_respond(long long action,
                            enum crmd_fsa_cause cause,
                            enum crmd_fsa_state cur_state,
                            enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *tmp1 = NULL;
    gboolean was_nack = TRUE;
    static gboolean first_join = TRUE;
    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
    const char *start_state = daemon_option("node_start_state");

    int join_id = -1;
    const char *op = crm_element_value(input->msg, F_CRM_TASK);
    const char *ack_nack = crm_element_value(input->msg, CRM_OP_JOIN_ACKNAK);
    const char *welcome_from = crm_element_value(input->msg, F_CRM_HOST_FROM);

    if (safe_str_neq(op, CRM_OP_JOIN_ACKNAK)) {
        crm_trace("Ignoring op=%s message", op);
        return;
    }

    /* calculate if it was an ack or a nack */
    if (crm_is_true(ack_nack)) {
        was_nack = FALSE;
    }

    crm_element_value_int(input->msg, F_CRM_JOIN_ID, &join_id);

    if (was_nack) {
        crm_err("Shutting down because cluster join with leader %s failed "
                CRM_XS" join-%d NACK'd", welcome_from, join_id);
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        return;
    }

    if (AM_I_DC == FALSE && safe_str_eq(welcome_from, fsa_our_uname)) {
        crm_warn("Discarding our own welcome - we're no longer the DC");
        return;
    }

    if (update_dc(input->msg) == FALSE) {
        crm_warn("Discarding %s from node %s (expected from %s)",
                 op, welcome_from, fsa_our_dc);
        return;
    }

    /* send our status section to the DC */
    tmp1 = do_lrm_query(TRUE, fsa_our_uname);
    if (tmp1 != NULL) {
        xmlNode *reply = create_request(CRM_OP_JOIN_CONFIRM, tmp1, fsa_our_dc,
                                        CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

        crm_xml_add_int(reply, F_CRM_JOIN_ID, join_id);

        crm_debug("Confirming join-%d: sending local operation history to %s",
                  join_id, fsa_our_dc);

        /*
         * If this is the node's first join since the crmd started on it, clear
         * any previous transient node attributes, to handle the case where
         * the node restarted so quickly that the cluster layer didn't notice.
         *
         * Do not remove the resources though, they'll be cleaned up in
         * do_dc_join_ack(). Removing them here creates a race condition if the
         * crmd is being recovered. Instead of a list of active resources from
         * the lrmd, we may end up with a blank status section. If we are _NOT_
         * lucky, we will probe for the "wrong" instance of anonymous clones and
         * end up with multiple active instances on the machine.
         */
        if (first_join && is_not_set(fsa_input_register, R_SHUTDOWN)) {
            first_join = FALSE;

            if (start_state) {
                init_transient_attrs(fsa_our_uname, start_state, 0);
            } else {
                erase_status_tag(fsa_our_uname, XML_TAG_TRANSIENT_NODEATTRS, 0);
            }

            update_attrd(fsa_our_uname, "terminate", NULL, NULL, FALSE);
            update_attrd(fsa_our_uname, XML_CIB_ATTR_SHUTDOWN, "0", NULL, FALSE);
        }

        send_cluster_message(crm_get_peer(0, fsa_our_dc), crm_msg_crmd, reply, TRUE);
        free_xml(reply);

        if (AM_I_DC == FALSE) {
            register_fsa_input_adv(cause, I_NOT_DC, NULL, A_NOTHING, TRUE, __FUNCTION__);
            update_attrd(NULL, NULL, NULL, NULL, FALSE);
        }

        free_xml(tmp1);

    } else {
        crm_err("Could not confirm join-%d with %s: Local operation history failed",
                join_id, fsa_our_dc);
        register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
    }
}
