/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

void join_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t * orig);

/*!
 * \internal
 * \brief Remember if DC is shutting down as we join
 *
 * If we're joining while the current DC is shutting down, update its expected
 * state, so we don't fence it if we become the new DC. (We weren't a peer
 * when it broadcast its shutdown request.)
 *
 * \param[in] msg  A join message from the DC
 */
static void
update_dc_expected(const xmlNode *msg)
{
    if ((controld_globals.dc_name != NULL)
        && pcmk__xe_attr_is_true(msg, PCMK__XA_DC_LEAVING)) {
        pcmk__node_status_t *dc_node =
            pcmk__get_node(0, controld_globals.dc_name, NULL,
                           pcmk__node_search_cluster_member);

        pcmk__update_peer_expected(__func__, dc_node, CRMD_JOINSTATE_DOWN);
    }
}

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
void
do_cl_join_query(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *req = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD, NULL,
                                     CRM_SYSTEM_DC, CRM_OP_JOIN_ANNOUNCE, NULL);

    sleep(1);                   // Give the cluster layer time to propagate to the DC
    update_dc(NULL);            /* Unset any existing value so that the result is not discarded */
    crm_debug("Querying for a DC");
    pcmk__cluster_send_message(NULL, pcmk_ipc_controld, req);
    pcmk__xml_free(req);
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
    /* don't announce if we're in one of these states */
    if (cur_state != S_PENDING) {
        crm_warn("Not announcing cluster join because in state %s",
                 fsa_state2string(cur_state));
        return;
    }

    if (!pcmk_is_set(controld_globals.fsa_input_register, R_STARTING)) {
        /* send as a broadcast */
        xmlNode *req = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD,
                                         NULL, CRM_SYSTEM_DC,
                                         CRM_OP_JOIN_ANNOUNCE, NULL);

        crm_debug("Announcing availability");
        update_dc(NULL);
        pcmk__cluster_send_message(NULL, pcmk_ipc_controld, req);
        pcmk__xml_free(req);

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
    cib_t *cib_conn = controld_globals.cib_conn;

    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
    const char *welcome_from;
    const char *join_id;

    CRM_CHECK(input != NULL, return);

    welcome_from = pcmk__xe_get(input->msg, PCMK__XA_SRC);
    join_id = pcmk__xe_get(input->msg, PCMK__XA_JOIN_ID);
    crm_trace("Accepting cluster join offer from node %s " QB_XS " join-%s",
              welcome_from, pcmk__xe_get(input->msg, PCMK__XA_JOIN_ID));

    /* we only ever want the last one */
    if (query_call_id > 0) {
        crm_trace("Cancelling previous join query: %d", query_call_id);
        remove_cib_op_callback(query_call_id, FALSE);
        query_call_id = 0;
    }

    if (update_dc(input->msg) == FALSE) {
        crm_warn("Discarding cluster join offer from node %s (expected %s)",
                 welcome_from, controld_globals.dc_name);
        return;
    }

    update_dc_expected(input->msg);

    query_call_id = cib_conn->cmds->query(cib_conn, NULL, NULL,
                                          cib_no_children);
    fsa_register_cib_callback(query_call_id, pcmk__str_copy(join_id),
                              join_query_callback);
    crm_trace("Registered join query callback: %d", query_call_id);

    controld_set_fsa_action_flags(A_DC_TIMER_STOP);
    controld_trigger_fsa();
}

void
join_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *join_id = user_data;
    xmlNode *generation = pcmk__xe_create(NULL, PCMK__XE_GENERATION_TUPLE);

    CRM_LOG_ASSERT(join_id != NULL);

    if (query_call_id != call_id) {
        crm_trace("Query %d superseded", call_id);
        goto done;
    }

    query_call_id = 0;
    if(rc != pcmk_ok || output == NULL) {
        crm_err("Could not retrieve version details for join-%s: %s (%d)",
                join_id, pcmk_strerror(rc), rc);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __func__);

    } else if (controld_globals.dc_name == NULL) {
        crm_debug("Membership is in flux, not continuing join-%s", join_id);

    } else {
        xmlNode *join_request = NULL;
        const pcmk__node_status_t *dc_node =
            pcmk__get_node(0, controld_globals.dc_name, NULL,
                           pcmk__node_search_cluster_member);

        crm_debug("Respond to join offer join-%s from %s",
                  join_id, controld_globals.dc_name);
        pcmk__xe_copy_attrs(generation, output, pcmk__xaf_none);

        join_request = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD,
                                         controld_globals.dc_name,
                                         CRM_SYSTEM_DC, CRM_OP_JOIN_REQUEST,
                                         generation);

        crm_xml_add(join_request, PCMK__XA_JOIN_ID, join_id);
        crm_xml_add(join_request, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
        pcmk__cluster_send_message(dc_node, pcmk_ipc_controld, join_request);
        pcmk__xml_free(join_request);
    }

  done:
    pcmk__xml_free(generation);
}

void
set_join_state(const char *start_state, const char *node_name, const char *node_uuid,
               bool remote)
{
    if (pcmk__str_eq(start_state, PCMK_VALUE_STANDBY, pcmk__str_casei)) {
        crm_notice("Forcing node %s to join in %s state per configured "
                   "environment", node_name, start_state);
        cib__update_node_attr(controld_globals.logger_out,
                              controld_globals.cib_conn, cib_sync_call,
                              PCMK_XE_NODES, node_uuid,
                              NULL, NULL, NULL, PCMK_NODE_ATTR_STANDBY,
                              PCMK_VALUE_TRUE, NULL,
                              (remote? PCMK_VALUE_REMOTE : NULL));

    } else if (pcmk__str_eq(start_state, PCMK_VALUE_ONLINE, pcmk__str_casei)) {
        crm_notice("Forcing node %s to join in %s state per configured "
                   "environment", node_name, start_state);
        cib__update_node_attr(controld_globals.logger_out,
                              controld_globals.cib_conn, cib_sync_call,
                              PCMK_XE_NODES, node_uuid,
                              NULL, NULL, NULL, PCMK_NODE_ATTR_STANDBY,
                              PCMK_VALUE_FALSE, NULL,
                              (remote? PCMK_VALUE_REMOTE : NULL));

    } else if (pcmk__str_eq(start_state, PCMK_VALUE_DEFAULT, pcmk__str_casei)) {
        crm_debug("Not forcing a starting state on node %s", node_name);

    } else {
        crm_warn("Unrecognized start state '%s', using "
                 "'" PCMK_VALUE_DEFAULT "' (%s)",
                 start_state, node_name);
    }
}

static int
update_conn_host_cache(xmlNode *node, void *userdata)
{
    const char *remote = pcmk__xe_get(node, PCMK_XA_ID);
    const char *conn_host = pcmk__xe_get(node, PCMK__XA_CONNECTION_HOST);
    const char *state = pcmk__xe_get(node, PCMK__XA_NODE_STATE);

    pcmk__node_status_t *remote_peer =
        pcmk__cluster_lookup_remote_node(remote);

    if (remote_peer == NULL) {
        return pcmk_rc_ok;
    }

    if (conn_host != NULL) {
        pcmk__str_update(&remote_peer->conn_host, conn_host);
    }

    if (state != NULL) {
        pcmk__update_peer_state(__func__, remote_peer, state, 0);
    }

    return pcmk_rc_ok;
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
    const char *start_state = pcmk__env_option(PCMK__ENV_NODE_START_STATE);

    int join_id = -1;
    const char *op = pcmk__xe_get(input->msg, PCMK__XA_CRM_TASK);
    const char *welcome_from = pcmk__xe_get(input->msg, PCMK__XA_SRC);

    if (!pcmk__str_eq(op, CRM_OP_JOIN_ACKNAK, pcmk__str_casei)) {
        crm_trace("Ignoring op=%s message", op);
        return;
    }

    /* calculate if it was an ack or a nack */
    if (pcmk__xe_attr_is_true(input->msg, CRM_OP_JOIN_ACKNAK)) {
        was_nack = FALSE;
    }

    pcmk__xe_get_int(input->msg, PCMK__XA_JOIN_ID, &join_id);

    if (was_nack) {
        crm_err("Shutting down because cluster join with leader %s failed "
                QB_XS " join-%d NACK'd", welcome_from, join_id);
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        controld_set_fsa_input_flags(R_STAYDOWN);
        return;
    }

    if (!AM_I_DC && controld_is_local_node(welcome_from)) {
        crm_warn("Discarding our own welcome - we're no longer the DC");
        return;
    }

    if (update_dc(input->msg) == FALSE) {
        crm_warn("Discarding %s from node %s (expected from %s)",
                 op, welcome_from, controld_globals.dc_name);
        return;
    }

    update_dc_expected(input->msg);

    /* record the node's feature set as a transient attribute */
    update_attrd(controld_globals.cluster->priv->node_name,
                 CRM_ATTR_FEATURE_SET, CRM_FEATURE_SET, NULL, FALSE);

    /* send our status section to the DC */
    tmp1 = controld_query_executor_state();
    if (tmp1 != NULL) {
        xmlNode *remotes = NULL;
        xmlNode *join_confirm = pcmk__new_request(pcmk_ipc_controld,
                                                  CRM_SYSTEM_CRMD,
                                                  controld_globals.dc_name,
                                                  CRM_SYSTEM_DC,
                                                  CRM_OP_JOIN_CONFIRM, tmp1);
        const pcmk__node_status_t *dc_node =
            pcmk__get_node(0, controld_globals.dc_name, NULL,
                           pcmk__node_search_cluster_member);

        crm_xml_add_int(join_confirm, PCMK__XA_JOIN_ID, join_id);

        crm_debug("Confirming join-%d: sending local operation history to %s",
                  join_id, controld_globals.dc_name);

        /*
         * If this is the node's first join since the controller started on it,
         * set its initial state (standby or member) according to the user's
         * preference.
         *
         * We do not clear the LRM history here. Even if the DC failed to do it
         * when we last left, removing them here creates a race condition if the
         * controller is being recovered. Instead of a list of active resources
         * from the executor, we may end up with a blank status section. If we
         * are _NOT_ lucky, we will probe for the "wrong" instance of anonymous
         * clones and end up with multiple active instances on the machine.
         */
        if (first_join
            && !pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {

            first_join = FALSE;
            if (start_state) {
                set_join_state(start_state,
                               controld_globals.cluster->priv->node_name,
                               controld_globals.our_uuid, false);
            }
        }

        pcmk__cluster_send_message(dc_node, pcmk_ipc_controld, join_confirm);
        pcmk__xml_free(join_confirm);

        if (AM_I_DC == FALSE) {
            register_fsa_input_adv(cause, I_NOT_DC, NULL, A_NOTHING, TRUE,
                                   __func__);
        }

        pcmk__xml_free(tmp1);

        /* Update the remote node cache with information about which node
         * is hosting the connection.
         */
        remotes = pcmk__xe_first_child(input->msg, PCMK_XE_NODES, NULL, NULL);
        if (remotes != NULL) {
            pcmk__xe_foreach_child(remotes, PCMK_XE_NODE,
                                   update_conn_host_cache, NULL);
        }

    } else {
        crm_err("Could not confirm join-%d with %s: Local operation history "
                "failed", join_id, controld_globals.dc_name);
        register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
    }
}
