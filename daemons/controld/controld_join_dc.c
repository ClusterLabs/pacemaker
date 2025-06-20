/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>               // PRIu32
#include <stdbool.h>                // bool, true, false
#include <stdio.h>                  // NULL
#include <stdlib.h>                 // free(), etc.

#include <glib.h>                   // gboolean, etc.
#include <libxml/tree.h>            // xmlNode

#include <crm/crm.h>

#include <crm/common/xml.h>
#include <crm/cluster.h>

#include <pacemaker-controld.h>

static char *max_generation_from = NULL;
static xmlNodePtr max_generation_xml = NULL;

/*!
 * \internal
 * \brief Nodes from which a CIB sync has failed since the peer joined
 *
 * This table is of the form (<tt>node_name -> join_id</tt>). \p node_name is
 * the name of a client node from which a CIB \p sync_from() call has failed in
 * \p do_dc_join_finalize() since the client joined the cluster as a peer.
 * \p join_id is the ID of the join round in which the \p sync_from() failed,
 * and is intended for use in nack log messages.
 */
static GHashTable *failed_sync_nodes = NULL;

void finalize_join_for(gpointer key, gpointer value, gpointer user_data);
void finalize_sync_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);
gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

/* Numeric counter used to identify join rounds (an unsigned int would be
 * appropriate, except we get and set it in XML as int)
 */
static int current_join_id = 0;

/*!
 * \internal
 * \brief Get log-friendly string equivalent of a controller group join phase
 *
 * \param[in] phase  Join phase
 *
 * \return Log-friendly string equivalent of \p phase
 */
static const char *
join_phase_text(enum controld_join_phase phase)
{
    switch (phase) {
        case controld_join_nack:
            return "nack";
        case controld_join_none:
            return "none";
        case controld_join_welcomed:
            return "welcomed";
        case controld_join_integrated:
            return "integrated";
        case controld_join_finalized:
            return "finalized";
        case controld_join_confirmed:
            return "confirmed";
        default:
            return "invalid";
    }
}

/*!
 * \internal
 * \brief Destroy the hash table containing failed sync nodes
 */
void
controld_destroy_failed_sync_table(void)
{
    if (failed_sync_nodes != NULL) {
        g_hash_table_destroy(failed_sync_nodes);
        failed_sync_nodes = NULL;
    }
}

/*!
 * \internal
 * \brief Remove a node from the failed sync nodes table if present
 *
 * \param[in] node_name  Node name to remove
 */
void
controld_remove_failed_sync_node(const char *node_name)
{
    if (failed_sync_nodes != NULL) {
        g_hash_table_remove(failed_sync_nodes, (gchar *) node_name);
    }
}

/*!
 * \internal
 * \brief Add to a hash table a node whose CIB failed to sync
 *
 * \param[in] node_name  Name of node whose CIB failed to sync
 * \param[in] join_id    Join round when the failure occurred
 */
static void
record_failed_sync_node(const char *node_name, gint join_id)
{
    if (failed_sync_nodes == NULL) {
        failed_sync_nodes = pcmk__strikey_table(g_free, NULL);
    }

    /* If the node is already in the table then we failed to nack it during the
     * filter offer step
     */
    CRM_LOG_ASSERT(g_hash_table_insert(failed_sync_nodes, g_strdup(node_name),
                                       GINT_TO_POINTER(join_id)));
}

/*!
 * \internal
 * \brief Look up a node name in the failed sync table
 *
 * \param[in]  node_name  Name of node to look up
 * \param[out] join_id    Where to store the join ID of when the sync failed
 *
 * \return Standard Pacemaker return code. Specifically, \p pcmk_rc_ok if the
 *         node name was found, or \p pcmk_rc_node_unknown otherwise.
 * \note \p *join_id is set to -1 if the node is not found.
 */
static int
lookup_failed_sync_node(const char *node_name, gint *join_id)
{
    *join_id = -1;

    if (failed_sync_nodes != NULL) {
        gpointer result = g_hash_table_lookup(failed_sync_nodes,
                                              (gchar *) node_name);
        if (result != NULL) {
            *join_id = GPOINTER_TO_INT(result);
            return pcmk_rc_ok;
        }
    }
    return pcmk_rc_node_unknown;
}

void
crm_update_peer_join(const char *source, pcmk__node_status_t *node,
                     enum controld_join_phase phase)
{
    enum controld_join_phase last = controld_get_join_phase(node);

    CRM_CHECK(node != NULL, return);

    /* Remote nodes do not participate in joins */
    if (pcmk_is_set(node->flags, pcmk__node_status_remote)) {
        return;
    }

    if (phase == last) {
        crm_trace("Node %s join-%d phase is still %s "
                  QB_XS " nodeid=%" PRIu32 " source=%s",
                  node->name, current_join_id, join_phase_text(last),
                  node->cluster_layer_id, source);
        return;
    }

    if ((phase <= controld_join_none) || (phase == (last + 1))) {
        struct controld_node_status_data *data = NULL;

        if (node->user_data == NULL) {
            node->user_data =
                pcmk__assert_alloc(1, sizeof(struct controld_node_status_data));
        }
        data = node->user_data;
        data->join_phase = phase;

        crm_trace("Node %s join-%d phase is now %s (was %s) "
                  QB_XS " nodeid=%" PRIu32 " source=%s",
                  node->name, current_join_id, join_phase_text(phase),
                  join_phase_text(last), node->cluster_layer_id,
                  source);
        return;
    }

    crm_warn("Rejecting join-%d phase update for node %s because can't go from "
             "%s to %s " QB_XS " nodeid=%" PRIu32 " source=%s",
             current_join_id, node->name, join_phase_text(last),
             join_phase_text(phase), node->cluster_layer_id, source);
}

static void
start_join_round(void)
{
    GHashTableIter iter;
    pcmk__node_status_t *peer = NULL;

    crm_debug("Starting new join round join-%d", current_join_id);

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &peer)) {
        crm_update_peer_join(__func__, peer, controld_join_none);
    }
    if (max_generation_from != NULL) {
        free(max_generation_from);
        max_generation_from = NULL;
    }
    if (max_generation_xml != NULL) {
        pcmk__xml_free(max_generation_xml);
        max_generation_xml = NULL;
    }
    controld_clear_fsa_input_flags(R_HAVE_CIB);
}

/*!
 * \internal
 * \brief Create a join message from the DC
 *
 * \param[in] join_op  Join operation name
 * \param[in] host_to  Recipient of message
 */
static xmlNode *
create_dc_message(const char *join_op, const char *host_to)
{
    xmlNode *msg = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_DC, host_to,
                                     CRM_SYSTEM_CRMD, join_op, NULL);

    /* Identify which election this is a part of */
    crm_xml_add_int(msg, PCMK__XA_JOIN_ID, current_join_id);

    /* Add a field specifying whether the DC is shutting down. This keeps the
     * joining node from fencing the old DC if it becomes the new DC.
     */
    pcmk__xe_set_bool_attr(msg, PCMK__XA_DC_LEAVING,
                           pcmk_is_set(controld_globals.fsa_input_register,
                                       R_SHUTDOWN));
    return msg;
}

static void
join_make_offer(gpointer key, gpointer value, gpointer user_data)
{
    /* @TODO We don't use user_data except to distinguish one particular call
     * from others. Make this clearer.
     */
    xmlNode *offer = NULL;
    pcmk__node_status_t *member = (pcmk__node_status_t *) value;

    pcmk__assert(member != NULL);
    if (!pcmk__cluster_is_node_active(member)) {
        crm_info("Not making join-%d offer to inactive node %s",
                 current_join_id, pcmk__s(member->name, "with unknown name"));
        if ((member->expected == NULL)
            && pcmk__str_eq(member->state, PCMK__VALUE_LOST, pcmk__str_none)) {
            /* You would think this unsafe, but in fact this plus an
             * active resource is what causes it to be fenced.
             *
             * Yes, this does mean that any node that dies at the same
             * time as the old DC and is not running resource (still)
             * won't be fenced.
             *
             * I'm not happy about this either.
             */
            pcmk__update_peer_expected(__func__, member, CRMD_JOINSTATE_DOWN);
        }
        return;
    }

    if (member->name == NULL) {
        crm_info("Not making join-%d offer to node uuid %s with unknown name",
                 current_join_id, member->xml_id);
        return;
    }

    if (controld_globals.membership_id != controld_globals.peer_seq) {
        controld_globals.membership_id = controld_globals.peer_seq;
        crm_info("Making join-%d offers based on membership event %llu",
                 current_join_id, controld_globals.peer_seq);
    }

    if (user_data != NULL) {
        enum controld_join_phase phase = controld_get_join_phase(member);

        if (phase > controld_join_none) {
            crm_info("Not making join-%d offer to already known node %s (%s)",
                     current_join_id, member->name, join_phase_text(phase));
            return;
        }
    }

    crm_update_peer_join(__func__, (pcmk__node_status_t*) member,
                         controld_join_none);

    offer = create_dc_message(CRM_OP_JOIN_OFFER, member->name);

    // Advertise our feature set so the joining node can bail if not compatible
    crm_xml_add(offer, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);

    crm_info("Sending join-%d offer to %s", current_join_id, member->name);
    pcmk__cluster_send_message(member, pcmk_ipc_controld, offer);
    pcmk__xml_free(offer);

    crm_update_peer_join(__func__, member, controld_join_welcomed);
}

/*	 A_DC_JOIN_OFFER_ALL	*/
void
do_dc_join_offer_all(long long action,
                     enum crmd_fsa_cause cause,
                     enum crmd_fsa_state cur_state,
                     enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int count;

    /* Reset everyone's status back to down or in_ccm in the CIB.
     * Any nodes that are active in the CIB but not in the cluster membership
     * will be seen as offline by the scheduler anyway.
     */
    current_join_id++;
    start_join_round();

    update_dc(NULL);
    if (cause == C_HA_MESSAGE && current_input == I_NODE_JOIN) {
        crm_info("A new node joined the cluster");
    }
    g_hash_table_foreach(pcmk__peer_cache, join_make_offer, NULL);

    count = crmd_join_phase_count(controld_join_welcomed);
    crm_info("Waiting on join-%d requests from %d outstanding node%s",
             current_join_id, count, pcmk__plural_s(count));

    // Don't waste time by invoking the scheduler yet
}

/*	 A_DC_JOIN_OFFER_ONE	*/
void
do_dc_join_offer_one(long long action,
                     enum crmd_fsa_cause cause,
                     enum crmd_fsa_state cur_state,
                     enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    pcmk__node_status_t *member = NULL;
    ha_msg_input_t *welcome = NULL;
    int count;
    const char *join_to = NULL;

    if (msg_data->data == NULL) {
        crm_info("Making join-%d offers to any unconfirmed nodes "
                 "because an unknown node joined", current_join_id);
        g_hash_table_foreach(pcmk__peer_cache, join_make_offer, &member);
        check_join_state(cur_state, __func__);
        return;
    }

    welcome = fsa_typed_data(fsa_dt_ha_msg);
    if (welcome == NULL) {
        // fsa_typed_data() already logged an error
        return;
    }

    join_to = crm_element_value(welcome->msg, PCMK__XA_SRC);
    if (join_to == NULL) {
        crm_err("Can't make join-%d offer to unknown node", current_join_id);
        return;
    }
    member = pcmk__get_node(0, join_to, NULL, pcmk__node_search_cluster_member);

    /* It is possible that a node will have been sick or starting up when the
     * original offer was made. However, it will either re-announce itself in
     * due course, or we can re-store the original offer on the client.
     */

    crm_update_peer_join(__func__, member, controld_join_none);
    join_make_offer(NULL, member, NULL);

    /* If the offer isn't to the local node, make an offer to the local node as
     * well, to ensure the correct value for max_generation_from.
     */
    if (!controld_is_local_node(join_to)) {
        member = controld_get_local_node_status();
        join_make_offer(NULL, member, NULL);
    }

    /* This was a genuine join request; cancel any existing transition and
     * invoke the scheduler.
     */
    abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart, "Node join",
                     NULL);

    count = crmd_join_phase_count(controld_join_welcomed);
    crm_info("Waiting on join-%d requests from %d outstanding node%s",
             current_join_id, count, pcmk__plural_s(count));

    // Don't waste time by invoking the scheduler yet
}

static int
compare_int_fields(xmlNode * left, xmlNode * right, const char *field)
{
    const char *elem_l = crm_element_value(left, field);
    const char *elem_r = crm_element_value(right, field);

    long long int_elem_l;
    long long int_elem_r;

    int rc = pcmk_rc_ok;

    rc = pcmk__scan_ll(elem_l, &int_elem_l, -1LL);
    if (rc != pcmk_rc_ok) { // Shouldn't be possible
        crm_warn("Comparing current CIB %s as -1 "
                 "because '%s' is not an integer", field, elem_l);
    }

    rc = pcmk__scan_ll(elem_r, &int_elem_r, -1LL);
    if (rc != pcmk_rc_ok) { // Shouldn't be possible
        crm_warn("Comparing joining node's CIB %s as -1 "
                 "because '%s' is not an integer", field, elem_r);
    }

    if (int_elem_l < int_elem_r) {
        return -1;

    } else if (int_elem_l > int_elem_r) {
        return 1;
    }

    return 0;
}

/*	 A_DC_JOIN_PROCESS_REQ	*/
void
do_dc_join_filter_offer(long long action,
                        enum crmd_fsa_cause cause,
                        enum crmd_fsa_state cur_state,
                        enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *generation = NULL;

    int cmp = 0;
    int join_id = -1;
    int count = 0;
    gint value = 0;
    gboolean ack_nack_bool = TRUE;
    ha_msg_input_t *join_ack = fsa_typed_data(fsa_dt_ha_msg);

    const char *join_from = crm_element_value(join_ack->msg, PCMK__XA_SRC);
    const char *ref = crm_element_value(join_ack->msg, PCMK_XA_REFERENCE);
    const char *join_version = crm_element_value(join_ack->msg,
                                                 PCMK_XA_CRM_FEATURE_SET);
    pcmk__node_status_t *join_node = NULL;

    if (join_from == NULL) {
        crm_err("Ignoring invalid join request without node name");
        return;
    }
    join_node = pcmk__get_node(0, join_from, NULL,
                               pcmk__node_search_cluster_member);

    crm_element_value_int(join_ack->msg, PCMK__XA_JOIN_ID, &join_id);
    if (join_id != current_join_id) {
        crm_debug("Ignoring join-%d request from %s because we are on join-%d",
                  join_id, join_from, current_join_id);
        check_join_state(cur_state, __func__);
        return;
    }

    generation = join_ack->xml;
    if (max_generation_xml != NULL && generation != NULL) {
        int lpc = 0;

        const char *attributes[] = {
            PCMK_XA_ADMIN_EPOCH,
            PCMK_XA_EPOCH,
            PCMK_XA_NUM_UPDATES,
        };

        /* It's not obvious that join_ack->xml is the PCMK__XE_GENERATION_TUPLE
         * element from the join client. The "if" guard is for clarity.
         */
        if (pcmk__xe_is(generation, PCMK__XE_GENERATION_TUPLE)) {
            for (lpc = 0; cmp == 0 && lpc < PCMK__NELEM(attributes); lpc++) {
                cmp = compare_int_fields(max_generation_xml, generation,
                                         attributes[lpc]);
            }

        } else {    // Should always be PCMK__XE_GENERATION_TUPLE
            CRM_LOG_ASSERT(false);
        }
    }

    if (ref == NULL) {
        ref = "none"; // for logging only
    }

    if (lookup_failed_sync_node(join_from, &value) == pcmk_rc_ok) {
        crm_err("Rejecting join-%d request from node %s because we failed to "
                "sync its CIB in join-%d " QB_XS " ref=%s",
                join_id, join_from, value, ref);
        ack_nack_bool = FALSE;

    } else if (!pcmk__cluster_is_node_active(join_node)) {
        if (match_down_event(join_from) != NULL) {
            /* The join request was received after the node was fenced or
             * otherwise shutdown in a way that we're aware of. No need to log
             * an error in this rare occurrence; we know the client was recently
             * shut down, and receiving a lingering in-flight request is not
             * cause for alarm.
             */
            crm_debug("Rejecting join-%d request from inactive node %s "
                      QB_XS " ref=%s", join_id, join_from, ref);
        } else {
            crm_err("Rejecting join-%d request from inactive node %s "
                    QB_XS " ref=%s", join_id, join_from, ref);
        }
        ack_nack_bool = FALSE;

    } else if (generation == NULL) {
        crm_err("Rejecting invalid join-%d request from node %s "
                "missing CIB generation " QB_XS " ref=%s",
                join_id, join_from, ref);
        ack_nack_bool = FALSE;

    } else if ((join_version == NULL)
               || !feature_set_compatible(CRM_FEATURE_SET, join_version)) {
        crm_err("Rejecting join-%d request from node %s because feature set %s"
                " is incompatible with ours (%s) " QB_XS " ref=%s",
                join_id, join_from, (join_version? join_version : "pre-3.1.0"),
                CRM_FEATURE_SET, ref);
        ack_nack_bool = FALSE;

    } else if (max_generation_xml == NULL) {
        const char *validation = crm_element_value(generation,
                                                   PCMK_XA_VALIDATE_WITH);

        if (pcmk__get_schema(validation) == NULL) {
            crm_err("Rejecting join-%d request from %s (with first CIB "
                    "generation) due to %s schema version %s " QB_XS " ref=%s",
                    join_id, join_from,
                    ((validation == NULL)? "missing" : "unknown"),
                    pcmk__s(validation, ""), ref);
            ack_nack_bool = FALSE;

        } else {
            crm_debug("Accepting join-%d request from %s (with first CIB "
                      "generation) " QB_XS " ref=%s",
                      join_id, join_from, ref);
            max_generation_xml = pcmk__xml_copy(NULL, generation);
            pcmk__str_update(&max_generation_from, join_from);
        }

    } else if ((cmp < 0)
               || ((cmp == 0) && controld_is_local_node(join_from))) {
        const char *validation = crm_element_value(generation,
                                                   PCMK_XA_VALIDATE_WITH);

        if (pcmk__get_schema(validation) == NULL) {
            crm_err("Rejecting join-%d request from %s (with better CIB "
                    "generation than current best from %s) due to %s "
                    "schema version %s " QB_XS " ref=%s",
                    join_id, join_from, max_generation_from,
                    ((validation == NULL)? "missing" : "unknown"),
                    pcmk__s(validation, ""), ref);
            ack_nack_bool = FALSE;

        } else {
            crm_debug("Accepting join-%d request from %s (with better CIB "
                      "generation than current best from %s) " QB_XS " ref=%s",
                      join_id, join_from, max_generation_from, ref);
            crm_log_xml_debug(max_generation_xml, "Old max generation");
            crm_log_xml_debug(generation, "New max generation");

            pcmk__xml_free(max_generation_xml);
            max_generation_xml = pcmk__xml_copy(NULL, join_ack->xml);
            pcmk__str_update(&max_generation_from, join_from);
        }

    } else {
        crm_debug("Accepting join-%d request from %s " QB_XS " ref=%s",
                  join_id, join_from, ref);
    }

    if (!ack_nack_bool) {
        crm_update_peer_join(__func__, join_node, controld_join_nack);
        pcmk__update_peer_expected(__func__, join_node, CRMD_JOINSTATE_NACK);

    } else {
        crm_update_peer_join(__func__, join_node, controld_join_integrated);
        pcmk__update_peer_expected(__func__, join_node, CRMD_JOINSTATE_MEMBER);
    }

    count = crmd_join_phase_count(controld_join_integrated);
    crm_debug("%d node%s currently integrated in join-%d",
              count, pcmk__plural_s(count), join_id);

    if (check_join_state(cur_state, __func__) == FALSE) {
        // Don't waste time by invoking the scheduler yet
        count = crmd_join_phase_count(controld_join_welcomed);
        crm_debug("Waiting on join-%d requests from %d outstanding node%s",
                  join_id, count, pcmk__plural_s(count));
    }
}

/*	A_DC_JOIN_FINALIZE	*/
void
do_dc_join_finalize(long long action,
                    enum crmd_fsa_cause cause,
                    enum crmd_fsa_state cur_state,
                    enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    char *sync_from = NULL;
    int rc = pcmk_ok;
    int count_welcomed = crmd_join_phase_count(controld_join_welcomed);
    int count_finalizable = crmd_join_phase_count(controld_join_integrated)
                            + crmd_join_phase_count(controld_join_nack);

    /* This we can do straight away and avoid clients timing us out
     *  while we compute the latest CIB
     */
    if (count_welcomed != 0) {
        crm_debug("Waiting on join-%d requests from %d outstanding node%s "
                  "before finalizing join", current_join_id, count_welcomed,
                  pcmk__plural_s(count_welcomed));
        crmd_join_phase_log(LOG_DEBUG);
        /* crmd_fsa_stall(FALSE); Needed? */
        return;

    } else if (count_finalizable == 0) {
        crm_debug("Finalization not needed for join-%d at the current time",
                  current_join_id);
        crmd_join_phase_log(LOG_DEBUG);
        check_join_state(controld_globals.fsa_state, __func__);
        return;
    }

    controld_clear_fsa_input_flags(R_HAVE_CIB);
    if ((max_generation_from == NULL)
        || controld_is_local_node(max_generation_from)) {
        controld_set_fsa_input_flags(R_HAVE_CIB);
    }

    if (!controld_globals.transition_graph->complete) {
        crm_warn("Delaying join-%d finalization while transition in progress",
                 current_join_id);
        crmd_join_phase_log(LOG_DEBUG);
        crmd_fsa_stall(FALSE);
        return;
    }

    if (pcmk_is_set(controld_globals.fsa_input_register, R_HAVE_CIB)) {
        // Send our CIB out to everyone
        sync_from = pcmk__str_copy(controld_globals.cluster->priv->node_name);
    } else {
        // Ask for the agreed best CIB
        sync_from = pcmk__str_copy(max_generation_from);
    }
    crm_notice("Finalizing join-%d for %d node%s (sync'ing CIB %s.%s.%s "
               "with schema %s and feature set %s from %s)",
               current_join_id, count_finalizable,
               pcmk__plural_s(count_finalizable),
               crm_element_value(max_generation_xml, PCMK_XA_ADMIN_EPOCH),
               crm_element_value(max_generation_xml, PCMK_XA_EPOCH),
               crm_element_value(max_generation_xml, PCMK_XA_NUM_UPDATES),
               crm_element_value(max_generation_xml, PCMK_XA_VALIDATE_WITH),
               crm_element_value(max_generation_xml, PCMK_XA_CRM_FEATURE_SET),
               sync_from);
    crmd_join_phase_log(LOG_DEBUG);

    rc = controld_globals.cib_conn->cmds->sync_from(controld_globals.cib_conn,
                                                    sync_from, NULL, cib_none);
    fsa_register_cib_callback(rc, sync_from, finalize_sync_callback);
}

void
free_max_generation(void)
{
    free(max_generation_from);
    max_generation_from = NULL;

    pcmk__xml_free(max_generation_xml);
    max_generation_xml = NULL;
}

void
finalize_sync_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    CRM_LOG_ASSERT(-EPERM != rc);

    if (rc != pcmk_ok) {
        const char *sync_from = (const char *) user_data;

        do_crm_log(((rc == -pcmk_err_old_data)? LOG_WARNING : LOG_ERR),
                   "Could not sync CIB from %s in join-%d: %s",
                   sync_from, current_join_id, pcmk_strerror(rc));

        if (rc != -pcmk_err_old_data) {
            record_failed_sync_node(sync_from, current_join_id);
        }

        /* restart the whole join process */
        register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION_DC, NULL, NULL,
                               __func__);

    } else if (!AM_I_DC) {
        crm_debug("Sync'ed CIB for join-%d but no longer DC", current_join_id);

    } else if (controld_globals.fsa_state != S_FINALIZE_JOIN) {
        crm_debug("Sync'ed CIB for join-%d but no longer in S_FINALIZE_JOIN "
                  "(%s)", current_join_id,
                  fsa_state2string(controld_globals.fsa_state));

    } else {
        controld_set_fsa_input_flags(R_HAVE_CIB);

        /* make sure dc_uuid is re-set to us */
        if (!check_join_state(controld_globals.fsa_state, __func__)) {
            int count_finalizable = 0;

            count_finalizable = crmd_join_phase_count(controld_join_integrated)
                                + crmd_join_phase_count(controld_join_nack);

            crm_debug("Notifying %d node%s of join-%d results",
                      count_finalizable, pcmk__plural_s(count_finalizable),
                      current_join_id);
            g_hash_table_foreach(pcmk__peer_cache, finalize_join_for, NULL);
        }
    }
}

static void
join_node_state_commit_callback(xmlNode *msg, int call_id, int rc,
                                xmlNode *output, void *user_data)
{
    const char *node = user_data;

    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;    // for register_fsa_error() macro

        crm_crit("join-%d node history update (via CIB call %d) for node %s "
                 "failed: %s",
                 current_join_id, call_id, node, pcmk_strerror(rc));
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }

    crm_debug("join-%d node history update (via CIB call %d) for node %s "
              "complete",
              current_join_id, call_id, node);
    check_join_state(controld_globals.fsa_state, __func__);
}

/*	A_DC_JOIN_PROCESS_ACK	*/
void
do_dc_join_ack(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int join_id = -1;
    ha_msg_input_t *join_ack = fsa_typed_data(fsa_dt_ha_msg);

    const char *op = crm_element_value(join_ack->msg, PCMK__XA_CRM_TASK);
    char *join_from = crm_element_value_copy(join_ack->msg, PCMK__XA_SRC);
    pcmk__node_status_t *peer = NULL;
    enum controld_join_phase phase = controld_join_none;

    enum controld_section_e section = controld_section_lrm;
    char *xpath = NULL;
    xmlNode *state = join_ack->xml;
    xmlNode *execd_state = NULL;

    cib_t *cib = controld_globals.cib_conn;
    int rc = pcmk_ok;

    // Sanity checks
    if (join_from == NULL) {
        crm_warn("Ignoring message received without node identification");
        goto done;
    }
    if (op == NULL) {
        crm_warn("Ignoring message received from %s without task", join_from);
        goto done;
    }

    if (strcmp(op, CRM_OP_JOIN_CONFIRM)) {
        crm_debug("Ignoring '%s' message from %s while waiting for '%s'",
                  op, join_from, CRM_OP_JOIN_CONFIRM);
        goto done;
    }

    if (crm_element_value_int(join_ack->msg, PCMK__XA_JOIN_ID, &join_id) != 0) {
        crm_warn("Ignoring join confirmation from %s without valid join ID",
                 join_from);
        goto done;
    }

    peer = pcmk__get_node(0, join_from, NULL, pcmk__node_search_cluster_member);
    phase = controld_get_join_phase(peer);
    if (phase != controld_join_finalized) {
        crm_info("Ignoring out-of-sequence join-%d confirmation from %s "
                 "(currently %s not %s)",
                 join_id, join_from, join_phase_text(phase),
                 join_phase_text(controld_join_finalized));
        goto done;
    }

    if (join_id != current_join_id) {
        crm_err("Rejecting join-%d confirmation from %s "
                "because currently on join-%d",
                join_id, join_from, current_join_id);
        crm_update_peer_join(__func__, peer, controld_join_nack);
        goto done;
    }

    crm_update_peer_join(__func__, peer, controld_join_confirmed);

    /* Update CIB with node's current executor state. A new transition will be
     * triggered later, when the CIB manager notifies us of the change.
     *
     * The delete and modify requests are part of an atomic transaction.
     */
    rc = cib->cmds->init_transaction(cib);
    if (rc != pcmk_ok) {
        goto done;
    }

    // Delete relevant parts of node's current executor state from CIB
    if (pcmk_is_set(controld_globals.flags, controld_shutdown_lock_enabled)) {
        section = controld_section_lrm_unlocked;
    }
    controld_node_state_deletion_strings(join_from, section, &xpath, NULL);

    rc = cib->cmds->remove(cib, xpath, NULL,
                           cib_xpath|cib_multiple|cib_transaction);
    if (rc != pcmk_ok) {
        goto done;
    }

    // Update CIB with node's latest known executor state
    if (controld_is_local_node(join_from)) {

        // Use the latest possible state if processing our own join ack
        execd_state = controld_query_executor_state();

        if (execd_state != NULL) {
            crm_debug("Updating local node history for join-%d from query "
                      "result",
                      current_join_id);
            state = execd_state;

        } else {
            crm_warn("Updating local node history from join-%d confirmation "
                     "because query failed",
                     current_join_id);
        }

    } else {
        crm_debug("Updating node history for %s from join-%d confirmation",
                  join_from, current_join_id);
    }

    rc = cib->cmds->modify(cib, PCMK_XE_STATUS, state,
                           cib_can_create|cib_transaction);
    pcmk__xml_free(execd_state);
    if (rc != pcmk_ok) {
        goto done;
    }

    // Commit the transaction
    rc = cib->cmds->end_transaction(cib, true, cib_none);
    fsa_register_cib_callback(rc, join_from, join_node_state_commit_callback);

    if (rc > 0) {
        // join_from will be freed after callback
        join_from = NULL;
        rc = pcmk_ok;
    }

done:
    if (rc != pcmk_ok) {
        crm_crit("join-%d node history update for node %s failed: %s",
                 current_join_id, join_from, pcmk_strerror(rc));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
    free(join_from);
    free(xpath);
}

void
finalize_join_for(gpointer key, gpointer value, gpointer user_data)
{
    xmlNode *acknak = NULL;
    xmlNode *tmp1 = NULL;
    pcmk__node_status_t *join_node = value;
    const char *join_to = join_node->name;
    enum controld_join_phase phase = controld_get_join_phase(join_node);
    bool integrated = false;

    switch (phase) {
        case controld_join_integrated:
            integrated = true;
            break;
        case controld_join_nack:
            break;
        default:
            crm_trace("Not updating non-integrated and non-nacked node %s (%s) "
                      "for join-%d",
                      join_to, join_phase_text(phase), current_join_id);
            return;
    }

    /* Update the <node> element with the node's name and UUID, in case they
     * weren't known before
     */
    crm_trace("Updating node name and UUID in CIB for %s", join_to);
    tmp1 = pcmk__xe_create(NULL, PCMK_XE_NODE);
    crm_xml_add(tmp1, PCMK_XA_ID, pcmk__cluster_get_xml_id(join_node));
    crm_xml_add(tmp1, PCMK_XA_UNAME, join_to);
    fsa_cib_anon_update(PCMK_XE_NODES, tmp1);
    pcmk__xml_free(tmp1);

    join_node = pcmk__get_node(0, join_to, NULL,
                               pcmk__node_search_cluster_member);
    if (!pcmk__cluster_is_node_active(join_node)) {
        /*
         * NACK'ing nodes that the membership layer doesn't know about yet
         * simply creates more churn
         *
         * Better to leave them waiting and let the join restart when
         * the new membership event comes in
         *
         * All other NACKs (due to versions etc) should still be processed
         */
        pcmk__update_peer_expected(__func__, join_node, CRMD_JOINSTATE_PENDING);
        return;
    }

    // Acknowledge or nack node's join request
    crm_debug("%sing join-%d request from %s",
              integrated? "Acknowledg" : "Nack", current_join_id, join_to);
    acknak = create_dc_message(CRM_OP_JOIN_ACKNAK, join_to);
    pcmk__xe_set_bool_attr(acknak, CRM_OP_JOIN_ACKNAK, integrated);

    if (integrated) {
        // No change needed for a nacked node
        crm_update_peer_join(__func__, join_node, controld_join_finalized);
        pcmk__update_peer_expected(__func__, join_node, CRMD_JOINSTATE_MEMBER);

        /* Iterate through the remote peer cache and add information on which
         * node hosts each to the ACK message.  This keeps new controllers in
         * sync with what has already happened.
         */
        if (pcmk__cluster_num_remote_nodes() > 0) {
            GHashTableIter iter;
            pcmk__node_status_t *node = NULL;
            xmlNode *remotes = pcmk__xe_create(acknak, PCMK_XE_NODES);

            g_hash_table_iter_init(&iter, pcmk__remote_peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                xmlNode *remote = NULL;

                if (!node->conn_host) {
                    continue;
                }

                remote = pcmk__xe_create(remotes, PCMK_XE_NODE);
                pcmk__xe_set_props(remote,
                                   PCMK_XA_ID, node->name,
                                   PCMK__XA_NODE_STATE, node->state,
                                   PCMK__XA_CONNECTION_HOST, node->conn_host,
                                   NULL);
            }
        }
    }
    pcmk__cluster_send_message(join_node, pcmk_ipc_controld, acknak);
    pcmk__xml_free(acknak);
    return;
}

gboolean
check_join_state(enum crmd_fsa_state cur_state, const char *source)
{
    static unsigned long long highest_seq = 0;

    if (controld_globals.membership_id != controld_globals.peer_seq) {
        crm_debug("join-%d: Membership changed from %llu to %llu "
                  QB_XS " highest=%llu state=%s for=%s",
                  current_join_id, controld_globals.membership_id,
                  controld_globals.peer_seq, highest_seq,
                  fsa_state2string(cur_state), source);
        if (highest_seq < controld_globals.peer_seq) {
            /* Don't spam the FSA with duplicates */
            highest_seq = controld_globals.peer_seq;
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }

    } else if (cur_state == S_INTEGRATION) {
        if (crmd_join_phase_count(controld_join_welcomed) == 0) {
            int count = crmd_join_phase_count(controld_join_integrated);

            crm_debug("join-%d: Integration of %d peer%s complete "
                      QB_XS " state=%s for=%s",
                      current_join_id, count, pcmk__plural_s(count),
                      fsa_state2string(cur_state), source);
            register_fsa_input_before(C_FSA_INTERNAL, I_INTEGRATED, NULL);
            return TRUE;
        }

    } else if (cur_state == S_FINALIZE_JOIN) {
        if (!pcmk_is_set(controld_globals.fsa_input_register, R_HAVE_CIB)) {
            crm_debug("join-%d: Delaying finalization until we have CIB "
                      QB_XS " state=%s for=%s",
                      current_join_id, fsa_state2string(cur_state), source);
            return TRUE;

        } else if (crmd_join_phase_count(controld_join_welcomed) != 0) {
            int count = crmd_join_phase_count(controld_join_welcomed);

            crm_debug("join-%d: Still waiting on %d welcomed node%s "
                      QB_XS " state=%s for=%s",
                      current_join_id, count, pcmk__plural_s(count),
                      fsa_state2string(cur_state), source);
            crmd_join_phase_log(LOG_DEBUG);

        } else if (crmd_join_phase_count(controld_join_integrated) != 0) {
            int count = crmd_join_phase_count(controld_join_integrated);

            crm_debug("join-%d: Still waiting on %d integrated node%s "
                      QB_XS " state=%s for=%s",
                      current_join_id, count, pcmk__plural_s(count),
                      fsa_state2string(cur_state), source);
            crmd_join_phase_log(LOG_DEBUG);

        } else if (crmd_join_phase_count(controld_join_finalized) != 0) {
            int count = crmd_join_phase_count(controld_join_finalized);

            crm_debug("join-%d: Still waiting on %d finalized node%s "
                      QB_XS " state=%s for=%s",
                      current_join_id, count, pcmk__plural_s(count),
                      fsa_state2string(cur_state), source);
            crmd_join_phase_log(LOG_DEBUG);

        } else {
            crm_debug("join-%d: Complete " QB_XS " state=%s for=%s",
                      current_join_id, fsa_state2string(cur_state), source);
            register_fsa_input_later(C_FSA_INTERNAL, I_FINALIZED, NULL);
            return TRUE;
        }
    }

    return FALSE;
}

void
do_dc_join_final(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    crm_debug("Ensuring DC, quorum and node attributes are up-to-date");
    crm_update_quorum(pcmk__cluster_has_quorum(), TRUE);
}

int crmd_join_phase_count(enum controld_join_phase phase)
{
    int count = 0;
    pcmk__node_status_t *peer;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &peer)) {
        if (controld_get_join_phase(peer) == phase) {
            count++;
        }
    }
    return count;
}

void crmd_join_phase_log(int level)
{
    pcmk__node_status_t *peer;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &peer)) {
        do_crm_log(level, "join-%d: %s=%s", current_join_id, peer->name,
                   join_phase_text(controld_get_join_phase(peer)));
    }
}
