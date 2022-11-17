/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include <pacemaker-controld.h>

static void
tengine_stonith_history_synced(stonith_t *st, stonith_event_t *st_event);

/*
 * stonith failure counting
 *
 * We don't want to get stuck in a permanent fencing loop. Keep track of the
 * number of fencing failures for each target node, and the most we'll restart a
 * transition for.
 */

struct st_fail_rec {
    int count;
};

static bool fence_reaction_panic = FALSE;
static unsigned long int stonith_max_attempts = 10;
static GHashTable *stonith_failures = NULL;

void
update_stonith_max_attempts(const char *value)
{
    stonith_max_attempts = char2score(value);
    if (stonith_max_attempts < 1UL) {
        stonith_max_attempts = 10UL;
    }
}

void
set_fence_reaction(const char *reaction_s)
{
    if (pcmk__str_eq(reaction_s, "panic", pcmk__str_casei)) {
        fence_reaction_panic = TRUE;

    } else {
        if (!pcmk__str_eq(reaction_s, "stop", pcmk__str_casei)) {
            crm_warn("Invalid value '%s' for %s, using 'stop'",
                     reaction_s, XML_CONFIG_ATTR_FENCE_REACTION);
        }
        fence_reaction_panic = FALSE;
    }
}

static gboolean
too_many_st_failures(const char *target)
{
    GHashTableIter iter;
    const char *key = NULL;
    struct st_fail_rec *value = NULL;

    if (stonith_failures == NULL) {
        return FALSE;
    }

    if (target == NULL) {
        g_hash_table_iter_init(&iter, stonith_failures);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
               (gpointer *) &value)) {

            if (value->count >= stonith_max_attempts) {
                target = (const char*)key;
                goto too_many;
            }
        }
    } else {
        value = g_hash_table_lookup(stonith_failures, target);
        if ((value != NULL) && (value->count >= stonith_max_attempts)) {
            goto too_many;
        }
    }
    return FALSE;

too_many:
    crm_warn("Too many failures (%d) to fence %s, giving up",
             value->count, target);
    return TRUE;
}

/*!
 * \internal
 * \brief Reset a stonith fail count
 *
 * \param[in] target  Name of node to reset, or NULL for all
 */
void
st_fail_count_reset(const char *target)
{
    if (stonith_failures == NULL) {
        return;
    }

    if (target) {
        struct st_fail_rec *rec = NULL;

        rec = g_hash_table_lookup(stonith_failures, target);
        if (rec) {
            rec->count = 0;
        }
    } else {
        GHashTableIter iter;
        const char *key = NULL;
        struct st_fail_rec *rec = NULL;

        g_hash_table_iter_init(&iter, stonith_failures);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                      (gpointer *) &rec)) {
            rec->count = 0;
        }
    }
}

static void
st_fail_count_increment(const char *target)
{
    struct st_fail_rec *rec = NULL;

    if (stonith_failures == NULL) {
        stonith_failures = pcmk__strkey_table(free, free);
    }

    rec = g_hash_table_lookup(stonith_failures, target);
    if (rec) {
        rec->count++;
    } else {
        rec = malloc(sizeof(struct st_fail_rec));
        if(rec == NULL) {
            return;
        }

        rec->count = 1;
        g_hash_table_insert(stonith_failures, strdup(target), rec);
    }
}

/* end stonith fail count functions */


static void
cib_fencing_updated(xmlNode *msg, int call_id, int rc, xmlNode *output,
                    void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Fencing update %d for %s: failed - %s (%d)",
                call_id, (char *)user_data, pcmk_strerror(rc), rc);
        crm_log_xml_warn(msg, "Failed update");
        abort_transition(INFINITY, pcmk__graph_shutdown, "CIB update failed",
                         NULL);

    } else {
        crm_info("Fencing update %d for %s: complete", call_id, (char *)user_data);
    }
}

static void
send_stonith_update(pcmk__graph_action_t *action, const char *target,
                    const char *uuid)
{
    int rc = pcmk_ok;
    crm_node_t *peer = NULL;

    /* We (usually) rely on the membership layer to do node_update_cluster,
     * and the peer status callback to do node_update_peer, because the node
     * might have already rejoined before we get the stonith result here.
     */
    int flags = node_update_join | node_update_expected;

    /* zero out the node-status & remove all LRM status info */
    xmlNode *node_state = NULL;

    CRM_CHECK(target != NULL, return);
    CRM_CHECK(uuid != NULL, return);

    /* Make sure the membership and join caches are accurate */
    peer = crm_get_peer_full(0, target, CRM_GET_PEER_ANY);

    CRM_CHECK(peer != NULL, return);

    if (peer->state == NULL) {
        /* Usually, we rely on the membership layer to update the cluster state
         * in the CIB. However, if the node has never been seen, do it here, so
         * the node is not considered unclean.
         */
        flags |= node_update_cluster;
    }

    if (peer->uuid == NULL) {
        crm_info("Recording uuid '%s' for node '%s'", uuid, target);
        peer->uuid = strdup(uuid);
    }

    crmd_peer_down(peer, TRUE);

    /* Generate a node state update for the CIB */
    node_state = create_node_state_update(peer, flags, NULL, __func__);

    /* we have to mark whether or not remote nodes have already been fenced */
    if (peer->flags & crm_remote_node) {
        char *now_s = pcmk__ttoa(time(NULL));

        crm_xml_add(node_state, XML_NODE_IS_FENCED, now_s);
        free(now_s);
    }

    /* Force our known ID */
    crm_xml_add(node_state, XML_ATTR_UUID, uuid);

    rc = fsa_cib_conn->cmds->update(fsa_cib_conn, XML_CIB_TAG_STATUS, node_state,
                                    cib_quorum_override | cib_scope_local | cib_can_create);

    /* Delay processing the trigger until the update completes */
    crm_debug("Sending fencing update %d for %s", rc, target);
    fsa_register_cib_callback(rc, FALSE, strdup(target), cib_fencing_updated);

    /* Make sure it sticks */
    /* fsa_cib_conn->cmds->bump_epoch(fsa_cib_conn, cib_quorum_override|cib_scope_local);    */

    controld_delete_node_state(peer->uname, controld_section_all,
                               cib_scope_local);
    free_xml(node_state);
    return;
}

/*!
 * \internal
 * \brief Abort transition due to stonith failure
 *
 * \param[in] abort_action  Whether to restart or stop transition
 * \param[in] target  Don't restart if this (NULL for any) has too many failures
 * \param[in] reason  Log this stonith action XML as abort reason (or NULL)
 */
static void
abort_for_stonith_failure(enum pcmk__graph_next abort_action,
                          const char *target, const xmlNode *reason)
{
    /* If stonith repeatedly fails, we eventually give up on starting a new
     * transition for that reason.
     */
    if ((abort_action != pcmk__graph_wait) && too_many_st_failures(target)) {
        abort_action = pcmk__graph_wait;
    }
    abort_transition(INFINITY, abort_action, "Stonith failed", reason);
}


/*
 * stonith cleanup list
 *
 * If the DC is shot, proper notifications might not go out.
 * The stonith cleanup list allows the cluster to (re-)send
 * notifications once a new DC is elected.
 */

static GList *stonith_cleanup_list = NULL;

/*!
 * \internal
 * \brief Add a node to the stonith cleanup list
 *
 * \param[in] target  Name of node to add
 */
void
add_stonith_cleanup(const char *target) {
    stonith_cleanup_list = g_list_append(stonith_cleanup_list, strdup(target));
}

/*!
 * \internal
 * \brief Remove a node from the stonith cleanup list
 *
 * \param[in] Name of node to remove
 */
void
remove_stonith_cleanup(const char *target)
{
    GList *iter = stonith_cleanup_list;

    while (iter != NULL) {
        GList *tmp = iter;
        char *iter_name = tmp->data;

        iter = iter->next;
        if (pcmk__str_eq(target, iter_name, pcmk__str_casei)) {
            crm_trace("Removing %s from the cleanup list", iter_name);
            stonith_cleanup_list = g_list_delete_link(stonith_cleanup_list, tmp);
            free(iter_name);
        }
    }
}

/*!
 * \internal
 * \brief Purge all entries from the stonith cleanup list
 */
void
purge_stonith_cleanup(void)
{
    if (stonith_cleanup_list) {
        GList *iter = NULL;

        for (iter = stonith_cleanup_list; iter != NULL; iter = iter->next) {
            char *target = iter->data;

            crm_info("Purging %s from stonith cleanup list", target);
            free(target);
        }
        g_list_free(stonith_cleanup_list);
        stonith_cleanup_list = NULL;
    }
}

/*!
 * \internal
 * \brief Send stonith updates for all entries in cleanup list, then purge it
 */
void
execute_stonith_cleanup(void)
{
    GList *iter;

    for (iter = stonith_cleanup_list; iter != NULL; iter = iter->next) {
        char *target = iter->data;
        crm_node_t *target_node = crm_get_peer(0, target);
        const char *uuid = crm_peer_uuid(target_node);

        crm_notice("Marking %s, target of a previous stonith action, as clean", target);
        send_stonith_update(NULL, target, uuid);
        free(target);
    }
    g_list_free(stonith_cleanup_list);
    stonith_cleanup_list = NULL;
}

/* end stonith cleanup list functions */


/* stonith API client
 *
 * Functions that need to interact directly with the fencer via its API
 */

static stonith_t *stonith_api = NULL;
static crm_trigger_t *stonith_reconnect = NULL;
static char *te_client_id = NULL;

static gboolean
fail_incompletable_stonith(pcmk__graph_t *graph)
{
    GList *lpc = NULL;
    const char *task = NULL;
    xmlNode *last_action = NULL;

    if (graph == NULL) {
        return FALSE;
    }

    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        GList *lpc2 = NULL;
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) lpc->data;

        if (pcmk_is_set(synapse->flags, pcmk__synapse_confirmed)) {
            continue;
        }

        for (lpc2 = synapse->actions; lpc2 != NULL; lpc2 = lpc2->next) {
            pcmk__graph_action_t *action = (pcmk__graph_action_t *) lpc2->data;

            if ((action->type != pcmk__cluster_graph_action)
                || pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
                continue;
            }

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
            if (task && pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)) {
                pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
                last_action = action->xml;
                pcmk__update_graph(graph, action);
                crm_notice("Failing action %d (%s): fencer terminated",
                           action->id, ID(action->xml));
            }
        }
    }

    if (last_action != NULL) {
        crm_warn("Fencer failure resulted in unrunnable actions");
        abort_for_stonith_failure(pcmk__graph_restart, NULL, last_action);
        return TRUE;
    }

    return FALSE;
}

static void
tengine_stonith_connection_destroy(stonith_t *st, stonith_event_t *e)
{
    te_cleanup_stonith_history_sync(st, FALSE);

    if (pcmk_is_set(controld_globals.fsa_input_register, R_ST_REQUIRED)) {
        crm_crit("Fencing daemon connection failed");
        mainloop_set_trigger(stonith_reconnect);

    } else {
        crm_info("Fencing daemon disconnected");
    }

    if (stonith_api) {
        /* the client API won't properly reconnect notifications
         * if they are still in the table - so remove them
         */
        if (stonith_api->state != stonith_disconnected) {
            stonith_api->cmds->disconnect(st);
        }
        stonith_api->cmds->remove_notification(stonith_api, NULL);
    }

    if (AM_I_DC) {
        fail_incompletable_stonith(transition_graph);
        trigger_graph();
    }
}

/*!
 * \internal
 * \brief Handle an event notification from the fencing API
 *
 * \param[in] st     Fencing API connection (ignored)
 * \param[in] event  Fencing API event notification
 */
static void
handle_fence_notification(stonith_t *st, stonith_event_t *event)
{
    bool succeeded = true;
    const char *executioner = "the cluster";
    const char *client = "a client";
    const char *reason = NULL;
    int exec_status;

    if (te_client_id == NULL) {
        te_client_id = crm_strdup_printf("%s.%lu", crm_system_name,
                                         (unsigned long) getpid());
    }

    if (event == NULL) {
        crm_err("Notify data not found");
        return;
    }

    if (event->executioner != NULL) {
        executioner = event->executioner;
    }
    if (event->client_origin != NULL) {
        client = event->client_origin;
    }

    exec_status = stonith__event_execution_status(event);
    if ((stonith__event_exit_status(event) != CRM_EX_OK)
        || (exec_status != PCMK_EXEC_DONE)) {
        succeeded = false;
        if (exec_status == PCMK_EXEC_DONE) {
            exec_status = PCMK_EXEC_ERROR;
        }
    }
    reason = stonith__event_exit_reason(event);

    crmd_alert_fencing_op(event);

    if (pcmk__str_eq("on", event->action, pcmk__str_none)) {
        // Unfencing doesn't need special handling, just a log message
        if (succeeded) {
            crm_notice("%s was unfenced by %s at the request of %s@%s",
                       event->target, executioner, client, event->origin);
        } else {
            crm_err("Unfencing of %s by %s failed (%s%s%s) with exit status %d",
                    event->target, executioner,
                    pcmk_exec_status_str(exec_status),
                    ((reason == NULL)? "" : ": "),
                    ((reason == NULL)? "" : reason),
                    stonith__event_exit_status(event));
        }
        return;
    }

    if (succeeded
        && pcmk__str_eq(event->target, controld_globals.our_nodename,
                        pcmk__str_casei)) {
        /* We were notified of our own fencing. Most likely, either fencing was
         * misconfigured, or fabric fencing that doesn't cut cluster
         * communication is in use.
         *
         * Either way, shutting down the local host is a good idea, to require
         * administrator intervention. Also, other nodes would otherwise likely
         * set our status to lost because of the fencing callback and discard
         * our subsequent election votes as "not part of our cluster".
         */
        crm_crit("We were allegedly just fenced by %s for %s!",
                 executioner, event->origin); // Dumps blackbox if enabled
        if (fence_reaction_panic) {
            pcmk__panic(__func__);
        } else {
            crm_exit(CRM_EX_FATAL);
        }
        return; // Should never get here
    }

    /* Update the count of fencing failures for this target, in case we become
     * DC later. The current DC has already updated its fail count in
     * tengine_stonith_callback().
     */
    if (!AM_I_DC) {
        if (succeeded) {
            st_fail_count_reset(event->target);
        } else {
            st_fail_count_increment(event->target);
        }
    }

    crm_notice("Peer %s was%s terminated (%s) by %s on behalf of %s@%s: "
               "%s%s%s%s " CRM_XS " event=%s",
               event->target, (succeeded? "" : " not"),
               event->action, executioner, client, event->origin,
               (succeeded? "OK" : pcmk_exec_status_str(exec_status)),
               ((reason == NULL)? "" : " ("),
               ((reason == NULL)? "" : reason),
               ((reason == NULL)? "" : ")"),
               event->id);

    if (succeeded) {
        crm_node_t *peer = pcmk__search_known_node_cache(0, event->target,
                                                         CRM_GET_PEER_ANY);
        const char *uuid = NULL;

        if (peer == NULL) {
            return;
        }

        uuid = crm_peer_uuid(peer);

        if (AM_I_DC) {
            /* The DC always sends updates */
            send_stonith_update(NULL, event->target, uuid);

            /* @TODO Ideally, at this point, we'd check whether the fenced node
             * hosted any guest nodes, and call remote_node_down() for them.
             * Unfortunately, the controller doesn't have a simple, reliable way
             * to map hosts to guests. It might be possible to track this in the
             * peer cache via crm_remote_peer_cache_refresh(). For now, we rely
             * on the scheduler creating fence pseudo-events for the guests.
             */

            if (!pcmk__str_eq(client, te_client_id, pcmk__str_casei)) {
                /* Abort the current transition if it wasn't the cluster that
                 * initiated fencing.
                 */
                crm_info("External fencing operation from %s fenced %s",
                         client, event->target);
                abort_transition(INFINITY, pcmk__graph_restart,
                                 "External Fencing Operation", NULL);
            }

        } else if (pcmk__str_eq(controld_globals.dc_name, event->target,
                                pcmk__str_null_matches|pcmk__str_casei)
                   && !pcmk_is_set(peer->flags, crm_remote_node)) {
            // Assume the target was our DC if we don't currently have one

            if (controld_globals.dc_name != NULL) {
                crm_notice("Fencing target %s was our DC", event->target);
            } else {
                crm_notice("Fencing target %s may have been our DC",
                           event->target);
            }

            /* Given the CIB resyncing that occurs around elections,
             * have one node update the CIB now and, if the new DC is different,
             * have them do so too after the election
             */
            if (pcmk__str_eq(event->executioner, controld_globals.our_nodename,
                             pcmk__str_casei)) {
                send_stonith_update(NULL, event->target, uuid);
            }
            add_stonith_cleanup(event->target);
        }

        /* If the target is a remote node, and we host its connection,
         * immediately fail all monitors so it can be recovered quickly.
         * The connection won't necessarily drop when a remote node is fenced,
         * so the failure might not otherwise be detected until the next poke.
         */
        if (pcmk_is_set(peer->flags, crm_remote_node)) {
            remote_ra_fail(event->target);
        }

        crmd_peer_down(peer, TRUE);
     }
}

/*!
 * \brief Connect to fencer
 *
 * \param[in] user_data  If NULL, retry failures now, otherwise retry in main loop
 *
 * \return TRUE
 * \note If user_data is NULL, this will wait 2s between attempts, for up to
 *       30 attempts, meaning the controller could be blocked as long as 58s.
 */
static gboolean
te_connect_stonith(gpointer user_data)
{
    int rc = pcmk_ok;

    if (stonith_api == NULL) {
        stonith_api = stonith_api_new();
        if (stonith_api == NULL) {
            crm_err("Could not connect to fencer: API memory allocation failed");
            return TRUE;
        }
    }

    if (stonith_api->state != stonith_disconnected) {
        crm_trace("Already connected to fencer, no need to retry");
        return TRUE;
    }

    if (user_data == NULL) {
        // Blocking (retry failures now until successful)
        rc = stonith_api_connect_retry(stonith_api, crm_system_name, 30);
        if (rc != pcmk_ok) {
            crm_err("Could not connect to fencer in 30 attempts: %s "
                    CRM_XS " rc=%d", pcmk_strerror(rc), rc);
        }
    } else {
        // Non-blocking (retry failures later in main loop)
        rc = stonith_api->cmds->connect(stonith_api, crm_system_name, NULL);
        if (rc != pcmk_ok) {
            if (pcmk_is_set(controld_globals.fsa_input_register,
                            R_ST_REQUIRED)) {
                crm_notice("Fencer connection failed (will retry): %s "
                           CRM_XS " rc=%d", pcmk_strerror(rc), rc);
                mainloop_set_trigger(stonith_reconnect);
            } else {
                crm_info("Fencer connection failed (ignoring because no longer required): %s "
                         CRM_XS " rc=%d", pcmk_strerror(rc), rc);
            }
            return TRUE;
        }
    }

    if (rc == pcmk_ok) {
        stonith_api->cmds->register_notification(stonith_api,
                                                 T_STONITH_NOTIFY_DISCONNECT,
                                                 tengine_stonith_connection_destroy);
        stonith_api->cmds->register_notification(stonith_api,
                                                 T_STONITH_NOTIFY_FENCE,
                                                 handle_fence_notification);
        stonith_api->cmds->register_notification(stonith_api,
                                                 T_STONITH_NOTIFY_HISTORY_SYNCED,
                                                 tengine_stonith_history_synced);
        te_trigger_stonith_history_sync(TRUE);
        crm_notice("Fencer successfully connected");
    }

    return TRUE;
}

/*!
    \internal
    \brief Schedule fencer connection attempt in main loop
*/
void
controld_trigger_fencer_connect(void)
{
    if (stonith_reconnect == NULL) {
        stonith_reconnect = mainloop_add_trigger(G_PRIORITY_LOW,
                                                 te_connect_stonith,
                                                 GINT_TO_POINTER(TRUE));
    }
    controld_set_fsa_input_flags(R_ST_REQUIRED);
    mainloop_set_trigger(stonith_reconnect);
}

void
controld_disconnect_fencer(bool destroy)
{
    if (stonith_api) {
        // Prevent fencer connection from coming up again
        controld_clear_fsa_input_flags(R_ST_REQUIRED);

        if (stonith_api->state != stonith_disconnected) {
            stonith_api->cmds->disconnect(stonith_api);
        }
        stonith_api->cmds->remove_notification(stonith_api, NULL);
    }
    if (destroy) {
        if (stonith_api) {
            stonith_api->cmds->free(stonith_api);
            stonith_api = NULL;
        }
        if (stonith_reconnect) {
            mainloop_destroy_trigger(stonith_reconnect);
            stonith_reconnect = NULL;
        }
        if (te_client_id) {
            free(te_client_id);
            te_client_id = NULL;
        }
    }
}

static gboolean
do_stonith_history_sync(gpointer user_data)
{
    if (stonith_api && (stonith_api->state != stonith_disconnected)) {
        stonith_history_t *history = NULL;

        te_cleanup_stonith_history_sync(stonith_api, FALSE);
        stonith_api->cmds->history(stonith_api,
                                   st_opt_sync_call | st_opt_broadcast,
                                   NULL, &history, 5);
        stonith_history_free(history);
        return TRUE;
    } else {
        crm_info("Skip triggering stonith history-sync as stonith is disconnected");
        return FALSE;
    }
}

static void
tengine_stonith_callback(stonith_t *stonith, stonith_callback_data_t *data)
{
    char *uuid = NULL;
    int stonith_id = -1;
    int transition_id = -1;
    pcmk__graph_action_t *action = NULL;
    const char *target = NULL;

    if ((data == NULL) || (data->userdata == NULL)) {
        crm_err("Ignoring fence operation %d result: "
                "No transition key given (bug?)",
                ((data == NULL)? -1 : data->call_id));
        return;
    }

    if (!AM_I_DC) {
        const char *reason = stonith__exit_reason(data);

        if (reason == NULL) {
           reason = pcmk_exec_status_str(stonith__execution_status(data));
        }
        crm_notice("Result of fence operation %d: %d (%s) " CRM_XS " key=%s",
                   data->call_id, stonith__exit_status(data), reason,
                   (const char *) data->userdata);
        return;
    }

    CRM_CHECK(decode_transition_key(data->userdata, &uuid, &transition_id,
                                    &stonith_id, NULL),
              goto bail);

    if (transition_graph->complete || (stonith_id < 0)
        || !pcmk__str_eq(uuid, te_uuid, pcmk__str_none)
        || (transition_graph->id != transition_id)) {
        crm_info("Ignoring fence operation %d result: "
                 "Not from current transition " CRM_XS
                 " complete=%s action=%d uuid=%s (vs %s) transition=%d (vs %d)",
                 data->call_id, pcmk__btoa(transition_graph->complete),
                 stonith_id, uuid, te_uuid, transition_id, transition_graph->id);
        goto bail;
    }

    action = controld_get_action(stonith_id);
    if (action == NULL) {
        crm_err("Ignoring fence operation %d result: "
                "Action %d not found in transition graph (bug?) "
                CRM_XS " uuid=%s transition=%d",
                data->call_id, stonith_id, uuid, transition_id);
        goto bail;
    }

    target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    if (target == NULL) {
        crm_err("Ignoring fence operation %d result: No target given (bug?)",
                data->call_id);
        goto bail;
    }

    stop_te_timer(action);
    if (stonith__exit_status(data) == CRM_EX_OK) {
        const char *uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
        const char *op = crm_meta_value(action->params, "stonith_action");

        crm_info("Fence operation %d for %s succeeded", data->call_id, target);
        if (!(pcmk_is_set(action->flags, pcmk__graph_action_confirmed))) {
            te_action_confirmed(action, NULL);
            if (pcmk__str_eq("on", op, pcmk__str_casei)) {
                const char *value = NULL;
                char *now = pcmk__ttoa(time(NULL));
                gboolean is_remote_node = FALSE;

                /* This check is not 100% reliable, since this node is not
                 * guaranteed to have the remote node cached. However, it
                 * doesn't have to be reliable, since the attribute manager can
                 * learn a node's "remoteness" by other means sooner or later.
                 * This allows it to learn more quickly if this node does have
                 * the information.
                 */
                if (g_hash_table_lookup(crm_remote_peer_cache, uuid) != NULL) {
                    is_remote_node = TRUE;
                }

                update_attrd(target, CRM_ATTR_UNFENCED, now, NULL,
                             is_remote_node);
                free(now);

                value = crm_meta_value(action->params, XML_OP_ATTR_DIGESTS_ALL);
                update_attrd(target, CRM_ATTR_DIGESTS_ALL, value, NULL,
                             is_remote_node);

                value = crm_meta_value(action->params, XML_OP_ATTR_DIGESTS_SECURE);
                update_attrd(target, CRM_ATTR_DIGESTS_SECURE, value, NULL,
                             is_remote_node);

            } else if (!(pcmk_is_set(action->flags, pcmk__graph_action_sent_update))) {
                send_stonith_update(action, target, uuid);
                pcmk__set_graph_action_flags(action,
                                             pcmk__graph_action_sent_update);
            }
        }
        st_fail_count_reset(target);

    } else {
        enum pcmk__graph_next abort_action = pcmk__graph_restart;
        int status = stonith__execution_status(data);
        const char *reason = stonith__exit_reason(data);

        if (reason == NULL) {
            if (status == PCMK_EXEC_DONE) {
                reason = "Agent returned error";
            } else {
                reason = pcmk_exec_status_str(status);
            }
        }
        pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);

        /* If no fence devices were available, there's no use in immediately
         * checking again, so don't start a new transition in that case.
         */
        if (status == PCMK_EXEC_NO_FENCE_DEVICE) {
            crm_warn("Fence operation %d for %s failed: %s "
                     "(aborting transition and giving up for now)",
                     data->call_id, target, reason);
            abort_action = pcmk__graph_wait;
        } else {
            crm_notice("Fence operation %d for %s failed: %s "
                       "(aborting transition)", data->call_id, target, reason);
        }

        /* Increment the fail count now, so abort_for_stonith_failure() can
         * check it. Non-DC nodes will increment it in
         * handle_fence_notification().
         */
        st_fail_count_increment(target);
        abort_for_stonith_failure(abort_action, target, NULL);
    }

    pcmk__update_graph(transition_graph, action);
    trigger_graph();

  bail:
    free(data->userdata);
    free(uuid);
    return;
}

static int
fence_with_delay(const char *target, const char *type, const char *delay)
{
    uint32_t options = st_opt_none; // Group of enum stonith_call_options
    int timeout_sec = (int) (transition_graph->stonith_timeout / 1000);
    int delay_i;

    if (crmd_join_phase_count(crm_join_confirmed) == 1) {
        stonith__set_call_options(options, target, st_opt_allow_suicide);
    }
    pcmk__scan_min_int(delay, &delay_i, 0);
    return stonith_api->cmds->fence_with_delay(stonith_api, options, target,
                                               type, timeout_sec, 0, delay_i);
}

/*!
 * \internal
 * \brief Execute a fencing action from a transition graph
 *
 * \param[in] graph   Transition graph being executed (ignored)
 * \param[in] action  Fencing action to execute
 *
 * \return Standard Pacemaker return code
 */
int
controld_execute_fence_action(pcmk__graph_t *graph,
                              pcmk__graph_action_t *action)
{
    int rc = 0;
    const char *id = NULL;
    const char *uuid = NULL;
    const char *target = NULL;
    const char *type = NULL;
    char *transition_key = NULL;
    const char *priority_delay = NULL;
    gboolean invalid_action = FALSE;

    id = ID(action->xml);
    target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
    type = crm_meta_value(action->params, "stonith_action");

    CRM_CHECK(id != NULL, invalid_action = TRUE);
    CRM_CHECK(uuid != NULL, invalid_action = TRUE);
    CRM_CHECK(type != NULL, invalid_action = TRUE);
    CRM_CHECK(target != NULL, invalid_action = TRUE);

    if (invalid_action) {
        crm_log_xml_warn(action->xml, "BadAction");
        return EPROTO;
    }

    priority_delay = crm_meta_value(action->params, XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY);

    crm_notice("Requesting fencing (%s) of node %s "
               CRM_XS " action=%s timeout=%u%s%s",
               type, target, id, transition_graph->stonith_timeout,
               priority_delay ? " priority_delay=" : "",
               priority_delay ? priority_delay : "");

    /* Passing NULL means block until we can connect... */
    te_connect_stonith(NULL);

    rc = fence_with_delay(target, type, priority_delay);
    transition_key = pcmk__transition_key(transition_graph->id, action->id, 0,
                                          te_uuid),
    stonith_api->cmds->register_callback(stonith_api, rc,
                                         (int) (transition_graph->stonith_timeout / 1000),
                                         st_opt_timeout_updates, transition_key,
                                         "tengine_stonith_callback", tengine_stonith_callback);
    return pcmk_rc_ok;
}

bool
controld_verify_stonith_watchdog_timeout(const char *value)
{
    const char *our_nodename = controld_globals.our_nodename;
    gboolean rv = TRUE;

    if (stonith_api && (stonith_api->state != stonith_disconnected) &&
        stonith__watchdog_fencing_enabled_for_node_api(stonith_api,
                                                       our_nodename)) {
        rv = pcmk__valid_sbd_timeout(value);
    }
    return rv;
}

/* end stonith API client functions */


/*
 * stonith history synchronization
 *
 * Each node's fencer keeps track of a cluster-wide fencing history. When a node
 * joins or leaves, we need to synchronize the history across all nodes.
 */

static crm_trigger_t *stonith_history_sync_trigger = NULL;
static mainloop_timer_t *stonith_history_sync_timer_short = NULL;
static mainloop_timer_t *stonith_history_sync_timer_long = NULL;

void
te_cleanup_stonith_history_sync(stonith_t *st, bool free_timers)
{
    if (free_timers) {
        mainloop_timer_del(stonith_history_sync_timer_short);
        stonith_history_sync_timer_short = NULL;
        mainloop_timer_del(stonith_history_sync_timer_long);
        stonith_history_sync_timer_long = NULL;
    } else {
        mainloop_timer_stop(stonith_history_sync_timer_short);
        mainloop_timer_stop(stonith_history_sync_timer_long);
    }

    if (st) {
        st->cmds->remove_notification(st, T_STONITH_NOTIFY_HISTORY_SYNCED);
    }
}

static void
tengine_stonith_history_synced(stonith_t *st, stonith_event_t *st_event)
{
    te_cleanup_stonith_history_sync(st, FALSE);
    crm_debug("Fence-history synced - cancel all timers");
}

static gboolean
stonith_history_sync_set_trigger(gpointer user_data)
{
    mainloop_set_trigger(stonith_history_sync_trigger);
    return FALSE;
}

void
te_trigger_stonith_history_sync(bool long_timeout)
{
    /* trigger a sync in 5s to give more nodes the
     * chance to show up so that we don't create
     * unnecessary stonith-history-sync traffic
     *
     * the long timeout of 30s is there as a fallback
     * so that after a successful connection to fenced
     * we will wait for 30s for the DC to trigger a
     * history-sync
     * if this doesn't happen we trigger a sync locally
     * (e.g. fenced segfaults and is restarted by pacemakerd)
     */

    /* as we are finally checking the stonith-connection
     * in do_stonith_history_sync we should be fine
     * leaving stonith_history_sync_time & stonith_history_sync_trigger
     * around
     */
    if (stonith_history_sync_trigger == NULL) {
        stonith_history_sync_trigger =
            mainloop_add_trigger(G_PRIORITY_LOW,
                                 do_stonith_history_sync, NULL);
    }

    if (long_timeout) {
        if(stonith_history_sync_timer_long == NULL) {
            stonith_history_sync_timer_long =
                mainloop_timer_add("history_sync_long", 30000,
                                   FALSE, stonith_history_sync_set_trigger,
                                   NULL);
        }
        crm_info("Fence history will be synchronized cluster-wide within 30 seconds");
        mainloop_timer_start(stonith_history_sync_timer_long);
    } else {
        if(stonith_history_sync_timer_short == NULL) {
            stonith_history_sync_timer_short =
                mainloop_timer_add("history_sync_short", 5000,
                                   FALSE, stonith_history_sync_set_trigger,
                                   NULL);
        }
        crm_info("Fence history will be synchronized cluster-wide within 5 seconds");
        mainloop_timer_start(stonith_history_sync_timer_short);
    }

}

/* end stonith history synchronization functions */
