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
#include <crm/common/xml.h>
#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>

#include <pacemaker-controld.h>

static void fencing_history_synced(stonith_t *st, stonith_event_t *st_event);

#define DEFAULT_FENCING_MAX_ATTEMPTS 10

static bool fence_reaction_panic = false;
static unsigned long int fencing_max_attempts = DEFAULT_FENCING_MAX_ATTEMPTS;

/*
 * Fencing failure counting
 *
 * We don't want to get stuck in a permanent fencing loop. Keep track of the
 * number of fencing failures for each target node, and the most we'll restart a
 * transition for.
 */
static GHashTable *fencing_fail_counts = NULL;

/*!
 * \internal
 * \brief Update max fencing attempts before giving up
 *
 * \param[in] value  New max fencing attempts
 */
static void
update_fencing_max_attempts(const char *value)
{
    int score = 0;
    int rc = pcmk_parse_score(value, &score, DEFAULT_FENCING_MAX_ATTEMPTS);

    // The option validator ensures invalid values shouldn't be possible
    CRM_CHECK((rc == pcmk_rc_ok) && (score > 0), return);

    if (fencing_max_attempts != score) {
        pcmk__debug("Maximum fencing attempts per transition is now %d "
                    "(was %lu)", score, fencing_max_attempts);
    }
    fencing_max_attempts = score;
}

/*!
 * \internal
 * \brief Configure reaction to notification of local node being fenced
 *
 * \param[in] reaction_s  Reaction type
 */
static void
set_fence_reaction(const char *reaction_s)
{
    if (pcmk__str_eq(reaction_s, "panic", pcmk__str_casei)) {
        fence_reaction_panic = true;

    } else {
        if (!pcmk__str_eq(reaction_s, PCMK_VALUE_STOP, pcmk__str_casei)) {
            pcmk__warn("Invalid value '%s' for " PCMK_OPT_FENCING_REACTION
                       ", using 'stop'",
                       reaction_s);
        }
        fence_reaction_panic = false;
    }
}

/*!
 * \internal
 * \brief Configure fencing options based on the CIB
 *
 * \param[in,out] options  Name/value pairs for configured options
 */
void
controld_configure_fencing(GHashTable *options)
{
    const char *value = NULL;

    value = g_hash_table_lookup(options, PCMK_OPT_FENCING_REACTION);
    set_fence_reaction(value);

    value = g_hash_table_lookup(options, PCMK_OPT_FENCING_MAX_ATTEMPTS);
    update_fencing_max_attempts(value);
}

static bool
too_many_fencing_failures(const char *target)
{
    GHashTableIter iter;
    gpointer value = NULL;

    if (fencing_fail_counts == NULL) {
        return false;
    }

    if (target == NULL) {
        g_hash_table_iter_init(&iter, fencing_fail_counts);
        while (g_hash_table_iter_next(&iter, (gpointer *) &target, &value)) {
            if (GPOINTER_TO_INT(value) >= fencing_max_attempts) {
                goto too_many;
            }
        }

    } else if (g_hash_table_lookup_extended(fencing_fail_counts, target, NULL,
                                            &value)
               && (GPOINTER_TO_INT(value) >= fencing_max_attempts)) {
        goto too_many;
    }
    return false;

too_many:
    pcmk__warn("Too many failures (%d) to fence %s, giving up",
               GPOINTER_TO_INT(value), target);
    return true;
}

/*!
 * \internal
 * \brief Reset the count of failed fencing operations for a node
 *
 * \param[in] target  Name of node whose count to reset, or \c NULL to reset all
 */
void
controld_reset_fencing_fail_count(const char *target)
{
    if (fencing_fail_counts == NULL) {
        return;
    }

    if (target != NULL) {
        g_hash_table_remove(fencing_fail_counts, target);

    } else {
        g_hash_table_remove_all(fencing_fail_counts);
    }
}

static void
increment_fencing_fail_count(const char *target)
{
    gpointer key = NULL;
    gpointer value = NULL;

    if (fencing_fail_counts == NULL) {
        fencing_fail_counts = pcmk__strikey_table(free, NULL);
    }

    if (g_hash_table_lookup_extended(fencing_fail_counts, target, &key,
                                     &value)) {
        gpointer new_value = GINT_TO_POINTER(GPOINTER_TO_INT(value) + 1);

        // Increment value in the table without freeing key
        g_hash_table_steal(fencing_fail_counts, key);
        g_hash_table_insert(fencing_fail_counts, key, new_value);

    } else {
        g_hash_table_insert(fencing_fail_counts, pcmk__str_copy(target),
                            GINT_TO_POINTER(1));
    }
}

/* end fencing fail count functions */


static void
cib_fencing_updated(xmlNode *msg, int call_id, int rc, xmlNode *output,
                    void *user_data)
{
    if (rc < pcmk_ok) {
        pcmk__err("Fencing update %d for %s: failed - %s (%d)",
                  call_id, (char *)user_data, pcmk_strerror(rc), rc);
        crm_log_xml_warn(msg, "Failed update");
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_shutdown,
                         "CIB update failed", NULL);

    } else {
        pcmk__info("Fencing update %d for %s: complete", call_id,
                   (const char *) user_data);
    }
}

/*!
 * \internal
 * \brief Update a fencing target's node state
 *
 * \param[in] target         Node that was successfully fenced
 * \param[in] target_xml_id  CIB XML ID of target
 */
static void
update_node_state_after_fencing(const char *target, const char *target_xml_id)
{
    int rc = pcmk_ok;
    pcmk__node_status_t *peer = NULL;
    xmlNode *node_state = NULL;

    /* We (usually) rely on the membership layer to do
     * controld_node_update_cluster, and the peer status callback to do
     * controld_node_update_peer, because the node might have already rejoined
     * before we get the fencing result here.
     */
    uint32_t flags = controld_node_update_join|controld_node_update_expected;

    CRM_CHECK((target != NULL) && (target_xml_id != NULL), return);

    // Ensure target is cached
    peer = pcmk__get_node(0, target, target_xml_id, pcmk__node_search_any);
    CRM_CHECK(peer != NULL, return);

    if (peer->state == NULL) {
        /* Usually, we rely on the membership layer to update the cluster state
         * in the CIB. However, if the node has never been seen, do it here, so
         * the node is not considered unclean.
         */
        flags |= controld_node_update_cluster;
    }

    if (peer->xml_id == NULL) {
        pcmk__info("Recording XML ID '%s' for node '%s'", target_xml_id,
                   target);
        peer->xml_id = pcmk__str_copy(target_xml_id);
    }

    crmd_peer_down(peer, TRUE);

    node_state = create_node_state_update(peer, flags, NULL, __func__);
    pcmk__xe_set(node_state, PCMK_XA_ID, target_xml_id);

    if (pcmk__is_set(peer->flags, pcmk__node_status_remote)) {
        char *now_s = pcmk__ttoa(time(NULL));

        pcmk__xe_set(node_state, PCMK__XA_NODE_FENCED, now_s);
        free(now_s);
    }

    rc = controld_globals.cib_conn->cmds->modify(controld_globals.cib_conn,
                                                 PCMK_XE_STATUS, node_state,
                                                 cib_can_create);
    pcmk__xml_free(node_state);

    pcmk__debug("Updating node state for %s after fencing (call %d)", target,
                rc);
    fsa_register_cib_callback(rc, pcmk__str_copy(target), cib_fencing_updated);

    // Delete node's resource history from CIB
    controld_delete_node_history(peer->name, false, cib_none);

    // Ask attribute manager to delete node's transient attributes
    // @TODO: This is the only call to controld_purge_node_attrs that doesn't
    //        want to also purge the node from the caches.  Why?
    controld_purge_node_attrs(peer->name, false);
}

/*!
 * \internal
 * \brief Abort transition due to fencing failure
 *
 * \param[in] abort_action  Whether to restart or stop transition
 * \param[in] target        Don't restart if this node has too many failures
 *                          (\c NULL to check if any node has too many failures)
 * \param[in] reason        Log this fencing action XML as abort reason (can be
 *                          \c NULL)
 */
static void
abort_for_fencing_failure(enum pcmk__graph_next abort_action,
                          const char *target, const xmlNode *reason)
{
    /* If fencing repeatedly fails, we eventually give up on starting a new
     * transition for that reason.
     */
    if ((abort_action != pcmk__graph_wait)
        && too_many_fencing_failures(target)) {

        abort_action = pcmk__graph_wait;
    }
    abort_transition(PCMK_SCORE_INFINITY, abort_action, "Stonith failed",
                     reason);
}


/*
 * Fencing cleanup list
 *
 * If the DC is fenced, proper notifications might not go out. The fencing
 * cleanup list allows the cluster to (re-)send notifications once a new DC is
 * elected.
 */

static GList *fencing_cleanup_list = NULL;

/*!
 * \internal
 * \brief Add a node to the fencing cleanup list
 *
 * \param[in] target  Name of node to add
 */
static void
add_fencing_cleanup(const char *target)
{
    fencing_cleanup_list = g_list_append(fencing_cleanup_list,
                                         pcmk__str_copy(target));
}

/*!
 * \internal
 * \brief Remove a node from the fencing cleanup list
 *
 * \param[in] Name of node to remove
 */
void
controld_remove_fencing_cleanup(const char *target)
{
    GList *iter = fencing_cleanup_list;

    while (iter != NULL) {
        GList *tmp = iter;
        char *iter_name = tmp->data;

        iter = iter->next;
        if (pcmk__str_eq(target, iter_name, pcmk__str_casei)) {
            pcmk__trace("Removing %s from the cleanup list", iter_name);
            fencing_cleanup_list = g_list_delete_link(fencing_cleanup_list,
                                                      tmp);
            free(iter_name);
        }
    }
}

/*!
 * \internal
 * \brief Purge all entries from the fencing cleanup list
 */
void
controld_purge_fencing_cleanup(void)
{
    for (GList *iter = fencing_cleanup_list; iter != NULL; iter = iter->next) {
        char *target = iter->data;

        pcmk__info("Purging %s from fencing cleanup list", target);
        free(target);
    }
    g_list_free(fencing_cleanup_list);
    fencing_cleanup_list = NULL;
}

/*!
 * \internal
 * \brief Send fencing updates for all entries in cleanup list, then purge it
 */
void
controld_execute_fencing_cleanup(void)
{
    for (GList *iter = fencing_cleanup_list; iter != NULL; iter = iter->next) {
        char *target = iter->data;
        pcmk__node_status_t *target_node =
            pcmk__get_node(0, target, NULL, pcmk__node_search_cluster_member);
        const char *uuid = pcmk__cluster_get_xml_id(target_node);

        pcmk__notice("Marking %s, target of a previous fencing action, as "
                     "clean", target);
        update_node_state_after_fencing(target, uuid);
        free(target);
    }
    g_list_free(fencing_cleanup_list);
    fencing_cleanup_list = NULL;
}

/* end fencing cleanup list functions */


/* Fencer API client
 *
 * Functions that need to interact directly with the fencer via its API
 */

static stonith_t *fencer_api = NULL;
static mainloop_timer_t *controld_fencer_connect_timer = NULL;
static char *te_client_id = NULL;

static bool
fail_incompletable_fencing(pcmk__graph_t *graph)
{
    GList *lpc = NULL;
    const char *task = NULL;
    xmlNode *last_action = NULL;

    if (graph == NULL) {
        return false;
    }

    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        GList *lpc2 = NULL;
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) lpc->data;

        if (pcmk__is_set(synapse->flags, pcmk__synapse_confirmed)) {
            continue;
        }

        for (lpc2 = synapse->actions; lpc2 != NULL; lpc2 = lpc2->next) {
            pcmk__graph_action_t *action = (pcmk__graph_action_t *) lpc2->data;

            if ((action->type != pcmk__cluster_graph_action)
                || pcmk__is_set(action->flags, pcmk__graph_action_confirmed)) {
                continue;
            }

            task = pcmk__xe_get(action->xml, PCMK_XA_OPERATION);
            if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_casei)) {
                pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
                last_action = action->xml;
                pcmk__update_graph(graph, action);
                pcmk__notice("Failing action %d (%s): fencer terminated",
                             action->id, pcmk__xe_id(action->xml));
            }
        }
    }

    if (last_action != NULL) {
        pcmk__warn("Fencing failure resulted in unrunnable actions");
        abort_for_fencing_failure(pcmk__graph_restart, NULL, last_action);
        return true;
    }

    return false;
}

static void
destroy_fencer_connection(stonith_t *st, stonith_event_t *e)
{
    controld_cleanup_fencing_history_sync(st, false);

    if (pcmk__is_set(controld_globals.fsa_input_register, R_ST_REQUIRED)) {
        pcmk__err("Lost fencer connection (will attempt to reconnect)");
        if (!mainloop_timer_running(controld_fencer_connect_timer)) {
            mainloop_timer_start(controld_fencer_connect_timer);
        }
    } else {
        pcmk__info("Disconnected from fencer");
    }

    if (fencer_api != NULL) {
        /* the client API won't properly reconnect notifications
         * if they are still in the table - so remove them
         */
        if (fencer_api->state != stonith_disconnected) {
            fencer_api->cmds->disconnect(st);
        }
        fencer_api->cmds->remove_notification(fencer_api, NULL);
    }

    if (AM_I_DC) {
        fail_incompletable_fencing(controld_globals.transition_graph);
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
        te_client_id = pcmk__assert_asprintf("%s.%lu", crm_system_name,
                                             (unsigned long) getpid());
    }

    if (event == NULL) {
        pcmk__err("Notify data not found");
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

    if (pcmk__str_eq(PCMK_ACTION_ON, event->action, pcmk__str_none)) {
        // Unfencing doesn't need special handling, just a log message
        if (succeeded) {
            pcmk__notice("%s was unfenced by %s at the request of %s@%s",
                         event->target, executioner, client, event->origin);
        } else {
            pcmk__err("Unfencing of %s by %s failed (%s%s%s) with exit status "
                      "%d",
                      event->target, executioner,
                      pcmk_exec_status_str(exec_status),
                      ((reason == NULL)? "" : ": "),
                      pcmk__s(reason, ""), stonith__event_exit_status(event));
        }
        return;
    }

    if (succeeded && controld_is_local_node(event->target)) {
        /* We were notified of our own fencing. Most likely, either fencing was
         * misconfigured, or fabric fencing that doesn't cut cluster
         * communication is in use.
         *
         * Either way, shutting down the local host is a good idea, to require
         * administrator intervention. Also, other nodes would otherwise likely
         * set our status to lost because of the fencing callback and discard
         * our subsequent election votes as "not part of our cluster".
         */
        pcmk__crit("We were allegedly just fenced by %s for %s!", executioner,
                   event->origin); // Dumps blackbox if enabled
        if (fence_reaction_panic) {
            pcmk__panic("Notified of own fencing");
        } else {
            crm_exit(CRM_EX_FATAL);
        }
        return; // Should never get here
    }

    /* Update the count of fencing failures for this target, in case we become
     * DC later. The current DC has already updated its fail count in
     * fencing_cb().
     */
    if (!AM_I_DC) {
        if (succeeded) {
            controld_reset_fencing_fail_count(event->target);
        } else {
            increment_fencing_fail_count(event->target);
        }
    }

    pcmk__notice("Peer %s was%s terminated (%s) by %s on behalf of %s@%s: "
                 "%s%s%s%s " QB_XS " event=%s",
                 event->target, (succeeded? "" : " not"), event->action,
                 executioner, client, event->origin,
                 (succeeded? "OK" : pcmk_exec_status_str(exec_status)),
                 ((reason != NULL)? " (" : ""), pcmk__s(reason, ""),
                 ((reason != NULL)? ")" : ""), event->id);

    if (succeeded) {
        const uint32_t flags = pcmk__node_search_any
                               |pcmk__node_search_cluster_cib;

        pcmk__node_status_t *peer = pcmk__search_node_caches(0, event->target,
                                                             NULL, flags);
        const char *uuid = NULL;

        if (peer == NULL) {
            return;
        }

        uuid = pcmk__cluster_get_xml_id(peer);

        if (AM_I_DC) {
            /* The DC always sends updates */
            update_node_state_after_fencing(event->target, uuid);

            /* @TODO Ideally, at this point, we'd check whether the fenced node
             * hosted any guest nodes, and call remote_node_down() for them.
             * Unfortunately, the controller doesn't have a simple, reliable way
             * to map hosts to guests. It might be possible to track this in the
             * peer cache via refresh_remote_nodes(). For now, we rely on the
             * scheduler creating fence pseudo-events for the guests.
             */

            if (!pcmk__str_eq(client, te_client_id, pcmk__str_casei)) {
                /* Abort the current transition if it wasn't the cluster that
                 * initiated fencing.
                 */
                pcmk__info("External fencing operation from %s fenced %s",
                           client, event->target);
                abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                                 "External Fencing Operation", NULL);
            }

        } else if (pcmk__str_eq(controld_globals.dc_name, event->target,
                                pcmk__str_null_matches|pcmk__str_casei)
                   && !pcmk__is_set(peer->flags, pcmk__node_status_remote)) {
            // Assume the target was our DC if we don't currently have one

            if (controld_globals.dc_name != NULL) {
                pcmk__notice("Fencing target %s was our DC", event->target);
            } else {
                pcmk__notice("Fencing target %s may have been our DC",
                             event->target);
            }

            /* Given the CIB resyncing that occurs around elections,
             * have one node update the CIB now and, if the new DC is different,
             * have them do so too after the election
             */
            if (controld_is_local_node(event->executioner)) {
                update_node_state_after_fencing(event->target, uuid);
            }
            add_fencing_cleanup(event->target);
        }

        /* If the target is a remote node, and we host its connection,
         * immediately fail all monitors so it can be recovered quickly.
         * The connection won't necessarily drop when a remote node is fenced,
         * so the failure might not otherwise be detected until the next poke.
         */
        if (pcmk__is_set(peer->flags, pcmk__node_status_remote)) {
            remote_ra_fail(event->target);
        }

        crmd_peer_down(peer, TRUE);
     }
}

/*!
 * \brief Connect to fencer
 *
 * \param[in] user_data  If NULL, retry failures now, otherwise retry in mainloop timer
 *
 * \return G_SOURCE_REMOVE on success, G_SOURCE_CONTINUE to retry
 * \note If user_data is NULL, this will wait 2s between attempts, for up to
 *       30 attempts, meaning the controller could be blocked as long as 58s.
 */
gboolean
controld_timer_fencer_connect(gpointer user_data)
{
    int rc = pcmk_ok;

    if (fencer_api == NULL) {
        fencer_api = stonith__api_new();
        if (fencer_api == NULL) {
            pcmk__err("Could not connect to fencer: API memory allocation "
                      "failed");
            return G_SOURCE_REMOVE;
        }
    }

    if (fencer_api->state != stonith_disconnected) {
        pcmk__trace("Already connected to fencer, no need to retry");
        return G_SOURCE_REMOVE;
    }

    if (user_data == NULL) {
        // Blocking (retry failures now until successful)
        rc = stonith__api_connect_retry(fencer_api, crm_system_name, 30);
        if (rc != pcmk_rc_ok) {
            pcmk__err("Could not connect to fencer in 30 attempts: %s "
                      QB_XS " rc=%d", pcmk_rc_str(rc), rc);
        }
    } else {
        // Non-blocking (retry failures later in main loop)
        rc = fencer_api->cmds->connect(fencer_api, crm_system_name, NULL);

        if (controld_fencer_connect_timer == NULL) {
            controld_fencer_connect_timer =
                mainloop_timer_add("controld_fencer_connect", 1000,
                                   TRUE, controld_timer_fencer_connect,
                                   GINT_TO_POINTER(TRUE));
        }

        if (rc != pcmk_ok) {
            if (pcmk__is_set(controld_globals.fsa_input_register,
                             R_ST_REQUIRED)) {
                pcmk__notice("Fencer connection failed (will retry): %s "
                             QB_XS " rc=%d",
                             pcmk_strerror(rc), rc);

                if (!mainloop_timer_running(controld_fencer_connect_timer)) {
                    mainloop_timer_start(controld_fencer_connect_timer);
                }

                return G_SOURCE_CONTINUE;
            } else {
                pcmk__info("Fencer connection failed (ignoring because no "
                           "longer required): %s " QB_XS " rc=%d",
                           pcmk_strerror(rc), rc);
            }
            return G_SOURCE_REMOVE;
        }
    }

    if (rc == pcmk_ok) {
        stonith_api_operations_t *cmds = fencer_api->cmds;

        cmds->register_notification(fencer_api,
                                    PCMK__VALUE_ST_NOTIFY_DISCONNECT,
                                    destroy_fencer_connection);
        cmds->register_notification(fencer_api, PCMK__VALUE_ST_NOTIFY_FENCE,
                                    handle_fence_notification);
        cmds->register_notification(fencer_api,
                                    PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED,
                                    fencing_history_synced);
        controld_trigger_fencing_history_sync(true);
        pcmk__notice("Fencer successfully connected");
    }

    return G_SOURCE_REMOVE;
}

void
controld_disconnect_fencer(bool destroy)
{
    if (fencer_api != NULL) {
        // Prevent fencer connection from coming up again
        controld_clear_fsa_input_flags(R_ST_REQUIRED);

        if (fencer_api->state != stonith_disconnected) {
            fencer_api->cmds->disconnect(fencer_api);
        }
        fencer_api->cmds->remove_notification(fencer_api, NULL);
    }
    if (destroy) {
        if (fencer_api != NULL) {
            fencer_api->cmds->free(fencer_api);
            fencer_api = NULL;
        }
        if (controld_fencer_connect_timer) {
            mainloop_timer_del(controld_fencer_connect_timer);
            controld_fencer_connect_timer = NULL;
        }
        if (te_client_id) {
            free(te_client_id);
            te_client_id = NULL;
        }
    }
}

static gboolean
sync_fencing_history(gpointer user_data)
{
    if ((fencer_api != NULL) && (fencer_api->state != stonith_disconnected)) {
        stonith_history_t *history = NULL;

        controld_cleanup_fencing_history_sync(fencer_api, false);
        fencer_api->cmds->history(fencer_api, st_opt_sync_call|st_opt_broadcast,
                                  NULL, &history, 5);
        stonith__history_free(history);
        return TRUE;
    } else {
        pcmk__info("Skipping triggering fencing history sync because fencer is "
                   "disconnected");
        return FALSE;
    }
}

static void
fencing_cb(stonith_t *stonith, stonith_callback_data_t *data)
{
    char *uuid = NULL;
    int transition_id = -1;
    int action_id = -1;
    pcmk__graph_action_t *action = NULL;
    const char *target = NULL;

    if ((data == NULL) || (data->userdata == NULL)) {
        pcmk__err("Ignoring fence operation %d result: No transition key given "
                  "(bug?)",
                  ((data == NULL)? -1 : data->call_id));
        return;
    }

    if (!AM_I_DC) {
        const char *reason = stonith__exit_reason(data);

        if (reason == NULL) {
           reason = pcmk_exec_status_str(stonith__execution_status(data));
        }
        pcmk__notice("Result of fence operation %d: %d (%s) " QB_XS " key=%s",
                     data->call_id, stonith__exit_status(data), reason,
                     (const char *) data->userdata);
        return;
    }

    CRM_CHECK(decode_transition_key(data->userdata, &uuid, &transition_id,
                                    &action_id, NULL),
              goto bail);

    if (controld_globals.transition_graph->complete || (action_id < 0)
        || !pcmk__str_eq(uuid, controld_globals.te_uuid, pcmk__str_none)
        || (controld_globals.transition_graph->id != transition_id)) {

        pcmk__info("Ignoring fence operation %d result: Not from current "
                   "transition " QB_XS " complete=%s action=%d uuid=%s (vs %s) "
                   "transition=%d (vs %d)",
                   data->call_id,
                   pcmk__btoa(controld_globals.transition_graph->complete),
                   action_id, uuid, controld_globals.te_uuid, transition_id,
                   controld_globals.transition_graph->id);
        goto bail;
    }

    action = controld_get_action(action_id);
    if (action == NULL) {
        pcmk__err("Ignoring fence operation %d result: Action %d not found in "
                  "transition graph (bug?) " QB_XS " uuid=%s transition=%d",
                  data->call_id, action_id, uuid, transition_id);
        goto bail;
    }

    target = pcmk__xe_get(action->xml, PCMK__META_ON_NODE);
    if (target == NULL) {
        pcmk__err("Ignoring fence operation %d result: No target given (bug?)",
                  data->call_id);
        goto bail;
    }

    stop_te_timer(action);
    if (stonith__exit_status(data) == CRM_EX_OK) {
        const char *uuid = pcmk__xe_get(action->xml, PCMK__META_ON_NODE_UUID);
        const char *op = crm_meta_value(action->params,
                                        PCMK__META_STONITH_ACTION);

        pcmk__info("Fence operation %d for %s succeeded", data->call_id,
                  target);
        if (!(pcmk__is_set(action->flags, pcmk__graph_action_confirmed))) {
            te_action_confirmed(action, NULL);
            if (pcmk__str_eq(PCMK_ACTION_ON, op, pcmk__str_casei)) {
                const char *value = NULL;
                char *now = pcmk__ttoa(time(NULL));
                bool is_remote_node = false;

                /* This check is not 100% reliable, since this node is not
                 * guaranteed to have the remote node cached. However, it
                 * doesn't have to be reliable, since the attribute manager can
                 * learn a node's "remoteness" by other means sooner or later.
                 * This allows it to learn more quickly if this node does have
                 * the information.
                 */
                if (g_hash_table_lookup(pcmk__remote_peer_cache,
                                        uuid) != NULL) {
                    is_remote_node = true;
                }

                update_attrd(target, CRM_ATTR_UNFENCED, now, is_remote_node);
                free(now);

                value = crm_meta_value(action->params, PCMK__META_DIGESTS_ALL);
                update_attrd(target, CRM_ATTR_DIGESTS_ALL, value,
                             is_remote_node);

                value = crm_meta_value(action->params,
                                       PCMK__META_DIGESTS_SECURE);
                update_attrd(target, CRM_ATTR_DIGESTS_SECURE, value,
                             is_remote_node);

            } else if (!pcmk__is_set(action->flags,
                                     pcmk__graph_action_sent_update)) {
                update_node_state_after_fencing(target, uuid);
                pcmk__set_graph_action_flags(action,
                                             pcmk__graph_action_sent_update);
            }
        }
        controld_reset_fencing_fail_count(target);

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
            pcmk__warn("Fence operation %d for %s failed: %s (aborting "
                       "transition and giving up for now)",
                       data->call_id, target, reason);
            abort_action = pcmk__graph_wait;
        } else {
            pcmk__notice("Fence operation %d for %s failed: %s (aborting "
                         "transition)",
                         data->call_id, target, reason);
        }

        /* Increment the fail count now, so abort_for_fencing_failure() can
         * check it. Non-DC nodes will increment it in
         * handle_fence_notification().
         */
        increment_fencing_fail_count(target);
        abort_for_fencing_failure(abort_action, target, NULL);
    }

    pcmk__update_graph(controld_globals.transition_graph, action);
    trigger_graph();

  bail:
    free(data->userdata);
    free(uuid);
    return;
}

static int
fence_with_delay(const char *target, const char *type, int delay)
{
    uint32_t options = st_opt_none; // Group of enum stonith_call_options
    int timeout_sec =
        pcmk__timeout_ms2s(controld_globals.transition_graph->fencing_timeout);

    if (crmd_join_phase_count(controld_join_confirmed) == 1) {
        stonith__set_call_options(options, target, st_opt_allow_self_fencing);
    }
    return fencer_api->cmds->fence_with_delay(fencer_api, options, target, type,
                                              timeout_sec, 0, delay);
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
    const char *id = pcmk__xe_id(action->xml);
    const char *uuid = pcmk__xe_get(action->xml, PCMK__META_ON_NODE_UUID);
    const char *target = pcmk__xe_get(action->xml, PCMK__META_ON_NODE);
    const char *type = crm_meta_value(action->params,
                                      PCMK__META_STONITH_ACTION);
    char *transition_key = NULL;
    const char *priority_delay = NULL;
    int delay_i = 0;
    gboolean invalid_action = FALSE;
    int timeout_sec =
        pcmk__timeout_ms2s(controld_globals.transition_graph->fencing_timeout);

    CRM_CHECK(id != NULL, invalid_action = TRUE);
    CRM_CHECK(uuid != NULL, invalid_action = TRUE);
    CRM_CHECK(type != NULL, invalid_action = TRUE);
    CRM_CHECK(target != NULL, invalid_action = TRUE);

    if (invalid_action) {
        crm_log_xml_warn(action->xml, "BadAction");
        return EPROTO;
    }

    priority_delay = crm_meta_value(action->params,
                                    PCMK_OPT_PRIORITY_FENCING_DELAY);

    pcmk__notice("Requesting fencing (%s) targeting node %s "
                 QB_XS " action=%s timeout=%i%s%s",
                 type, target, id, timeout_sec,
                 ((priority_delay != NULL)? " priority_delay=" : ""),
                 pcmk__s(priority_delay, ""));

    /* Passing NULL means block until we can connect... */
    controld_timer_fencer_connect(NULL);

    pcmk__scan_min_int(priority_delay, &delay_i, 0);
    rc = fence_with_delay(target, type, delay_i);
    transition_key = pcmk__transition_key(controld_globals.transition_graph->id,
                                          action->id, 0,
                                          controld_globals.te_uuid),
    fencer_api->cmds->register_callback(fencer_api, rc,
                                        (timeout_sec
                                         + (delay_i > 0 ? delay_i : 0)),
                                        st_opt_timeout_updates, transition_key,
                                        "fencing_cb", fencing_cb);
    return pcmk_rc_ok;
}

void
controld_validate_fencing_watchdog_timeout(const char *value)
{
    const char *our_nodename = controld_globals.cluster->priv->node_name;

    // Validate only if the timeout will be used
    if ((fencer_api != NULL) && (fencer_api->state != stonith_disconnected)
        && stonith__watchdog_fencing_enabled_for_node_api(fencer_api,
                                                          our_nodename)) {

        pcmk__valid_fencing_watchdog_timeout(value);
    }
}

/* end fencer API client functions */


/*
 * Fencing history synchronization
 *
 * Each node's fencer keeps track of a cluster-wide fencing history. When a node
 * joins or leaves, we need to synchronize the history across all nodes.
 */

static crm_trigger_t *fencing_history_sync_trigger = NULL;
static mainloop_timer_t *fencing_history_sync_timer_short = NULL;
static mainloop_timer_t *fencing_history_sync_timer_long = NULL;

void
controld_cleanup_fencing_history_sync(stonith_t *st, bool free_timers)
{
    if (free_timers) {
        mainloop_timer_del(fencing_history_sync_timer_short);
        fencing_history_sync_timer_short = NULL;
        mainloop_timer_del(fencing_history_sync_timer_long);
        fencing_history_sync_timer_long = NULL;
    } else {
        mainloop_timer_stop(fencing_history_sync_timer_short);
        mainloop_timer_stop(fencing_history_sync_timer_long);
    }

    if (st) {
        st->cmds->remove_notification(st, PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED);
    }
}

static void
fencing_history_synced(stonith_t *st, stonith_event_t *st_event)
{
    controld_cleanup_fencing_history_sync(st, false);
    pcmk__debug("Fencing history synced - cancel all timers");
}

static gboolean
fencing_history_sync_set_trigger(gpointer user_data)
{
    mainloop_set_trigger(fencing_history_sync_trigger);
    return FALSE;
}

void
controld_trigger_fencing_history_sync(bool long_timeout)
{
    /* trigger a sync in 5s to give more nodes the
     * chance to show up so that we don't create
     * unnecessary fencing-history-sync traffic
     *
     * the long timeout of 30s is there as a fallback
     * so that after a successful connection to fenced
     * we will wait for 30s for the DC to trigger a
     * history-sync
     * if this doesn't happen we trigger a sync locally
     * (e.g. fenced segfaults and is restarted by pacemakerd)
     */

    /* as we are finally checking the fencer connection
     * in sync_fencing_history() we should be fine
     * leaving fencing_history_sync_timer_short,
     * fencing_history_sync_timer_long, and fencing_history_sync_trigger
     * around
     */
    if (fencing_history_sync_trigger == NULL) {
        fencing_history_sync_trigger =
            mainloop_add_trigger(G_PRIORITY_LOW, sync_fencing_history, NULL);
    }

    if (long_timeout) {
        if (fencing_history_sync_timer_long == NULL) {
            fencing_history_sync_timer_long =
                mainloop_timer_add("history_sync_long", 30000,
                                   FALSE, fencing_history_sync_set_trigger,
                                   NULL);
        }
        pcmk__info("Fence history will be synchronized cluster-wide within 30 "
                   "seconds");
        mainloop_timer_start(fencing_history_sync_timer_long);

    } else {
        if (fencing_history_sync_timer_short == NULL) {
            fencing_history_sync_timer_short =
                mainloop_timer_add("history_sync_short", 5000,
                                   FALSE, fencing_history_sync_set_trigger,
                                   NULL);
        }
        pcmk__info("Fence history will be synchronized cluster-wide within 5 "
                   "seconds");
        mainloop_timer_start(fencing_history_sync_timer_short);
    }

}

/* end fencing history synchronization functions */
