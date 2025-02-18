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

#define DEFAULT_STONITH_MAX_ATTEMPTS 10

static bool fence_reaction_panic = false;
static unsigned long int stonith_max_attempts = DEFAULT_STONITH_MAX_ATTEMPTS;
static GHashTable *stonith_failures = NULL;

/*!
 * \internal
 * \brief Update max fencing attempts before giving up
 *
 * \param[in] value  New max fencing attempts
 */
static void
update_stonith_max_attempts(const char *value)
{
    int score = 0;
    int rc = pcmk_parse_score(value, &score, DEFAULT_STONITH_MAX_ATTEMPTS);

    // The option validator ensures invalid values shouldn't be possible
    CRM_CHECK((rc == pcmk_rc_ok) && (score > 0), return);

    if (stonith_max_attempts != score) {
        crm_debug("Maximum fencing attempts per transition is now %d (was %lu)",
                  score, stonith_max_attempts);
    }
    stonith_max_attempts = score;
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
            crm_warn("Invalid value '%s' for %s, using 'stop'",
                     reaction_s, PCMK_OPT_FENCE_REACTION);
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

    value = g_hash_table_lookup(options, PCMK_OPT_FENCE_REACTION);
    set_fence_reaction(value);

    value = g_hash_table_lookup(options, PCMK_OPT_STONITH_MAX_ATTEMPTS);
    update_stonith_max_attempts(value);
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
        g_hash_table_insert(stonith_failures, pcmk__str_copy(target), rec);
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
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_shutdown,
                         "CIB update failed", NULL);

    } else {
        crm_info("Fencing update %d for %s: complete", call_id, (char *)user_data);
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

    /* We (usually) rely on the membership layer to do node_update_cluster,
     * and the peer status callback to do node_update_peer, because the node
     * might have already rejoined before we get the stonith result here.
     */
    int flags = node_update_join | node_update_expected;

    CRM_CHECK((target != NULL) && (target_xml_id != NULL), return);

    // Ensure target is cached
    peer = pcmk__get_node(0, target, target_xml_id, pcmk__node_search_any);
    CRM_CHECK(peer != NULL, return);

    if (peer->state == NULL) {
        /* Usually, we rely on the membership layer to update the cluster state
         * in the CIB. However, if the node has never been seen, do it here, so
         * the node is not considered unclean.
         */
        flags |= node_update_cluster;
    }

    if (peer->xml_id == NULL) {
        crm_info("Recording XML ID '%s' for node '%s'", target_xml_id, target);
        peer->xml_id = pcmk__str_copy(target_xml_id);
    }

    crmd_peer_down(peer, TRUE);

    node_state = create_node_state_update(peer, flags, NULL, __func__);
    crm_xml_add(node_state, PCMK_XA_ID, target_xml_id);

    if (pcmk_is_set(peer->flags, pcmk__node_status_remote)) {
        char *now_s = pcmk__ttoa(time(NULL));

        crm_xml_add(node_state, PCMK__XA_NODE_FENCED, now_s);
        free(now_s);
    }

    rc = controld_globals.cib_conn->cmds->modify(controld_globals.cib_conn,
                                                 PCMK_XE_STATUS, node_state,
                                                 cib_can_create);
    pcmk__xml_free(node_state);

    crm_debug("Updating node state for %s after fencing (call %d)", target, rc);
    fsa_register_cib_callback(rc, pcmk__str_copy(target), cib_fencing_updated);

    // Delete node's resource history from CIB
    controld_delete_node_history(peer->name, false, cib_none);

    // Ask attribute manager to delete node's transient attributes
    controld_purge_node_attrs(peer->name, false);
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
    abort_transition(PCMK_SCORE_INFINITY, abort_action, "Stonith failed",
                     reason);
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
    stonith_cleanup_list = g_list_append(stonith_cleanup_list,
                                         pcmk__str_copy(target));
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
        pcmk__node_status_t *target_node =
            pcmk__get_node(0, target, NULL, pcmk__node_search_cluster_member);
        const char *uuid = pcmk__cluster_get_xml_id(target_node);

        crm_notice("Marking %s, target of a previous stonith action, as clean", target);
        update_node_state_after_fencing(target, uuid);
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
static mainloop_timer_t *controld_fencer_connect_timer = NULL;
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

            task = crm_element_value(action->xml, PCMK_XA_OPERATION);
            if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_casei)) {
                pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
                last_action = action->xml;
                pcmk__update_graph(graph, action);
                crm_notice("Failing action %d (%s): fencer terminated",
                           action->id, pcmk__xe_id(action->xml));
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
        crm_err("Lost fencer connection (will attempt to reconnect)");
        if (!mainloop_timer_running(controld_fencer_connect_timer)) {
            mainloop_timer_start(controld_fencer_connect_timer);
        }
    } else {
        crm_info("Disconnected from fencer");
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
        fail_incompletable_stonith(controld_globals.transition_graph);
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

    if (pcmk__str_eq(PCMK_ACTION_ON, event->action, pcmk__str_none)) {
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
        crm_crit("We were allegedly just fenced by %s for %s!",
                 executioner, event->origin); // Dumps blackbox if enabled
        if (fence_reaction_panic) {
            pcmk__panic("Notified of own fencing");
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
               "%s%s%s%s " QB_XS " event=%s",
               event->target, (succeeded? "" : " not"),
               event->action, executioner, client, event->origin,
               (succeeded? "OK" : pcmk_exec_status_str(exec_status)),
               ((reason == NULL)? "" : " ("),
               ((reason == NULL)? "" : reason),
               ((reason == NULL)? "" : ")"),
               event->id);

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
                crm_info("External fencing operation from %s fenced %s",
                         client, event->target);
                abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                                 "External Fencing Operation", NULL);
            }

        } else if (pcmk__str_eq(controld_globals.dc_name, event->target,
                                pcmk__str_null_matches|pcmk__str_casei)
                   && !pcmk_is_set(peer->flags, pcmk__node_status_remote)) {
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
            if (controld_is_local_node(event->executioner)) {
                update_node_state_after_fencing(event->target, uuid);
            }
            add_stonith_cleanup(event->target);
        }

        /* If the target is a remote node, and we host its connection,
         * immediately fail all monitors so it can be recovered quickly.
         * The connection won't necessarily drop when a remote node is fenced,
         * so the failure might not otherwise be detected until the next poke.
         */
        if (pcmk_is_set(peer->flags, pcmk__node_status_remote)) {
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

    if (stonith_api == NULL) {
        stonith_api = stonith_api_new();
        if (stonith_api == NULL) {
            crm_err("Could not connect to fencer: API memory allocation failed");
            return G_SOURCE_REMOVE;
        }
    }

    if (stonith_api->state != stonith_disconnected) {
        crm_trace("Already connected to fencer, no need to retry");
        return G_SOURCE_REMOVE;
    }

    if (user_data == NULL) {
        // Blocking (retry failures now until successful)
        rc = stonith_api_connect_retry(stonith_api, crm_system_name, 30);
        if (rc != pcmk_ok) {
            crm_err("Could not connect to fencer in 30 attempts: %s "
                    QB_XS " rc=%d", pcmk_strerror(rc), rc);
        }
    } else {
        // Non-blocking (retry failures later in main loop)
        rc = stonith_api->cmds->connect(stonith_api, crm_system_name, NULL);

        if (controld_fencer_connect_timer == NULL) {
            controld_fencer_connect_timer =
                mainloop_timer_add("controld_fencer_connect", 1000,
                                   TRUE, controld_timer_fencer_connect,
                                   GINT_TO_POINTER(TRUE));
        }

        if (rc != pcmk_ok) {
            if (pcmk_is_set(controld_globals.fsa_input_register,
                            R_ST_REQUIRED)) {
                crm_notice("Fencer connection failed (will retry): %s "
                           QB_XS " rc=%d", pcmk_strerror(rc), rc);

                if (!mainloop_timer_running(controld_fencer_connect_timer)) {
                    mainloop_timer_start(controld_fencer_connect_timer);
                }

                return G_SOURCE_CONTINUE;
            } else {
                crm_info("Fencer connection failed (ignoring because no longer required): %s "
                         QB_XS " rc=%d", pcmk_strerror(rc), rc);
            }
            return G_SOURCE_REMOVE;
        }
    }

    if (rc == pcmk_ok) {
        stonith_api_operations_t *cmds = stonith_api->cmds;

        cmds->register_notification(stonith_api,
                                    PCMK__VALUE_ST_NOTIFY_DISCONNECT,
                                    tengine_stonith_connection_destroy);
        cmds->register_notification(stonith_api, PCMK__VALUE_ST_NOTIFY_FENCE,
                                    handle_fence_notification);
        cmds->register_notification(stonith_api,
                                    PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED,
                                    tengine_stonith_history_synced);
        te_trigger_stonith_history_sync(TRUE);
        crm_notice("Fencer successfully connected");
    }

    return G_SOURCE_REMOVE;
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
        crm_notice("Result of fence operation %d: %d (%s) " QB_XS " key=%s",
                   data->call_id, stonith__exit_status(data), reason,
                   (const char *) data->userdata);
        return;
    }

    CRM_CHECK(decode_transition_key(data->userdata, &uuid, &transition_id,
                                    &stonith_id, NULL),
              goto bail);

    if (controld_globals.transition_graph->complete || (stonith_id < 0)
        || !pcmk__str_eq(uuid, controld_globals.te_uuid, pcmk__str_none)
        || (controld_globals.transition_graph->id != transition_id)) {
        crm_info("Ignoring fence operation %d result: "
                 "Not from current transition " QB_XS
                 " complete=%s action=%d uuid=%s (vs %s) transition=%d (vs %d)",
                 data->call_id,
                 pcmk__btoa(controld_globals.transition_graph->complete),
                 stonith_id, uuid, controld_globals.te_uuid, transition_id,
                 controld_globals.transition_graph->id);
        goto bail;
    }

    action = controld_get_action(stonith_id);
    if (action == NULL) {
        crm_err("Ignoring fence operation %d result: "
                "Action %d not found in transition graph (bug?) "
                QB_XS " uuid=%s transition=%d",
                data->call_id, stonith_id, uuid, transition_id);
        goto bail;
    }

    target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    if (target == NULL) {
        crm_err("Ignoring fence operation %d result: No target given (bug?)",
                data->call_id);
        goto bail;
    }

    stop_te_timer(action);
    if (stonith__exit_status(data) == CRM_EX_OK) {
        const char *uuid = crm_element_value(action->xml,
                                             PCMK__META_ON_NODE_UUID);
        const char *op = crm_meta_value(action->params,
                                        PCMK__META_STONITH_ACTION);

        crm_info("Fence operation %d for %s succeeded", data->call_id, target);
        if (!(pcmk_is_set(action->flags, pcmk__graph_action_confirmed))) {
            te_action_confirmed(action, NULL);
            if (pcmk__str_eq(PCMK_ACTION_ON, op, pcmk__str_casei)) {
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
                if (g_hash_table_lookup(pcmk__remote_peer_cache,
                                        uuid) != NULL) {
                    is_remote_node = TRUE;
                }

                update_attrd(target, CRM_ATTR_UNFENCED, now, NULL,
                             is_remote_node);
                free(now);

                value = crm_meta_value(action->params, PCMK__META_DIGESTS_ALL);
                update_attrd(target, CRM_ATTR_DIGESTS_ALL, value, NULL,
                             is_remote_node);

                value = crm_meta_value(action->params,
                                       PCMK__META_DIGESTS_SECURE);
                update_attrd(target, CRM_ATTR_DIGESTS_SECURE, value, NULL,
                             is_remote_node);

            } else if (!(pcmk_is_set(action->flags, pcmk__graph_action_sent_update))) {
                update_node_state_after_fencing(target, uuid);
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
    int timeout_sec = pcmk__timeout_ms2s(controld_globals.transition_graph->stonith_timeout);

    if (crmd_join_phase_count(controld_join_confirmed) == 1) {
        stonith__set_call_options(options, target, st_opt_allow_self_fencing);
    }
    return stonith_api->cmds->fence_with_delay(stonith_api, options, target,
                                               type, timeout_sec, 0, delay);
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
    const char *uuid = crm_element_value(action->xml, PCMK__META_ON_NODE_UUID);
    const char *target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *type = crm_meta_value(action->params,
                                      PCMK__META_STONITH_ACTION);
    char *transition_key = NULL;
    const char *priority_delay = NULL;
    int delay_i = 0;
    gboolean invalid_action = FALSE;
    int stonith_timeout = pcmk__timeout_ms2s(controld_globals.transition_graph->stonith_timeout);

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

    crm_notice("Requesting fencing (%s) targeting node %s "
               QB_XS " action=%s timeout=%i%s%s",
               type, target, id, stonith_timeout,
               priority_delay ? " priority_delay=" : "",
               priority_delay ? priority_delay : "");

    /* Passing NULL means block until we can connect... */
    controld_timer_fencer_connect(NULL);

    pcmk__scan_min_int(priority_delay, &delay_i, 0);
    rc = fence_with_delay(target, type, delay_i);
    transition_key = pcmk__transition_key(controld_globals.transition_graph->id,
                                          action->id, 0,
                                          controld_globals.te_uuid),
    stonith_api->cmds->register_callback(stonith_api, rc,
                                         (stonith_timeout
                                          + (delay_i > 0 ? delay_i : 0)),
                                         st_opt_timeout_updates, transition_key,
                                         "tengine_stonith_callback",
                                         tengine_stonith_callback);
    return pcmk_rc_ok;
}

bool
controld_verify_stonith_watchdog_timeout(const char *value)
{
    long long st_timeout = (value != NULL)? crm_get_msec(value) : 0;
    const char *our_nodename = controld_globals.cluster->priv->node_name;

    if (st_timeout == 0
        || (stonith_api && (stonith_api->state != stonith_disconnected) &&
            stonith__watchdog_fencing_enabled_for_node_api(stonith_api,
                                                           our_nodename))) {
        return pcmk__valid_stonith_watchdog_timeout(value);
    }
    return true;
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
        st->cmds->remove_notification(st, PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED);
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
