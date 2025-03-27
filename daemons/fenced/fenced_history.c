/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <pacemaker-fenced.h>

#define MAX_STONITH_HISTORY 500

/*!
 * \internal
 * \brief Send a broadcast to all nodes to trigger cleanup or
 *        history synchronisation
 *
 * \param[in] history   Optional history to be attached
 * \param[in] callopts  We control cleanup via a flag in the callopts
 * \param[in] target    Cleanup can be limited to certain fence-targets
 */
static void
stonith_send_broadcast_history(xmlNode *history,
                               int callopts,
                               const char *target)
{
    xmlNode *bcast = pcmk__xe_create(NULL, PCMK__XE_STONITH_COMMAND);
    xmlNode *wrapper = pcmk__xe_create(bcast, PCMK__XE_ST_CALLDATA);
    xmlNode *call_data = pcmk__xe_create(wrapper, __func__);

    pcmk__xe_set(bcast, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
    pcmk__xe_set(bcast, PCMK__XA_SUBT, PCMK__VALUE_BROADCAST);
    pcmk__xe_set(bcast, PCMK__XA_ST_OP, STONITH_OP_FENCE_HISTORY);
    pcmk__xe_set_int(bcast, PCMK__XA_ST_CALLOPT, callopts);

    pcmk__xml_copy(call_data, history);
    if (target != NULL) {
        pcmk__xe_set(call_data, PCMK__XA_ST_TARGET, target);
    }

    pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, bcast);

    pcmk__xml_free(bcast);
}

static gboolean
stonith_remove_history_entry (gpointer key,
                              gpointer value,
                              gpointer user_data)
{
    remote_fencing_op_t *op = value;
    const char *target = (const char *) user_data;

    if ((op->state == st_failed) || (op->state == st_done)) {
        if ((target) && (strcmp(op->target, target) != 0)) {
            return FALSE;
        }
        return TRUE;
    }

    return FALSE; /* don't clean pending operations */
}

/*!
 * \internal
 * \brief Send out a cleanup broadcast or do a local history-cleanup
 *
 * \param[in] target    Cleanup can be limited to certain fence-targets
 * \param[in] broadcast Send out a cleanup broadcast
 */
static void
stonith_fence_history_cleanup(const char *target,
                              gboolean broadcast)
{
    if (broadcast) {
        stonith_send_broadcast_history(NULL,
                                       st_opt_cleanup | st_opt_discard_reply,
                                       target);
        /* we'll do the local clean when we receive back our own broadcast */
    } else if (stonith_remote_op_list) {
        g_hash_table_foreach_remove(stonith_remote_op_list,
                             stonith_remove_history_entry,
                             (gpointer) target);
        fenced_send_notification(PCMK__VALUE_ST_NOTIFY_HISTORY, NULL, NULL);
    }
}

/* keeping the length of fence-history within bounds
 * =================================================
 *
 * If things are really running wild a lot of fencing-attempts
 * might fill up the hash-map, eventually using up a lot
 * of memory and creating huge history-sync messages.
 * Before the history being synced across nodes at least
 * the reboot of a cluster-node helped keeping the
 * history within bounds even though not in a reliable
 * manner.
 *
 * stonith_remote_op_list isn't sorted for time-stamps
 * thus it would be kind of expensive to delete e.g.
 * the oldest entry if it would grow past MAX_STONITH_HISTORY
 * entries.
 * It is more efficient to purge MAX_STONITH_HISTORY/2
 * entries whenever the list grows beyond MAX_STONITH_HISTORY.
 * (sort for age + purge the MAX_STONITH_HISTORY/2 oldest)
 * That done on a per-node-base might raise the
 * probability of large syncs to occur.
 * Things like introducing a broadcast to purge
 * MAX_STONITH_HISTORY/2 entries or not sync above a certain
 * threshold coming to mind ...
 * Simplest thing though is to purge the full history
 * throughout the cluster once MAX_STONITH_HISTORY is reached.
 * On the other hand this leads to purging the history in
 * situations where it would be handy to have it probably.
 */

/*!
 * \internal
 * \brief Compare two remote fencing operations by status and completion time
 *
 * A pending operation is ordered before a completed operation. If both
 * operations have completed, then the more recently completed operation is
 * ordered first. Two pending operations are considered equal.
 *
 * \param[in] a  First \c remote_fencing_op_t to compare
 * \param[in] b  Second \c remote_fencing_op_t to compare
 *
 * \return Standard comparison result (a negative integer if \p a is lesser,
 *         0 if the values are equal, and a positive integer if \p a is greater)
 */
static gint
cmp_op_by_completion(gconstpointer a, gconstpointer b)
{
    const remote_fencing_op_t *op1 = a;
    const remote_fencing_op_t *op2 = b;
    bool op1_pending = stonith__op_state_pending(op1->state);
    bool op2_pending = stonith__op_state_pending(op2->state);

    if (op1_pending && op2_pending) {
        return 0;
    }
    if (op1_pending) {
        return -1;
    }
    if (op2_pending) {
        return 1;
    }
    if (op1->completed > op2->completed) {
        return -1;
    }
    if (op1->completed < op2->completed) {
        return 1;
    }
    if (op1->completed_nsec > op2->completed_nsec) {
        return -1;
    }
    if (op1->completed_nsec < op2->completed_nsec) {
        return 1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Remove a completed operation from \c stonith_remote_op_list
 *
 * \param[in] data       \c remote_fencing_op_t to remove
 * \param[in] user_data  Ignored
 */
static void
remove_completed_remote_op(gpointer data, gpointer user_data)
{
    const remote_fencing_op_t *op = data;

    if (!stonith__op_state_pending(op->state)) {
        g_hash_table_remove(stonith_remote_op_list, op->id);
    }
}

/*!
 * \internal
 * \brief Do a local history-trim to MAX_STONITH_HISTORY / 2 entries
 *        once over MAX_STONITH_HISTORY
 */
void
stonith_fence_history_trim(void)
{
    if (stonith_remote_op_list == NULL) {
        return;
    }

    if (g_hash_table_size(stonith_remote_op_list) > MAX_STONITH_HISTORY) {
        GList *ops = g_hash_table_get_values(stonith_remote_op_list);

        crm_trace("More than %d entries in fencing history, purging oldest "
                  "completed operations", MAX_STONITH_HISTORY);

        ops = g_list_sort(ops, cmp_op_by_completion);

        // Always keep pending ops regardless of number of entries
        g_list_foreach(g_list_nth(ops, MAX_STONITH_HISTORY / 2),
                       remove_completed_remote_op, NULL);

        // No need for a notification after purging old data
        g_list_free(ops);
    }
}

/*!
 * \internal
 * \brief Convert xml fence-history to a hash-table like stonith_remote_op_list
 *
 * \param[in] history   Fence-history in xml
 *
 * \return Fence-history as hash-table
 */
static GHashTable *
stonith_xml_history_to_list(const xmlNode *history)
{
    xmlNode *xml_op = NULL;
    GHashTable *rv = NULL;

    init_stonith_remote_op_hash_table(&rv);

    CRM_LOG_ASSERT(rv != NULL);

    for (xml_op = pcmk__xe_first_child(history, NULL, NULL, NULL);
         xml_op != NULL; xml_op = pcmk__xe_next(xml_op, NULL)) {

        remote_fencing_op_t *op = NULL;
        char *id = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_REMOTE_OP);
        int state;
        int exit_status = CRM_EX_OK;
        int execution_status = PCMK_EXEC_DONE;

        if (!id) {
            crm_warn("Malformed fencing history received from peer");
            continue;
        }

        crm_trace("Attaching op %s to hashtable", id);

        op = pcmk__assert_alloc(1, sizeof(remote_fencing_op_t));

        op->id = id;
        op->target = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_TARGET);
        op->action = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_DEVICE_ACTION);
        op->originator = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_ORIGIN);
        op->delegate = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_DELEGATE);
        op->client_name = pcmk__xe_get_copy(xml_op, PCMK__XA_ST_CLIENTNAME);
        pcmk__xe_get_time(xml_op, PCMK__XA_ST_DATE, &op->completed);
        pcmk__xe_get_ll(xml_op, PCMK__XA_ST_DATE_NSEC, &op->completed_nsec);
        pcmk__xe_get_int(xml_op, PCMK__XA_ST_STATE, &state);
        op->state = (enum op_state) state;

        /* @COMPAT We can't use stonith__xe_get_result() here because
         * fencers <2.1.3 didn't include results, leading it to assume an error
         * status. Instead, set an unknown status in that case.
         */
        if ((pcmk__xe_get_int(xml_op, PCMK__XA_RC_CODE,
                              &exit_status) != pcmk_rc_ok)
            || (pcmk__xe_get_int(xml_op, PCMK__XA_OP_STATUS,
                                 &execution_status) != pcmk_rc_ok)) {
            exit_status = CRM_EX_INDETERMINATE;
            execution_status = PCMK_EXEC_UNKNOWN;
        }
        pcmk__set_result(&op->result, exit_status, execution_status,
                         pcmk__xe_get(xml_op, PCMK_XA_EXIT_REASON));
        pcmk__set_result_output(&op->result,
                                pcmk__xe_get_copy(xml_op, PCMK__XA_ST_OUTPUT),
                                NULL);


        g_hash_table_replace(rv, id, op);
        CRM_LOG_ASSERT(g_hash_table_lookup(rv, id) != NULL);
    }

    return rv;
}

/*!
 * \internal
 * \brief Craft xml difference between local fence-history and a history
 *        coming from remote, and merge the remote history into the local
 *
 * \param[in,out] remote_history  Fence-history as hash-table (may be NULL)
 * \param[in]     add_id          If crafting the answer for an API
 *                                history-request there is no need for the id
 * \param[in]     target          Optionally limit to certain fence-target
 *
 * \return The fence-history as xml
 */
static xmlNode *
stonith_local_history_diff_and_merge(GHashTable *remote_history,
                                     gboolean add_id, const char *target)
{
    xmlNode *history = NULL;
    GHashTableIter iter;
    remote_fencing_op_t *op = NULL;
    gboolean updated = FALSE;
    int cnt = 0;

    if (stonith_remote_op_list) {
            char *id = NULL;

            history = pcmk__xe_create(NULL, PCMK__XE_ST_HISTORY);

            g_hash_table_iter_init(&iter, stonith_remote_op_list);
            while (g_hash_table_iter_next(&iter, (void **)&id, (void **)&op)) {
                xmlNode *entry = NULL;

                if (remote_history) {
                    remote_fencing_op_t *remote_op =
                        g_hash_table_lookup(remote_history, op->id);

                    if (remote_op) {
                        if (stonith__op_state_pending(op->state)
                            && !stonith__op_state_pending(remote_op->state)) {

                            crm_debug("Updating outdated pending operation %.8s "
                                      "(state=%s) according to the one (state=%s) from "
                                      "remote peer history",
                                      op->id, stonith_op_state_str(op->state),
                                      stonith_op_state_str(remote_op->state));

                            g_hash_table_steal(remote_history, op->id);
                            op->id = remote_op->id;
                            remote_op->id = id;
                            g_hash_table_iter_replace(&iter, remote_op);

                            updated = TRUE;
                            continue; /* skip outdated entries */

                        } else if (!stonith__op_state_pending(op->state)
                                   && stonith__op_state_pending(remote_op->state)) {

                            crm_debug("Broadcasting operation %.8s (state=%s) to "
                                      "update the outdated pending one "
                                      "(state=%s) in remote peer history",
                                      op->id, stonith_op_state_str(op->state),
                                      stonith_op_state_str(remote_op->state));

                            g_hash_table_remove(remote_history, op->id);

                        } else {
                            g_hash_table_remove(remote_history, op->id);
                            continue; /* skip entries broadcasted already */
                        }
                    }
                }

                if (!pcmk__str_eq(target, op->target, pcmk__str_null_matches)) {
                    continue;
                }

                cnt++;
                crm_trace("Attaching op %s", op->id);
                entry = pcmk__xe_create(history, STONITH_OP_EXEC);
                if (add_id) {
                    pcmk__xe_set(entry, PCMK__XA_ST_REMOTE_OP, op->id);
                }
                pcmk__xe_set(entry, PCMK__XA_ST_TARGET, op->target);
                pcmk__xe_set(entry, PCMK__XA_ST_DEVICE_ACTION, op->action);
                pcmk__xe_set(entry, PCMK__XA_ST_ORIGIN, op->originator);
                pcmk__xe_set(entry, PCMK__XA_ST_DELEGATE, op->delegate);
                pcmk__xe_set(entry, PCMK__XA_ST_CLIENTNAME, op->client_name);
                pcmk__xe_set_time(entry, PCMK__XA_ST_DATE, op->completed);
                pcmk__xe_set_ll(entry, PCMK__XA_ST_DATE_NSEC,
                                op->completed_nsec);
                pcmk__xe_set_int(entry, PCMK__XA_ST_STATE, op->state);
                stonith__xe_set_result(entry, &op->result);
            }
    }

    if (remote_history) {
        init_stonith_remote_op_hash_table(&stonith_remote_op_list);

        updated |= g_hash_table_size(remote_history);

        g_hash_table_iter_init(&iter, remote_history);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&op)) {
            if (stonith__op_state_pending(op->state) &&
                pcmk__str_eq(op->originator, fenced_get_local_node(),
                             pcmk__str_casei)) {

                crm_warn("Failing pending operation %.8s originated by us but "
                         "known only from peer history", op->id);
                op->state = st_failed;
                set_fencing_completed(op);

                /* CRM_EX_EXPIRED + PCMK_EXEC_INVALID prevents finalize_op()
                 * from setting a delegate
                 */
                pcmk__set_result(&op->result, CRM_EX_EXPIRED, PCMK_EXEC_INVALID,
                                 "Initiated by earlier fencer "
                                 "process and presumed failed");
                fenced_broadcast_op_result(op, false);
            }

            g_hash_table_iter_steal(&iter);
            g_hash_table_replace(stonith_remote_op_list, op->id, op);
            /* we could trim the history here but if we bail
             * out after trim we might miss more recent entries
             * of those that might still be in the list
             * if we don't bail out trimming once is more
             * efficient and memory overhead is minimal as
             * we are just moving pointers from one hash to
             * another
             */
        }

        g_hash_table_destroy(remote_history); /* remove what is left */
    }

    if (updated) {
        stonith_fence_history_trim();
        fenced_send_notification(PCMK__VALUE_ST_NOTIFY_HISTORY, NULL, NULL);
    }

    if (cnt == 0) {
        pcmk__xml_free(history);
        return NULL;
    } else {
        return history;
    }
}

/*!
 * \internal
 * \brief Craft xml from the local fence-history
 *
 * \param[in] add_id            If crafting the answer for an API
 *                              history-request there is no need for the id
 * \param[in] target            Optionally limit to certain fence-target
 *
 * \return The fence-history as xml
 */
static xmlNode *
stonith_local_history(gboolean add_id, const char *target)
{
    return stonith_local_history_diff_and_merge(NULL, add_id, target);
}

/*!
 * \internal
 * \brief Handle fence-history messages (from API or coming in as broadcasts)
 *
 * \param[in,out] msg          Request XML
 * \param[out]    output       Where to set local history, if requested
 * \param[in]     remote_peer  If broadcast, peer that sent it
 * \param[in]     options      Call options from the request
 */
void
stonith_fence_history(xmlNode *msg, xmlNode **output,
                      const char *remote_peer, int options)
{
    const char *target = NULL;
    xmlNode *dev = pcmk__xpath_find_one(msg->doc,
                                        "//*[@" PCMK__XA_ST_TARGET "]",
                                        LOG_NEVER);
    xmlNode *out_history = NULL;

    if (dev) {
        target = pcmk__xe_get(dev, PCMK__XA_ST_TARGET);
        if (target && (options & st_opt_cs_nodeid)) {
            int nodeid;
            pcmk__node_status_t *node = NULL;

            pcmk__scan_min_int(target, &nodeid, 0);
            node = pcmk__search_node_caches(nodeid, NULL, NULL,
                                            pcmk__node_search_any
                                            |pcmk__node_search_cluster_cib);
            if (node != NULL) {
                target = node->name;
            }
        }
    }

    if (options & st_opt_cleanup) {
        const char *call_id = pcmk__xe_get(msg, PCMK__XA_ST_CALLID);

        crm_trace("Cleaning up operations on %s in %p", target,
                  stonith_remote_op_list);
        stonith_fence_history_cleanup(target, (call_id != NULL));

    } else if (options & st_opt_broadcast) {
        /* there is no clear sign atm for when a history sync
           is done so send a notification for anything
           that smells like history-sync
         */
        fenced_send_notification(PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED, NULL,
                                 NULL);
        if (pcmk__xe_get(msg, PCMK__XA_ST_CALLID) != NULL) {
            /* this is coming from the stonith-API
            *
            * craft a broadcast with node's history
            * so that every node can merge and broadcast
            * what it has on top
            */
            out_history = stonith_local_history(TRUE, NULL);
            crm_trace("Broadcasting history to peers");
            stonith_send_broadcast_history(out_history,
                                        st_opt_broadcast | st_opt_discard_reply,
                                        NULL);
        } else if (remote_peer &&
                   !pcmk__str_eq(remote_peer, fenced_get_local_node(),
                                 pcmk__str_casei)) {
            xmlNode *history = pcmk__xpath_find_one(msg->doc,
                                                    "//" PCMK__XE_ST_HISTORY,
                                                    LOG_NEVER);

            /* either a broadcast created directly upon stonith-API request
            * or a diff as response to such a thing
            *
            * in both cases it may have a history or not
            * if we have differential data
            * merge in what we've received and stop
            * otherwise broadcast what we have on top
            * marking as differential and merge in afterwards
            */
            if (!history
                || !pcmk__xe_attr_is_true(history, PCMK__XA_ST_DIFFERENTIAL)) {

                GHashTable *received_history = NULL;

                if (history != NULL) {
                    received_history = stonith_xml_history_to_list(history);
                }
                out_history =
                    stonith_local_history_diff_and_merge(received_history, TRUE, NULL);
                if (out_history) {
                    crm_trace("Broadcasting history-diff to peers");
                    pcmk__xe_set_bool_attr(out_history,
                                           PCMK__XA_ST_DIFFERENTIAL, true);
                    stonith_send_broadcast_history(out_history,
                        st_opt_broadcast | st_opt_discard_reply,
                        NULL);
                } else {
                    crm_trace("History-diff is empty - skip broadcast");
                }
            }
        } else {
            crm_trace("Skipping history-query-broadcast (%s%s)"
                      " we sent ourselves",
                      remote_peer?"remote-peer=":"local-ipc",
                      remote_peer?remote_peer:"");
        }
    } else {
        /* plain history request */
        crm_trace("Looking for operations on %s in %p", target,
                  stonith_remote_op_list);
        *output = stonith_local_history(FALSE, target);
    }
    pcmk__xml_free(out_history);
}
