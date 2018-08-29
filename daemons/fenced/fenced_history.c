/*
 * Copyright 2009-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

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
    xmlNode *bcast = create_xml_node(NULL, "stonith_command");
    xmlNode *data = create_xml_node(NULL, __FUNCTION__);

    if (target) {
        crm_xml_add(data, F_STONITH_TARGET, target);
    }
    crm_xml_add(bcast, F_TYPE, T_STONITH_NG);
    crm_xml_add(bcast, F_SUBTYPE, "broadcast");
    crm_xml_add(bcast, F_STONITH_OPERATION, STONITH_OP_FENCE_HISTORY);
    crm_xml_add_int(bcast, F_STONITH_CALLOPTS, callopts);
    if (history) {
        add_node_copy(data, history);
    }
    add_message_xml(bcast, F_STONITH_CALLDATA, data);
    send_cluster_message(NULL, crm_msg_stonith_ng, bcast, FALSE);

    free_xml(data);
    free_xml(bcast);
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
        do_stonith_notify(0, T_STONITH_NOTIFY_HISTORY, 0, NULL);
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


static int
op_time_sort(const void *a_voidp, const void *b_voidp)
{
    const remote_fencing_op_t **a = (const remote_fencing_op_t **) a_voidp;
    const remote_fencing_op_t **b = (const remote_fencing_op_t **) b_voidp;
    gboolean a_pending = ((*a)->state != st_failed) && ((*a)->state != st_done);
    gboolean b_pending = ((*b)->state != st_failed) && ((*b)->state != st_done);

    if (a_pending && b_pending) {
        return 0;
    } else if (a_pending) {
        return -1;
    } else if (b_pending) {
        return 1;
    } else if ((*b)->completed == (*a)->completed) {
        return 0;
    } else if ((*b)->completed > (*a)->completed) {
        return 1;
    }

    return -1;
}


/*!
 * \internal
 * \brief Do a local history-trim to MAX_STONITH_HISTORY / 2 entries
 *        once over MAX_STONITH_HISTORY
 */
void
stonith_fence_history_trim(void)
{
    guint num_ops;

    if (!stonith_remote_op_list) {
        return;
    }
    num_ops = g_hash_table_size(stonith_remote_op_list);
    if (num_ops > MAX_STONITH_HISTORY) {
        remote_fencing_op_t *ops[num_ops];
        remote_fencing_op_t *op = NULL;
        GHashTableIter iter;
        int i;

        crm_trace("Fencing History growing beyond limit of %d so purge "
                  "half of failed/successful attempts", MAX_STONITH_HISTORY);

        /* write all ops into an array */
        i = 0;
        g_hash_table_iter_init(&iter, stonith_remote_op_list);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&op)) {
            ops[i++] = op;
        }
        /* run quicksort over the array so that we get pending ops
         * first and then sorted most recent to oldest
         */
        qsort(ops, num_ops, sizeof(remote_fencing_op_t *), op_time_sort);
        /* purgest oldest half of the history entries */
        for (i = MAX_STONITH_HISTORY / 2; i < num_ops; i++) {
            /* keep pending ops even if they shouldn't fill more than
             * half of our buffer
             */
            if ((ops[i]->state == st_failed) || (ops[i]->state == st_done)) {
                g_hash_table_remove(stonith_remote_op_list, ops[i]->id);
            }
        }
        /* we've just purged valid data from the list so there is no need
         * to create a notification - if displayed it can stay
         */
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
stonith_xml_history_to_list(xmlNode *history)
{
    xmlNode *xml_op = NULL;
    GHashTable *rv = NULL;

    init_stonith_remote_op_hash_table(&rv);

    CRM_LOG_ASSERT(rv != NULL);

    for (xml_op = __xml_first_child(history); xml_op != NULL;
         xml_op = __xml_next(xml_op)) {
        remote_fencing_op_t *op = NULL;
        char *id = crm_element_value_copy(xml_op, F_STONITH_REMOTE_OP_ID);
        int completed, state;

        if (!id) {
            crm_warn("History to convert to hashtable has no id in entry");
            continue;
        }

        crm_trace("Attaching op %s to hashtable", id);

        op = calloc(1, sizeof(remote_fencing_op_t));

        op->id = id;
        op->target = crm_element_value_copy(xml_op, F_STONITH_TARGET);
        op->action = crm_element_value_copy(xml_op, F_STONITH_ACTION);
        op->originator = crm_element_value_copy(xml_op, F_STONITH_ORIGIN);
        op->delegate = crm_element_value_copy(xml_op, F_STONITH_DELEGATE);
        op->client_name = crm_element_value_copy(xml_op, F_STONITH_CLIENTNAME);
        crm_element_value_int(xml_op, F_STONITH_DATE, &completed);
        op->completed = (time_t) completed;
        crm_element_value_int(xml_op, F_STONITH_STATE, &state);
        op->state = (enum op_state) state;

        g_hash_table_replace(rv, id, op);
        CRM_LOG_ASSERT(g_hash_table_lookup(rv, id) != NULL);
    }

    return rv;
}

/*!
 * \internal
 * \brief Craft xml difference between local fence-history and a history
 *        coming from remote
 *
 * \param[in] remote_history    Fence-history as hash-table (may be NULL)
 * \param[in] add_id            If crafting the answer for an API
 *                              history-request there is no need for the id
 * \param[in] target            Optionally limit to certain fence-target
 *
 * \return The fence-history as xml
 */
static xmlNode *
stonith_local_history_diff(GHashTable *remote_history,
                           gboolean add_id,
                           const char *target)
{
    xmlNode *history = NULL;
    int cnt = 0;

    if (stonith_remote_op_list) {
            GHashTableIter iter;
            remote_fencing_op_t *op = NULL;

            history = create_xml_node(NULL, F_STONITH_HISTORY_LIST);

            g_hash_table_iter_init(&iter, stonith_remote_op_list);
            while (g_hash_table_iter_next(&iter, NULL, (void **)&op)) {
                xmlNode *entry = NULL;

                if (remote_history &&
                    g_hash_table_lookup(remote_history, op->id)) {
                    continue; /* skip entries broadcasted already */
                }

                if (target && strcmp(op->target, target) != 0) {
                    continue;
                }

                cnt++;
                crm_trace("Attaching op %s", op->id);
                entry = create_xml_node(history, STONITH_OP_EXEC);
                if (add_id) {
                    crm_xml_add(entry, F_STONITH_REMOTE_OP_ID, op->id);
                }
                crm_xml_add(entry, F_STONITH_TARGET, op->target);
                crm_xml_add(entry, F_STONITH_ACTION, op->action);
                crm_xml_add(entry, F_STONITH_ORIGIN, op->originator);
                crm_xml_add(entry, F_STONITH_DELEGATE, op->delegate);
                crm_xml_add(entry, F_STONITH_CLIENTNAME, op->client_name);
                crm_xml_add_int(entry, F_STONITH_DATE, op->completed);
                crm_xml_add_int(entry, F_STONITH_STATE, op->state);
            }
    }

    if (cnt == 0) {
        free_xml(history);
        return NULL;
    } else {
        return history;
    }
}

/*!
 * \internal
 * \brief Merge fence-history coming from remote into local history
 *
 * \param[in] history   Hash-table holding remote history to be merged in
 */
static void
stonith_merge_in_history_list(GHashTable *history)
{
    GHashTableIter iter;
    remote_fencing_op_t *op = NULL;
    gboolean updated = FALSE;

    if (!history) {
        return;
    }

    init_stonith_remote_op_hash_table(&stonith_remote_op_list);

    g_hash_table_iter_init(&iter, history);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&op)) {
        remote_fencing_op_t *stored_op =
            g_hash_table_lookup(stonith_remote_op_list, op->id);

        if (stored_op) {
            continue; /* skip over existant - state-merging migh be desirable */
        }

        updated = TRUE;
        g_hash_table_iter_steal(&iter);
        g_hash_table_insert(stonith_remote_op_list, op->id, op);
        /* we could trim the history here but if we bail
         * out after trim we might miss more recent entries
         * of those that might still be in the list
         * if we don't bail out trimming once is more
         * efficient and memory overhead is minimal as
         * we are just moving pointers from one hash to
         * another
         */
    }
    stonith_fence_history_trim();
    if (updated) {
        do_stonith_notify(0, T_STONITH_NOTIFY_HISTORY, 0, NULL);
    }
    g_hash_table_destroy(history); /* remove what is left */
}

/*!
 * \internal
 * \brief Handle fence-history messages (either from API or coming in as
 *        broadcasts
 *
 * \param[in] msg       Request message
 * \param[in] output    In case of a request from the API used to craft
 *                      a reply from
 * \param[in] remote_peer
 * \param[in] options   call-options from the request
 *
 * \return always success as there is actully nothing that can go really wrong
 */
int
stonith_fence_history(xmlNode *msg, xmlNode **output,
                      const char *remote_peer, int options)
{
    int rc = 0;
    const char *target = NULL;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, msg, LOG_TRACE);
    char *nodename = NULL;
    xmlNode *out_history = NULL;

    if (dev) {
        target = crm_element_value(dev, F_STONITH_TARGET);
        if (target && (options & st_opt_cs_nodeid)) {
            int nodeid = crm_atoi(target, NULL);

            nodename = stonith_get_peer_name(nodeid);
            if (nodename) {
                target = nodename;
            }
        }
    }

    if (options & st_opt_cleanup) {
        crm_trace("Cleaning up operations on %s in %p", target,
                  stonith_remote_op_list);

        stonith_fence_history_cleanup(target,
            crm_element_value(msg, F_STONITH_CALLID) != NULL);
    } else if (options & st_opt_broadcast) {
        if (crm_element_value(msg, F_STONITH_CALLID)) {
            /* this is coming from the stonith-API
            *
            * craft a broadcast with node's history
            * so that every node can merge and broadcast
            * what it has on top
            */
            out_history = stonith_local_history_diff(NULL, TRUE, NULL);
            crm_trace("Broadcasting history to peers");
            stonith_send_broadcast_history(out_history,
                                        st_opt_broadcast | st_opt_discard_reply,
                                        NULL);
        } else if (remote_peer &&
                   !safe_str_eq(remote_peer, stonith_our_uname)) {
            xmlNode *history =
                get_xpath_object("//" F_STONITH_HISTORY_LIST, msg, LOG_TRACE);
            GHashTable *received_history =
                history?stonith_xml_history_to_list(history):NULL;

            /* either a broadcast created directly upon stonith-API request
            * or a diff as response to such a thing
            *
            * in both cases it may have a history or not
            * if we have differential data
            * merge in what we've received and stop
            * otherwise broadcast what we have on top
            * marking as differential and merge in afterwards
            */
            if (!history ||
                !crm_is_true(crm_element_value(history,
                                               F_STONITH_DIFFERENTIAL))) {
                out_history =
                    stonith_local_history_diff(received_history, TRUE, NULL);
                if (out_history) {
                    crm_trace("Broadcasting history-diff to peers");
                    crm_xml_add(out_history, F_STONITH_DIFFERENTIAL,
                                XML_BOOLEAN_TRUE);
                    stonith_send_broadcast_history(out_history,
                        st_opt_broadcast | st_opt_discard_reply,
                        NULL);
                } else {
                    crm_trace("History-diff is empty - skip broadcast");
                }
            }
            stonith_merge_in_history_list(received_history);
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
        *output = stonith_local_history_diff(NULL, FALSE, target);
    }
    free(nodename);
    free_xml(out_history);
    return rc;
}
