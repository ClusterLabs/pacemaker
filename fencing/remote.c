/*
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/util.h>
#include <internal.h>

#define TIMEOUT_MULTIPLY_FACTOR 1.2

typedef struct st_query_result_s {
    char *host;
    int devices;
    /* only try peers for non-topology based operations once */
    gboolean tried;
    GListPtr device_list;
    GHashTable *custom_action_timeouts;
    /* Subset of devices that peer has verified connectivity on */
    GHashTable *verified_devices;

} st_query_result_t;

GHashTable *remote_op_list = NULL;
void call_remote_stonith(remote_fencing_op_t * op, st_query_result_t * peer);
static void remote_op_done(remote_fencing_op_t * op, xmlNode * data, int rc, int dup);
extern xmlNode *stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data,
                                  int call_options);

static void report_timeout_period(remote_fencing_op_t * op, int op_timeout);
static int get_op_total_timeout(remote_fencing_op_t * op, st_query_result_t * chosen_peer,
                                int default_timeout);

static void
free_remote_query(gpointer data)
{
    if (data) {
        st_query_result_t *query = data;

        crm_trace("Free'ing query result from %s", query->host);
        free(query->host);
        g_list_free_full(query->device_list, free);
        g_hash_table_destroy(query->custom_action_timeouts);
        g_hash_table_destroy(query->verified_devices);
        free(query);
    }
}

static void
clear_remote_op_timers(remote_fencing_op_t * op)
{
    if (op->query_timer) {
        g_source_remove(op->query_timer);
        op->query_timer = 0;
    }
    if (op->op_timer_total) {
        g_source_remove(op->op_timer_total);
        op->op_timer_total = 0;
    }
    if (op->op_timer_one) {
        g_source_remove(op->op_timer_one);
        op->op_timer_one = 0;
    }
}

static void
free_remote_op(gpointer data)
{
    remote_fencing_op_t *op = data;

    crm_trace("Free'ing op %s for %s", op->id, op->target);
    crm_log_xml_debug(op->request, "Destroying");

    clear_remote_op_timers(op);

    free(op->id);
    free(op->action);
    free(op->target);
    free(op->client_id);
    free(op->client_name);
    free(op->originator);

    if (op->query_results) {
        g_list_free_full(op->query_results, free_remote_query);
    }
    if (op->request) {
        free_xml(op->request);
        op->request = NULL;
    }
    free(op);
}

static xmlNode *
create_op_done_notify(remote_fencing_op_t * op, int rc)
{
    xmlNode *notify_data = create_xml_node(NULL, T_STONITH_NOTIFY_FENCE);

    crm_xml_add_int(notify_data, "state", op->state);
    crm_xml_add_int(notify_data, F_STONITH_RC, rc);
    crm_xml_add(notify_data, F_STONITH_TARGET, op->target);
    crm_xml_add(notify_data, F_STONITH_ACTION, op->action);
    crm_xml_add(notify_data, F_STONITH_DELEGATE, op->delegate);
    crm_xml_add(notify_data, F_STONITH_REMOTE_OP_ID, op->id);
    crm_xml_add(notify_data, F_STONITH_ORIGIN, op->originator);
    crm_xml_add(notify_data, F_STONITH_CLIENTID, op->client_id);
    crm_xml_add(notify_data, F_STONITH_CLIENTNAME, op->client_name);

    return notify_data;
}

static void
bcast_result_to_peers(remote_fencing_op_t * op, int rc)
{
    static int count = 0;
    xmlNode *bcast = create_xml_node(NULL, T_STONITH_REPLY);
    xmlNode *notify_data = create_op_done_notify(op, rc);

    count++;
    crm_trace("Broadcasting result to peers");
    crm_xml_add(bcast, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(bcast, F_SUBTYPE, "broadcast");
    crm_xml_add(bcast, F_STONITH_OPERATION, T_STONITH_NOTIFY);
    crm_xml_add_int(bcast, "count", count);
    add_message_xml(bcast, F_STONITH_CALLDATA, notify_data);
    send_cluster_message(NULL, crm_msg_stonith_ng, bcast, FALSE);
    free_xml(notify_data);
    free_xml(bcast);

    return;
}

static void
handle_local_reply_and_notify(remote_fencing_op_t * op, xmlNode * data, int rc)
{
    xmlNode *notify_data = NULL;
    xmlNode *reply = NULL;

    if (op->notify_sent == TRUE) {
        /* nothing to do */
        return;
    }

    /* Do notification with a clean data object */
    notify_data = create_op_done_notify(op, rc);
    crm_xml_add_int(data, "state", op->state);
    crm_xml_add(data, F_STONITH_TARGET, op->target);
    crm_xml_add(data, F_STONITH_OPERATION, op->action);

    reply = stonith_construct_reply(op->request, NULL, data, rc);
    crm_xml_add(reply, F_STONITH_DELEGATE, op->delegate);

    /* Send fencing OP reply to local client that initiated fencing */
    do_local_reply(reply, op->client_id, op->call_options & st_opt_sync_call, FALSE);

    /* bcast to all local clients that the fencing operation happend */
    do_stonith_notify(0, T_STONITH_NOTIFY_FENCE, rc, notify_data);

    /* mark this op as having notify's already sent */
    op->notify_sent = TRUE;
    free_xml(reply);
    free_xml(notify_data);
}

static void
handle_duplicates(remote_fencing_op_t * op, xmlNode * data, int rc)
{
    GListPtr iter = NULL;

    for (iter = op->duplicates; iter != NULL; iter = iter->next) {
        remote_fencing_op_t *other = iter->data;

        if (other->state == st_duplicate) {
            /* Ie. it hasn't timed out already */
            other->state = op->state;
            crm_debug("Peforming duplicate notification for %s@%s.%.8s = %s", other->client_name,
                      other->originator, other->id, pcmk_strerror(rc));
            remote_op_done(other, data, rc, TRUE);

        } else {
            crm_err("Skipping duplicate notification for %s@%s - %d", other->client_name,
                    other->originator, other->state);
        }
    }
}

/*!
 * \internal
 * \brief Finalize a remote operation.
 *
 * \description This function has two code paths.
 *
 * Path 1. This node is the owner of the operation and needs
 *         to notify the cpg group via a broadcast as to the operation's
 *         results.
 *
 * Path 2. The cpg broadcast is received. All nodes notify their local
 *         stonith clients the operation results.
 *
 * So, The owner of the operation first notifies the cluster of the result,
 * and once that cpg notify is received back it notifies all the local clients.
 *
 * Nodes that are passive watchers of the operation will receive the
 * broadcast and only need to notify their local clients the operation finished.
 *
 * \param op, The fencing operation to finalize
 * \param data, The xml msg reply (if present) of the last delegated fencing
 *              operation.
 * \param dup, Is this operation a duplicate, if so treat it a little differently
 *             making sure the broadcast is not sent out.
 */
static void
remote_op_done(remote_fencing_op_t * op, xmlNode * data, int rc, int dup)
{
    int level = LOG_ERR;
    const char *subt = NULL;
    xmlNode *local_data = NULL;

    op->completed = time(NULL);
    clear_remote_op_timers(op);

    if (op->notify_sent == TRUE) {
        crm_err("Already sent notifications for '%s of %s by %s' (for=%s@%s.%.8s, state=%d): %s",
                op->action, op->target, op->delegate ? op->delegate : "<no-one>",
                op->client_name, op->originator, op->id, op->state, pcmk_strerror(rc));
        goto remote_op_done_cleanup;
    }

    if (!op->delegate && data) {
        op->delegate = crm_element_value_copy(data, F_ORIG);
    }

    if (data == NULL) {
        data = create_xml_node(NULL, "remote-op");
        local_data = data;
    }

    /* Tell everyone the operation is done, we will continue
     * with doing the local notifications once we receive
     * the broadcast back. */
    subt = crm_element_value(data, F_SUBTYPE);
    if (dup == FALSE && safe_str_neq(subt, "broadcast")) {
        /* Defer notification until the bcast message arrives */
        bcast_result_to_peers(op, rc);
        goto remote_op_done_cleanup;
    }

    if (rc == pcmk_ok || dup) {
        level = LOG_NOTICE;
    } else if (safe_str_neq(op->originator, stonith_our_uname)) {
        level = LOG_NOTICE;
    }

    do_crm_log(level,
               "Operation %s of %s by %s for %s@%s.%.8s: %s",
               op->action, op->target, op->delegate ? op->delegate : "<no-one>",
               op->client_name, op->originator, op->id, pcmk_strerror(rc));

    handle_local_reply_and_notify(op, data, rc);

    if (dup == FALSE) {
        handle_duplicates(op, data, rc);
    }

    /* Free non-essential parts of the record
     * Keep the record around so we can query the history
     */
    if (op->query_results) {
        g_list_free_full(op->query_results, free_remote_query);
        op->query_results = NULL;
    }

    if (op->request) {
        free_xml(op->request);
        op->request = NULL;
    }

  remote_op_done_cleanup:
    free_xml(local_data);
}

static gboolean
remote_op_timeout_one(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_one = 0;

    crm_notice("Remote %s operation on %s for %s.%8s timed out",
               op->action, op->target, op->client_name, op->id);
    call_remote_stonith(op, NULL);
    return FALSE;
}

static gboolean
remote_op_timeout(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_total = 0;

    if (op->state == st_done) {
        crm_debug("Action %s (%s) for %s (%s) already completed",
                  op->action, op->id, op->target, op->client_name);
        return FALSE;
    }

    crm_debug("Action %s (%s) for %s (%s) timed out",
              op->action, op->id, op->target, op->client_name);
    op->state = st_failed;
    remote_op_done(op, NULL, -ETIME, FALSE);

    return FALSE;
}

static gboolean
remote_op_query_timeout(gpointer data)
{
    remote_fencing_op_t *op = data;

    op->query_timer = 0;
    if (op->state == st_done) {
        crm_debug("Operation %s for %s already completed", op->id, op->target);
    } else if (op->state == st_exec) {
        crm_debug("Operation %s for %s already in progress", op->id, op->target);
    } else if (op->query_results) {
        crm_debug("Query %s for %s complete: %d", op->id, op->target, op->state);
        call_remote_stonith(op, NULL);
    } else {
        crm_debug("Query %s for %s timed out: %d", op->id, op->target, op->state);
        if (op->op_timer_total) {
            g_source_remove(op->op_timer_total);
            op->op_timer_total = 0;
        }
        remote_op_timeout(op);
    }

    return FALSE;
}

static int
stonith_topology_next(remote_fencing_op_t * op)
{
    stonith_topology_t *tp = NULL;

    if (op->target) {
        /* Queries don't have a target set */
        tp = g_hash_table_lookup(topology, op->target);
    }
    if (tp == NULL) {
        return pcmk_ok;
    }

    set_bit(op->call_options, st_opt_topology);

    do {
        op->level++;

    } while (op->level < ST_LEVEL_MAX && tp->levels[op->level] == NULL);

    if (op->level < ST_LEVEL_MAX) {
        crm_trace("Attempting fencing level %d for %s (%d devices) - %s@%s.%.8s",
                  op->level, op->target, g_list_length(tp->levels[op->level]),
                  op->client_name, op->originator, op->id);
        op->devices = tp->levels[op->level];
        return pcmk_ok;
    }

    crm_notice("All fencing options to fence %s for %s@%s.%.8s failed",
               op->target, op->client_name, op->originator, op->id);
    return -EINVAL;
}

/*!
 * \brief Check to see if this operation is a duplicate of another in flight
 * operation. If so merge this operation into the inflight operation, and mark
 * it as a duplicate.
 */
static void
merge_duplicates(remote_fencing_op_t * op)
{
    GHashTableIter iter;
    remote_fencing_op_t *other = NULL;

    time_t now = time(NULL);

    g_hash_table_iter_init(&iter, remote_op_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&other)) {
        crm_node_t *peer = NULL;

        if (other->state > st_exec) {
            /* Must be in-progress */
            continue;
        } else if (safe_str_neq(op->target, other->target)) {
            /* Must be for the same node */
            continue;
        } else if (safe_str_neq(op->action, other->action)) {
            crm_trace("Must be for the same action: %s vs. ", op->action, other->action);
            continue;
        } else if (safe_str_eq(op->client_name, other->client_name)) {
            crm_trace("Must be for different clients: %s", op->client_name);
            continue;
        } else if (safe_str_eq(other->target, other->originator)) {
            crm_trace("Can't be a suicide operation: %s", other->target);
            continue;
        }

        peer = crm_get_peer(0, other->originator);
        if(fencing_peer_active(peer) == FALSE) {
            crm_notice("Failing stonith action %s for node %s originating from %s@%s.%.8s: Originator is dead",
                       other->action, other->target, other->client_name, other->originator, other->id);
            other->state = st_failed;
            continue;

        } else if(other->total_timeout > 0 && now > (other->total_timeout + other->created)) {
            crm_info("Stonith action %s for node %s originating from %s@%s.%.8s is too old: %d vs. %d + %d",
                     other->action, other->target, other->client_name, other->originator, other->id,
                     now, other->created, other->total_timeout);
            continue;
        }

        /* There is another in-flight request to fence the same host
         * Piggyback on that instead.  If it fails, so do we.
         */
        other->duplicates = g_list_append(other->duplicates, op);
        if (other->total_timeout == 0) {
            crm_trace("Making a best-guess as to the timeout used");
            other->total_timeout = op->total_timeout =
                TIMEOUT_MULTIPLY_FACTOR * get_op_total_timeout(op, NULL, op->base_timeout);
        }
        crm_notice
            ("Merging stonith action %s for node %s originating from client %s.%.8s with identical request from %s@%s.%.8s (%ds)",
             op->action, op->target, op->client_name, op->id, other->client_name, other->originator,
             other->id, other->total_timeout);
        report_timeout_period(op, other->total_timeout);
        op->state = st_duplicate;
    }
}

static uint32_t fencing_active_peers(void)
{
    uint32_t count = 0;
    crm_node_t *entry;
    GHashTableIter gIter;

    g_hash_table_iter_init(&gIter, crm_peer_cache);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        if(fencing_peer_active(entry)) {
            count++;
        }
    }
    return count;
}

int
stonith_manual_ack(xmlNode * msg, remote_fencing_op_t * op)
{
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, msg, LOG_ERR);

    op->state = st_done;
    op->completed = time(NULL);
    op->delegate = strdup("a human");

    crm_notice("Injecting manual confirmation that %s is safely off/down",
               crm_element_value(dev, F_STONITH_TARGET));

    remote_op_done(op, msg, pcmk_ok, FALSE);

    /* Replies are sent via done_cb->stonith_send_async_reply()->do_local_reply() */
    return -EINPROGRESS;
}

/*!
 * \internal
 * \brief Create a new remote stonith op
 * \param client, he local stonith client id that initaited the operation
 * \param request, The request from the client that started the operation
 * \param peer, Is this operation owned by another stonith peer? Operations
 *        owned by other peers are stored on all the stonith nodes, but only the
 *        owner executes the operation.  All the nodes get the results to the operation
 *        once the owner finishes executing it.
 */
void *
create_remote_stonith_op(const char *client, xmlNode * request, gboolean peer)
{
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, request, LOG_TRACE);

    if (remote_op_list == NULL) {
        remote_op_list = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_remote_op);
    }

    /* If this operation is owned by another node, check to make
     * sure we haven't already created this operation. */
    if (peer && dev) {
        const char *op_id = crm_element_value(dev, F_STONITH_REMOTE_OP_ID);

        CRM_CHECK(op_id != NULL, return NULL);

        op = g_hash_table_lookup(remote_op_list, op_id);
        if (op) {
            crm_debug("%s already exists", op_id);
            return op;
        }
    }

    op = calloc(1, sizeof(remote_fencing_op_t));

    crm_element_value_int(request, F_STONITH_TIMEOUT, (int *)&(op->base_timeout));

    if (peer && dev) {
        op->id = crm_element_value_copy(dev, F_STONITH_REMOTE_OP_ID);
    } else {
        op->id = crm_generate_uuid();
    }

    g_hash_table_replace(remote_op_list, op->id, op);
    CRM_LOG_ASSERT(g_hash_table_lookup(remote_op_list, op->id) != NULL);
    crm_trace("Created %s", op->id);

    op->state = st_query;
    op->replies_expected = fencing_active_peers();
    op->action = crm_element_value_copy(dev, F_STONITH_ACTION);
    op->originator = crm_element_value_copy(dev, F_STONITH_ORIGIN);
    op->created = time(NULL);

    if (op->originator == NULL) {
        /* Local or relayed request */
        op->originator = strdup(stonith_our_uname);
    }

    CRM_LOG_ASSERT(client != NULL);
    if (client) {
        op->client_id = strdup(client);
    }

    op->client_name = crm_element_value_copy(request, F_STONITH_CLIENTNAME);

    op->target = crm_element_value_copy(dev, F_STONITH_TARGET);
    op->request = copy_xml(request);    /* TODO: Figure out how to avoid this */
    crm_element_value_int(request, F_STONITH_CALLOPTS, (int *)&(op->call_options));
    crm_element_value_int(request, F_STONITH_CALLID, (int *)&(op->client_callid));

    crm_trace("%s new stonith op: %s - %s of %s for %s",
              (peer
               && dev) ? "Recorded" : "Generated", op->id, op->action, op->target, op->client_name);

    if (op->call_options & st_opt_cs_nodeid) {
        int nodeid = crm_atoi(op->target, NULL);
        crm_node_t *node = crm_get_peer(nodeid, NULL);

        /* Ensure the conversion only happens once */
        op->call_options &= ~st_opt_cs_nodeid;

        if (node && node->uname) {
            free(op->target);
            op->target = strdup(node->uname);
        } else {
            crm_warn("Could not expand nodeid '%s' into a host name (%p)", op->target, node);
        }
    }

    /* check to see if this is a duplicate operation of another in-flight operation */
    merge_duplicates(op);

    return op;
}

remote_fencing_op_t *
initiate_remote_stonith_op(crm_client_t * client, xmlNode * request, gboolean manual_ack)
{
    int query_timeout = 0;
    xmlNode *query = NULL;
    const char *client_id = NULL;
    remote_fencing_op_t *op = NULL;

    if (client) {
        client_id = client->id;
    } else {
        client_id = crm_element_value(request, F_STONITH_CLIENTID);
    }

    CRM_LOG_ASSERT(client_id != NULL);
    op = create_remote_stonith_op(client_id, request, FALSE);
    op->owner = TRUE;
    if (manual_ack) {
        crm_notice("Initiating manual confirmation for %s: %s",
                   op->target, op->id);
        return op;
    }
    
    CRM_CHECK(op->action, return NULL);

    if (stonith_topology_next(op) != pcmk_ok) {
        op->state = st_failed;
    }

    switch (op->state) {
        case st_failed:
            crm_warn("Initiation of remote operation %s for %s: failed (%s)", op->action,
                     op->target, op->id);
            remote_op_done(op, NULL, -EINVAL, FALSE);
            return op;

        case st_duplicate:
            crm_info("Initiating remote operation %s for %s: %s (duplicate)", op->action,
                     op->target, op->id);
            return op;

        default:
            crm_notice("Initiating remote operation %s for %s: %s (%d)", op->action, op->target,
                       op->id, op->state);
    }

    query = stonith_create_op(op->client_callid, op->id, STONITH_OP_QUERY, NULL, 0);

    crm_xml_add(query, F_STONITH_REMOTE_OP_ID, op->id);
    crm_xml_add(query, F_STONITH_TARGET, op->target);
    crm_xml_add(query, F_STONITH_ACTION, op->action);
    crm_xml_add(query, F_STONITH_ORIGIN, op->originator);
    crm_xml_add(query, F_STONITH_CLIENTID, op->client_id);
    crm_xml_add(query, F_STONITH_CLIENTNAME, op->client_name);
    crm_xml_add_int(query, F_STONITH_TIMEOUT, op->base_timeout);

    send_cluster_message(NULL, crm_msg_stonith_ng, query, FALSE);
    free_xml(query);

    query_timeout = op->base_timeout * TIMEOUT_MULTIPLY_FACTOR;
    op->query_timer = g_timeout_add((1000 * query_timeout), remote_op_query_timeout, op);

    return op;
}

static gint
sort_strings(gconstpointer a, gconstpointer b)
{
    return strcmp(a, b);
}

enum find_best_peer_options {
    /*! Skip checking the target peer for capable fencing devices */
    FIND_PEER_SKIP_TARGET = 0x0001,
    /*! Only check the target peer for capable fencing devices */
    FIND_PEER_TARGET_ONLY = 0x0002,
    /*! Skip peers and devices that are not verified */
    FIND_PEER_VERIFIED_ONLY = 0x0004,
};

static st_query_result_t *
find_best_peer(const char *device, remote_fencing_op_t * op, enum find_best_peer_options options)
{
    GListPtr iter = NULL;
    gboolean verified_devices_only = (options & FIND_PEER_VERIFIED_ONLY) ? TRUE : FALSE;

    if (!device && is_set(op->call_options, st_opt_topology)) {
        return NULL;
    }

    for (iter = op->query_results; iter != NULL; iter = iter->next) {
        st_query_result_t *peer = iter->data;

        if ((options & FIND_PEER_SKIP_TARGET) && safe_str_eq(peer->host, op->target)) {
            continue;
        }
        if ((options & FIND_PEER_TARGET_ONLY) && safe_str_neq(peer->host, op->target)) {
            continue;
        }

        if (is_set(op->call_options, st_opt_topology)) {
            /* Do they have the next device of the current fencing level? */
            GListPtr match = NULL;

            if (verified_devices_only && !g_hash_table_lookup(peer->verified_devices, device)) {
                continue;
            }

            match = g_list_find_custom(peer->device_list, device, sort_strings);
            if (match) {
                crm_trace("Removing %s from %s (%d remaining)", (char *)match->data, peer->host,
                          g_list_length(peer->device_list));
                peer->device_list = g_list_remove(peer->device_list, match->data);
                return peer;
            }

        } else if (peer->devices > 0 && peer->tried == FALSE) {
            if (verified_devices_only && !g_hash_table_size(peer->verified_devices)) {
                continue;
            }

            /* No topology: Use the current best peer */
            crm_trace("Simple fencing");
            return peer;
        }
    }

    return NULL;
}

static st_query_result_t *
stonith_choose_peer(remote_fencing_op_t * op)
{
    st_query_result_t *peer = NULL;
    const char *device = NULL;

    do {
        if (op->devices) {
            device = op->devices->data;
            crm_trace("Checking for someone to fence %s with %s", op->target,
                      (char *)op->devices->data);
        } else {
            crm_trace("Checking for someone to fence %s", op->target);
        }

        if ((peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET | FIND_PEER_VERIFIED_ONLY))) {
            return peer;
        } else if ((peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET))) {
            return peer;
        } else if ((peer = find_best_peer(device, op, FIND_PEER_TARGET_ONLY))) {
            return peer;
        }

        /* Try the next fencing level if there is one */
    } while (is_set(op->call_options, st_opt_topology)
             && stonith_topology_next(op) == pcmk_ok);

    if (op->devices) {
        crm_debug("Couldn't find anyone to fence %s with %s", op->target,
                  (char *)op->devices->data);
    } else {
        crm_debug("Couldn't find anyone to fence %s", op->target);
    }

    return NULL;
}

static int
get_device_timeout(st_query_result_t * peer, const char *device, int default_timeout)
{
    gpointer res;

    if (!peer || !device) {
        return default_timeout;
    }

    res = g_hash_table_lookup(peer->custom_action_timeouts, device);

    return res ? GPOINTER_TO_INT(res) : default_timeout;
}

static int
get_peer_timeout(st_query_result_t * peer, int default_timeout)
{
    int total_timeout = 0;

    GListPtr cur = NULL;

    for (cur = peer->device_list; cur; cur = cur->next) {
        total_timeout += get_device_timeout(peer, cur->data, default_timeout);
    }

    return total_timeout ? total_timeout : default_timeout;
}

static int
get_op_total_timeout(remote_fencing_op_t * op, st_query_result_t * chosen_peer, int default_timeout)
{
    stonith_topology_t *tp = g_hash_table_lookup(topology, op->target);
    int total_timeout = 0;

    if (is_set(op->call_options, st_opt_topology) && tp) {
        int i;
        GListPtr device_list = NULL;
        GListPtr iter = NULL;

        /* Yep, this looks scary, nested loops all over the place.
         * Here is what is going on.
         * Loop1: Iterate through fencing levels.
         * Loop2: If a fencing level has devices, loop through each device
         * Loop3: For each device in a fencing level, see what peer owns it
         *        and what that peer has reported the timeout is for the device.
         */
        for (i = 0; i < ST_LEVEL_MAX; i++) {
            if (!tp->levels[i]) {
                continue;
            }
            for (device_list = tp->levels[i]; device_list; device_list = device_list->next) {
                for (iter = op->query_results; iter != NULL; iter = iter->next) {
                    st_query_result_t *peer = iter->data;

                    if (g_list_find_custom(peer->device_list, device_list->data, sort_strings)) {
                        total_timeout +=
                            get_device_timeout(peer, device_list->data, default_timeout);
                        break;
                    }
                }               /* End Loop3: match device with peer that owns device, find device's timeout period */
            }                   /* End Loop2: iterate through devices at a specific level */
        }                       /*End Loop1: iterate through fencing levels */

    } else if (chosen_peer) {
        total_timeout = get_peer_timeout(chosen_peer, default_timeout);
    } else {
        total_timeout = default_timeout;
    }

    return total_timeout ? total_timeout : default_timeout;
}

static void
report_timeout_period(remote_fencing_op_t * op, int op_timeout)
{
    GListPtr iter = NULL;
    xmlNode *update = NULL;
    const char *client_node = NULL;
    const char *client_id = NULL;
    const char *call_id = NULL;

    if (op->call_options & st_opt_sync_call) {
        /* There is no reason to report the timeout for a syncronous call. It
         * is impossible to use the reported timeout to do anything when the client
         * is blocking for the response.  This update is only important for
         * async calls that require a callback to report the results in. */
        return;
    } else if (!op->request) {
        return;
    }

    crm_trace("Reporting timeout for %s.%.8s", op->client_name, op->id);
    client_node = crm_element_value(op->request, F_STONITH_CLIENTNODE);
    call_id = crm_element_value(op->request, F_STONITH_CALLID);
    client_id = crm_element_value(op->request, F_STONITH_CLIENTID);
    if (!client_node || !call_id || !client_id) {
        return;
    }

    if (safe_str_eq(client_node, stonith_our_uname)) {
        /* The client is connected to this node, send the update direclty to them */
        do_stonith_async_timeout_update(client_id, call_id, op_timeout);
        return;
    }

    /* The client is connected to another node, relay this update to them */
    update = stonith_create_op(op->client_callid, op->id, STONITH_OP_TIMEOUT_UPDATE, NULL, 0);
    crm_xml_add(update, F_STONITH_REMOTE_OP_ID, op->id);
    crm_xml_add(update, F_STONITH_CLIENTID, client_id);
    crm_xml_add(update, F_STONITH_CALLID, call_id);
    crm_xml_add_int(update, F_STONITH_TIMEOUT, op_timeout);

    send_cluster_message(crm_get_peer(0, client_node), crm_msg_stonith_ng, update, FALSE);

    free_xml(update);

    for (iter = op->duplicates; iter != NULL; iter = iter->next) {
        remote_fencing_op_t *dup = iter->data;

        crm_trace("Reporting timeout for duplicate %s.%.8s", dup->client_name, dup->id);
        report_timeout_period(iter->data, op_timeout);
    }
}

void
call_remote_stonith(remote_fencing_op_t * op, st_query_result_t * peer)
{
    const char *device = NULL;
    int timeout = op->base_timeout;

    crm_trace("State for %s.%.8s: %s %d", op->target, op->client_name, op->id, op->state);
    if (peer == NULL && !is_set(op->call_options, st_opt_topology)) {
        peer = stonith_choose_peer(op);
    }

    if (!op->op_timer_total) {
        int total_timeout = get_op_total_timeout(op, peer, op->base_timeout);

        op->total_timeout = TIMEOUT_MULTIPLY_FACTOR * total_timeout;
        op->op_timer_total = g_timeout_add(1000 * op->total_timeout, remote_op_timeout, op);
        report_timeout_period(op, op->total_timeout);
        crm_info("Total remote op timeout set to %d for fencing of node %s for %s.%.8s",
                 total_timeout, op->target, op->client_name, op->id);
    }

    if (is_set(op->call_options, st_opt_topology) && op->devices) {
        /* Ignore any preference, they might not have the device we need */
        /* When using topology, the stonith_choose_peer function pops off
         * the peer from the op's query results.  Make sure to calculate
         * the op_timeout before calling this function when topology is in use */
        peer = stonith_choose_peer(op);
        device = op->devices->data;
        timeout = get_device_timeout(peer, device, op->base_timeout);
    }

    if (peer) {
        int timeout_one = 0;
        xmlNode *query = stonith_create_op(op->client_callid, op->id, STONITH_OP_FENCE, NULL, 0);

        crm_xml_add(query, F_STONITH_REMOTE_OP_ID, op->id);
        crm_xml_add(query, F_STONITH_TARGET, op->target);
        crm_xml_add(query, F_STONITH_ACTION, op->action);
        crm_xml_add(query, F_STONITH_ORIGIN, op->originator);
        crm_xml_add(query, F_STONITH_CLIENTID, op->client_id);
        crm_xml_add(query, F_STONITH_CLIENTNAME, op->client_name);
        crm_xml_add_int(query, F_STONITH_TIMEOUT, timeout);

        if (device) {
            timeout_one =
                TIMEOUT_MULTIPLY_FACTOR * get_device_timeout(peer, device, op->base_timeout);
            crm_info("Requesting that %s perform op %s %s with %s for %s (%ds)", peer->host,
                     op->action, op->target, device, op->client_name, timeout_one);
            crm_xml_add(query, F_STONITH_DEVICE, device);
            crm_xml_add(query, F_STONITH_MODE, "slave");

        } else {
            timeout_one = TIMEOUT_MULTIPLY_FACTOR * get_peer_timeout(peer, op->base_timeout);
            crm_info("Requesting that %s perform op %s %s for %s (%ds)",
                     peer->host, op->action, op->target, op->client_name, timeout_one);
            crm_xml_add(query, F_STONITH_MODE, "smart");
        }

        op->state = st_exec;
        if (op->op_timer_one) {
            g_source_remove(op->op_timer_one);
        }
        op->op_timer_one = g_timeout_add((1000 * timeout_one), remote_op_timeout_one, op);

        send_cluster_message(crm_get_peer(0, peer->host), crm_msg_stonith_ng, query, FALSE);
        peer->tried = TRUE;
        free_xml(query);
        return;

    } else if (op->owner == FALSE) {
        crm_err("The termination of %s for %s is not ours to control", op->target, op->client_name);

    } else if (op->query_timer == 0) {
        /* We've exhausted all available peers */
        crm_info("No remaining peers capable of terminating %s for %s (%d)", op->target,
                 op->client_name, op->state);
        CRM_LOG_ASSERT(op->state < st_done);
        remote_op_timeout(op);

    } else if(op->replies >= op->replies_expected || op->replies >= fencing_active_peers()) {
        crm_info("None of the %d peers are capable of terminating %s for %s (%d)",
                 op->replies, op->target, op->client_name, op->state);

        op->state = st_failed;
        remote_op_done(op, NULL, -EHOSTUNREACH, FALSE);

    } else if (device) {
        crm_info("Waiting for additional peers capable of terminating %s with %s for %s.%.8s",
                 op->target, device, op->client_name, op->id);
    } else {
        crm_info("Waiting for additional peers capable of terminating %s for %s%.8s",
                 op->target, op->client_name, op->id);
    }
}

static gint
sort_peers(gconstpointer a, gconstpointer b)
{
    const st_query_result_t *peer_a = a;
    const st_query_result_t *peer_b = a;

    if (peer_a->devices > peer_b->devices) {
        return -1;
    } else if (peer_a->devices > peer_b->devices) {
        return 1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Determine if all the devices in the topology are found or not
 */
static gboolean
all_topology_devices_found(remote_fencing_op_t * op)
{
    GListPtr device = NULL;
    GListPtr iter = NULL;
    GListPtr match = NULL;
    stonith_topology_t *tp = NULL;
    gboolean skip_target = FALSE;
    int i;

    tp = g_hash_table_lookup(topology, op->target);

    if (!tp) {
        return FALSE;
    }
    if (safe_str_eq(op->action, "off") || safe_str_eq(op->action, "reboot")) {
        /* Don't count the devices on the target node if we are killing
         * the target node. */
        skip_target = TRUE;
    }

    for (i = 0; i < ST_LEVEL_MAX; i++) {
        for (device = tp->levels[i]; device; device = device->next) {
            match = FALSE;
            for (iter = op->query_results; iter != NULL; iter = iter->next) {
                st_query_result_t *peer = iter->data;

                if (skip_target && safe_str_eq(peer->host, op->target)) {
                    continue;
                }
                match = g_list_find_custom(peer->device_list, device->data, sort_strings);
            }
            if (!match) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

int
process_remote_stonith_query(xmlNode * msg)
{
    int devices = 0;
    gboolean host_is_target = FALSE;
    const char *id = NULL;
    const char *host = NULL;
    remote_fencing_op_t *op = NULL;
    st_query_result_t *result = NULL;
    uint32_t active = fencing_active_peers();
    xmlNode *dev = get_xpath_object("//@" F_STONITH_REMOTE_OP_ID, msg, LOG_ERR);
    xmlNode *child = NULL;

    CRM_CHECK(dev != NULL, return -EPROTO);

    id = crm_element_value(dev, F_STONITH_REMOTE_OP_ID);
    CRM_CHECK(id != NULL, return -EPROTO);

    dev = get_xpath_object("//@st-available-devices", msg, LOG_ERR);
    CRM_CHECK(dev != NULL, return -EPROTO);
    crm_element_value_int(dev, "st-available-devices", &devices);

    op = g_hash_table_lookup(remote_op_list, id);
    if (op == NULL) {
        crm_debug("Unknown or expired remote op: %s", id);
        return -EOPNOTSUPP;
    }

    op->replies++;
    host = crm_element_value(msg, F_ORIG);
    host_is_target = safe_str_eq(host, op->target);

    if (devices <= 0) {
        /* If we're doing 'known' then we might need to fire anyway */
        crm_trace("Query result from %s (%d devices)", host, devices);
        if(op->state == st_query && (op->replies >= op->replies_expected || op->replies >= active)) {
            crm_info("All queries have arrived, continuing (%d, %d, %d) ", op->replies_expected, active, op->replies);
            call_remote_stonith(op, NULL);
        }
        return pcmk_ok;

    } else if (host_is_target) {
        if (op->call_options & st_opt_allow_suicide) {
            crm_trace("Allowing %s to potentialy fence itself", op->target);
        } else {
            crm_info("Ignoring reply from %s, hosts are not permitted to commit suicide",
                     op->target);
            return pcmk_ok;
        }
    }

    crm_info("Query result %d of %d from %s (%d devices)", op->replies, op->replies_expected, host, devices);
    result = calloc(1, sizeof(st_query_result_t));
    result->host = strdup(host);
    result->devices = devices;
    result->custom_action_timeouts = g_hash_table_new_full(crm_str_hash, g_str_equal, free, NULL);
    result->verified_devices = g_hash_table_new_full(crm_str_hash, g_str_equal, free, NULL);

    for (child = __xml_first_child(dev); child != NULL; child = __xml_next(child)) {
        const char *device = ID(child);
        int action_timeout = 0;
        int verified = 0;

        if (device) {
            result->device_list = g_list_prepend(result->device_list, strdup(device));
            crm_element_value_int(child, F_STONITH_ACTION_TIMEOUT, &action_timeout);
            crm_element_value_int(child, F_STONITH_DEVICE_VERIFIED, &verified);
            if (action_timeout) {
                crm_trace("Peer %s with device %s returned action timeout %d",
                          result->host, device, action_timeout);
                g_hash_table_insert(result->custom_action_timeouts,
                                    strdup(device), GINT_TO_POINTER(action_timeout));
            }
            if (verified) {
                crm_trace("Peer %s has confirmed a verified device %s", result->host, device);
                g_hash_table_insert(result->verified_devices,
                                    strdup(device), GINT_TO_POINTER(verified));
            }
        }
    }

    CRM_CHECK(devices == g_list_length(result->device_list),
              crm_err("Mis-match: Query claimed to have %d devices but %d found", devices,
                      g_list_length(result->device_list)));

    op->query_results = g_list_insert_sorted(op->query_results, result, sort_peers);

    if (is_set(op->call_options, st_opt_topology)) {
        /* If we start the fencing before all the topology results are in,
         * it is possible fencing levels will be skipped because of the missing
         * query results. */
        if (op->state == st_query && all_topology_devices_found(op)) {
            /* All the query results are in for the topology, start the fencing ops. */
            crm_trace("All topology devices found");
            call_remote_stonith(op, result);

        } else if(op->state == st_query && (op->replies >= op->replies_expected || op->replies >= active)) {
            crm_info("All topology queries have arrived, continuing (%d, %d, %d) ", op->replies_expected, active, op->replies);
            call_remote_stonith(op, NULL);
        }

    } else if (op->state == st_query) {
        /* We have a result for a non-topology fencing op that looks promising,
         * go ahead and start fencing before query timeout */
        if (host_is_target == FALSE && g_hash_table_size(result->verified_devices)) {
            /* we have a verified device living on a peer that is not the target */
            crm_trace("Found %d verified devices", g_hash_table_size(result->verified_devices));
            call_remote_stonith(op, result);

        } else if (safe_str_eq(op->action, "on")) {
            crm_trace("Unfencing %s", op->target);
            call_remote_stonith(op, result);

        } else if(op->replies >= op->replies_expected || op->replies >= active) {
            crm_info("All queries have arrived, continuing (%d, %d, %d) ", op->replies_expected, active, op->replies);
            call_remote_stonith(op, NULL);

        } else {
            crm_trace("Waiting for more peer results before launching fencing operation");
        }

    } else if (op->state == st_done) {
        crm_info("Discarding query result from %s (%d devices): Operation is in state %d",
                 result->host, result->devices, op->state);
    }

    return pcmk_ok;
}

int
process_remote_stonith_exec(xmlNode * msg)
{
    int rc = 0;
    const char *id = NULL;
    const char *device = NULL;
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_REMOTE_OP_ID, msg, LOG_ERR);

    CRM_CHECK(dev != NULL, return -EPROTO);

    id = crm_element_value(dev, F_STONITH_REMOTE_OP_ID);
    CRM_CHECK(id != NULL, return -EPROTO);

    dev = get_xpath_object("//@" F_STONITH_RC, msg, LOG_ERR);
    CRM_CHECK(dev != NULL, return -EPROTO);

    crm_element_value_int(dev, F_STONITH_RC, &rc);

    device = crm_element_value(dev, F_STONITH_DEVICE);

    if (remote_op_list) {
        op = g_hash_table_lookup(remote_op_list, id);
    }

    if (op == NULL && rc == pcmk_ok) {
        /* Record successful fencing operations */
        const char *client_id = crm_element_value(dev, F_STONITH_CLIENTID);

        op = create_remote_stonith_op(client_id, dev, TRUE);
    }

    if (op == NULL) {
        /* Could be for an event that began before we started */
        /* TODO: Record the op for later querying */
        crm_info("Unknown or expired remote op: %s", id);
        return -EOPNOTSUPP;
    }

    if (op->devices && device && safe_str_neq(op->devices->data, device)) {
        crm_err
            ("Received outdated reply for device %s (instead of %s) to %s node %s. Operation already timed out at remote level.",
             device, op->devices->data, op->action, op->target);
        return rc;
    }

    if (safe_str_eq(crm_element_value(msg, F_SUBTYPE), "broadcast")) {
        crm_debug("Marking call to %s for %s on behalf of %s@%s.%.8s: %s (%d)",
                  op->action, op->target, op->client_name, op->id, op->originator,
                  pcmk_strerror(rc), rc);
        if (rc == pcmk_ok) {
            op->state = st_done;
        } else {
            op->state = st_failed;
        }
        remote_op_done(op, msg, rc, FALSE);
        return pcmk_ok;
    } else if (safe_str_neq(op->originator, stonith_our_uname)) {
        /* If this isn't a remote level broadcast, and we are not the
         * originator of the operation, we should not be receiving this msg. */
        crm_err
            ("%s received non-broadcast fencing result for operation it does not own (device %s targeting %s)",
             stonith_our_uname, device, op->target);
        return rc;
    }

    if (is_set(op->call_options, st_opt_topology)) {
        const char *device = crm_element_value(msg, F_STONITH_DEVICE);

        crm_notice("Call to %s for %s on behalf of %s@%s: %s (%d)",
                   device, op->target, op->client_name, op->originator,
                   pcmk_strerror(rc), rc);

        /* We own the op, and it is complete. broadcast the result to all nodes
         * and notify our local clients. */
        if (op->state == st_done) {
            remote_op_done(op, msg, rc, FALSE);
            return rc;
        }

        /* An operation completed succesfully but has not yet been marked as done.
         * Continue the topology if more devices exist at the current level, otherwise
         * mark as done. */
        if (rc == pcmk_ok) {
            if (op->devices) {
                /* Success, are there any more? */
                op->devices = op->devices->next;
            }
            /* if no more devices at this fencing level, we are done,
             * else we need to contine with executing the next device in the list */
            if (op->devices == NULL) {
                crm_trace("Marking complex fencing op for %s as complete", op->target);
                op->state = st_done;
                remote_op_done(op, msg, rc, FALSE);
                return rc;
            }
        } else {
            /* This device failed, time to try another topology level. If no other
             * levels are available, mark this operation as failed and report results. */
            if (stonith_topology_next(op) != pcmk_ok) {
                op->state = st_failed;
                remote_op_done(op, msg, rc, FALSE);
                return rc;
            }
        }
    } else if (rc == pcmk_ok && op->devices == NULL) {
        crm_trace("All done for %s", op->target);

        op->state = st_done;
        remote_op_done(op, msg, rc, FALSE);
        return rc;
    }

    /* Retry on failure or execute the rest of the topology */
    crm_trace("Next for %s on behalf of %s@%s (rc was %d)", op->target, op->originator,
              op->client_name, rc);
    call_remote_stonith(op, NULL);
    return rc;
}

int
stonith_fence_history(xmlNode * msg, xmlNode ** output)
{
    int rc = 0;
    const char *target = NULL;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_TARGET, msg, LOG_TRACE);

    if (dev) {
        int options = 0;

        target = crm_element_value(dev, F_STONITH_TARGET);
        crm_element_value_int(msg, F_STONITH_CALLOPTS, &options);
        if (target && (options & st_opt_cs_nodeid)) {
            int nodeid = crm_atoi(target, NULL);
            crm_node_t *node = crm_get_peer(nodeid, NULL);

            if (node) {
                target = node->uname;
            }
        }
    }

    crm_trace("Looking for operations on %s in %p", target, remote_op_list);

    *output = create_xml_node(NULL, F_STONITH_HISTORY_LIST);
    if (remote_op_list) {
        GHashTableIter iter;
        remote_fencing_op_t *op = NULL;

        g_hash_table_iter_init(&iter, remote_op_list);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&op)) {
            xmlNode *entry = NULL;

            if (target && strcmp(op->target, target) != 0) {
                continue;
            }

            rc = 0;
            crm_trace("Attaching op %s", op->id);
            entry = create_xml_node(*output, STONITH_OP_EXEC);
            crm_xml_add(entry, F_STONITH_TARGET, op->target);
            crm_xml_add(entry, F_STONITH_ACTION, op->action);
            crm_xml_add(entry, F_STONITH_ORIGIN, op->originator);
            crm_xml_add(entry, F_STONITH_DELEGATE, op->delegate);
            crm_xml_add_int(entry, F_STONITH_DATE, op->completed);
            crm_xml_add_int(entry, F_STONITH_STATE, op->state);
        }
    }

    return rc;
}

gboolean
stonith_check_fence_tolerance(int tolerance, const char *target, const char *action)
{
    GHashTableIter iter;
    time_t now = time(NULL);
    remote_fencing_op_t *rop = NULL;

    crm_trace("tolerance=%d, remote_op_list=%p", tolerance, remote_op_list);

    if (tolerance <= 0 || !remote_op_list || target == NULL || action == NULL) {
        return FALSE;
    }

    g_hash_table_iter_init(&iter, remote_op_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&rop)) {
        if (strcmp(rop->target, target) != 0) {
            continue;
        } else if (rop->state != st_done) {
            continue;
        } else if (strcmp(rop->action, action) != 0) {
            continue;
        } else if ((rop->completed + tolerance) < now) {
            continue;
        }

        crm_notice("Target %s was fenced (%s) less than %ds ago by %s on behalf of %s",
                   target, action, tolerance, rop->delegate, rop->originator);
        return TRUE;
    }
    return FALSE;
}
