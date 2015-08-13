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
#include <regex.h>

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

/* When one stonithd queries its peers for devices able to handle a fencing
 * request, each peer will reply with a list of such devices available to it.
 * Each reply will be parsed into a st_query_result_t, with each device's
 * information kept in a device_properties_t.
 */

typedef struct device_properties_s {
    /* Whether access to this device has been verified */
    gboolean verified;

    /* The remaining members are indexed by the operation's "phase" */

    /* Whether this device has been executed in each phase */
    gboolean executed[3];
    /* Whether this device is disallowed from executing in each phase */
    gboolean disallowed[3];
    /* Action-specific timeout for each phase */
    int custom_action_timeout[3];
    /* Action-specific maximum random delay for each phase */
    int delay_max[3];
} device_properties_t;

typedef struct st_query_result_s {
    /* Name of peer that sent this result */
    char *host;
    /* Only try peers for non-topology based operations once */
    gboolean tried;
    /* Number of entries in the devices table */
    int ndevices;
    /* Devices available to this host that are capable of fencing the target */
    GHashTable *devices;
} st_query_result_t;

GHashTable *remote_op_list = NULL;
void call_remote_stonith(remote_fencing_op_t * op, st_query_result_t * peer);
static void remote_op_done(remote_fencing_op_t * op, xmlNode * data, int rc, int dup);
extern xmlNode *stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data,
                                  int call_options);

static void report_timeout_period(remote_fencing_op_t * op, int op_timeout);
static int get_op_total_timeout(const remote_fencing_op_t *op,
                                const st_query_result_t *chosen_peer);

static gint
sort_strings(gconstpointer a, gconstpointer b)
{
    return strcmp(a, b);
}

static void
free_remote_query(gpointer data)
{
    if (data) {
        st_query_result_t *query = data;

        crm_trace("Free'ing query result from %s", query->host);
        g_hash_table_destroy(query->devices);
        free(query->host);
        free(query);
    }
}

struct peer_count_data {
    const remote_fencing_op_t *op;
    gboolean verified_only;
    int count;
};

/*!
 * \internal
 * \brief Increment a counter if a device has not been executed yet
 *
 * \param[in] key        Device ID (ignored)
 * \param[in] value      Device properties
 * \param[in] user_data  Peer count data
 */
static void
count_peer_device(gpointer key, gpointer value, gpointer user_data)
{
    device_properties_t *props = (device_properties_t*)value;
    struct peer_count_data *data = user_data;

    if (!props->executed[data->op->phase]
        && (!data->verified_only || props->verified)) {
        ++(data->count);
    }
}

/*!
 * \internal
 * \brief Check the number of available devices in a peer's query results
 *
 * \param[in] op             Operation that results are for
 * \param[in] peer           Peer to count
 * \param[in] verified_only  Whether to count only verified devices
 *
 * \return Number of devices available to peer that were not already executed
 */
static int
count_peer_devices(const remote_fencing_op_t *op, const st_query_result_t *peer,
                   gboolean verified_only)
{
    struct peer_count_data data;

    data.op = op;
    data.verified_only = verified_only;
    data.count = 0;
    if (peer) {
        g_hash_table_foreach(peer->devices, count_peer_device, &data);
    }
    return data.count;
}

/*!
 * \internal
 * \brief Search for a device in a query result
 *
 * \param[in] op      Operation that result is for
 * \param[in] peer    Query result for a peer
 * \param[in] device  Device ID to search for
 *
 * \return Device properties if found, NULL otherwise
 */
static device_properties_t *
find_peer_device(const remote_fencing_op_t *op, const st_query_result_t *peer,
                 const char *device)
{
    device_properties_t *props = g_hash_table_lookup(peer->devices, device);

    return (props && !props->executed[op->phase]
           && !props->disallowed[op->phase])? props : NULL;
}

/*!
 * \internal
 * \brief Find a device in a peer's device list and mark it as executed
 *
 * \param[in]     op                     Operation that peer result is for
 * \param[in,out] peer                   Peer with results to search
 * \param[in]     device                 ID of device to mark as done
 * \param[in]     verified_devices_only  Only consider verified devices
 *
 * \return TRUE if device was found and marked, FALSE otherwise
 */
static gboolean
grab_peer_device(const remote_fencing_op_t *op, st_query_result_t *peer,
                 const char *device, gboolean verified_devices_only)
{
    device_properties_t *props = find_peer_device(op, peer, device);

    if ((props == NULL) || (verified_devices_only && !props->verified)) {
        return FALSE;
    }

    crm_trace("Removing %s from %s (%d remaining)",
              device, peer->host, count_peer_devices(op, peer, FALSE));
    props->executed[op->phase] = TRUE;
    return TRUE;
}

/*
 * \internal
 * \brief Free the list of required devices for a particular phase
 *
 * \param[in,out] op     Operation to modify
 * \param[in]     phase  Phase to modify
 */
static void
free_required_list(remote_fencing_op_t *op, enum st_remap_phase phase)
{
    if (op->required_list[phase]) {
        g_list_free_full(op->required_list[phase], free);
        op->required_list[phase] = NULL;
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
    if (op->devices_list) {
        g_list_free_full(op->devices_list, free);
        op->devices_list = NULL;
    }
    free_required_list(op, st_phase_requested);
    free_required_list(op, st_phase_off);
    free_required_list(op, st_phase_on);
    free(op);
}

/*
 * \internal
 * \brief Return an operation's originally requested action (before any remap)
 *
 * \param[in] op  Operation to check
 *
 * \return Operation's original action
 */
static const char *
op_requested_action(const remote_fencing_op_t *op)
{
    return ((op->phase > st_phase_requested)? "reboot" : op->action);
}

/*
 * \internal
 * \brief Remap a "reboot" operation to the "off" phase
 *
 * \param[in,out] op      Operation to remap
 */
static void
op_phase_off(remote_fencing_op_t *op)
{
    crm_info("Remapping multiple-device reboot of %s (%s) to off",
             op->target, op->id);
    op->phase = st_phase_off;

    /* Happily, "off" and "on" are shorter than "reboot", so we can reuse the
     * memory allocation at each phase.
     */
    strcpy(op->action, "off");
}

/*!
 * \internal
 * \brief Advance a remapped reboot operation to the "on" phase
 *
 * \param[in,out] op  Operation to remap
 */
static void
op_phase_on(remote_fencing_op_t *op)
{
    GListPtr iter = NULL;

    crm_info("Remapped off of %s complete, remapping to on for %s.%.8s",
             op->target, op->client_name, op->id);
    op->phase = st_phase_on;
    strcpy(op->action, "on");

    /* Any devices that are required for "on" will be automatically executed by
     * the cluster when the node next joins, so we skip them here.
     */
    for (iter = op->required_list[op->phase]; iter != NULL; iter = iter->next) {
        GListPtr match = g_list_find_custom(op->devices_list, iter->data,
                                            sort_strings);

        if (match) {
            op->devices_list = g_list_remove(op->devices_list, match->data);
        }
    }

    /* We know this level will succeed, because phase 1 completed successfully
     * and we ignore any errors from phase 2. So we can free the required list,
     * which will keep them from being executed after the device list is done.
     */
    free_required_list(op, op->phase);

    /* Rewind device list pointer */
    op->devices = op->devices_list;
}

/*!
 * \internal
 * \brief Reset a remapped reboot operation
 *
 * \param[in,out] op  Operation to reset
 */
static void
undo_op_remap(remote_fencing_op_t *op)
{
    if (op->phase > 0) {
        crm_info("Undoing remap of reboot of %s for %s.%.8s",
                 op->target, op->client_name, op->id);
        op->phase = st_phase_requested;
        strcpy(op->action, "reboot");
    }
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
    undo_op_remap(op);

    if (op->notify_sent == TRUE) {
        crm_err("Already sent notifications for '%s of %s by %s' (for=%s@%s.%.8s, state=%d): %s",
                op->action, op->target, op->delegate ? op->delegate : "<no-one>",
                op->client_name, op->originator, op->id, op->state, pcmk_strerror(rc));
        goto remote_op_done_cleanup;
    }

    if (!op->delegate && data && rc != -ENODEV && rc != -EHOSTUNREACH) {
        xmlNode *ndata = get_xpath_object("//@" F_STONITH_DELEGATE, data, LOG_TRACE);
        if(ndata) {
            op->delegate = crm_element_value_copy(ndata, F_STONITH_DELEGATE);
        } else { 
            op->delegate = crm_element_value_copy(data, F_ORIG);
        }
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
remote_op_watchdog_done(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_one = 0;

    crm_notice("Remote %s operation on %s for %s.%8s assumed complete",
               op->action, op->target, op->client_name, op->id);
    op->state = st_done;
    remote_op_done(op, NULL, pcmk_ok, FALSE);
    return FALSE;
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

    if (op->phase == st_phase_on) {
        /* A remapped reboot operation timed out in the "on" phase, but the
         * "off" phase completed successfully, so quit trying any further
         * devices, and return success.
         */
        remote_op_done(op, NULL, pcmk_ok, FALSE);
        return FALSE;
    }

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

static gboolean
topology_is_empty(stonith_topology_t *tp)
{
    int i;

    if (tp == NULL) {
        return TRUE;
    }

    for (i = 0; i < ST_LEVEL_MAX; i++) {
        if (tp->levels[i] != NULL) {
            return FALSE;
        }
    }
    return TRUE;
}

/*
 * \internal
 * \brief Add a device to the required list for a particular phase
 *
 * \param[in,out] op      Operation to modify
 * \param[in]     phase   Phase to modify
 * \param[in]     device  Device ID to add
 */
static void
add_required_device(remote_fencing_op_t *op, enum st_remap_phase phase,
                    const char *device)
{
    GListPtr match  = g_list_find_custom(op->required_list[phase], device,
                                         sort_strings);

    if (!match) {
        op->required_list[phase] = g_list_prepend(op->required_list[phase],
                                                  strdup(device));
    }
}

/*
 * \internal
 * \brief Remove a device from the required list for the current phase
 *
 * \param[in,out] op      Operation to modify
 * \param[in]     device  Device ID to remove
 */
static void
remove_required_device(remote_fencing_op_t *op, const char *device)
{
    GListPtr match = g_list_find_custom(op->required_list[op->phase], device,
                                        sort_strings);

    if (match) {
        op->required_list[op->phase] = g_list_remove(op->required_list[op->phase],
                                                     match->data);
    }
}

/* deep copy the device list */
static void
set_op_device_list(remote_fencing_op_t * op, GListPtr devices)
{
    GListPtr lpc = NULL;

    if (op->devices_list) {
        g_list_free_full(op->devices_list, free);
        op->devices_list = NULL;
    }
    for (lpc = devices; lpc != NULL; lpc = lpc->next) {
        op->devices_list = g_list_append(op->devices_list, strdup(lpc->data));
    }
    op->devices = op->devices_list;
}

stonith_topology_t *
find_topology_for_host(const char *host) 
{
    stonith_topology_t *tp = g_hash_table_lookup(topology, host);

    if(tp == NULL) {
        int status = 1;
        regex_t r_patt;
        GHashTableIter tIter;

        crm_trace("Testing %d topologies for a match", g_hash_table_size(topology));
        g_hash_table_iter_init(&tIter, topology);
        while (g_hash_table_iter_next(&tIter, NULL, (gpointer *) & tp)) {

            if (regcomp(&r_patt, tp->node, REG_EXTENDED)) {
                crm_info("Bad regex '%s' for fencing level", tp->node);
            } else {
                status = regexec(&r_patt, host, 0, NULL, 0);
                regfree(&r_patt);
            }

            if (status == 0) {
                crm_notice("Matched %s with %s", host, tp->node);
                break;
            }
            crm_trace("No match for %s with %s", host, tp->node);
            tp = NULL;
        }
    }

    return tp;
}

/*!
 * \internal
 * \brief Set fencing operation's device list to target's next topology level
 *
 * \param[in,out] op  Remote fencing operation to modify
 *
 * \return pcmk_ok if successful, target was not specified (i.e. queries) or
 *         target has no topology, or -EINVAL if no more topology levels to try
 */
static int
stonith_topology_next(remote_fencing_op_t * op)
{
    stonith_topology_t *tp = NULL;

    if (op->target) {
        /* Queries don't have a target set */
        tp = find_topology_for_host(op->target);
    }
    if (topology_is_empty(tp)) {
        return pcmk_ok;
    }

    set_bit(op->call_options, st_opt_topology);

    /* This is a new level, so undo any remapping left over from previous */
    undo_op_remap(op);

    do {
        op->level++;

    } while (op->level < ST_LEVEL_MAX && tp->levels[op->level] == NULL);

    if (op->level < ST_LEVEL_MAX) {
        crm_trace("Attempting fencing level %d for %s (%d devices) - %s@%s.%.8s",
                  op->level, op->target, g_list_length(tp->levels[op->level]),
                  op->client_name, op->originator, op->id);
        set_op_device_list(op, tp->levels[op->level]);

        if (g_list_next(op->devices_list) && safe_str_eq(op->action, "reboot")) {
            /* A reboot has been requested for a topology level with multiple
             * devices. Instead of rebooting the devices sequentially, we will
             * turn them all off, then turn them all on again. (Think about
             * switched power outlets for redundant power supplies.)
             */
            op_phase_off(op);
        }
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
        const char *other_action = op_requested_action(other);

        if (other->state > st_exec) {
            /* Must be in-progress */
            continue;
        } else if (safe_str_neq(op->target, other->target)) {
            /* Must be for the same node */
            continue;
        } else if (safe_str_neq(op->action, other_action)) {
            crm_trace("Must be for the same action: %s vs. %s",
                      op->action, other_action);
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
                TIMEOUT_MULTIPLY_FACTOR * get_op_total_timeout(op, NULL);
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
    int call_options = 0;

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

    crm_element_value_int(request, F_STONITH_TIMEOUT, &(op->base_timeout));

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
    op->delegate = crm_element_value_copy(dev, F_STONITH_DELEGATE); /* May not be set */
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
    crm_element_value_int(request, F_STONITH_CALLOPTS, &call_options);
    op->call_options = call_options;

    crm_element_value_int(request, F_STONITH_CALLID, &(op->client_callid));

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

    query = stonith_create_op(op->client_callid, op->id, STONITH_OP_QUERY,
                              NULL, op->call_options);

    crm_xml_add(query, F_STONITH_REMOTE_OP_ID, op->id);
    crm_xml_add(query, F_STONITH_TARGET, op->target);
    crm_xml_add(query, F_STONITH_ACTION, op_requested_action(op));
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

        crm_trace("Testing result from %s for %s with %d devices: %d %x",
                  peer->host, op->target, peer->ndevices, peer->tried, options);
        if ((options & FIND_PEER_SKIP_TARGET) && safe_str_eq(peer->host, op->target)) {
            continue;
        }
        if ((options & FIND_PEER_TARGET_ONLY) && safe_str_neq(peer->host, op->target)) {
            continue;
        }

        if (is_set(op->call_options, st_opt_topology)) {

            if (grab_peer_device(op, peer, device, verified_devices_only)) {
                return peer;
            }

        } else if ((peer->tried == FALSE)
                   && count_peer_devices(op, peer, verified_devices_only)) {

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
    const char *device = NULL;
    st_query_result_t *peer = NULL;
    uint32_t active = fencing_active_peers();

    do {
        if (op->devices) {
            device = op->devices->data;
            crm_trace("Checking for someone to fence (%s) %s with %s",
                      op->action, op->target, device);
        } else {
            crm_trace("Checking for someone to fence (%s) %s",
                      op->action, op->target);
        }

        /* Best choice is a peer other than the target with verified access */
        peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET|FIND_PEER_VERIFIED_ONLY);
        if (peer) {
            crm_trace("Found verified peer %s for %s", peer->host, device?device:"<any>");
            return peer;
        }

        if(op->query_timer != 0 && op->replies < QB_MIN(op->replies_expected, active)) {
            crm_trace("Waiting before looking for unverified devices to fence %s", op->target);
            return NULL;
        }

        /* If no other peer has verified access, next best is unverified access */
        peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET);
        if (peer) {
            crm_trace("Found best unverified peer %s", peer->host);
            return peer;
        }

        /* If no other peer can do it, last option is self-fencing
         * (which is never allowed for the "on" phase of a remapped reboot)
         */
        if (op->phase != st_phase_on) {
            peer = find_best_peer(device, op, FIND_PEER_TARGET_ONLY);
            if (peer) {
                crm_trace("%s will fence itself", peer->host);
                return peer;
            }
        }

        /* Try the next fencing level if there is one (unless we're in the "on"
         * phase of a remapped "reboot", because we ignore errors in that case)
         */
    } while ((op->phase != st_phase_on)
             && is_set(op->call_options, st_opt_topology)
             && stonith_topology_next(op) == pcmk_ok);

    crm_notice("Couldn't find anyone to fence (%s) %s with %s",
               op->action, op->target, (device? device : "any device"));
    return NULL;
}

static int
get_device_timeout(const remote_fencing_op_t *op, const st_query_result_t *peer,
                   const char *device)
{
    device_properties_t *props;

    if (!peer || !device) {
        return op->base_timeout;
    }

    props = g_hash_table_lookup(peer->devices, device);
    if (!props) {
        return op->base_timeout;
    }

    return (props->custom_action_timeout[op->phase]?
           props->custom_action_timeout[op->phase] : op->base_timeout)
           + props->delay_max[op->phase];
}

struct timeout_data {
    const remote_fencing_op_t *op;
    const st_query_result_t *peer;
    int total_timeout;
};

/*!
 * \internal
 * \brief Add timeout to a total if device has not been executed yet
 *
 * \param[in] key        GHashTable key (device ID)
 * \param[in] value      GHashTable value (device properties)
 * \param[in] user_data  Timeout data
 */
static void
add_device_timeout(gpointer key, gpointer value, gpointer user_data)
{
    const char *device_id = key;
    device_properties_t *props = value;
    struct timeout_data *timeout = user_data;

    if (!props->executed[timeout->op->phase]
        && !props->disallowed[timeout->op->phase]) {
        timeout->total_timeout += get_device_timeout(timeout->op,
                                                     timeout->peer, device_id);
    }
}

static int
get_peer_timeout(const remote_fencing_op_t *op, const st_query_result_t *peer)
{
    struct timeout_data timeout;

    timeout.op = op;
    timeout.peer = peer;
    timeout.total_timeout = 0;

    g_hash_table_foreach(peer->devices, add_device_timeout, &timeout);

    return (timeout.total_timeout? timeout.total_timeout : op->base_timeout);
}

static int
get_op_total_timeout(const remote_fencing_op_t *op,
                     const st_query_result_t *chosen_peer)
{
    int total_timeout = 0;
    stonith_topology_t *tp = find_topology_for_host(op->target);

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
                    const st_query_result_t *peer = iter->data;

                    if (find_peer_device(op, peer, device_list->data)) {
                        total_timeout += get_device_timeout(op, peer,
                                                            device_list->data);
                        break;
                    }
                }               /* End Loop3: match device with peer that owns device, find device's timeout period */
            }                   /* End Loop2: iterate through devices at a specific level */
        }                       /*End Loop1: iterate through fencing levels */

    } else if (chosen_peer) {
        total_timeout = get_peer_timeout(op, chosen_peer);
    } else {
        total_timeout = op->base_timeout;
    }

    return total_timeout ? total_timeout : op->base_timeout;
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

/*
 * \internal
 * \brief Advance an operation to the next device in its topology
 *
 * \param[in,out] op      Operation to advance
 * \param[in]     device  ID of device just completed
 * \param[in]     msg     XML reply that contained device result (if available)
 * \param[in]     rc      Return code of device's execution
 */
static void
advance_op_topology(remote_fencing_op_t *op, const char *device, xmlNode *msg,
                    int rc)
{
    /* Advance to the next device at this topology level, if any */
    if (op->devices) {
        op->devices = op->devices->next;
    }

    /* If this device was required, it's not anymore */
    remove_required_device(op, device);

    /* If there are no more devices at this topology level,
     * run through any required devices not already executed
     */
    if (op->devices == NULL) {
        op->devices = op->required_list[op->phase];
    }

    if ((op->devices == NULL) && (op->phase == st_phase_off)) {
        /* We're done with this level and with required devices, but we had
         * remapped "reboot" to "off", so start over with "on". If any devices
         * need to be turned back on, op->devices will be non-NULL after this.
         */
        op_phase_on(op);
    }

    if (op->devices) {
        /* Necessary devices remain, so execute the next one */
        crm_trace("Next for %s on behalf of %s@%s (rc was %d)",
                  op->target, op->originator, op->client_name, rc);
        call_remote_stonith(op, NULL);
    } else {
        /* We're done with all devices and phases, so finalize operation */
        crm_trace("Marking complex fencing op for %s as complete", op->target);
        op->state = st_done;
        remote_op_done(op, msg, rc, FALSE);
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
        int total_timeout = get_op_total_timeout(op, peer);

        op->total_timeout = TIMEOUT_MULTIPLY_FACTOR * total_timeout;
        op->op_timer_total = g_timeout_add(1000 * op->total_timeout, remote_op_timeout, op);
        report_timeout_period(op, op->total_timeout);
        crm_info("Total remote op timeout set to %d for fencing of node %s for %s.%.8s",
                 total_timeout, op->target, op->client_name, op->id);
    }

    if (is_set(op->call_options, st_opt_topology) && op->devices) {
        /* Ignore any peer preference, they might not have the device we need */
        /* When using topology, stonith_choose_peer() removes the device from
         * further consideration, so be sure to calculate timeout beforehand */
        peer = stonith_choose_peer(op);

        device = op->devices->data;
        timeout = get_device_timeout(op, peer, device);
    }

    if (peer) {
        int timeout_one = 0;
        xmlNode *remote_op = stonith_create_op(op->client_callid, op->id, STONITH_OP_FENCE, NULL, 0);

        crm_xml_add(remote_op, F_STONITH_REMOTE_OP_ID, op->id);
        crm_xml_add(remote_op, F_STONITH_TARGET, op->target);
        crm_xml_add(remote_op, F_STONITH_ACTION, op->action);
        crm_xml_add(remote_op, F_STONITH_ORIGIN, op->originator);
        crm_xml_add(remote_op, F_STONITH_CLIENTID, op->client_id);
        crm_xml_add(remote_op, F_STONITH_CLIENTNAME, op->client_name);
        crm_xml_add_int(remote_op, F_STONITH_TIMEOUT, timeout);
        crm_xml_add_int(remote_op, F_STONITH_CALLOPTS, op->call_options);

        if (device) {
            timeout_one = TIMEOUT_MULTIPLY_FACTOR *
                          get_device_timeout(op, peer, device);
            crm_info("Requesting that %s perform op %s %s with %s for %s (%ds)", peer->host,
                     op->action, op->target, device, op->client_name, timeout_one);
            crm_xml_add(remote_op, F_STONITH_DEVICE, device);
            crm_xml_add(remote_op, F_STONITH_MODE, "slave");

        } else {
            timeout_one = TIMEOUT_MULTIPLY_FACTOR * get_peer_timeout(op, peer);
            crm_info("Requesting that %s perform op %s %s for %s (%ds, %ds)",
                     peer->host, op->action, op->target, op->client_name, timeout_one, stonith_watchdog_timeout_ms);
            crm_xml_add(remote_op, F_STONITH_MODE, "smart");

        }

        op->state = st_exec;
        if (op->op_timer_one) {
            g_source_remove(op->op_timer_one);
        }

        if(stonith_watchdog_timeout_ms > 0 && device && safe_str_eq(device, "watchdog")) {
            crm_notice("Waiting %ds for %s to self-fence (%s) for %s.%.8s (%p)",
                       stonith_watchdog_timeout_ms/1000, op->target,
                       op->action, op->client_name, op->id, device);
            op->op_timer_one = g_timeout_add(stonith_watchdog_timeout_ms, remote_op_watchdog_done, op);

            /* TODO check devices to verify watchdog will be in use */
        } else if(stonith_watchdog_timeout_ms > 0
                  && safe_str_eq(peer->host, op->target)
                  && safe_str_neq(op->action, "on")) {
            crm_notice("Waiting %ds for %s to self-fence (%s) for %s.%.8s (%p)",
                       stonith_watchdog_timeout_ms/1000, op->target,
                       op->action, op->client_name, op->id, device);
            op->op_timer_one = g_timeout_add(stonith_watchdog_timeout_ms, remote_op_watchdog_done, op);

        } else {
            op->op_timer_one = g_timeout_add((1000 * timeout_one), remote_op_timeout_one, op);
        }


        send_cluster_message(crm_get_peer(0, peer->host), crm_msg_stonith_ng, remote_op, FALSE);
        peer->tried = TRUE;
        free_xml(remote_op);
        return;

    } else if (op->phase == st_phase_on) {
        /* A remapped "on" cannot be executed, but the node was already
         * turned off successfully, so ignore the error and continue.
         */
        crm_warn("Ignoring %s 'on' failure (no capable peers) for %s after successful 'off'",
                 device, op->target);
        advance_op_topology(op, device, NULL, pcmk_ok);
        return;

    } else if (op->owner == FALSE) {
        crm_err("Fencing (%s) of %s for %s is not ours to control",
                op->action, op->target, op->client_name);

    } else if (op->query_timer == 0) {
        /* We've exhausted all available peers */
        crm_info("No remaining peers capable of fencing (%s) %s for %s (%d)",
                 op->target, op->action, op->client_name, op->state);
        CRM_LOG_ASSERT(op->state < st_done);
        remote_op_timeout(op);

    } else if(op->replies >= op->replies_expected || op->replies >= fencing_active_peers()) {
        int rc = -EHOSTUNREACH;

        /* if the operation never left the query state,
         * but we have all the expected replies, then no devices
         * are available to execute the fencing operation. */

        if(stonith_watchdog_timeout_ms && (device == NULL || safe_str_eq(device, "watchdog"))) {
            crm_notice("Waiting %ds for %s to self-fence (%s) for %s.%.8s (%p)",
                     stonith_watchdog_timeout_ms/1000, op->target,
                     op->action, op->client_name, op->id, device);

            op->op_timer_one = g_timeout_add(stonith_watchdog_timeout_ms, remote_op_watchdog_done, op);
            return;
        }

        if (op->state == st_query) {
           crm_info("None of the %d peers have devices capable of fencing (%s) %s for %s (%d)",
                   op->replies, op->action, op->target, op->client_name,
                   op->state);

            rc = -ENODEV;
        } else {
           crm_info("None of the %d peers are capable of fencing (%s) %s for %s (%d)",
                   op->replies, op->action, op->target, op->client_name,
                   op->state);
        }

        op->state = st_failed;
        remote_op_done(op, NULL, rc, FALSE);

    } else if (device) {
        crm_info("Waiting for additional peers capable of fencing (%s) %s with %s for %s.%.8s",
                 op->action, op->target, device, op->client_name, op->id);
    } else {
        crm_info("Waiting for additional peers capable of fencing (%s) %s for %s%.8s",
                 op->action, op->target, op->client_name, op->id);
    }
}

/*!
 * \internal
 * \brief Comparison function for sorting query results
 *
 * \param[in] a  GList item to compare
 * \param[in] b  GList item to compare
 *
 * \return Per the glib documentation, "a negative integer if the first value
 *         comes before the second, 0 if they are equal, or a positive integer
 *         if the first value comes after the second."
 */
static gint
sort_peers(gconstpointer a, gconstpointer b)
{
    const st_query_result_t *peer_a = a;
    const st_query_result_t *peer_b = b;

    return (peer_b->ndevices - peer_a->ndevices);
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
    device_properties_t *match = NULL;
    stonith_topology_t *tp = NULL;
    gboolean skip_target = FALSE;
    int i;

    tp = find_topology_for_host(op->target);
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
            match = NULL;
            for (iter = op->query_results; iter && !match; iter = iter->next) {
                st_query_result_t *peer = iter->data;

                if (skip_target && safe_str_eq(peer->host, op->target)) {
                    continue;
                }
                match = find_peer_device(op, peer, device->data);
            }
            if (!match) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
 * \internal
 * \brief Parse action-specific device properties from XML
 *
 * \param[in]     msg     XML element containing the properties
 * \param[in]     peer    Name of peer that sent XML (for logs)
 * \param[in]     device  Device ID (for logs)
 * \param[in]     action  Action the properties relate to (for logs)
 * \param[in]     phase   Phase the properties relate to
 * \param[in,out] props   Device properties to update
 */
static void
parse_action_specific(xmlNode *xml, const char *peer, const char *device,
                      const char *action, remote_fencing_op_t *op,
                      enum st_remap_phase phase, device_properties_t *props)
{
    int required;

    props->custom_action_timeout[phase] = 0;
    crm_element_value_int(xml, F_STONITH_ACTION_TIMEOUT,
                          &props->custom_action_timeout[phase]);
    if (props->custom_action_timeout[phase]) {
        crm_trace("Peer %s with device %s returned %s action timeout %d",
                  peer, device, action, props->custom_action_timeout[phase]);
    }

    props->delay_max[phase] = 0;
    crm_element_value_int(xml, F_STONITH_DELAY_MAX, &props->delay_max[phase]);
    if (props->delay_max[phase]) {
        crm_trace("Peer %s with device %s returned maximum of random delay %d for %s",
                  peer, device, props->delay_max[phase], action);
    }

    required = 0;
    crm_element_value_int(xml, F_STONITH_DEVICE_REQUIRED, &required);
    if (required) {
        /* If the action is marked as required, add the device to the
         * operation's list of required devices for this phase. We use this
         * for unfencing when executing a topology. In phase 0 (requested
         * action) or phase 1 (remapped "off"), required devices get executed
         * regardless of their topology level; in phase 2 (remapped "on"),
         * required devices are not attempted, because the cluster will
         * execute them automatically later.
         */
        crm_trace("Peer %s requires device %s to execute for action %s",
                  peer, device, action);
        add_required_device(op, phase, device);
    }

    /* If a reboot is remapped to off+on, it's possible that a node is allowed
     * to perform one action but not another.
     */
    if (crm_is_true(crm_element_value(xml, F_STONITH_ACTION_DISALLOWED))) {
        props->disallowed[phase] = TRUE;
        crm_trace("Peer %s is disallowed from executing %s for device %s",
                  peer, action, device);
    }
}

/*
 * \internal
 * \brief Parse one device's properties from peer's XML query reply
 *
 * \param[in]     xml       XML node containing device properties
 * \param[in,out] op        Operation that query and reply relate to
 * \param[in,out] result    Peer's results
 * \param[in]     device    ID of device being parsed
 */
static void
add_device_properties(xmlNode *xml, remote_fencing_op_t *op,
                      st_query_result_t *result, const char *device)
{
    xmlNode *child;
    int verified = 0;
    device_properties_t *props = calloc(1, sizeof(device_properties_t));

    /* Add a new entry to this result's devices list */
    CRM_ASSERT(props != NULL);
    g_hash_table_insert(result->devices, strdup(device), props);

    /* Peers with verified (monitored) access will be preferred */
    crm_element_value_int(xml, F_STONITH_DEVICE_VERIFIED, &verified);
    if (verified) {
        crm_trace("Peer %s has confirmed a verified device %s",
                  result->host, device);
        props->verified = TRUE;
    }

    /* Parse action-specific device properties */
    parse_action_specific(xml, result->host, device, op_requested_action(op),
                          op, st_phase_requested, props);
    for (child = __xml_first_child(xml); child != NULL; child = __xml_next(child)) {
        /* Replies for "reboot" operations will include the action-specific
         * values for "off" and "on" in child elements, just in case the reboot
         * winds up getting remapped.
         */
        if (safe_str_eq(ID(child), "off")) {
            parse_action_specific(child, result->host, device, "off",
                                  op, st_phase_off, props);
        } else if (safe_str_eq(ID(child), "on")) {
            parse_action_specific(child, result->host, device, "on",
                                  op, st_phase_on, props);
        }
    }
}

/*
 * \internal
 * \brief Parse a peer's XML query reply and add it to operation's results
 *
 * \param[in,out] op        Operation that query and reply relate to
 * \param[in]     host      Name of peer that sent this reply
 * \param[in]     ndevices  Number of devices expected in reply
 * \param[in]     xml       XML node containing device list
 *
 * \return Newly allocated result structure with parsed reply
 */
static st_query_result_t *
add_result(remote_fencing_op_t *op, const char *host, int ndevices, xmlNode *xml)
{
    st_query_result_t *result = calloc(1, sizeof(st_query_result_t));
    xmlNode *child;

    CRM_CHECK(result != NULL, return NULL);
    result->host = strdup(host);
    result->devices = g_hash_table_new_full(crm_str_hash, g_str_equal, free, free);

    /* Each child element describes one capable device available to the peer */
    for (child = __xml_first_child(xml); child != NULL; child = __xml_next(child)) {
        const char *device = ID(child);

        if (device) {
            add_device_properties(child, op, result, device);
        }
    }

    result->ndevices = g_hash_table_size(result->devices);
    CRM_CHECK(ndevices == result->ndevices,
              crm_err("Query claimed to have %d devices but %d found",
                      ndevices, result->ndevices));

    op->query_results = g_list_insert_sorted(op->query_results, result, sort_peers);
    return result;
}

/*
 * \internal
 * \brief Handle a peer's reply to our fencing query
 *
 * Parse a query result from XML and store it in the remote operation
 * table, and when enough replies have been received, issue a fencing request.
 *
 * \param[in] msg  XML reply received
 *
 * \return pcmk_ok on success, -errno on error
 *
 * \note See initiate_remote_stonith_op() for how the XML query was initially
 *       formed, and stonith_query() for how the peer formed its XML reply.
 */
int
process_remote_stonith_query(xmlNode * msg)
{
    int ndevices = 0;
    gboolean host_is_target = FALSE;
    gboolean have_all_replies = FALSE;
    const char *id = NULL;
    const char *host = NULL;
    remote_fencing_op_t *op = NULL;
    st_query_result_t *result = NULL;
    uint32_t replies_expected;
    xmlNode *dev = get_xpath_object("//@" F_STONITH_REMOTE_OP_ID, msg, LOG_ERR);

    CRM_CHECK(dev != NULL, return -EPROTO);

    id = crm_element_value(dev, F_STONITH_REMOTE_OP_ID);
    CRM_CHECK(id != NULL, return -EPROTO);

    dev = get_xpath_object("//@" F_STONITH_AVAILABLE_DEVICES, msg, LOG_ERR);
    CRM_CHECK(dev != NULL, return -EPROTO);
    crm_element_value_int(dev, F_STONITH_AVAILABLE_DEVICES, &ndevices);

    op = g_hash_table_lookup(remote_op_list, id);
    if (op == NULL) {
        crm_debug("Unknown or expired remote op: %s", id);
        return -EOPNOTSUPP;
    }

    replies_expected = QB_MIN(op->replies_expected, fencing_active_peers());
    if ((++op->replies >= replies_expected) && (op->state == st_query)) {
        have_all_replies = TRUE;
    }
    host = crm_element_value(msg, F_ORIG);
    host_is_target = safe_str_eq(host, op->target);

    crm_info("Query result %d of %d from %s for %s/%s (%d devices) %s",
             op->replies, replies_expected, host,
             op->target, op->action, ndevices, id);
    if (ndevices > 0) {
        result = add_result(op, host, ndevices, dev);
    }

    if (is_set(op->call_options, st_opt_topology)) {
        /* If we start the fencing before all the topology results are in,
         * it is possible fencing levels will be skipped because of the missing
         * query results. */
        if (op->state == st_query && all_topology_devices_found(op)) {
            /* All the query results are in for the topology, start the fencing ops. */
            crm_trace("All topology devices found");
            call_remote_stonith(op, result);

        } else if (have_all_replies) {
            crm_info("All topology query replies have arrived, continuing (%d expected/%d received) ",
                     replies_expected, op->replies);
            call_remote_stonith(op, NULL);
        }

    } else if (op->state == st_query) {
        int nverified = count_peer_devices(op, result, TRUE);

        /* We have a result for a non-topology fencing op that looks promising,
         * go ahead and start fencing before query timeout */
        if (result && (host_is_target == FALSE) && nverified) {
            /* we have a verified device living on a peer that is not the target */
            crm_trace("Found %d verified devices", nverified);
            call_remote_stonith(op, result);

        } else if (have_all_replies) {
            crm_info("All query replies have arrived, continuing (%d expected/%d received) ",
                     replies_expected, op->replies);
            call_remote_stonith(op, NULL);

        } else {
            crm_trace("Waiting for more peer results before launching fencing operation");
        }

    } else if (result && (op->state == st_done)) {
        crm_info("Discarding query result from %s (%d devices): Operation is in state %d",
                 result->host, result->ndevices, op->state);
    }

    return pcmk_ok;
}

/*
 * \internal
 * \brief Handle a peer's reply to a fencing request
 *
 * Parse a fencing reply from XML, and either finalize the operation
 * or attempt another device as appropriate.
 *
 * \param[in] msg  XML reply received
 *
 * \return pcmk_ok on success, -errno on error
 */
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

        if ((op->phase == 2) && (rc != pcmk_ok)) {
            /* A remapped "on" failed, but the node was already turned off
             * successfully, so ignore the error and continue.
             */
            crm_warn("Ignoring %s 'on' failure (exit code %d) for %s after successful 'off'",
                     device, rc, op->target);
            rc = pcmk_ok;
        }

        if (rc == pcmk_ok) {
            /* An operation completed successfully. Try another device if
             * necessary, otherwise mark the operation as done. */
            advance_op_topology(op, device, msg, rc);
            return rc;
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
    } else if (rc == -ETIME && op->devices == NULL) {
        /* If the operation timed out don't bother retrying other peers. */
        op->state = st_failed;
        remote_op_done(op, msg, rc, FALSE);
        return rc;
    } else {
        /* fall-through and attempt other fencing action using another peer */
    }

    /* Retry on failure */
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
            crm_xml_add(entry, F_STONITH_CLIENTNAME, op->client_name);
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
        /* We don't have to worry about remapped reboots here
         * because if state is done, any remapping has been undone
         */
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
