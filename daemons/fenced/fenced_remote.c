/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdbool.h>
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

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/util.h>
#include <pacemaker-fenced.h>

#define TIMEOUT_MULTIPLY_FACTOR 1.2

/* When one fencer queries its peers for devices able to handle a fencing
 * request, each peer will reply with a list of such devices available to it.
 * Each reply will be parsed into a peer_device_info_t, with each device's
 * information kept in a device_properties_t.
 */

typedef struct {
    /* Whether access to this device has been verified */
    gboolean verified;

    /* The remaining members are indexed by the operation's "phase" */

    /* Whether this device has been executed in each phase */
    gboolean executed[st_phase_max];
    /* Whether this device is disallowed from executing in each phase */
    gboolean disallowed[st_phase_max];
    /* Action-specific timeout for each phase */
    int custom_action_timeout[st_phase_max];
    /* Action-specific maximum random delay for each phase */
    int delay_max[st_phase_max];
    /* Action-specific base delay for each phase */
    int delay_base[st_phase_max];
    /* Group of enum st_device_flags */
    uint32_t device_support_flags;
} device_properties_t;

typedef struct {
    /* Name of peer that sent this result */
    char *host;
    /* Only try peers for non-topology based operations once */
    gboolean tried;
    /* Number of entries in the devices table */
    int ndevices;
    /* Devices available to this host that are capable of fencing the target */
    GHashTable *devices;
} peer_device_info_t;

GHashTable *stonith_remote_op_list = NULL;

extern xmlNode *stonith_create_op(int call_id, const char *token, const char *op, xmlNode * data,
                                  int call_options);

static void request_peer_fencing(remote_fencing_op_t *op,
                                 peer_device_info_t *peer);
static void finalize_op(remote_fencing_op_t *op, xmlNode *data, bool dup);
static void report_timeout_period(remote_fencing_op_t * op, int op_timeout);
static int get_op_total_timeout(const remote_fencing_op_t *op,
                                const peer_device_info_t *chosen_peer);

static gint
sort_strings(gconstpointer a, gconstpointer b)
{
    return strcmp(a, b);
}

static void
free_remote_query(gpointer data)
{
    if (data != NULL) {
        peer_device_info_t *peer = data;

        g_hash_table_destroy(peer->devices);
        free(peer->host);
        free(peer);
    }
}

void
free_stonith_remote_op_list(void)
{
    if (stonith_remote_op_list != NULL) {
        g_hash_table_destroy(stonith_remote_op_list);
        stonith_remote_op_list = NULL;
    }
}

struct peer_count_data {
    const remote_fencing_op_t *op;
    gboolean verified_only;
    uint32_t support_action_only;
    int count;
};

/*!
 * \internal
 * \brief Increment a counter if a device has not been executed yet
 *
 * \param[in]     key        Device ID (ignored)
 * \param[in]     value      Device properties
 * \param[in,out] user_data  Peer count data
 */
static void
count_peer_device(gpointer key, gpointer value, gpointer user_data)
{
    device_properties_t *props = (device_properties_t*)value;
    struct peer_count_data *data = user_data;

    if (!props->executed[data->op->phase]
        && (!data->verified_only || props->verified)
        && ((data->support_action_only == fenced_df_none)
            || pcmk__is_set(props->device_support_flags,
                           data->support_action_only))) {
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
 * \param[in] support_action_only Whether to count only devices that support action
 *
 * \return Number of devices available to peer that were not already executed
 */
static int
count_peer_devices(const remote_fencing_op_t *op,
                   const peer_device_info_t *peer, gboolean verified_only, uint32_t support_on_action_only)
{
    struct peer_count_data data;

    data.op = op;
    data.verified_only = verified_only;
    data.support_action_only = support_on_action_only;
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
find_peer_device(const remote_fencing_op_t *op, const peer_device_info_t *peer,
                 const char *device, uint32_t support_action_only)
{
    device_properties_t *props = g_hash_table_lookup(peer->devices, device);

    if (props == NULL) {
        return NULL;
    }
    if ((support_action_only != fenced_df_none)
        && !pcmk__is_set(props->device_support_flags, support_action_only)) {
        return NULL;
    }
    if (props->executed[op->phase] || props->disallowed[op->phase]) {
        return NULL;
    }
    return props;
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
grab_peer_device(const remote_fencing_op_t *op, peer_device_info_t *peer,
                 const char *device, gboolean verified_devices_only)
{
    device_properties_t *props = find_peer_device(op, peer, device,
                                                  fenced_support_flag(op->action));

    if ((props == NULL) || (verified_devices_only && !props->verified)) {
        return FALSE;
    }

    pcmk__trace("Removing %s from %s (%d remaining)", device, peer->host,
                count_peer_devices(op, peer, FALSE, fenced_df_none));
    props->executed[op->phase] = TRUE;
    return TRUE;
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

    pcmk__log_xml_debug(op->request, "Destroying");

    clear_remote_op_timers(op);

    free(op->id);
    free(op->action);
    free(op->delegate);
    free(op->target);
    free(op->client_id);
    free(op->client_name);
    free(op->originator);

    if (op->query_results) {
        g_list_free_full(op->query_results, free_remote_query);
    }
    if (op->request) {
        pcmk__xml_free(op->request);
        op->request = NULL;
    }
    if (op->devices_list) {
        g_list_free_full(op->devices_list, free);
        op->devices_list = NULL;
    }
    g_list_free_full(op->automatic_list, free);
    g_list_free(op->duplicates);

    pcmk__reset_result(&op->result);
    free(op);
}

void
init_stonith_remote_op_hash_table(GHashTable **table)
{
    if (*table == NULL) {
        *table = pcmk__strkey_table(NULL, free_remote_op);
    }
}

/*!
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
    return ((op->phase > st_phase_requested)? PCMK_ACTION_REBOOT : op->action);
}

/*!
 * \internal
 * \brief Remap a "reboot" operation to the "off" phase
 *
 * \param[in,out] op      Operation to remap
 */
static void
op_phase_off(remote_fencing_op_t *op)
{
    pcmk__info("Remapping multiple-device reboot targeting %s to 'off' "
               QB_XS " id=%.8s",
               op->target, op->id);
    op->phase = st_phase_off;

    /* Happily, "off" and "on" are shorter than "reboot", so we can reuse the
     * memory allocation at each phase.
     */
    strcpy(op->action, PCMK_ACTION_OFF);
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
    GList *iter = NULL;

    pcmk__info("Remapped 'off' targeting %s complete, remapping to 'on' for "
               "%s " QB_XS " id=%.8s",
               op->target, op->client_name, op->id);
    op->phase = st_phase_on;
    strcpy(op->action, PCMK_ACTION_ON);

    /* Skip devices with automatic unfencing, because the cluster will handle it
     * when the node rejoins.
     */
    for (iter = op->automatic_list; iter != NULL; iter = iter->next) {
        GList *match = g_list_find_custom(op->devices_list, iter->data,
                                            sort_strings);

        if (match) {
            op->devices_list = g_list_remove(op->devices_list, match->data);
        }
    }
    g_list_free_full(op->automatic_list, free);
    op->automatic_list = NULL;

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
        pcmk__info("Undoing remap of reboot targeting %s for %s "
                   QB_XS " id=%.8s",
                   op->target, op->client_name, op->id);
        op->phase = st_phase_requested;
        strcpy(op->action, PCMK_ACTION_REBOOT);
    }
}

/*!
 * \internal
 * \brief Create notification data XML for a fencing operation result
 *
 * \param[in,out] parent  Parent XML element for newly created element
 * \param[in]     op      Fencer operation that completed
 *
 * \return Newly created XML to add as notification data
 * \note The caller is responsible for freeing the result.
 */
static xmlNode *
fencing_result2xml(xmlNode *parent, const remote_fencing_op_t *op)
{
    xmlNode *notify_data = pcmk__xe_create(parent, PCMK__XE_ST_NOTIFY_FENCE);

    pcmk__xe_set_int(notify_data, PCMK_XA_STATE, op->state);
    pcmk__xe_set(notify_data, PCMK__XA_ST_TARGET, op->target);
    pcmk__xe_set(notify_data, PCMK__XA_ST_DEVICE_ACTION, op->action);
    pcmk__xe_set(notify_data, PCMK__XA_ST_DELEGATE, op->delegate);
    pcmk__xe_set(notify_data, PCMK__XA_ST_REMOTE_OP, op->id);
    pcmk__xe_set(notify_data, PCMK__XA_ST_ORIGIN, op->originator);
    pcmk__xe_set(notify_data, PCMK__XA_ST_CLIENTID, op->client_id);
    pcmk__xe_set(notify_data, PCMK__XA_ST_CLIENTNAME, op->client_name);

    return notify_data;
}

/*!
 * \internal
 * \brief Broadcast a fence result notification to all CPG peers
 *
 * \param[in] op         Fencer operation that completed
 * \param[in] op_merged  Whether this operation is a duplicate of another
 */
void
fenced_broadcast_op_result(const remote_fencing_op_t *op, bool op_merged)
{
    static int count = 0;
    xmlNode *bcast = pcmk__xe_create(NULL, PCMK__XE_ST_REPLY);
    xmlNode *wrapper = NULL;
    xmlNode *notify_data = NULL;

    count++;
    pcmk__trace("Broadcasting result to peers");
    pcmk__xe_set(bcast, PCMK__XA_T, PCMK__VALUE_ST_NOTIFY);
    pcmk__xe_set(bcast, PCMK__XA_SUBT, PCMK__VALUE_BROADCAST);
    pcmk__xe_set(bcast, PCMK__XA_ST_OP, STONITH_OP_NOTIFY);
    pcmk__xe_set_int(bcast, PCMK_XA_COUNT, count);

    if (op_merged) {
        pcmk__xe_set_bool(bcast, PCMK__XA_ST_OP_MERGED, true);
    }

    wrapper = pcmk__xe_create(bcast, PCMK__XE_ST_CALLDATA);
    notify_data = fencing_result2xml(wrapper, op);
    stonith__xe_set_result(notify_data, &op->result);

    pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, bcast);
    pcmk__xml_free(bcast);
}

/*!
 * \internal
 * \brief Reply to a local request originator and notify all subscribed clients
 *
 * \param[in,out] op    Fencer operation that completed
 * \param[in,out] data  Top-level XML to add notification to
 */
static void
handle_local_reply_and_notify(remote_fencing_op_t *op, xmlNode *data)
{
    xmlNode *notify_data = NULL;
    xmlNode *reply = NULL;
    pcmk__client_t *client = NULL;

    if (op->notify_sent == TRUE) {
        /* nothing to do */
        return;
    }

    /* Do notification with a clean data object */
    pcmk__xe_set_int(data, PCMK_XA_STATE, op->state);
    pcmk__xe_set(data, PCMK__XA_ST_TARGET, op->target);
    pcmk__xe_set(data, PCMK__XA_ST_OP, op->action);

    reply = fenced_construct_reply(op->request, data, &op->result);
    pcmk__xe_set(reply, PCMK__XA_ST_DELEGATE, op->delegate);

    /* Send fencing OP reply to local client that initiated fencing */
    client = pcmk__find_client_by_id(op->client_id);
    if (client == NULL) {
        pcmk__trace("Skipping reply to %s: no longer a client", op->client_id);
    } else {
        do_local_reply(reply, client, op->call_options);
    }

    /* bcast to all local clients that the fencing operation happend */
    notify_data = fencing_result2xml(NULL, op);
    fenced_send_notification(PCMK__VALUE_ST_NOTIFY_FENCE, &op->result,
                             notify_data);
    pcmk__xml_free(notify_data);
    fenced_send_notification(PCMK__VALUE_ST_NOTIFY_HISTORY, NULL, NULL);

    /* mark this op as having notify's already sent */
    op->notify_sent = TRUE;
    pcmk__xml_free(reply);
}

/*!
 * \internal
 * \brief Finalize all duplicates of a given fencer operation
 *
 * \param[in,out] op    Fencer operation that completed
 * \param[in,out] data  Top-level XML to add notification to
 */
static void
finalize_op_duplicates(remote_fencing_op_t *op, xmlNode *data)
{
    for (GList *iter = op->duplicates; iter != NULL; iter = iter->next) {
        remote_fencing_op_t *other = iter->data;

        if (other->state == st_duplicate) {
            other->state = op->state;
            pcmk__debug("Performing duplicate notification for %s@%s: %s "
                        QB_XS " id=%.8s",
                        other->client_name, other->originator,
                        pcmk_exec_status_str(op->result.execution_status),
                        other->id);
            pcmk__copy_result(&op->result, &other->result);
            finalize_op(other, data, true);

        } else {
            // Possible if (for example) it timed out already
            pcmk__err("Skipping duplicate notification for %s@%s "
                      QB_XS " state=%s id=%.8s",
                      other->client_name, other->originator,
                      stonith__op_state_text(other->state), other->id);
        }
    }
}

static char *
delegate_from_xml(xmlNode *xml)
{
    xmlNode *match = pcmk__xpath_find_one(xml->doc,
                                          "//*[@" PCMK__XA_ST_DELEGATE "]",
                                          PCMK__LOG_NEVER);

    if (match == NULL) {
        return pcmk__xe_get_copy(xml, PCMK__XA_SRC);
    } else {
        return pcmk__xe_get_copy(match, PCMK__XA_ST_DELEGATE);
    }
}

/*!
 * \internal
 * \brief Finalize a peer fencing operation
 *
 * Clean up after a fencing operation completes. This function has two code
 * paths: the executioner uses it to broadcast the result to CPG peers, and then
 * each peer (including the executioner) uses it to process that broadcast and
 * notify its IPC clients of the result.
 *
 * \param[in,out] op      Fencer operation that completed
 * \param[in,out] data    If not NULL, XML reply of last delegated operation
 * \param[in]     dup     Whether this operation is a duplicate of another
 *                        (in which case, do not broadcast the result)
 *
 *  \note The operation result should be set before calling this function.
 */
static void
finalize_op(remote_fencing_op_t *op, xmlNode *data, bool dup)
{
    int level = LOG_ERR;
    const char *subt = NULL;
    xmlNode *local_data = NULL;
    gboolean op_merged = FALSE;

    CRM_CHECK((op != NULL), return);

    // This is a no-op if timers have already been cleared
    clear_remote_op_timers(op);

    if (op->notify_sent) {
        // Most likely, this is a timed-out action that eventually completed
        pcmk__notice("Operation '%s'%s%s by %s for %s@%s%s: Result arrived too "
                     "late " QB_XS " id=%.8s",
                     op->action, (op->target? " targeting " : ""),
                     pcmk__s(op->target, ""),
                     pcmk__s(op->delegate, "unknown node"), op->client_name,
                     op->originator, (op_merged? " (merged)" : ""), op->id);
        return;
    }

    set_fencing_completed(op);
    undo_op_remap(op);

    if (data == NULL) {
        data = pcmk__xe_create(NULL, "remote-op");
        local_data = data;

    } else if (op->delegate == NULL) {
        switch (op->result.execution_status) {
            case PCMK_EXEC_NO_FENCE_DEVICE:
                break;

            case PCMK_EXEC_INVALID:
                if (op->result.exit_status != CRM_EX_EXPIRED) {
                    op->delegate = delegate_from_xml(data);
                }
                break;

            default:
                op->delegate = delegate_from_xml(data);
                break;
        }
    }

    if (dup || (pcmk__xe_get(data, PCMK__XA_ST_OP_MERGED) != NULL)) {
        op_merged = true;
    }

    /* Tell everyone the operation is done, we will continue
     * with doing the local notifications once we receive
     * the broadcast back. */
    subt = pcmk__xe_get(data, PCMK__XA_SUBT);
    if (!dup && !pcmk__str_eq(subt, PCMK__VALUE_BROADCAST, pcmk__str_none)) {
        /* Defer notification until the bcast message arrives */
        fenced_broadcast_op_result(op, op_merged);
        pcmk__xml_free(local_data);
        return;
    }

    if (pcmk__result_ok(&op->result) || dup
        || !pcmk__str_eq(op->originator, fenced_get_local_node(),
                         pcmk__str_casei)) {
        level = LOG_NOTICE;
    }
    do_crm_log(level, "Operation '%s'%s%s by %s for %s@%s%s: %s (%s%s%s) "
               QB_XS " id=%.8s", op->action, (op->target? " targeting " : ""),
               (op->target? op->target : ""),
               (op->delegate? op->delegate : "unknown node"),
               op->client_name, op->originator,
               (op_merged? " (merged)" : ""),
               crm_exit_str(op->result.exit_status),
               pcmk_exec_status_str(op->result.execution_status),
               ((op->result.exit_reason == NULL)? "" : ": "),
               ((op->result.exit_reason == NULL)? "" : op->result.exit_reason),
               op->id);

    handle_local_reply_and_notify(op, data);

    if (!dup) {
        finalize_op_duplicates(op, data);
    }

    /* Free non-essential parts of the record
     * Keep the record around so we can query the history
     */
    if (op->query_results) {
        g_list_free_full(op->query_results, free_remote_query);
        op->query_results = NULL;
    }
    if (op->request) {
        pcmk__xml_free(op->request);
        op->request = NULL;
    }

    pcmk__xml_free(local_data);
}

/*!
 * \internal
 * \brief Finalize a watchdog fencer op after the waiting time expires
 *
 * \param[in,out] userdata  Fencer operation that completed
 *
 * \return G_SOURCE_REMOVE (which tells glib not to restart timer)
 */
static gboolean
remote_op_watchdog_done(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_one = 0;

    pcmk__notice("Self-fencing (%s) by %s for %s assumed complete "
                 QB_XS " id=%.8s",
                 op->action, op->target, op->client_name, op->id);
    op->state = st_done;
    pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    finalize_op(op, NULL, false);
    return G_SOURCE_REMOVE;
}

static gboolean
remote_op_timeout_one(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_one = 0;

    pcmk__notice("Peer's '%s' action targeting %s for client %s timed out "
                 QB_XS " id=%.8s",
                 op->action, op->target, op->client_name, op->id);
    pcmk__set_result(&op->result, CRM_EX_ERROR, PCMK_EXEC_TIMEOUT,
                     "Peer did not return fence result within timeout");

    // The requested delay has been applied for the first device
    if (op->client_delay > 0) {
        op->client_delay = 0;
        pcmk__trace("Try another device for '%s' action targeting %s for "
                    "client %s without delay " QB_XS " id=%.8s",
                    op->action, op->target, op->client_name, op->id);
    }

    // Try another device, if appropriate
    request_peer_fencing(op, NULL);
    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief Finalize a remote fencer operation that timed out
 *
 * \param[in,out] op      Fencer operation that timed out
 * \param[in]     reason  Readable description of what step timed out
 */
static void
finalize_timed_out_op(remote_fencing_op_t *op, const char *reason)
{
    pcmk__debug("Action '%s' targeting %s for client %s timed out "
                QB_XS " id=%.8s",
                op->action, op->target, op->client_name, op->id);

    if (op->phase == st_phase_on) {
        /* A remapped reboot operation timed out in the "on" phase, but the
         * "off" phase completed successfully, so quit trying any further
         * devices, and return success.
         */
        op->state = st_done;
        pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        op->state = st_failed;
        pcmk__set_result(&op->result, CRM_EX_ERROR, PCMK_EXEC_TIMEOUT, reason);
    }
    finalize_op(op, NULL, false);
}

/*!
 * \internal
 * \brief Finalize a remote fencer operation that timed out
 *
 * \param[in,out] userdata  Fencer operation that timed out
 *
 * \return G_SOURCE_REMOVE (which tells glib not to restart timer)
 */
static gboolean
remote_op_timeout(gpointer userdata)
{
    remote_fencing_op_t *op = userdata;

    op->op_timer_total = 0;

    if (op->state == st_done) {
        pcmk__debug("Action '%s' targeting %s for client %s already completed "
                    QB_XS " id=%.8s",
                    op->action, op->target, op->client_name, op->id);
    } else {
        finalize_timed_out_op(userdata, "Fencing did not complete within a "
                                        "total timeout based on the "
                                        "configured timeout and retries for "
                                        "any devices attempted");
    }
    return G_SOURCE_REMOVE;
}

static gboolean
remote_op_query_timeout(gpointer data)
{
    remote_fencing_op_t *op = data;

    op->query_timer = 0;

    if (op->state == st_done) {
        pcmk__debug("Operation %.8s targeting %s already completed", op->id,
                    op->target);

    } else if (op->state == st_exec) {
        pcmk__debug("Operation %.8s targeting %s already in progress", op->id,
                    op->target);

    } else if (op->query_results) {
        // Query succeeded, so attempt the actual fencing
        pcmk__debug("Query %.8s targeting %s complete (state=%s)",
                    op->id, op->target, stonith__op_state_text(op->state));
        request_peer_fencing(op, NULL);

    } else {
        pcmk__debug("Query %.8s targeting %s timed out (state=%s)",
                    op->id, op->target, stonith__op_state_text(op->state));
        finalize_timed_out_op(op,
                              "No capable peers replied to device query within "
                              "timeout");
    }

    return G_SOURCE_REMOVE;
}

static gboolean
topology_is_empty(stonith_topology_t *tp)
{
    int i;

    if (tp == NULL) {
        return TRUE;
    }

    for (i = 0; i < ST__LEVEL_COUNT; i++) {
        if (tp->levels[i] != NULL) {
            return FALSE;
        }
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Add a device to an operation's automatic unfencing list
 *
 * \param[in,out] op      Operation to modify
 * \param[in]     device  Device ID to add
 */
static void
add_required_device(remote_fencing_op_t *op, const char *device)
{
    GList *match  = g_list_find_custom(op->automatic_list, device,
                                         sort_strings);

    if (!match) {
        op->automatic_list = g_list_prepend(op->automatic_list,
                                            pcmk__str_copy(device));
    }
}

/*!
 * \internal
 * \brief Remove a device from the automatic unfencing list
 *
 * \param[in,out] op      Operation to modify
 * \param[in]     device  Device ID to remove
 */
static void
remove_required_device(remote_fencing_op_t *op, const char *device)
{
    GList *match = g_list_find_custom(op->automatic_list, device,
                                        sort_strings);

    if (match) {
        op->automatic_list = g_list_remove(op->automatic_list, match->data);
    }
}

/* deep copy the device list */
static void
set_op_device_list(remote_fencing_op_t * op, GList *devices)
{
    GList *lpc = NULL;

    if (op->devices_list) {
        g_list_free_full(op->devices_list, free);
        op->devices_list = NULL;
    }
    for (lpc = devices; lpc != NULL; lpc = lpc->next) {
        const char *device = lpc->data;

        op->devices_list = g_list_append(op->devices_list,
                                         pcmk__str_copy(device));
    }
    op->devices = op->devices_list;
}

/*!
 * \internal
 * \brief Check whether a node matches a topology target
 *
 * \param[in] tp    Topology table entry to check
 * \param[in] node  Name of node to check
 *
 * \return TRUE if node matches topology target
 */
static gboolean
topology_matches(const stonith_topology_t *tp, const char *node)
{
    regex_t r_patt;

    CRM_CHECK(node && tp && tp->target, return FALSE);
    switch (tp->kind) {
        case fenced_target_by_attribute:
            /* This level targets by attribute, so tp->target is a NAME=VALUE pair
             * of a permanent attribute applied to targeted nodes. The test below
             * relies on the locally cached copy of the CIB, so if fencing needs to
             * be done before the initial CIB is received or after a malformed CIB
             * is received, then the topology will be unable to be used.
             */
            if (node_has_attr(node, tp->target_attribute, tp->target_value)) {
                pcmk__notice("Matched %s with %s by attribute", node,
                             tp->target);
                return TRUE;
            }
            break;

        case fenced_target_by_pattern:
            /* This level targets node names matching a pattern, so tp->target
             * (and tp->target_pattern) is a regular expression.
             */
            if (regcomp(&r_patt, tp->target_pattern, REG_EXTENDED|REG_NOSUB)) {
                pcmk__info("Bad regex '%s' for fencing level", tp->target);
            } else {
                int status = regexec(&r_patt, node, 0, NULL, 0);

                regfree(&r_patt);
                if (status == 0) {
                    pcmk__notice("Matched %s with %s by name", node,
                                 tp->target);
                    return TRUE;
                }
            }
            break;

        case fenced_target_by_name:
            pcmk__trace("Testing %s against %s", node, tp->target);
            return pcmk__str_eq(tp->target, node, pcmk__str_casei);

        default:
            break;
    }
    pcmk__trace("No match for %s with %s", node, tp->target);
    return FALSE;
}

stonith_topology_t *
find_topology_for_host(const char *host) 
{
    GHashTableIter tIter;
    stonith_topology_t *tp = g_hash_table_lookup(topology, host);

    if(tp != NULL) {
        pcmk__trace("Found %s for %s in %u entries", tp->target, host,
                    g_hash_table_size(topology));
        return tp;
    }

    g_hash_table_iter_init(&tIter, topology);
    while (g_hash_table_iter_next(&tIter, NULL, (gpointer *) & tp)) {
        if (topology_matches(tp, host)) {
            pcmk__trace("Found %s for %s in %u entries", tp->target, host,
                        g_hash_table_size(topology));
            return tp;
        }
    }

    pcmk__trace("No matches for %s in %u topology entries", host,
                g_hash_table_size(topology));
    return NULL;
}

/*!
 * \internal
 * \brief Set fencing operation's device list to target's next topology level
 *
 * \param[in,out] op        Remote fencing operation to modify
 * \param[in]     empty_ok  If true, an operation without a target (i.e.
 *                          queries) or a target without a topology will get a
 *                          pcmk_rc_ok return value instead of ENODEV
 *
 * \return Standard Pacemaker return value
 */
static int
advance_topology_level(remote_fencing_op_t *op, bool empty_ok)
{
    stonith_topology_t *tp = NULL;

    if (op->target) {
        tp = find_topology_for_host(op->target);
    }
    if (topology_is_empty(tp)) {
        return empty_ok? pcmk_rc_ok : ENODEV;
    }

    pcmk__assert(tp->levels != NULL);

    stonith__set_call_options(op->call_options, op->id, st_opt_topology);

    /* This is a new level, so undo any remapping left over from previous */
    undo_op_remap(op);

    do {
        op->level++;

    } while (op->level < ST__LEVEL_COUNT && tp->levels[op->level] == NULL);

    if (op->level < ST__LEVEL_COUNT) {
        pcmk__trace("Attempting fencing level %d targeting %s (%d devices) for "
                    "client %s@%s (id=%.8s)",
                    op->level, op->target, g_list_length(tp->levels[op->level]),
                    op->client_name, op->originator, op->id);
        set_op_device_list(op, tp->levels[op->level]);

        // The requested delay has been applied for the first fencing level
        if ((op->level > 1) && (op->client_delay > 0)) {
            op->client_delay = 0;
        }

        if ((g_list_next(op->devices_list) != NULL)
            && pcmk__str_eq(op->action, PCMK_ACTION_REBOOT, pcmk__str_none)) {
            /* A reboot has been requested for a topology level with multiple
             * devices. Instead of rebooting the devices sequentially, we will
             * turn them all off, then turn them all on again. (Think about
             * switched power outlets for redundant power supplies.)
             */
            op_phase_off(op);
        }
        return pcmk_rc_ok;
    }

    pcmk__info("All %sfencing options targeting %s for client %s@%s failed "
               QB_XS " id=%.8s",
               ((fencing_watchdog_timeout_ms > 0) ? "non-watchdog " : ""),
               op->target, op->client_name, op->originator, op->id);
    return ENODEV;
}

/*!
 * \internal
 * \brief If fencing operation is a duplicate, merge it into the other one
 *
 * \param[in,out] op  Fencing operation to check
 */
static void
merge_duplicates(remote_fencing_op_t *op)
{
    GHashTableIter iter;
    remote_fencing_op_t *other = NULL;

    time_t now = time(NULL);

    g_hash_table_iter_init(&iter, stonith_remote_op_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&other)) {
        const char *other_action = op_requested_action(other);
        pcmk__node_status_t *node = NULL;

        if (!strcmp(op->id, other->id)) {
            continue; // Don't compare against self
        }
        if (other->state > st_exec) {
            pcmk__trace("%.8s not duplicate of %.8s: not in progress", op->id,
                        other->id);
            continue;
        }
        if (!pcmk__str_eq(op->target, other->target, pcmk__str_casei)) {
            pcmk__trace("%.8s not duplicate of %.8s: node %s vs. %s", op->id,
                        other->id, op->target, other->target);
            continue;
        }
        if (!pcmk__str_eq(op->action, other_action, pcmk__str_none)) {
            pcmk__trace("%.8s not duplicate of %.8s: action %s vs. %s", op->id,
                        other->id, op->action, other_action);
            continue;
        }
        if (pcmk__str_eq(op->client_name, other->client_name, pcmk__str_casei)) {
            pcmk__trace("%.8s not duplicate of %.8s: same client %s", op->id,
                        other->id, op->client_name);
            continue;
        }
        if (pcmk__str_eq(other->target, other->originator, pcmk__str_casei)) {
            pcmk__trace("%.8s not duplicate of %.8s: self-fencing for %s",
                        op->id, other->id, other->target);
            continue;
        }

        node = pcmk__get_node(0, other->originator, NULL,
                              pcmk__node_search_cluster_member);

        if (!fencing_peer_active(node)) {
            pcmk__notice("Failing action '%s' targeting %s originating from "
                         "client %s@%s: Originator is dead " QB_XS " id=%.8s",
                         other->action, other->target, other->client_name,
                         other->originator, other->id);
            pcmk__trace("%.8s not duplicate of %.8s: originator dead", op->id,
                        other->id);
            other->state = st_failed;
            continue;
        }
        if ((other->total_timeout > 0)
            && (now > (other->total_timeout + other->created))) {
            pcmk__trace("%.8s not duplicate of %.8s: old (%lld vs. %lld + %ds)",
                        op->id, other->id, (long long) now,
                        (long long) other->created, other->total_timeout);
            continue;
        }

        /* There is another in-flight request to fence the same host
         * Piggyback on that instead.  If it fails, so do we.
         */
        other->duplicates = g_list_append(other->duplicates, op);
        if (other->total_timeout == 0) {
            other->total_timeout = op->total_timeout =
                TIMEOUT_MULTIPLY_FACTOR * get_op_total_timeout(op, NULL);
            pcmk__trace("Best guess as to timeout used for %.8s: %ds",
                        other->id, other->total_timeout);
        }
        pcmk__notice("Merging fencing action '%s' targeting %s originating "
                     "from client %s with identical request from %s@%s "
                     QB_XS " original=%.8s duplicate=%.8s total_timeout=%ds",
                     op->action, op->target, op->client_name,
                     other->client_name, other->originator,
                     op->id, other->id, other->total_timeout);
        report_timeout_period(op, other->total_timeout);
        op->state = st_duplicate;
    }
}

static uint32_t fencing_active_peers(void)
{
    uint32_t count = 0;
    pcmk__node_status_t *entry = NULL;
    GHashTableIter gIter;

    g_hash_table_iter_init(&gIter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        if(fencing_peer_active(entry)) {
            count++;
        }
    }
    return count;
}

/*!
 * \internal
 * \brief Process a manual confirmation of a pending fence action
 *
 * \param[in]     client  IPC client that sent confirmation
 * \param[in,out] msg     Request XML with manual confirmation
 *
 * \return Standard Pacemaker return code
 */
int
fenced_handle_manual_confirmation(const pcmk__client_t *client, xmlNode *msg)
{
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = pcmk__xpath_find_one(msg->doc,
                                        "//*[@" PCMK__XA_ST_TARGET "]",
                                        LOG_ERR);

    CRM_CHECK(dev != NULL, return EPROTO);

    pcmk__notice("Received manual confirmation that %s has been fenced",
                 pcmk__s(pcmk__xe_get(dev, PCMK__XA_ST_TARGET),
                         "unknown target"));
    op = initiate_remote_stonith_op(client, msg, TRUE);
    if (op == NULL) {
        return EPROTO;
    }
    op->state = st_done;
    op->delegate = pcmk__str_copy("a human");

    // For the fencer's purposes, the fencing operation is done
    pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    finalize_op(op, msg, false);

    /* For the requester's purposes, the operation is still pending. The
     * actual result will be sent asynchronously via the operation's done_cb().
     */
    return EINPROGRESS;
}

/*!
 * \internal
 * \brief Create a new remote stonith operation
 *
 * \param[in] client   ID of local stonith client that initiated the operation
 * \param[in] request  The request from the client that started the operation
 * \param[in] peer     TRUE if this operation is owned by another stonith peer
 *                     (an operation owned by one peer is stored on all peers,
 *                     but only the owner executes it; all nodes get the results
 *                     once the owner finishes execution)
 */
void *
create_remote_stonith_op(const char *client, xmlNode *request, gboolean peer)
{
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = pcmk__xpath_find_one(request->doc,
                                        "//*[@" PCMK__XA_ST_TARGET "]",
                                        PCMK__LOG_NEVER);
    int rc = pcmk_rc_ok;
    const char *operation = NULL;

    CRM_CHECK(dev != NULL, return NULL);

    init_stonith_remote_op_hash_table(&stonith_remote_op_list);

    /* If this operation is owned by another node, check to make
     * sure we haven't already created this operation. */
    if (peer) {
        const char *op_id = pcmk__xe_get(dev, PCMK__XA_ST_REMOTE_OP);

        CRM_CHECK(op_id != NULL, return NULL);

        op = g_hash_table_lookup(stonith_remote_op_list, op_id);
        if (op) {
            pcmk__debug("Reusing existing remote fencing op %.8s for %s", op_id,
                        pcmk__s(client, "unknown client"));
            return op;
        }
    }

    op = pcmk__assert_alloc(1, sizeof(remote_fencing_op_t));

    pcmk__xe_get_int(request, PCMK__XA_ST_TIMEOUT, &(op->base_timeout));

    // Value -1 means disable any static/random fencing delays
    pcmk__xe_get_int(request, PCMK__XA_ST_DELAY, &(op->client_delay));

    if (peer) {
        op->id = pcmk__xe_get_copy(dev, PCMK__XA_ST_REMOTE_OP);
    } else {
        op->id = pcmk__generate_uuid();
    }

    g_hash_table_replace(stonith_remote_op_list, op->id, op);

    op->state = st_query;
    op->replies_expected = fencing_active_peers();
    op->action = pcmk__xe_get_copy(dev, PCMK__XA_ST_DEVICE_ACTION);

    /* The node initiating the stonith operation. If an operation is relayed,
     * this is the last node the operation lands on. When in standalone mode,
     * origin is the ID of the client that originated the operation.
     *
     * Or may be the name of the function that created the operation.
     */
    op->originator = pcmk__xe_get_copy(dev, PCMK__XA_ST_ORIGIN);
    if (op->originator == NULL) {
        /* Local or relayed request */
        op->originator = pcmk__str_copy(fenced_get_local_node());
    }

    // Delegate may not be set
    op->delegate = pcmk__xe_get_copy(dev, PCMK__XA_ST_DELEGATE);
    op->created = time(NULL);

    CRM_LOG_ASSERT(client != NULL);
    op->client_id = pcmk__str_copy(client);

    /* For a RELAY operation, set fenced on the client. */
    operation = pcmk__xe_get(request, PCMK__XA_ST_OP);

    if (pcmk__str_eq(operation, STONITH_OP_RELAY, pcmk__str_none)) {
        op->client_name = pcmk__assert_asprintf("%s.%lu", crm_system_name,
                                                (unsigned long) getpid());
    } else {
        op->client_name = pcmk__xe_get_copy(request, PCMK__XA_ST_CLIENTNAME);
    }

    op->target = pcmk__xe_get_copy(dev, PCMK__XA_ST_TARGET);

    // @TODO Figure out how to avoid copying XML here
    op->request = pcmk__xml_copy(NULL, request);

    rc = pcmk__xe_get_flags(request, PCMK__XA_ST_CALLOPT, &(op->call_options),
                            0U);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request %s: %s", op->id,
                   pcmk_rc_str(rc));
    }

    pcmk__xe_get_int(request, PCMK__XA_ST_CALLID, &(op->client_callid));

    pcmk__trace("%s new fencing op %s ('%s' targeting %s for client %s, base "
                "timeout %ds, %u %s expected)",
                (peer? "Recorded" : "Generated"), op->id, op->action,
                op->target, op->client_name, op->base_timeout,
                op->replies_expected,
                pcmk__plural_alt(op->replies_expected, "reply", "replies"));

    if (op->call_options & st_opt_cs_nodeid) {
        int nodeid;
        pcmk__node_status_t *node = NULL;

        pcmk__scan_min_int(op->target, &nodeid, 0);
        node = pcmk__search_node_caches(nodeid, NULL, NULL,
                                        pcmk__node_search_any
                                        |pcmk__node_search_cluster_cib);

        /* Ensure the conversion only happens once */
        stonith__clear_call_options(op->call_options, op->id, st_opt_cs_nodeid);

        if ((node != NULL) && (node->name != NULL)) {
            pcmk__str_update(&(op->target), node->name);

        } else {
            pcmk__warn("Could not expand nodeid '%s' into a host name",
                       op->target);
        }
    }

    /* check to see if this is a duplicate operation of another in-flight operation */
    merge_duplicates(op);

    if (op->state != st_duplicate) {
        /* kick history readers */
        fenced_send_notification(PCMK__VALUE_ST_NOTIFY_HISTORY, NULL, NULL);
    }

    /* safe to trim as long as that doesn't touch pending ops */
    stonith_fence_history_trim();

    return op;
}

/*!
 * \internal
 * \brief Create a peer fencing operation from a request, and initiate it
 *
 * \param[in] client     IPC client that made request (NULL to get from request)
 * \param[in] request    Request XML
 * \param[in] manual_ack Whether this is a manual action confirmation
 *
 * \return Newly created operation on success, otherwise NULL
 */
remote_fencing_op_t *
initiate_remote_stonith_op(const pcmk__client_t *client, xmlNode *request,
                           gboolean manual_ack)
{
    int query_timeout = 0;
    xmlNode *query = NULL;
    const char *client_id = NULL;
    remote_fencing_op_t *op = NULL;
    const char *relay_op_id = NULL;
    const char *operation = NULL;

    if (client) {
        client_id = client->id;
    } else {
        client_id = pcmk__xe_get(request, PCMK__XA_ST_CLIENTID);
    }

    CRM_LOG_ASSERT(client_id != NULL);
    op = create_remote_stonith_op(client_id, request, FALSE);
    op->owner = TRUE;
    if (manual_ack) {
        return op;
    }

    CRM_CHECK(op->action, return NULL);

    if (advance_topology_level(op, true) != pcmk_rc_ok) {
        op->state = st_failed;
    }

    switch (op->state) {
        case st_failed:
            // advance_topology_level() exhausted levels
            pcmk__set_result(&op->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                             "All topology levels failed");
            pcmk__warn("Could not request peer fencing (%s) targeting %s "
                       QB_XS " id=%.8s",
                       op->action, op->target, op->id);
            finalize_op(op, NULL, false);
            return op;

        case st_duplicate:
            pcmk__info("Requesting peer fencing (%s) targeting %s (duplicate) "
                       QB_XS " id=%.8s",
                       op->action, op->target, op->id);
            return op;

        default:
            pcmk__notice("Requesting peer fencing (%s) targeting %s "
                         QB_XS " id=%.8s state=%s base_timeout=%ds",
                         op->action, op->target, op->id,
                         stonith__op_state_text(op->state), op->base_timeout);
    }

    query = stonith_create_op(op->client_callid, op->id, STONITH_OP_QUERY,
                              NULL, op->call_options);

    pcmk__xe_set(query, PCMK__XA_ST_REMOTE_OP, op->id);
    pcmk__xe_set(query, PCMK__XA_ST_TARGET, op->target);
    pcmk__xe_set(query, PCMK__XA_ST_DEVICE_ACTION, op_requested_action(op));
    pcmk__xe_set(query, PCMK__XA_ST_ORIGIN, op->originator);
    pcmk__xe_set(query, PCMK__XA_ST_CLIENTID, op->client_id);
    pcmk__xe_set(query, PCMK__XA_ST_CLIENTNAME, op->client_name);
    pcmk__xe_set_int(query, PCMK__XA_ST_TIMEOUT, op->base_timeout);

    /* In case of RELAY operation, RELAY information is added to the query to delete the original operation of RELAY. */
    operation = pcmk__xe_get(request, PCMK__XA_ST_OP);
    if (pcmk__str_eq(operation, STONITH_OP_RELAY, pcmk__str_none)) {
        relay_op_id = pcmk__xe_get(request, PCMK__XA_ST_REMOTE_OP);
        if (relay_op_id) {
            pcmk__xe_set(query, PCMK__XA_ST_REMOTE_OP_RELAY, relay_op_id);
        }
    }

    pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, query);
    pcmk__xml_free(query);

    query_timeout = op->base_timeout * TIMEOUT_MULTIPLY_FACTOR;
    op->query_timer = pcmk__create_timer((1000 * query_timeout), remote_op_query_timeout, op);

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

static bool
is_watchdog_fencing(const remote_fencing_op_t *op, const char *device)
{
    return ((fencing_watchdog_timeout_ms > 0)
            // Only an explicit mismatch is considered not a watchdog fencing.
            && pcmk__str_eq(device, STONITH_WATCHDOG_ID, pcmk__str_null_matches)
            && pcmk__is_fencing_action(op->action)
            && node_does_watchdog_fencing(op->target));
}

static peer_device_info_t *
find_best_peer(const char *device, remote_fencing_op_t * op, enum find_best_peer_options options)
{
    GList *iter = NULL;
    gboolean verified_devices_only = (options & FIND_PEER_VERIFIED_ONLY) ? TRUE : FALSE;

    if ((device == NULL) && pcmk__is_set(op->call_options, st_opt_topology)) {
        return NULL;
    }

    for (iter = op->query_results; iter != NULL; iter = iter->next) {
        peer_device_info_t *peer = iter->data;

        pcmk__trace("Testing result from %s targeting %s with %d device%s: %d "
                    "%x",
                    peer->host, op->target, peer->ndevices,
                    pcmk__plural_s(peer->ndevices), peer->tried, options);
        if ((options & FIND_PEER_SKIP_TARGET) && pcmk__str_eq(peer->host, op->target, pcmk__str_casei)) {
            continue;
        }
        if ((options & FIND_PEER_TARGET_ONLY) && !pcmk__str_eq(peer->host, op->target, pcmk__str_casei)) {
            continue;
        }

        if (pcmk__is_set(op->call_options, st_opt_topology)) {
            if (grab_peer_device(op, peer, device, verified_devices_only)) {
                return peer;
            }

        } else if (!peer->tried
                   && count_peer_devices(op, peer, verified_devices_only,
                                         fenced_support_flag(op->action))) {
            /* No topology: Use the current best peer */
            pcmk__trace("Simple fencing");
            return peer;
        }
    }

    return NULL;
}

static peer_device_info_t *
stonith_choose_peer(remote_fencing_op_t * op)
{
    const char *device = NULL;
    peer_device_info_t *peer = NULL;
    uint32_t active = fencing_active_peers();

    do {
        if (op->devices) {
            device = op->devices->data;
            pcmk__trace("Checking for someone to fence (%s) %s using %s",
                        op->action, op->target, device);
        } else {
            pcmk__trace("Checking for someone to fence (%s) %s", op->action,
                        op->target);
        }

        /* Best choice is a peer other than the target with verified access */
        peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET|FIND_PEER_VERIFIED_ONLY);
        if (peer) {
            pcmk__trace("Found verified peer %s for %s", peer->host,
                        pcmk__s(device, "<any>"));
            return peer;
        }

        if(op->query_timer != 0 && op->replies < QB_MIN(op->replies_expected, active)) {
            pcmk__trace("Waiting before looking for unverified devices to "
                        "fence %s",
                        op->target);
            return NULL;
        }

        /* If no other peer has verified access, next best is unverified access */
        peer = find_best_peer(device, op, FIND_PEER_SKIP_TARGET);
        if (peer) {
            pcmk__trace("Found best unverified peer %s", peer->host);
            return peer;
        }

        /* If no other peer can do it, last option is self-fencing
         * (which is never allowed for the "on" phase of a remapped reboot)
         */
        if (op->phase != st_phase_on) {
            peer = find_best_peer(device, op, FIND_PEER_TARGET_ONLY);
            if (peer) {
                pcmk__trace("%s will fence itself", peer->host);
                return peer;
            }
        }

        /* Try the next fencing level if there is one (unless we're in the "on"
         * phase of a remapped "reboot", because we ignore errors in that case)
         */
    } while ((op->phase != st_phase_on)
             && pcmk__is_set(op->call_options, st_opt_topology)
             && (advance_topology_level(op, false) == pcmk_rc_ok));

    /* With a simple watchdog fencing configuration without a topology,
     * "device" is NULL here. Consider it should be done with watchdog fencing.
     */
    if (is_watchdog_fencing(op, device)) {
        pcmk__info("Couldn't contact watchdog-fencing target-node (%s)",
                   op->target);
        /* check_watchdog_fencing_and_wait will log additional info */
    } else {
        pcmk__notice("Couldn't find anyone to fence (%s) %s using %s",
                     op->action, op->target, pcmk__s(device, "any device"));
    }
    return NULL;
}

static int
valid_fencing_timeout(int specified_timeout, bool action_specific,
                      const remote_fencing_op_t *op, const char *device)
{
    int timeout = specified_timeout;

    if (!is_watchdog_fencing(op, device)) {
        return timeout;
    }

    timeout = (int) QB_MIN(QB_MAX(specified_timeout,
                                  pcmk__timeout_ms2s(fencing_watchdog_timeout_ms)),
                           INT_MAX);

    if (timeout > specified_timeout) {
        if (action_specific) {
            pcmk__warn("pcmk_%s_timeout %ds for %s is too short (must be >= "
                       PCMK_OPT_FENCING_WATCHDOG_TIMEOUT " %ds), using %ds "
                       "instead",
                       op->action, specified_timeout,
                       pcmk__s(device, "watchdog"), timeout, timeout);

        } else {
            pcmk__warn("Fencing timeout %ds is too short (must be >= "
                       PCMK_OPT_FENCING_WATCHDOG_TIMEOUT " %ds), using %ds "
                       "instead",
                       specified_timeout, timeout, timeout);
        }
    }

    return timeout;
}

static int
get_device_timeout(const remote_fencing_op_t *op,
                   const peer_device_info_t *peer, const char *device,
                   bool with_delay)
{
    int timeout = valid_fencing_timeout(op->base_timeout, false, op, device);
    device_properties_t *props;

    if (!peer || !device) {
        return timeout;
    }

    props = g_hash_table_lookup(peer->devices, device);
    if (!props) {
        return timeout;
    }

    if (props->custom_action_timeout[op->phase]) {
        timeout = valid_fencing_timeout(props->custom_action_timeout[op->phase],
                                        true, op, device);
    }

    // op->client_delay < 0 means disable any static/random fencing delays
    if (with_delay && (op->client_delay >= 0)) {
        // delay_base is eventually limited by delay_max
        timeout += (props->delay_max[op->phase] > 0 ?
                    props->delay_max[op->phase] : props->delay_base[op->phase]);
    }

    return timeout;
}

struct timeout_data {
    const remote_fencing_op_t *op;
    const peer_device_info_t *peer;
    int total_timeout;
};

/*!
 * \internal
 * \brief Add timeout to a total if device has not been executed yet
 *
 * \param[in]     key        GHashTable key (device ID)
 * \param[in]     value      GHashTable value (device properties)
 * \param[in,out] user_data  Timeout data
 */
static void
add_device_timeout(gpointer key, gpointer value, gpointer user_data)
{
    const char *device_id = key;
    device_properties_t *props = value;
    struct timeout_data *timeout = user_data;

    if (!props->executed[timeout->op->phase]
        && !props->disallowed[timeout->op->phase]) {
        timeout->total_timeout += get_device_timeout(timeout->op, timeout->peer,
                                                     device_id, true);
    }
}

static int
get_peer_timeout(const remote_fencing_op_t *op, const peer_device_info_t *peer)
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
                     const peer_device_info_t *chosen_peer)
{
    long long total_timeout = 0;
    stonith_topology_t *tp = find_topology_for_host(op->target);

    if (pcmk__is_set(op->call_options, st_opt_topology) && (tp != NULL)) {
        int i;
        GList *device_list = NULL;
        GList *iter = NULL;
        GList *auto_list = NULL;

        if (pcmk__str_eq(op->action, PCMK_ACTION_ON, pcmk__str_none)
            && (op->automatic_list != NULL)) {
            auto_list = g_list_copy(op->automatic_list);
        }

        /* Yep, this looks scary, nested loops all over the place.
         * Here is what is going on.
         * Loop1: Iterate through fencing levels.
         * Loop2: If a fencing level has devices, loop through each device
         * Loop3: For each device in a fencing level, see what peer owns it
         *        and what that peer has reported the timeout is for the device.
         */
        for (i = 0; i < ST__LEVEL_COUNT; i++) {
            if (!tp->levels[i]) {
                continue;
            }
            for (device_list = tp->levels[i]; device_list; device_list = device_list->next) {
                bool found = false;

                for (iter = op->query_results; iter != NULL; iter = iter->next) {
                    const peer_device_info_t *peer = iter->data;

                    if (auto_list) {
                        GList *match = g_list_find_custom(auto_list, device_list->data,
                                        sort_strings);
                        if (match) {
                            auto_list = g_list_remove(auto_list, match->data);
                        }
                    }

                    if (find_peer_device(op, peer, device_list->data,
                                         fenced_support_flag(op->action))) {
                        total_timeout += get_device_timeout(op, peer,
                                                            device_list->data,
                                                            true);
                        found = true;
                        break;
                    }
                }               /* End Loop3: match device with peer that owns device, find device's timeout period */

                /* in case of watchdog-device we add the timeout to the budget
                   if didn't get a reply
                 */
                if (!found && is_watchdog_fencing(op, device_list->data)) {
                    total_timeout += pcmk__timeout_ms2s(fencing_watchdog_timeout_ms);
                }
            }                   /* End Loop2: iterate through devices at a specific level */
        }                       /*End Loop1: iterate through fencing levels */

        //Add only exists automatic_list device timeout
        if (auto_list) {
            for (iter = auto_list; iter != NULL; iter = iter->next) {
                GList *iter2 = NULL;

                for (iter2 = op->query_results; iter2 != NULL; iter2 = iter2->next) {
                    peer_device_info_t *peer = iter2->data;
                    if (find_peer_device(op, peer, iter->data,
                                         fenced_df_supports_on)) {
                        total_timeout += get_device_timeout(op, peer,
                                                            iter->data, true);
                        break;
                    }
                }
            }
        }

        g_list_free(auto_list);

    } else if (chosen_peer) {
        total_timeout = get_peer_timeout(op, chosen_peer);

    } else {
        total_timeout = valid_fencing_timeout(op->base_timeout, false, op,
                                              NULL);
    }

    if (total_timeout <= 0) {
        total_timeout = op->base_timeout;
    }

    /* Take any requested fencing delay into account to prevent it from eating
     * up the total timeout.
     */
    if (op->client_delay > 0) {
        total_timeout += op->client_delay;
    }
    return (int) QB_MIN(total_timeout, INT_MAX);
}

static void
report_timeout_period(remote_fencing_op_t * op, int op_timeout)
{
    GList *iter = NULL;
    xmlNode *update = NULL;
    const char *client_node = NULL;
    const char *client_id = NULL;
    const char *call_id = NULL;

    if (op->call_options & st_opt_sync_call) {
        /* There is no reason to report the timeout for a synchronous call. It
         * is impossible to use the reported timeout to do anything when the client
         * is blocking for the response.  This update is only important for
         * async calls that require a callback to report the results in. */
        return;
    } else if (!op->request) {
        return;
    }

    pcmk__trace("Reporting timeout for %s (id=%.8s)", op->client_name, op->id);
    client_node = pcmk__xe_get(op->request, PCMK__XA_ST_CLIENTNODE);
    call_id = pcmk__xe_get(op->request, PCMK__XA_ST_CALLID);
    client_id = pcmk__xe_get(op->request, PCMK__XA_ST_CLIENTID);
    if (!client_node || !call_id || !client_id) {
        return;
    }

    if (pcmk__str_eq(client_node, fenced_get_local_node(), pcmk__str_casei)) {
        // Client is connected to this node, so send update directly to them
        do_stonith_async_timeout_update(client_id, call_id, op_timeout);
        return;
    }

    /* The client is connected to another node, relay this update to them */
    update = stonith_create_op(op->client_callid, op->id, STONITH_OP_TIMEOUT_UPDATE, NULL, 0);
    pcmk__xe_set(update, PCMK__XA_ST_REMOTE_OP, op->id);
    pcmk__xe_set(update, PCMK__XA_ST_CLIENTID, client_id);
    pcmk__xe_set(update, PCMK__XA_ST_CALLID, call_id);
    pcmk__xe_set_int(update, PCMK__XA_ST_TIMEOUT, op_timeout);

    pcmk__cluster_send_message(pcmk__get_node(0, client_node, NULL,
                                              pcmk__node_search_cluster_member),
                               pcmk_ipc_fenced, update);

    pcmk__xml_free(update);

    for (iter = op->duplicates; iter != NULL; iter = iter->next) {
        remote_fencing_op_t *dup = iter->data;

        pcmk__trace("Reporting timeout for duplicate %.8s to client %s",
                    dup->id, dup->client_name);
        report_timeout_period(iter->data, op_timeout);
    }
}

/*!
 * \internal
 * \brief Advance an operation to the next device in its topology
 *
 * \param[in,out] op      Fencer operation to advance
 * \param[in]     device  ID of device that just completed
 * \param[in,out] msg     If not NULL, XML reply of last delegated operation
 */
static void
advance_topology_device_in_level(remote_fencing_op_t *op, const char *device,
                                 xmlNode *msg)
{
    /* Advance to the next device at this topology level, if any */
    if (op->devices) {
        op->devices = op->devices->next;
    }

    /* Handle automatic unfencing if an "on" action was requested */
    if ((op->phase == st_phase_requested)
        && pcmk__str_eq(op->action, PCMK_ACTION_ON, pcmk__str_none)) {
        /* If the device we just executed was required, it's not anymore */
        remove_required_device(op, device);

        /* If there are no more devices at this topology level, run through any
         * remaining devices with automatic unfencing
         */
        if (op->devices == NULL) {
            op->devices = op->automatic_list;
        }
    }

    if ((op->devices == NULL) && (op->phase == st_phase_off)) {
        /* We're done with this level and with required devices, but we had
         * remapped "reboot" to "off", so start over with "on". If any devices
         * need to be turned back on, op->devices will be non-NULL after this.
         */
        op_phase_on(op);
    }

    // This function is only called if the previous device succeeded
    pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

    if (op->devices) {
        /* Necessary devices remain, so execute the next one */
        pcmk__trace("Next targeting %s on behalf of %s@%s", op->target,
                    op->client_name, op->originator);

        // The requested delay has been applied for the first device
        if (op->client_delay > 0) {
            op->client_delay = 0;
        }

        request_peer_fencing(op, NULL);
    } else {
        /* We're done with all devices and phases, so finalize operation */
        pcmk__trace("Marking complex fencing op targeting %s as complete",
                    op->target);
        op->state = st_done;
        finalize_op(op, msg, false);
    }
}

static gboolean
check_watchdog_fencing_and_wait(remote_fencing_op_t * op)
{
    if (node_does_watchdog_fencing(op->target)) {
        guint timeout_ms = QB_MIN(fencing_watchdog_timeout_ms, UINT_MAX);

        pcmk__notice("Waiting %s for %s to self-fence (%s) for client %s "
                     QB_XS " id=%.8s",
                     pcmk__readable_interval(timeout_ms), op->target,
                     op->action, op->client_name, op->id);

        if (op->op_timer_one) {
            g_source_remove(op->op_timer_one);
        }
        op->op_timer_one = pcmk__create_timer(timeout_ms, remote_op_watchdog_done,
                                              op);
        return TRUE;
    } else {
        pcmk__debug("Skipping fallback to watchdog-fencing as %s is not in "
                    "host-list",
                    op->target);
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Ask a peer to execute a fencing operation
 *
 * \param[in,out] op      Fencing operation to be executed
 * \param[in,out] peer    If NULL or topology is in use, choose best peer to
 *                        execute the fencing, otherwise use this peer
 */
static void
request_peer_fencing(remote_fencing_op_t *op, peer_device_info_t *peer)
{
    const char *device = NULL;
    int timeout;

    CRM_CHECK(op != NULL, return);

    pcmk__trace("Action %.8s targeting %s for %s is %s", op->id, op->target,
                op->client_name, stonith__op_state_text(op->state));

    if ((op->phase == st_phase_on) && (op->devices != NULL)) {
        /* We are in the "on" phase of a remapped topology reboot. If this
         * device has pcmk_reboot_action="off", or doesn't support the "on"
         * action, skip it.
         *
         * We can't check device properties at this point because we haven't
         * chosen a peer for this stage yet. Instead, we check the local node's
         * knowledge about the device. If different versions of the fence agent
         * are installed on different nodes, there's a chance this could be
         * mistaken, but the worst that could happen is we don't try turning the
         * node back on when we should.
         */
        device = op->devices->data;
        if (pcmk__str_eq(fenced_device_reboot_action(device), PCMK_ACTION_OFF,
                         pcmk__str_none)) {
            pcmk__info("Not turning %s back on using %s because the device is "
                       "configured to stay off (pcmk_reboot_action='off')",
                       op->target, device);
            advance_topology_device_in_level(op, device, NULL);
            return;
        }
        if (!fenced_device_supports_on(device)) {
            pcmk__info("Not turning %s back on using %s because the agent "
                       "doesn't support 'on'",
                       op->target, device);
            advance_topology_device_in_level(op, device, NULL);
            return;
        }
    }

    timeout = op->base_timeout;
    if ((peer == NULL) && !pcmk__is_set(op->call_options, st_opt_topology)) {
        peer = stonith_choose_peer(op);
    }

    if (!op->op_timer_total) {
        op->total_timeout = TIMEOUT_MULTIPLY_FACTOR * get_op_total_timeout(op, peer);
        op->op_timer_total = pcmk__create_timer(1000 * op->total_timeout, remote_op_timeout, op);
        report_timeout_period(op, op->total_timeout);
        pcmk__info("Total timeout set to %ds for peer's fencing targeting %s "
                   "for %s " QB_XS " id=%.8s",
                   op->total_timeout, op->target, op->client_name, op->id);
    }

    if (pcmk__is_set(op->call_options, st_opt_topology)
        && (op->devices != NULL)) {
        /* Ignore the caller's peer preference if topology is in use, because
         * that peer might not have access to the required device. With
         * topology, stonith_choose_peer() removes the device from further
         * consideration, so the timeout must be calculated beforehand.
         *
         * @TODO Basing the total timeout on the caller's preferred peer (above)
         *       is less than ideal.
         */
        peer = stonith_choose_peer(op);

        device = op->devices->data;
        /* Fencing timeout sent to peer takes no delay into account.
         * The peer will add a dedicated timer for any delay upon
         * schedule_stonith_command().
         */
        timeout = get_device_timeout(op, peer, device, false);
    }

    if (peer) {
        int timeout_one = 0;
        xmlNode *remote_op = stonith_create_op(op->client_callid, op->id, STONITH_OP_FENCE, NULL, 0);
        const pcmk__node_status_t *peer_node =
            pcmk__get_node(0, peer->host, NULL,
                           pcmk__node_search_cluster_member);

        if (op->client_delay > 0) {
           /* Take requested fencing delay into account to prevent it from
            * eating up the timeout.
            */
            timeout_one = TIMEOUT_MULTIPLY_FACTOR * op->client_delay;
        }

        pcmk__xe_set(remote_op, PCMK__XA_ST_REMOTE_OP, op->id);
        pcmk__xe_set(remote_op, PCMK__XA_ST_TARGET, op->target);
        pcmk__xe_set(remote_op, PCMK__XA_ST_DEVICE_ACTION, op->action);
        pcmk__xe_set(remote_op, PCMK__XA_ST_ORIGIN, op->originator);
        pcmk__xe_set(remote_op, PCMK__XA_ST_CLIENTID, op->client_id);
        pcmk__xe_set(remote_op, PCMK__XA_ST_CLIENTNAME, op->client_name);
        pcmk__xe_set_int(remote_op, PCMK__XA_ST_TIMEOUT, timeout);
        pcmk__xe_set_int(remote_op, PCMK__XA_ST_CALLOPT, op->call_options);
        pcmk__xe_set_int(remote_op, PCMK__XA_ST_DELAY, op->client_delay);

        if (device) {
            timeout_one += TIMEOUT_MULTIPLY_FACTOR *
                           get_device_timeout(op, peer, device, true);
            pcmk__notice("Requesting that %s perform '%s' action targeting %s "
                         "using %s " QB_XS " for client %s (%ds)",
                         peer->host, op->action, op->target, device,
                         op->client_name, timeout_one);
            pcmk__xe_set(remote_op, PCMK__XA_ST_DEVICE_ID, device);

        } else {
            timeout_one += TIMEOUT_MULTIPLY_FACTOR * get_peer_timeout(op, peer);
            pcmk__notice("Requesting that %s perform '%s' action targeting %s "
                         QB_XS " for client %s (%ds, %s)",
                         peer->host, op->action, op->target, op->client_name,
                         timeout_one,
                         pcmk__readable_interval(fencing_watchdog_timeout_ms));
        }

        op->state = st_exec;
        if (op->op_timer_one) {
            g_source_remove(op->op_timer_one);
            op->op_timer_one = 0;
        }

        if (!is_watchdog_fencing(op, device)
            || !check_watchdog_fencing_and_wait(op)) {

            /* Some thoughts about self-fencing cases reaching this point:
               - Actually check in check_watchdog_fencing_and_wait
                 shouldn't fail if STONITH_WATCHDOG_ID is
                 chosen as fencing-device and it being present implies
                 watchdog-fencing is enabled anyway
               - If watchdog-fencing is disabled either in general or for
                 a specific target - detected in check_watchdog_fencing_and_wait -
                 for some other kind of self-fencing we can't expect
                 a success answer but timeout is fine if the node doesn't
                 come back in between
               - Delicate might be the case where we have watchdog-fencing
                 enabled for a node but the watchdog-fencing-device isn't
                 explicitly chosen for self-fencing. Local scheduler execution
                 in sbd might detect the node as unclean and lead to timely
                 self-fencing. Otherwise the selection of
                 PCMK_OPT_FENCING_WATCHDOG_TIMEOUT at least is questionable.
             */

            /* coming here we're not waiting for watchdog timeout -
               thus engage timer with timout evaluated before */
            op->op_timer_one = pcmk__create_timer((1000 * timeout_one), remote_op_timeout_one, op);
        }

        pcmk__cluster_send_message(peer_node, pcmk_ipc_fenced, remote_op);
        peer->tried = TRUE;
        pcmk__xml_free(remote_op);
        return;

    } else if (op->phase == st_phase_on) {
        /* A remapped "on" cannot be executed, but the node was already
         * turned off successfully, so ignore the error and continue.
         */
        pcmk__warn("Ignoring %s 'on' failure (no capable peers) targeting %s "
                   "after successful 'off'",
                   device, op->target);
        advance_topology_device_in_level(op, device, NULL);
        return;

    } else if (op->owner == FALSE) {
        pcmk__err("Fencing (%s) targeting %s for client %s is not ours to "
                  "control",
                  op->action, op->target, op->client_name);

    } else if (op->query_timer == 0) {
        /* We've exhausted all available peers */
        pcmk__info("No remaining peers capable of fencing (%s) %s for client "
                   "%s " QB_XS " state=%s",
                   op->action, op->target, op->client_name,
                   stonith__op_state_text(op->state));
        CRM_CHECK(op->state < st_done, return);
        finalize_timed_out_op(op, "All nodes failed, or are unable, to "
                                  "fence target");

    } else if(op->replies >= op->replies_expected || op->replies >= fencing_active_peers()) {
        /* if the operation never left the query state,
         * but we have all the expected replies, then no devices
         * are available to execute the fencing operation. */

        if (is_watchdog_fencing(op, device)
            && check_watchdog_fencing_and_wait(op)) {
            /* Consider a watchdog fencing targeting an offline node executing
             * once it starts waiting for the target to self-fence. So that when
             * the query timer pops, remote_op_query_timeout() considers the
             * fencing already in progress.
             */
            op->state = st_exec;
            return;
        }

        if (op->state == st_query) {
            pcmk__info("No peers (out of %d) have devices capable of fencing "
                       "(%s) %s for client %s " QB_XS " state=%s",
                       op->replies, op->action, op->target, op->client_name,
                       stonith__op_state_text(op->state));

            pcmk__reset_result(&op->result);
            pcmk__set_result(&op->result, CRM_EX_ERROR,
                             PCMK_EXEC_NO_FENCE_DEVICE, NULL);
        } else {
            if (pcmk__is_set(op->call_options, st_opt_topology)) {
                pcmk__reset_result(&op->result);
                pcmk__set_result(&op->result, CRM_EX_ERROR,
                                 PCMK_EXEC_NO_FENCE_DEVICE, NULL);
            }
            /* ... else use existing result from previous failed attempt
             * (topology is not in use, and no devices remain to be attempted).
             * Overwriting the result with PCMK_EXEC_NO_FENCE_DEVICE would
             * prevent finalize_op() from setting the correct delegate if
             * needed.
             */

            pcmk__info("No peers (out of %d) are capable of fencing (%s) %s "
                       "for client %s " QB_XS " state=%s",
                       op->replies, op->action, op->target, op->client_name,
                       stonith__op_state_text(op->state));
        }

        op->state = st_failed;
        finalize_op(op, NULL, false);

    } else {
        pcmk__info("Waiting for additional peers capable of fencing (%s) "
                   "%s%s%s for client %s " QB_XS " id=%.8s",
                   op->action, op->target, ((device != NULL)? " using " : ""),
                   pcmk__s(device, ""), op->client_name, op->id);
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
    const peer_device_info_t *peer_a = a;
    const peer_device_info_t *peer_b = b;

    return (peer_b->ndevices - peer_a->ndevices);
}

/*!
 * \internal
 * \brief Determine if all the devices in the topology are found or not
 *
 * \param[in] op  Fencing operation with topology to check
 */
static gboolean
all_topology_devices_found(const remote_fencing_op_t *op)
{
    GList *device = NULL;
    GList *iter = NULL;
    device_properties_t *match = NULL;
    stonith_topology_t *tp = NULL;
    gboolean skip_target = FALSE;
    int i;

    tp = find_topology_for_host(op->target);
    if (!tp) {
        return FALSE;
    }
    if (pcmk__is_fencing_action(op->action)) {
        /* Don't count the devices on the target node if we are killing
         * the target node. */
        skip_target = TRUE;
    }

    for (i = 0; i < ST__LEVEL_COUNT; i++) {
        for (device = tp->levels[i]; device; device = device->next) {
            match = NULL;
            for (iter = op->query_results; iter && !match; iter = iter->next) {
                peer_device_info_t *peer = iter->data;

                if (skip_target && pcmk__str_eq(peer->host, op->target, pcmk__str_casei)) {
                    continue;
                }
                match = find_peer_device(op, peer, device->data,
                                         fenced_df_none);
            }
            if (!match) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Parse action-specific device properties from XML
 *
 * \param[in]     xml     XML element containing the properties
 * \param[in]     peer    Name of peer that sent XML (for logs)
 * \param[in]     device  Device ID (for logs)
 * \param[in]     action  Action the properties relate to (for logs)
 * \param[in,out] op      Fencing operation that properties are being parsed for
 * \param[in]     phase   Phase the properties relate to
 * \param[in,out] props   Device properties to update
 */
static void
parse_action_specific(const xmlNode *xml, const char *peer, const char *device,
                      const char *action, remote_fencing_op_t *op,
                      enum st_remap_phase phase, device_properties_t *props)
{
    props->custom_action_timeout[phase] = 0;
    pcmk__xe_get_int(xml, PCMK__XA_ST_ACTION_TIMEOUT,
                     &props->custom_action_timeout[phase]);
    if (props->custom_action_timeout[phase]) {
        pcmk__trace("Peer %s with device %s returned %s action timeout %ds",
                    peer, device, action, props->custom_action_timeout[phase]);
    }

    props->delay_max[phase] = 0;
    pcmk__xe_get_int(xml, PCMK__XA_ST_DELAY_MAX, &props->delay_max[phase]);
    if (props->delay_max[phase]) {
        pcmk__trace("Peer %s with device %s returned maximum of random delay "
                    "%ds for %s",
                    peer, device, props->delay_max[phase], action);
    }

    props->delay_base[phase] = 0;
    pcmk__xe_get_int(xml, PCMK__XA_ST_DELAY_BASE, &props->delay_base[phase]);
    if (props->delay_base[phase]) {
        pcmk__trace("Peer %s with device %s returned base delay %ds for %s",
                    peer, device, props->delay_base[phase], action);
    }

    /* Handle devices with automatic unfencing */
    if (pcmk__str_eq(action, PCMK_ACTION_ON, pcmk__str_none)) {
        int required = 0;

        pcmk__xe_get_int(xml, PCMK__XA_ST_REQUIRED, &required);
        if (required) {
            pcmk__trace("Peer %s requires device %s to execute for action %s",
                        peer, device, action);
            add_required_device(op, device);
        }
    }

    /* If a reboot is remapped to off+on, it's possible that a node is allowed
     * to perform one action but not another.
     */
    if (pcmk__xe_attr_is_true(xml, PCMK__XA_ST_ACTION_DISALLOWED)) {
        props->disallowed[phase] = TRUE;
        pcmk__trace("Peer %s is disallowed from executing %s for device %s",
                    peer, action, device);
    }
}

/*!
 * \internal
 * \brief Parse one device's properties from peer's XML query reply
 *
 * \param[in]     xml       XML node containing device properties
 * \param[in,out] op        Operation that query and reply relate to
 * \param[in,out] peer      Peer's device information
 * \param[in]     device    ID of device being parsed
 */
static void
add_device_properties(const xmlNode *xml, remote_fencing_op_t *op,
                      peer_device_info_t *peer, const char *device)
{
    xmlNode *child;
    int verified = 0;
    device_properties_t *props =
        pcmk__assert_alloc(1, sizeof(device_properties_t));
    int rc = pcmk_rc_ok;

    /* Add a new entry to this peer's devices list */
    g_hash_table_insert(peer->devices, pcmk__str_copy(device), props);

    /* Peers with verified (monitored) access will be preferred */
    pcmk__xe_get_int(xml, PCMK__XA_ST_MONITOR_VERIFIED, &verified);
    if (verified) {
        pcmk__trace("Peer %s has confirmed a verified device %s", peer->host,
                    device);
        props->verified = TRUE;
    }

    // Nodes <2.1.5 won't set this, so assume unfencing in that case
    rc = pcmk__xe_get_flags(xml, PCMK__XA_ST_DEVICE_SUPPORT_FLAGS,
                            &(props->device_support_flags),
                            fenced_df_supports_on);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't determine device support for %s "
                   "(assuming unfencing): %s",
                   device, pcmk_rc_str(rc));
    }

    /* Parse action-specific device properties */
    parse_action_specific(xml, peer->host, device, op_requested_action(op),
                          op, st_phase_requested, props);
    for (child = pcmk__xe_first_child(xml, NULL, NULL, NULL); child != NULL;
         child = pcmk__xe_next(child, NULL)) {
        /* Replies for "reboot" operations will include the action-specific
         * values for "off" and "on" in child elements, just in case the reboot
         * winds up getting remapped.
         */
        if (pcmk__str_eq(pcmk__xe_id(child), PCMK_ACTION_OFF, pcmk__str_none)) {
            parse_action_specific(child, peer->host, device, PCMK_ACTION_OFF,
                                  op, st_phase_off, props);

        } else if (pcmk__str_eq(pcmk__xe_id(child), PCMK_ACTION_ON,
                                pcmk__str_none)) {
            parse_action_specific(child, peer->host, device, PCMK_ACTION_ON,
                                  op, st_phase_on, props);
        }
    }
}

/*!
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
static peer_device_info_t *
add_result(remote_fencing_op_t *op, const char *host, int ndevices,
           const xmlNode *xml)
{
    peer_device_info_t *peer = pcmk__assert_alloc(1,
                                                  sizeof(peer_device_info_t));
    xmlNode *child;

    peer->host = pcmk__str_copy(host);
    peer->devices = pcmk__strkey_table(free, free);

    /* Each child element describes one capable device available to the peer */
    for (child = pcmk__xe_first_child(xml, NULL, NULL, NULL); child != NULL;
         child = pcmk__xe_next(child, NULL)) {
        const char *device = pcmk__xe_id(child);

        if (device) {
            add_device_properties(child, op, peer, device);
        }
    }

    peer->ndevices = g_hash_table_size(peer->devices);
    CRM_CHECK(ndevices == peer->ndevices,
              pcmk__err("Query claimed to have %d device%s but %d found",
                        ndevices, pcmk__plural_s(ndevices), peer->ndevices));

    op->query_results = g_list_insert_sorted(op->query_results, peer, sort_peers);
    return peer;
}

/*!
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
process_remote_stonith_query(xmlNode *msg)
{
    int ndevices = 0;
    gboolean host_is_target = FALSE;
    gboolean have_all_replies = FALSE;
    const char *id = NULL;
    const char *host = NULL;
    remote_fencing_op_t *op = NULL;
    peer_device_info_t *peer = NULL;
    uint32_t replies_expected;
    xmlNode *dev = pcmk__xpath_find_one(msg->doc,
                                        "//*[@" PCMK__XA_ST_REMOTE_OP "]",
                                        LOG_ERR);

    CRM_CHECK(dev != NULL, return -EPROTO);

    id = pcmk__xe_get(dev, PCMK__XA_ST_REMOTE_OP);
    CRM_CHECK(id != NULL, return -EPROTO);

    dev = pcmk__xpath_find_one(msg->doc,
                               "//*[@" PCMK__XA_ST_AVAILABLE_DEVICES "]",
                               LOG_ERR);
    CRM_CHECK(dev != NULL, return -EPROTO);
    pcmk__xe_get_int(dev, PCMK__XA_ST_AVAILABLE_DEVICES, &ndevices);

    op = g_hash_table_lookup(stonith_remote_op_list, id);
    if (op == NULL) {
        pcmk__debug("Received query reply for unknown or expired operation %s",
                    id);
        return -EOPNOTSUPP;
    }

    replies_expected = fencing_active_peers();
    if (op->replies_expected < replies_expected) {
        replies_expected = op->replies_expected;
    }
    if ((++op->replies >= replies_expected) && (op->state == st_query)) {
        have_all_replies = TRUE;
    }
    host = pcmk__xe_get(msg, PCMK__XA_SRC);
    host_is_target = pcmk__str_eq(host, op->target, pcmk__str_casei);

    pcmk__info("Query result %d of %d from %s for %s/%s (%d device%s) %s",
               op->replies, replies_expected, host, op->target, op->action,
               ndevices, pcmk__plural_s(ndevices), id);
    if (ndevices > 0) {
        peer = add_result(op, host, ndevices, dev);
    }

    pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

    if (pcmk__is_set(op->call_options, st_opt_topology)) {
        /* If we start the fencing before all the topology results are in,
         * it is possible fencing levels will be skipped because of the missing
         * query results. */
        if (op->state == st_query && all_topology_devices_found(op)) {
            /* All the query results are in for the topology, start the fencing ops. */
            pcmk__trace("All topology devices found");
            request_peer_fencing(op, peer);

        } else if (have_all_replies) {
            pcmk__info("All topology query replies have arrived, continuing "
                       "(%d expected/%d received) ",
                       replies_expected, op->replies);
            request_peer_fencing(op, NULL);
        }

    } else if (op->state == st_query) {
        int nverified = count_peer_devices(op, peer, TRUE,
                                           fenced_support_flag(op->action));

        /* We have a result for a non-topology fencing op that looks promising,
         * go ahead and start fencing before query timeout */
        if ((peer != NULL) && !host_is_target && nverified) {
            /* we have a verified device living on a peer that is not the target */
            pcmk__trace("Found %d verified device%s", nverified,
                        pcmk__plural_s(nverified));
            request_peer_fencing(op, peer);

        } else if (have_all_replies) {
            pcmk__info("All query replies have arrived, continuing (%d "
                       "expected/%d received) ",
                       replies_expected, op->replies);
            request_peer_fencing(op, NULL);

        } else {
            pcmk__trace("Waiting for more peer results before launching "
                        "fencing operation");
        }

    } else if ((peer != NULL) && (op->state == st_done)) {
        pcmk__info("Discarding query result from %s (%d device%s): Operation "
                   "is %s",
                   peer->host, peer->ndevices, pcmk__plural_s(peer->ndevices),
                   stonith__op_state_text(op->state));
    }

    return pcmk_ok;
}

/*!
 * \internal
 * \brief Handle a peer's reply to a fencing request
 *
 * Parse a fencing reply from XML, and either finalize the operation
 * or attempt another device as appropriate.
 *
 * \param[in] msg  XML reply received
 */
void
fenced_process_fencing_reply(xmlNode *msg)
{
    const char *id = NULL;
    const char *device = NULL;
    remote_fencing_op_t *op = NULL;
    xmlNode *dev = pcmk__xpath_find_one(msg->doc,
                                        "//*[@" PCMK__XA_ST_REMOTE_OP "]",
                                        LOG_ERR);
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    CRM_CHECK(dev != NULL, return);

    id = pcmk__xe_get(dev, PCMK__XA_ST_REMOTE_OP);
    CRM_CHECK(id != NULL, return);

    dev = stonith__find_xe_with_result(msg);
    CRM_CHECK(dev != NULL, return);

    stonith__xe_get_result(dev, &result);

    device = pcmk__xe_get(dev, PCMK__XA_ST_DEVICE_ID);

    if (stonith_remote_op_list) {
        op = g_hash_table_lookup(stonith_remote_op_list, id);
    }

    if ((op == NULL) && pcmk__result_ok(&result)) {
        /* Record successful fencing operations */
        const char *client_id = pcmk__xe_get(dev, PCMK__XA_ST_CLIENTID);

        op = create_remote_stonith_op(client_id, dev, TRUE);
    }

    if (op == NULL) {
        /* Could be for an event that began before we started */
        /* TODO: Record the op for later querying */
        pcmk__info("Received peer result of unknown or expired operation %s",
                   id);
        pcmk__reset_result(&result);
        return;
    }

    pcmk__reset_result(&op->result);
    op->result = result; // The operation takes ownership of the result

    if (op->devices && device && !pcmk__str_eq(op->devices->data, device, pcmk__str_casei)) {
        pcmk__err("Received outdated reply for device %s (instead of %s) to "
                  "fence (%s) %s. Operation already timed out at peer level.",
                  device, (const char *) op->devices->data, op->action,
                  op->target);
        return;
    }

    if (pcmk__str_eq(pcmk__xe_get(msg, PCMK__XA_SUBT), PCMK__VALUE_BROADCAST,
                     pcmk__str_none)) {

        if (pcmk__result_ok(&op->result)) {
            op->state = st_done;
        } else {
            op->state = st_failed;
        }
        finalize_op(op, msg, false);
        return;

    } else if (!pcmk__str_eq(op->originator, fenced_get_local_node(),
                             pcmk__str_casei)) {
        /* If this isn't a remote level broadcast, and we are not the
         * originator of the operation, we should not be receiving this msg. */
        pcmk__err("Received non-broadcast fencing result for operation %.8s we "
                  "do not own (device %s targeting %s)",
                  op->id, device, op->target);
        return;
    }

    if (pcmk__is_set(op->call_options, st_opt_topology)) {
        const char *device = NULL;
        const char *reason = op->result.exit_reason;

        /* We own the op, and it is complete. broadcast the result to all nodes
         * and notify our local clients. */
        if (op->state == st_done) {
            finalize_op(op, msg, false);
            return;
        }

        device = pcmk__xe_get(msg, PCMK__XA_ST_DEVICE_ID);

        if ((op->phase == 2) && !pcmk__result_ok(&op->result)) {
            /* A remapped "on" failed, but the node was already turned off
             * successfully, so ignore the error and continue.
             */
            pcmk__warn("Ignoring %s 'on' failure (%s%s%s) targeting %s after "
                       "successful 'off'",
                       device,
                       pcmk_exec_status_str(op->result.execution_status),
                       ((reason != NULL)? ": " : ""), pcmk__s(reason, ""),
                       op->target);
            pcmk__set_result(&op->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        } else {
            pcmk__notice("Action '%s' targeting %s%s%s on behalf of %s@%s: "
                         "%s%s%s%s",
                         op->action, op->target,
                         ((device == NULL)? "" : " using "),
                         pcmk__s(device, ""), op->client_name, op->originator,
                         pcmk_exec_status_str(op->result.execution_status),
                         ((reason != NULL)? " (" : ""), pcmk__s(reason, ""),
                         ((reason != NULL)? ")" : ""));
        }

        if (pcmk__result_ok(&op->result)) {
            /* An operation completed successfully. Try another device if
             * necessary, otherwise mark the operation as done. */
            advance_topology_device_in_level(op, device, msg);
            return;
        } else {
            /* This device failed, time to try another topology level. If no other
             * levels are available, mark this operation as failed and report results. */
            if (advance_topology_level(op, false) != pcmk_rc_ok) {
                op->state = st_failed;
                finalize_op(op, msg, false);
                return;
            }
        }

    } else if (pcmk__result_ok(&op->result) && (op->devices == NULL)) {
        op->state = st_done;
        finalize_op(op, msg, false);
        return;

    } else if ((op->result.execution_status == PCMK_EXEC_TIMEOUT)
               && (op->devices == NULL)) {
        /* If the operation timed out don't bother retrying other peers. */
        op->state = st_failed;
        finalize_op(op, msg, false);
        return;

    } else {
        /* fall-through and attempt other fencing action using another peer */
    }

    /* Retry on failure */
    pcmk__trace("Next for %s on behalf of %s@%s (result was: %s)", op->target,
                op->originator, op->client_name,
                pcmk_exec_status_str(op->result.execution_status));
    request_peer_fencing(op, NULL);
}

gboolean
stonith_check_fence_tolerance(int tolerance, const char *target, const char *action)
{
    GHashTableIter iter;
    time_t now = time(NULL);
    remote_fencing_op_t *rop = NULL;

    if (tolerance <= 0 || !stonith_remote_op_list || target == NULL ||
        action == NULL) {
        return FALSE;
    }

    g_hash_table_iter_init(&iter, stonith_remote_op_list);
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

        pcmk__notice("Target %s was fenced (%s) less than %ds ago by %s on "
                     "behalf of %s",
                     target, action, tolerance, rop->delegate, rop->originator);
        return TRUE;
    }
    return FALSE;
}
