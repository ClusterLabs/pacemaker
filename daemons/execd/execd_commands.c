/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/fencing/internal.h>

#include <glib.h>
#include <libxml/tree.h>                // xmlNode

// Check whether we have a high-resolution monotonic clock
#undef PCMK__TIME_USE_CGT
#if HAVE_DECL_CLOCK_MONOTONIC && defined(CLOCK_MONOTONIC)
#  define PCMK__TIME_USE_CGT
#  include <time.h>  /* clock_gettime */
#endif

#include <unistd.h>

#include <crm/crm.h>
#include <crm/fencing/internal.h>
#include <crm/services.h>
#include <crm/services_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include "pacemaker-execd.h"

GHashTable *rsc_list = NULL;

typedef struct {
    int timeout;
    guint interval_ms;
    int start_delay;
    int timeout_orig;

    int call_id;

    int call_opts;
    /* Timer ids, must be removed on cmd destruction. */
    int delay_id;
    int stonith_recurring_id;

    int rsc_deleted;

    int service_flags;

    char *client_id;
    char *origin;
    char *rsc_id;
    char *action;
    char *real_action;
    char *userdata_str;

    pcmk__action_result_t result;

    /* We can track operation queue time and run time, to be saved with the CIB
     * resource history (and displayed in cluster status). We need
     * high-resolution monotonic time for this purpose, so we use
     * clock_gettime(CLOCK_MONOTONIC, ...) (if available, otherwise this feature
     * is disabled).
     *
     * However, we also need epoch timestamps for recording the time the command
     * last ran and the time its return value last changed, for use in time
     * displays (as opposed to interval calculations). We keep time_t values for
     * this purpose.
     *
     * The last run time is used for both purposes, so we keep redundant
     * monotonic and epoch values for this. Technically the two could represent
     * different times, but since time_t has only second resolution and the
     * values are used for distinct purposes, that is not significant.
     */
#ifdef PCMK__TIME_USE_CGT
    /* Recurring and systemd operations may involve more than one executor
     * command per operation, so they need info about the original and the most
     * recent.
     */
    struct timespec t_first_run;    // When op first ran
    struct timespec t_run;          // When op most recently ran
    struct timespec t_first_queue;  // When op was first queued
    struct timespec t_queue;        // When op was most recently queued
#endif
    time_t epoch_last_run;          // Epoch timestamp of when op last ran
    time_t epoch_rcchange;          // Epoch timestamp of when rc last changed

    bool first_notify_sent;
    int last_notify_rc;
    int last_notify_op_status;
    int last_pid;

    GHashTable *params;
} lrmd_cmd_t;

static void cmd_finalize(lrmd_cmd_t * cmd, lrmd_rsc_t * rsc);
static gboolean execute_resource_action(gpointer user_data);
static void cancel_all_recurring(lrmd_rsc_t * rsc, const char *client_id);

#ifdef PCMK__TIME_USE_CGT

/*!
 * \internal
 * \brief Check whether a struct timespec has been set
 *
 * \param[in] timespec  Time to check
 *
 * \return true if timespec has been set (i.e. is nonzero), false otherwise
 */
static inline bool
time_is_set(const struct timespec *timespec)
{
    return (timespec != NULL) &&
           ((timespec->tv_sec != 0) || (timespec->tv_nsec != 0));
}

/*
 * \internal
 * \brief Set a timespec (and its original if unset) to the current time
 *
 * \param[out] t_current  Where to store current time
 * \param[out] t_orig     Where to copy t_current if unset
 */
static void
get_current_time(struct timespec *t_current, struct timespec *t_orig)
{
    clock_gettime(CLOCK_MONOTONIC, t_current);
    if ((t_orig != NULL) && !time_is_set(t_orig)) {
        *t_orig = *t_current;
    }
}

/*!
 * \internal
 * \brief Return difference between two times in milliseconds
 *
 * \param[in] now  More recent time (or NULL to use current time)
 * \param[in] old  Earlier time
 *
 * \return milliseconds difference (or 0 if old is NULL or unset)
 *
 * \note Can overflow on 32bit machines when the differences is around
 *       24 days or more.
 */
static int
time_diff_ms(const struct timespec *now, const struct timespec *old)
{
    int diff_ms = 0;

    if (time_is_set(old)) {
        struct timespec local_now = { 0, };

        if (now == NULL) {
            clock_gettime(CLOCK_MONOTONIC, &local_now);
            now = &local_now;
        }
        diff_ms = (now->tv_sec - old->tv_sec) * 1000
                  + (now->tv_nsec - old->tv_nsec) / 1000000;
    }
    return diff_ms;
}

/*!
 * \internal
 * \brief Reset a command's operation times to their original values.
 *
 * Reset a command's run and queued timestamps to the timestamps of the original
 * command, so we report the entire time since then and not just the time since
 * the most recent command (for recurring and systemd operations).
 *
 * \param[in,out] cmd  Executor command object to reset
 *
 * \note It's not obvious what the queued time should be for a systemd
 *       start/stop operation, which might go like this:
 *         initial command queued 5ms, runs 3s
 *         monitor command queued 10ms, runs 10s
 *         monitor command queued 10ms, runs 10s
 *       Is the queued time for that operation 5ms, 10ms or 25ms? The current
 *       implementation will report 5ms. If it's 25ms, then we need to
 *       subtract 20ms from the total exec time so as not to count it twice.
 *       We can implement that later if it matters to anyone ...
 */
static void
cmd_original_times(lrmd_cmd_t * cmd)
{
    cmd->t_run = cmd->t_first_run;
    cmd->t_queue = cmd->t_first_queue;
}
#endif

static inline bool
action_matches(const lrmd_cmd_t *cmd, const char *action, guint interval_ms)
{
    return (cmd->interval_ms == interval_ms)
           && pcmk__str_eq(cmd->action, action, pcmk__str_casei);
}

/*!
 * \internal
 * \brief Log the result of an asynchronous command
 *
 * \param[in] cmd            Command to log result for
 * \param[in] exec_time_ms   Execution time in milliseconds, if known
 * \param[in] queue_time_ms  Queue time in milliseconds, if known
 */
static void
log_finished(const lrmd_cmd_t *cmd, int exec_time_ms, int queue_time_ms)
{
    int log_level = LOG_INFO;
    GString *str = g_string_sized_new(100); // reasonable starting size

    if (pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR, pcmk__str_casei)) {
        log_level = LOG_DEBUG;
    }

    g_string_append_printf(str, "%s %s (call %d",
                           cmd->rsc_id, cmd->action, cmd->call_id);
    if (cmd->last_pid != 0) {
        g_string_append_printf(str, ", PID %d", cmd->last_pid);
    }
    switch (cmd->result.execution_status) {
        case PCMK_EXEC_DONE:
            g_string_append_printf(str, ") exited with status %d",
                                   cmd->result.exit_status);
            break;
        case PCMK_EXEC_CANCELLED:
            g_string_append_printf(str, ") cancelled");
            break;
        default:
            pcmk__g_strcat(str, ") could not be executed: ",
                           pcmk_exec_status_str(cmd->result.execution_status),
                           NULL);
            break;
    }
    if (cmd->result.exit_reason != NULL) {
        pcmk__g_strcat(str, " (", cmd->result.exit_reason, ")", NULL);
    }

#ifdef PCMK__TIME_USE_CGT
    pcmk__g_strcat(str, " (execution time ",
                   pcmk__readable_interval(exec_time_ms), NULL);
    if (queue_time_ms > 0) {
        pcmk__g_strcat(str, " after being queued ",
                       pcmk__readable_interval(queue_time_ms), NULL);
    }
    g_string_append_c(str, ')');
#endif

    do_crm_log(log_level, "%s", str->str);
    g_string_free(str, TRUE);
}

static void
log_execute(lrmd_cmd_t * cmd)
{
    int log_level = LOG_INFO;

    if (pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR, pcmk__str_casei)) {
        log_level = LOG_DEBUG;
    }

    do_crm_log(log_level, "executing - rsc:%s action:%s call_id:%d",
               cmd->rsc_id, cmd->action, cmd->call_id);
}

static const char *
normalize_action_name(lrmd_rsc_t * rsc, const char *action)
{
    if (pcmk__str_eq(action, PCMK_ACTION_MONITOR, pcmk__str_casei) &&
        pcmk__is_set(pcmk_get_ra_caps(rsc->class), pcmk_ra_cap_status)) {
        return PCMK_ACTION_STATUS;
    }
    return action;
}

static lrmd_rsc_t *
build_rsc_from_xml(xmlNode * msg)
{
    xmlNode *rsc_xml = pcmk__xpath_find_one(msg->doc, "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    lrmd_rsc_t *rsc = NULL;

    rsc = pcmk__assert_alloc(1, sizeof(lrmd_rsc_t));

    pcmk__xe_get_int(msg, PCMK__XA_LRMD_CALLOPT, &rsc->call_opts);

    rsc->rsc_id = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_RSC_ID);
    rsc->class = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_CLASS);
    rsc->provider = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_PROVIDER);
    rsc->type = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_TYPE);
    rsc->work = mainloop_add_trigger(G_PRIORITY_HIGH, execute_resource_action,
                                     rsc);

    // Initialize fence device probes (to return "not running")
    pcmk__set_result(&rsc->fence_probe_result, CRM_EX_ERROR,
                     PCMK_EXEC_NO_FENCE_DEVICE, NULL);
    return rsc;
}

static lrmd_cmd_t *
create_lrmd_cmd(xmlNode *msg, pcmk__client_t *client)
{
    int call_options = 0;
    xmlNode *rsc_xml = pcmk__xpath_find_one(msg->doc, "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    lrmd_cmd_t *cmd = NULL;

    cmd = pcmk__assert_alloc(1, sizeof(lrmd_cmd_t));

    pcmk__xe_get_int(msg, PCMK__XA_LRMD_CALLOPT, &call_options);
    cmd->call_opts = call_options;
    cmd->client_id = pcmk__str_copy(client->id);

    pcmk__xe_get_int(msg, PCMK__XA_LRMD_CALLID, &cmd->call_id);
    pcmk__xe_get_guint(rsc_xml, PCMK__XA_LRMD_RSC_INTERVAL, &cmd->interval_ms);
    pcmk__xe_get_int(rsc_xml, PCMK__XA_LRMD_TIMEOUT, &cmd->timeout);
    pcmk__xe_get_int(rsc_xml, PCMK__XA_LRMD_RSC_START_DELAY, &cmd->start_delay);
    cmd->timeout_orig = cmd->timeout;

    cmd->origin = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_ORIGIN);
    cmd->action = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_RSC_ACTION);
    cmd->userdata_str = pcmk__xe_get_copy(rsc_xml,
                                          PCMK__XA_LRMD_RSC_USERDATA_STR);
    cmd->rsc_id = pcmk__xe_get_copy(rsc_xml, PCMK__XA_LRMD_RSC_ID);

    cmd->params = xml2list(rsc_xml);

    if (pcmk__str_eq(g_hash_table_lookup(cmd->params, "CRM_meta_on_fail"),
                     PCMK_VALUE_BLOCK, pcmk__str_casei)) {
        pcmk__debug("Setting flag to leave pid group on timeout and only kill "
                    "action pid for " PCMK__OP_FMT,
                    cmd->rsc_id, cmd->action, cmd->interval_ms);
        cmd->service_flags = pcmk__set_flags_as(__func__, __LINE__,
                                                LOG_TRACE, "Action",
                                                cmd->action, 0,
                                                SVC_ACTION_LEAVE_GROUP,
                                                "SVC_ACTION_LEAVE_GROUP");
    }
    return cmd;
}

static void
stop_recurring_timer(lrmd_cmd_t *cmd)
{
    if (cmd) {
        if (cmd->stonith_recurring_id) {
            g_source_remove(cmd->stonith_recurring_id);
        }
        cmd->stonith_recurring_id = 0;
    }
}

static void
free_lrmd_cmd(lrmd_cmd_t * cmd)
{
    stop_recurring_timer(cmd);
    if (cmd->delay_id) {
        g_source_remove(cmd->delay_id);
    }
    if (cmd->params) {
        g_hash_table_destroy(cmd->params);
    }
    pcmk__reset_result(&(cmd->result));
    free(cmd->origin);
    free(cmd->action);
    free(cmd->real_action);
    free(cmd->userdata_str);
    free(cmd->rsc_id);
    free(cmd->client_id);
    free(cmd);
}

static gboolean
stonith_recurring_op_helper(gpointer data)
{
    lrmd_cmd_t *cmd = data;
    lrmd_rsc_t *rsc;

    cmd->stonith_recurring_id = 0;

    if (!cmd->rsc_id) {
        return FALSE;
    }

    rsc = g_hash_table_lookup(rsc_list, cmd->rsc_id);

    pcmk__assert(rsc != NULL);
    /* take it out of recurring_ops list, and put it in the pending ops
     * to be executed */
    rsc->recurring_ops = g_list_remove(rsc->recurring_ops, cmd);
    rsc->pending_ops = g_list_append(rsc->pending_ops, cmd);
#ifdef PCMK__TIME_USE_CGT
    get_current_time(&(cmd->t_queue), &(cmd->t_first_queue));
#endif
    mainloop_set_trigger(rsc->work);

    return FALSE;
}

static inline void
start_recurring_timer(lrmd_cmd_t *cmd)
{
    if (!cmd || (cmd->interval_ms <= 0)) {
        return;
    }

    cmd->stonith_recurring_id = pcmk__create_timer(cmd->interval_ms,
                                                   stonith_recurring_op_helper,
                                                   cmd);
}

static gboolean
start_delay_helper(gpointer data)
{
    lrmd_cmd_t *cmd = data;
    lrmd_rsc_t *rsc = NULL;

    cmd->delay_id = 0;
    rsc = cmd->rsc_id ? g_hash_table_lookup(rsc_list, cmd->rsc_id) : NULL;

    if (rsc) {
        mainloop_set_trigger(rsc->work);
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Check whether a list already contains the equivalent of a given action
 *
 * \param[in] action_list  List to search
 * \param[in] cmd          Action to search for
 */
static lrmd_cmd_t *
find_duplicate_action(const GList *action_list, const lrmd_cmd_t *cmd)
{
    for (const GList *item = action_list; item != NULL; item = item->next) {
        lrmd_cmd_t *dup = item->data;

        if (action_matches(cmd, dup->action, dup->interval_ms)) {
            return dup;
        }
    }
    return NULL;
}

static bool
merge_recurring_duplicate(lrmd_rsc_t * rsc, lrmd_cmd_t * cmd)
{
    lrmd_cmd_t * dup = NULL;
    bool dup_pending = true;

    if (cmd->interval_ms == 0) {
        return false;
    }

    // Search for a duplicate of this action (in-flight or not)
    dup = find_duplicate_action(rsc->pending_ops, cmd);
    if (dup == NULL) {
        dup_pending = false;
        dup = find_duplicate_action(rsc->recurring_ops, cmd);
        if (dup == NULL) {
            return false;
        }
    }

    /* Do not merge fencing monitors marked for cancellation, so we can reply to
     * the cancellation separately.
     */
    if (pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH,
                     pcmk__str_casei)
        && (dup->result.execution_status == PCMK_EXEC_CANCELLED)) {
        return false;
    }

    /* This should not occur. If it does, we need to investigate how something
     * like this is possible in the controller.
     */
    pcmk__warn("Duplicate recurring op entry detected (" PCMK__OP_FMT "), "
               "merging with previous op entry",
               rsc->rsc_id, normalize_action_name(rsc, dup->action),
               dup->interval_ms);

    // Merge new action's call ID and user data into existing action
    dup->first_notify_sent = false;
    free(dup->userdata_str);
    dup->userdata_str = cmd->userdata_str;
    cmd->userdata_str = NULL;
    dup->call_id = cmd->call_id;
    free_lrmd_cmd(cmd);
    cmd = NULL;

    /* If dup is not pending, that means it has already executed at least once
     * and is waiting in the interval. In that case, stop waiting and initiate
     * a new instance now.
     */
    if (!dup_pending) {
        if (pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH,
                         pcmk__str_casei)) {
            stop_recurring_timer(dup);
            stonith_recurring_op_helper(dup);
        } else {
            services_action_kick(rsc->rsc_id,
                                 normalize_action_name(rsc, dup->action),
                                 dup->interval_ms);
        }
    }
    return true;
}

static void
schedule_lrmd_cmd(lrmd_rsc_t * rsc, lrmd_cmd_t * cmd)
{
    CRM_CHECK(cmd != NULL, return);
    CRM_CHECK(rsc != NULL, return);

    pcmk__trace("Scheduling %s on %s", cmd->action, rsc->rsc_id);

    if (merge_recurring_duplicate(rsc, cmd)) {
        // Equivalent of cmd has already been scheduled
        return;
    }

    /* The controller expects the executor to automatically cancel
     * recurring operations before a resource stops.
     */
    if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP, pcmk__str_casei)) {
        cancel_all_recurring(rsc, NULL);
    }

    rsc->pending_ops = g_list_append(rsc->pending_ops, cmd);
#ifdef PCMK__TIME_USE_CGT
    get_current_time(&(cmd->t_queue), &(cmd->t_first_queue));
#endif
    mainloop_set_trigger(rsc->work);

    if (cmd->start_delay) {
        cmd->delay_id = pcmk__create_timer(cmd->start_delay, start_delay_helper, cmd);
    }
}

xmlNode *
execd_create_reply_as(const char *origin, int rc, int call_id)
{
    xmlNode *reply = pcmk__xe_create(NULL, PCMK__XE_LRMD_REPLY);

    pcmk__xe_set(reply, PCMK__XA_LRMD_ORIGIN, origin);
    pcmk__xe_set_int(reply, PCMK__XA_LRMD_RC, rc);
    pcmk__xe_set_int(reply, PCMK__XA_LRMD_CALLID, call_id);
    return reply;
}

static void
send_client_notify(gpointer key, gpointer value, gpointer user_data)
{
    xmlNode *update_msg = user_data;
    pcmk__client_t *client = value;
    int rc;
    int log_level = LOG_WARNING;
    const char *msg = NULL;

    CRM_CHECK(client != NULL, return);
    if (client->name == NULL) {
        pcmk__trace("Skipping notification to client without name");
        return;
    }
    if (pcmk__is_set(client->flags, pcmk__client_to_proxy)) {
        /* We only want to notify clients of the executor IPC API. If we are
         * running as Pacemaker Remote, we may have clients proxied to other
         * IPC services in the cluster, so skip those.
         */
        pcmk__trace("Skipping executor API notification to client %s",
                    pcmk__client_name(client));
        return;
    }

    rc = lrmd_server_send_notify(client, update_msg);
    if (rc == pcmk_rc_ok) {
        return;
    }

    switch (rc) {
        case ENOTCONN:
        case EPIPE: // Client exited without waiting for notification
            log_level = LOG_INFO;
            msg = "Disconnected";
            break;

        default:
            msg = pcmk_rc_str(rc);
            break;
    }
    do_crm_log(log_level, "Could not notify client %s: %s " QB_XS " rc=%d",
               pcmk__client_name(client), msg, rc);
}

static void
send_cmd_complete_notify(lrmd_cmd_t * cmd)
{
    xmlNode *notify = NULL;
    int exec_time = 0;
    int queue_time = 0;

#ifdef PCMK__TIME_USE_CGT
    exec_time = time_diff_ms(NULL, &(cmd->t_run));
    queue_time = time_diff_ms(&cmd->t_run, &(cmd->t_queue));
#endif
    log_finished(cmd, exec_time, queue_time);

    /* If the originator requested to be notified only for changes in recurring
     * operation results, skip the notification if the result hasn't changed.
     */
    if (cmd->first_notify_sent
        && pcmk__is_set(cmd->call_opts, lrmd_opt_notify_changes_only)
        && (cmd->last_notify_rc == cmd->result.exit_status)
        && (cmd->last_notify_op_status == cmd->result.execution_status)) {
        return;
    }

    cmd->first_notify_sent = true;
    cmd->last_notify_rc = cmd->result.exit_status;
    cmd->last_notify_op_status = cmd->result.execution_status;

    notify = pcmk__xe_create(NULL, PCMK__XE_LRMD_NOTIFY);

    pcmk__xe_set(notify, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_TIMEOUT, cmd->timeout);
    pcmk__xe_set_guint(notify, PCMK__XA_LRMD_RSC_INTERVAL, cmd->interval_ms);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_RSC_START_DELAY, cmd->start_delay);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_EXEC_RC, cmd->result.exit_status);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_EXEC_OP_STATUS,
                     cmd->result.execution_status);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_CALLID, cmd->call_id);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_RSC_DELETED, cmd->rsc_deleted);

    pcmk__xe_set_time(notify, PCMK__XA_LRMD_RUN_TIME, cmd->epoch_last_run);
    pcmk__xe_set_time(notify, PCMK__XA_LRMD_RCCHANGE_TIME, cmd->epoch_rcchange);
#ifdef PCMK__TIME_USE_CGT
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_EXEC_TIME, exec_time);
    pcmk__xe_set_int(notify, PCMK__XA_LRMD_QUEUE_TIME, queue_time);
#endif

    pcmk__xe_set(notify, PCMK__XA_LRMD_OP, LRMD_OP_RSC_EXEC);
    pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_ID, cmd->rsc_id);
    if(cmd->real_action) {
        pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_ACTION, cmd->real_action);
    } else {
        pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_ACTION, cmd->action);
    }
    pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_USERDATA_STR, cmd->userdata_str);
    pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_EXIT_REASON, cmd->result.exit_reason);

    if (cmd->result.action_stderr != NULL) {
        pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_OUTPUT,
                     cmd->result.action_stderr);

    } else if (cmd->result.action_stdout != NULL) {
        pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_OUTPUT,
                     cmd->result.action_stdout);
    }

    if (cmd->params) {
        char *key = NULL;
        char *value = NULL;
        GHashTableIter iter;

        xmlNode *args = pcmk__xe_create(notify, PCMK__XE_ATTRIBUTES);

        g_hash_table_iter_init(&iter, cmd->params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            hash2smartfield((gpointer) key, (gpointer) value, args);
        }
    }
    if ((cmd->client_id != NULL)
        && pcmk__is_set(cmd->call_opts, lrmd_opt_notify_orig_only)) {

        pcmk__client_t *client = pcmk__find_client_by_id(cmd->client_id);

        if (client != NULL) {
            send_client_notify(client->id, client, notify);
        }
    } else {
        pcmk__foreach_ipc_client(send_client_notify, notify);
    }

    pcmk__xml_free(notify);
}

void
execd_send_generic_notify(int rc, xmlNode *request)
{
    if (pcmk__ipc_client_count() != 0) {
        int call_id = 0;
        xmlNode *notify = NULL;
        xmlNode *rsc_xml = pcmk__xpath_find_one(request->doc,
                                                "//" PCMK__XE_LRMD_RSC,
                                                LOG_ERR);
        const char *rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);
        const char *op = pcmk__xe_get(request, PCMK__XA_LRMD_OP);

        pcmk__xe_get_int(request, PCMK__XA_LRMD_CALLID, &call_id);

        notify = pcmk__xe_create(NULL, PCMK__XE_LRMD_NOTIFY);
        pcmk__xe_set(notify, PCMK__XA_LRMD_ORIGIN, __func__);
        pcmk__xe_set_int(notify, PCMK__XA_LRMD_RC, rc);
        pcmk__xe_set_int(notify, PCMK__XA_LRMD_CALLID, call_id);
        pcmk__xe_set(notify, PCMK__XA_LRMD_OP, op);
        pcmk__xe_set(notify, PCMK__XA_LRMD_RSC_ID, rsc_id);

        pcmk__foreach_ipc_client(send_client_notify, notify);

        pcmk__xml_free(notify);
    }
}

static void
cmd_reset(lrmd_cmd_t * cmd)
{
    cmd->last_pid = 0;
#ifdef PCMK__TIME_USE_CGT
    memset(&cmd->t_run, 0, sizeof(cmd->t_run));
    memset(&cmd->t_queue, 0, sizeof(cmd->t_queue));
#endif
    cmd->epoch_last_run = 0;

    pcmk__reset_result(&(cmd->result));
    cmd->result.execution_status = PCMK_EXEC_DONE;
}

static void
cmd_finalize(lrmd_cmd_t * cmd, lrmd_rsc_t * rsc)
{
    pcmk__trace("Resource operation rsc:%s action:%s completed (%p %p)",
                cmd->rsc_id, cmd->action, ((rsc != NULL)? rsc->active : NULL),
                cmd);

    if (rsc && (rsc->active == cmd)) {
        rsc->active = NULL;
        mainloop_set_trigger(rsc->work);
    }

    if (!rsc) {
        cmd->rsc_deleted = 1;
    }

    /* reset original timeout so client notification has correct information */
    cmd->timeout = cmd->timeout_orig;

    send_cmd_complete_notify(cmd);

    if ((cmd->interval_ms != 0)
        && (cmd->result.execution_status == PCMK_EXEC_CANCELLED)) {

        if (rsc) {
            rsc->recurring_ops = g_list_remove(rsc->recurring_ops, cmd);
            rsc->pending_ops = g_list_remove(rsc->pending_ops, cmd);
        }
        free_lrmd_cmd(cmd);
    } else if (cmd->interval_ms == 0) {
        if (rsc) {
            rsc->pending_ops = g_list_remove(rsc->pending_ops, cmd);
        }
        free_lrmd_cmd(cmd);
    } else {
        /* Clear all the values pertaining just to the last iteration of a recurring op. */
        cmd_reset(cmd);
    }
}

struct notify_new_client_data {
    xmlNode *notify;
    pcmk__client_t *new_client;
};

static void
notify_one_client(gpointer key, gpointer value, gpointer user_data)
{
    pcmk__client_t *client = value;
    struct notify_new_client_data *data = user_data;

    if (!pcmk__str_eq(client->id, data->new_client->id, pcmk__str_casei)) {
        send_client_notify(key, (gpointer) client, (gpointer) data->notify);
    }
}

void
notify_of_new_client(pcmk__client_t *new_client)
{
    struct notify_new_client_data data;

    data.new_client = new_client;
    data.notify = pcmk__xe_create(NULL, PCMK__XE_LRMD_NOTIFY);
    pcmk__xe_set(data.notify, PCMK__XA_LRMD_ORIGIN, __func__);
    pcmk__xe_set(data.notify, PCMK__XA_LRMD_OP, LRMD_OP_NEW_CLIENT);
    pcmk__foreach_ipc_client(notify_one_client, &data);
    pcmk__xml_free(data.notify);
}

void
client_disconnect_cleanup(const char *client_id)
{
    GHashTableIter iter;
    lrmd_rsc_t *rsc = NULL;
    char *key = NULL;

    g_hash_table_iter_init(&iter, rsc_list);
    while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & rsc)) {
        if (pcmk__is_set(rsc->call_opts, lrmd_opt_drop_recurring)) {
            /* This client is disconnecting, drop any recurring operations
             * it may have initiated on the resource */
            cancel_all_recurring(rsc, client_id);
        }
    }
}

static void
action_complete(svc_action_t * action)
{
    lrmd_rsc_t *rsc;
    lrmd_cmd_t *cmd = action->cb_data;
    enum ocf_exitcode code;

#ifdef PCMK__TIME_USE_CGT
    const char *rclass = NULL;
    bool goagain = false;
    int time_sum = 0;
    int timeout_left = 0;
    int delay = 0;
#endif

    if (!cmd) {
        pcmk__err("Completed executor action (%s) does not match any known "
                  "operations",
                  action->id);
        return;
    }

#ifdef PCMK__TIME_USE_CGT
    if (cmd->result.exit_status != action->rc) {
        cmd->epoch_rcchange = time(NULL);
    }
#endif

    cmd->last_pid = action->pid;

    // Cast variable instead of function return to keep compilers happy
    code = services_result2ocf(action->standard, cmd->action, action->rc);
    pcmk__set_result(&(cmd->result), (int) code,
                     action->status, services__exit_reason(action));

    rsc = cmd->rsc_id ? g_hash_table_lookup(rsc_list, cmd->rsc_id) : NULL;

#ifdef PCMK__TIME_USE_CGT
    if (rsc != NULL) {
        rclass = rsc->class;
#if PCMK__ENABLE_SERVICE
        if (pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_SERVICE,
                         pcmk__str_casei)) {
            rclass = resources_find_service_class(rsc->type);
        }
#endif
    }

    if (!pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_SYSTEMD, pcmk__str_casei)) {
        goto finalize;
    }

    if (pcmk__result_ok(&(cmd->result))
        && pcmk__strcase_any_of(cmd->action, PCMK_ACTION_START,
                                PCMK_ACTION_STOP, NULL)) {
        /* Getting results for when a start or stop action completes is now
         * handled by watching for JobRemoved() signals from systemd and
         * reacting to them. So, we can bypass the rest of the code in this
         * function for those actions, and simply finalize cmd.
         *
         * @TODO When monitors are handled in the same way, this function
         * can either be drastically simplified or done away with entirely.
         */
        services__copy_result(action, &(cmd->result));
        goto finalize;

    } else if (cmd->result.execution_status == PCMK_EXEC_PENDING &&
               pcmk__str_any_of(cmd->action, PCMK_ACTION_MONITOR, PCMK_ACTION_STATUS, NULL) &&
               cmd->interval_ms == 0 &&
               cmd->real_action == NULL) {
        /* If the state is Pending at the time of probe, execute follow-up monitor. */
        goagain = true;
        cmd->real_action = cmd->action;
        cmd->action = pcmk__str_copy(PCMK_ACTION_MONITOR);
    } else if (cmd->real_action != NULL) {
        // This is follow-up monitor to check whether start/stop/probe(monitor) completed
        if (cmd->result.execution_status == PCMK_EXEC_PENDING) {
            goagain = true;

        } else if (pcmk__result_ok(&(cmd->result))
                   && pcmk__str_eq(cmd->real_action, PCMK_ACTION_STOP,
                                   pcmk__str_casei)) {
            goagain = true;

        } else {
            int time_sum = time_diff_ms(NULL, &(cmd->t_first_run));
            int timeout_left = cmd->timeout_orig - time_sum;

            pcmk__debug("%s systemd %s is now complete (elapsed=%dms, "
                        "remaining=%dms): %s (%d)",
                        cmd->rsc_id, cmd->real_action, time_sum, timeout_left,
                        crm_exit_str(cmd->result.exit_status),
                        cmd->result.exit_status);
            cmd_original_times(cmd);

            // Monitors may return "not running", but start/stop shouldn't
            if ((cmd->result.execution_status == PCMK_EXEC_DONE)
                && (cmd->result.exit_status == PCMK_OCF_NOT_RUNNING)) {

                if (pcmk__str_eq(cmd->real_action, PCMK_ACTION_START,
                                 pcmk__str_casei)) {
                    cmd->result.exit_status = PCMK_OCF_UNKNOWN_ERROR;
                } else if (pcmk__str_eq(cmd->real_action, PCMK_ACTION_STOP,
                                        pcmk__str_casei)) {
                    cmd->result.exit_status = PCMK_OCF_OK;
                }
            }
        }
    } else if (pcmk__str_any_of(cmd->action, PCMK_ACTION_MONITOR, PCMK_ACTION_STATUS, NULL)
               && (cmd->interval_ms > 0)) {
        /* For monitors, excluding follow-up monitors,                                  */
        /* if the pending state persists from the first notification until its timeout, */
        /* it will be treated as a timeout.                                             */

        if ((cmd->result.execution_status == PCMK_EXEC_PENDING) &&
            (cmd->last_notify_op_status == PCMK_EXEC_PENDING)) {
            int time_left = time(NULL) - (cmd->epoch_rcchange + (cmd->timeout_orig/1000));

            if (time_left >= 0) {
                pcmk__notice("Giving up on %s %s (rc=%d): monitor pending "
                             "timeout (first pending notification=%s "
                             "timeout=%dms)",
                             cmd->rsc_id, cmd->action, cmd->result.exit_status,
                             g_strchomp(ctime(&cmd->epoch_rcchange)),
                             cmd->timeout_orig);
                pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                                 PCMK_EXEC_TIMEOUT,
                                 "Investigate reason for timeout, and adjust "
                                 "configured operation timeout if necessary");
                cmd_original_times(cmd);
            }
        }
    }

    if (!goagain) {
        goto finalize;
    }

    time_sum = time_diff_ms(NULL, &(cmd->t_first_run));
    timeout_left = cmd->timeout_orig - time_sum;
    delay = cmd->timeout_orig / 10;

    if (delay >= timeout_left && timeout_left > 20) {
        delay = timeout_left/2;
    }

    delay = QB_MIN(2000, delay);
    if (delay < timeout_left) {
        cmd->start_delay = delay;
        cmd->timeout = timeout_left;

        if (pcmk__result_ok(&(cmd->result))) {
            pcmk__debug("%s %s may still be in progress: re-scheduling "
                        "(elapsed=%dms, remaining=%dms, start_delay=%dms)",
                        cmd->rsc_id, cmd->real_action, time_sum, timeout_left,
                        delay);

        } else if (cmd->result.execution_status == PCMK_EXEC_PENDING) {
            pcmk__info("%s %s is still in progress: re-scheduling "
                       "(elapsed=%dms, remaining=%dms, start_delay=%dms)",
                       cmd->rsc_id, cmd->action, time_sum, timeout_left, delay);

        } else {
            pcmk__notice("%s %s failed: %s: Re-scheduling (remaining timeout "
                         "%s) "
                         QB_XS " exitstatus=%d elapsed=%dms start_delay=%dms)",
                         cmd->rsc_id, cmd->action,
                         crm_exit_str(cmd->result.exit_status),
                         pcmk__readable_interval(timeout_left),
                         cmd->result.exit_status, time_sum, delay);
        }

        cmd_reset(cmd);
        if (rsc) {
            rsc->active = NULL;
        }
        schedule_lrmd_cmd(rsc, cmd);

        /* Don't finalize cmd, we're not done with it yet */
        return;

    } else {
        pcmk__notice("Giving up on %s %s (rc=%d): timeout (elapsed=%dms, "
                     "remaining=%dms)",
                     cmd->rsc_id, pcmk__s(cmd->real_action, cmd->action),
                     cmd->result.exit_status, time_sum, timeout_left);
        pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_TIMEOUT,
                         "Investigate reason for timeout, and adjust "
                         "configured operation timeout if necessary");
        cmd_original_times(cmd);
    }
#endif

finalize:
    pcmk__set_result_output(&(cmd->result), services__grab_stdout(action),
                            services__grab_stderr(action));
    cmd_finalize(cmd, rsc);
}

/*!
 * \internal
 * \brief Process the result of a fence device action (start, stop, or monitor)
 *
 * \param[in,out] cmd               Fence device action that completed
 * \param[in]     exit_status       Fencer API exit status for action
 * \param[in]     execution_status  Fencer API execution status for action
 * \param[in]     exit_reason       Human-friendly detail, if action failed
 */
static void
fencing_rsc_action_complete(lrmd_cmd_t *cmd, int exit_status,
                            enum pcmk_exec_status execution_status,
                            const char *exit_reason)
{
    // This can be NULL if resource was removed before command completed
    lrmd_rsc_t *rsc = g_hash_table_lookup(rsc_list, cmd->rsc_id);

    // Simplify fencer exit status to uniform exit status
    if (exit_status != CRM_EX_OK) {
        exit_status = PCMK_OCF_UNKNOWN_ERROR;
    }

    if (cmd->result.execution_status == PCMK_EXEC_CANCELLED) {
        /* An in-flight fence action was cancelled. The execution status is
         * already correct, so don't overwrite it.
         */
        execution_status = PCMK_EXEC_CANCELLED;

    } else {
        /* Some execution status codes have specific meanings for the fencer
         * that executor clients may not expect, so map them to a simple error
         * status.
         */
        switch (execution_status) {
            case PCMK_EXEC_NOT_CONNECTED:
            case PCMK_EXEC_INVALID:
                execution_status = PCMK_EXEC_ERROR;
                break;

            case PCMK_EXEC_NO_FENCE_DEVICE:
                /* This should be possible only for probes in practice, but
                 * interpret for all actions to be safe.
                 */
                if (pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                                 pcmk__str_none)) {
                    exit_status = PCMK_OCF_NOT_RUNNING;

                } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP,
                                        pcmk__str_none)) {
                    exit_status = PCMK_OCF_OK;

                } else {
                    exit_status = PCMK_OCF_NOT_INSTALLED;
                }
                execution_status = PCMK_EXEC_ERROR;
                break;

            case PCMK_EXEC_NOT_SUPPORTED:
                exit_status = PCMK_OCF_UNIMPLEMENT_FEATURE;
                break;

            default:
                break;
        }
    }

    pcmk__set_result(&cmd->result, exit_status, execution_status, exit_reason);

    // Certain successful actions change the known state of the resource
    if ((rsc != NULL) && pcmk__result_ok(&(cmd->result))) {

        if (pcmk__str_eq(cmd->action, PCMK_ACTION_START, pcmk__str_casei)) {
            pcmk__set_result(&rsc->fence_probe_result, CRM_EX_OK,
                             PCMK_EXEC_DONE, NULL); // "running"

        } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP,
                                pcmk__str_casei)) {
            pcmk__set_result(&rsc->fence_probe_result, CRM_EX_ERROR,
                             PCMK_EXEC_NO_FENCE_DEVICE, NULL); // "not running"
        }
    }

    /* The recurring timer should not be running at this point in any case, but
     * as a failsafe, stop it if it is.
     */
    stop_recurring_timer(cmd);

    /* Reschedule this command if appropriate. If a recurring command is *not*
     * rescheduled, its status must be PCMK_EXEC_CANCELLED, otherwise it will
     * not be removed from recurring_ops by cmd_finalize().
     */
    if (rsc && (cmd->interval_ms > 0)
        && (cmd->result.execution_status != PCMK_EXEC_CANCELLED)) {
        start_recurring_timer(cmd);
    }

    cmd_finalize(cmd, rsc);
}

void
execd_fencer_connection_failed(void)
{
    GHashTableIter iter;
    lrmd_rsc_t *rsc = NULL;

    pcmk__warn("Connection to fencer lost (any pending operations for fence "
               "devices will be considered failed)");

    g_hash_table_iter_init(&iter, rsc_list);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &rsc)) {
        if (!pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH,
                          pcmk__str_none)) {
            continue;
        }

        /* If we registered this fence device, we don't know whether the
         * fencer still has the registration or not. Cause future probes to
         * return an error until the resource is stopped or started
         * successfully. This is especially important if the controller also
         * went away (possibly due to a cluster layer restart) and won't
         * receive our client notification of any monitors finalized below.
         */
        if (rsc->fence_probe_result.execution_status == PCMK_EXEC_DONE) {
            pcmk__set_result(&rsc->fence_probe_result, CRM_EX_ERROR,
                             PCMK_EXEC_NOT_CONNECTED,
                             "Lost connection to fencer");
        }

        // Consider any active, pending, or recurring operations as failed

        for (GList *op = rsc->recurring_ops; op != NULL; op = op->next) {
            lrmd_cmd_t *cmd = op->data;

            /* This won't free a recurring op but instead restart its timer.
             * If cmd is rsc->active, this will set rsc->active to NULL, so we
             * don't have to worry about finalizing it a second time below.
             */
            fencing_rsc_action_complete(cmd, CRM_EX_ERROR,
                                        PCMK_EXEC_NOT_CONNECTED,
                                        "Lost connection to fencer");
        }

        if (rsc->active != NULL) {
            rsc->pending_ops = g_list_prepend(rsc->pending_ops, rsc->active);
        }
        while (rsc->pending_ops != NULL) {
            // This will free the op and remove it from rsc->pending_ops
            fencing_rsc_action_complete((lrmd_cmd_t *) rsc->pending_ops->data,
                                        CRM_EX_ERROR, PCMK_EXEC_NOT_CONNECTED,
                                        "Lost connection to fencer");
        }
    }
}

/*!
 * \internal
 * \brief Execute a fencing resource "start" action
 *
 * Start a fencing resource by registering it with the fencer. (Fencing agents
 * don't have a start command.)
 *
 * \param[in,out] fencer_api  Connection to fencer
 * \param[in]     rsc         Fencing resource to start
 * \param[in]     cmd         Start command to execute
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static int
start_fencing_rsc(stonith_t *fencer_api, const lrmd_rsc_t *rsc,
                  const lrmd_cmd_t *cmd)
{
    char *key = NULL;
    char *value = NULL;
    stonith_key_value_t *device_params = NULL;
    int rc = pcmk_ok;

    // Convert command parameters to fencer API key/values
    if (cmd->params) {
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, cmd->params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            device_params = stonith__key_value_add(device_params, key, value);
        }
    }

    /* The fencer will automatically register devices via CIB notifications
     * when the CIB changes, but to avoid a possible race condition between
     * the fencer receiving the notification and the executor requesting that
     * resource, the executor registers the device as well. The fencer knows how
     * to handle duplicate registrations.
     */
    rc = fencer_api->cmds->register_device(fencer_api, st_opt_sync_call,
                                           cmd->rsc_id, rsc->provider,
                                           rsc->type, device_params);

    stonith__key_value_freeall(device_params, true, true);
    return rc;
}

/*!
 * \internal
 * \brief Execute a fencing resource "stop" action
 *
 * Stop a fencing resource by unregistering it with the fencer. (Fencing agents
 * don't have a stop command.)
 *
 * \param[in,out] fencer_api  Connection to fencer
 * \param[in]     rsc         Fencing resource to stop
 *
 * \return pcmk_ok on success, -errno otherwise
 */
static inline int
stop_fencing_rsc(stonith_t *fencer_api, const lrmd_rsc_t *rsc)
{
    /* @TODO Failure would indicate a problem communicating with fencer;
     * perhaps we should try reconnecting and retrying a few times?
     */
    return fencer_api->cmds->remove_device(fencer_api, st_opt_sync_call,
                                           rsc->rsc_id);
}

static void
fencing_rsc_monitor_cb(stonith_t *stonith, stonith_callback_data_t *data)
{
    if ((data == NULL) || (data->userdata == NULL)) {
        pcmk__err("Ignoring fencing resource monitor result: "
                  "Invalid callback arguments (bug?)");
    } else {
        fencing_rsc_action_complete((lrmd_cmd_t *) data->userdata,
                                    stonith__exit_status(data),
                                    stonith__execution_status(data),
                                    stonith__exit_reason(data));
    }
}

/*!
 * \internal
 * \brief Initiate a fencing resource recurring "monitor" action
 *
 * \param[in,out] fencer_api  Connection to fencer
 * \param[in,out] rsc         Fencing resource to monitor
 * \param[in]     cmd         Monitor command being executed
 *
 * \return pcmk_ok if monitor was successfully initiated, -errno otherwise
 */
static inline int
monitor_fencing_rsc(stonith_t *fencer_api, lrmd_rsc_t *rsc, lrmd_cmd_t *cmd)
{
    int rc = fencer_api->cmds->monitor(fencer_api, 0, cmd->rsc_id,
                                       pcmk__timeout_ms2s(cmd->timeout));

    rc = fencer_api->cmds->register_callback(fencer_api, rc, 0, 0, cmd,
                                             "fencing_rsc_monitor_cb",
                                             fencing_rsc_monitor_cb);
    if (rc == TRUE) {
        rsc->active = cmd;
        rc = pcmk_ok;
    } else {
        rc = -pcmk_err_generic;
    }
    return rc;
}

static void
execute_stonith_action(lrmd_rsc_t *rsc, lrmd_cmd_t *cmd)
{
    int rc = pcmk_ok;
    const char *rc_s = NULL;
    bool do_monitor = false;

    // Don't free; belongs to pacemaker-execd.c
    stonith_t *fencer_api = execd_get_fencer_connection();

    if (pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR, pcmk__str_casei)
        && (cmd->interval_ms == 0)) {
        // Probes don't require a fencer connection
        fencing_rsc_action_complete(cmd, rsc->fence_probe_result.exit_status,
                                    rsc->fence_probe_result.execution_status,
                                    rsc->fence_probe_result.exit_reason);
        return;
    }

    if (fencer_api == NULL) {
        fencing_rsc_action_complete(cmd, PCMK_OCF_UNKNOWN_ERROR,
                                    PCMK_EXEC_NOT_CONNECTED,
                                    "No connection to fencer");
        return;
    }

    if (pcmk__str_eq(cmd->action, PCMK_ACTION_START, pcmk__str_casei)) {
        rc = start_fencing_rsc(fencer_api, rsc, cmd);
        if (rc == pcmk_ok) {
            do_monitor = true;
        }

    } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP, pcmk__str_casei)) {
        rc = stop_fencing_rsc(fencer_api, rsc);

    } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                            pcmk__str_casei)) {
        do_monitor = true;

    } else {
        fencing_rsc_action_complete(cmd, PCMK_OCF_UNIMPLEMENT_FEATURE,
                                    PCMK_EXEC_ERROR,
                                    "Invalid fence device action (bug?)");
        return;
    }

    if (do_monitor) {
        rc = monitor_fencing_rsc(fencer_api, rsc, cmd);
        if (rc == pcmk_ok) {
            // Don't clean up yet. We will get the result of the monitor later.
            return;
        }
    }

    if (rc != -pcmk_err_generic) {
        rc_s = pcmk_strerror(rc);
    }
    fencing_rsc_action_complete(cmd,
                                ((rc == pcmk_rc_ok)? CRM_EX_OK : CRM_EX_ERROR),
                                stonith__legacy2status(rc), rc_s);
}

static void
execute_nonstonith_action(lrmd_rsc_t *rsc, lrmd_cmd_t *cmd)
{
    svc_action_t *action = NULL;
    GHashTable *params_copy = NULL;

    pcmk__assert((rsc != NULL) && (cmd != NULL));

    pcmk__trace("Creating action, resource:%s action:%s class:%s provider:%s "
                "agent:%s",
                rsc->rsc_id, cmd->action, rsc->class, rsc->provider, rsc->type);

    params_copy = pcmk__str_table_dup(cmd->params);

    action = services__create_resource_action(rsc->rsc_id, rsc->class, rsc->provider,
                                     rsc->type,
                                     normalize_action_name(rsc, cmd->action),
                                     cmd->interval_ms, cmd->timeout,
                                     params_copy, cmd->service_flags);

    if (action == NULL) {
        pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_ERROR, strerror(ENOMEM));
        cmd_finalize(cmd, rsc);
        return;
    }

    if (action->rc != PCMK_OCF_UNKNOWN) {
        services__copy_result(action, &(cmd->result));
        services_action_free(action);
        cmd_finalize(cmd, rsc);
        return;
    }

    action->cb_data = cmd;

    if (services_action_async(action, action_complete)) {
        /* The services library has taken responsibility for the action. It
         * could be pending, blocked, or merged into a duplicate recurring
         * action, in which case the action callback (action_complete())
         * will be called when the action completes, otherwise the callback has
         * already been called.
         *
         * action_complete() calls cmd_finalize() which can free cmd, so cmd
         * cannot be used here.
         */
    } else {
        /* This is a recurring action that is not being cancelled and could not
         * be initiated. It has been rescheduled, and the action callback
         * (action_complete()) has been called, which in this case has already
         * called cmd_finalize(), which in this case should only reset (not
         * free) cmd.
         */
        services__copy_result(action, &(cmd->result));
        services_action_free(action);
    }
}

static gboolean
execute_resource_action(gpointer user_data)
{
    lrmd_rsc_t *rsc = (lrmd_rsc_t *) user_data;
    lrmd_cmd_t *cmd = NULL;

    CRM_CHECK(rsc != NULL, return FALSE);

    if (rsc->active) {
        pcmk__trace("%s is still active", rsc->rsc_id);
        return TRUE;
    }

    if (rsc->pending_ops) {
        GList *first = rsc->pending_ops;

        cmd = first->data;
        if (cmd->delay_id) {
            pcmk__trace("Command %s %s was asked to run too early, waiting for "
                        "start_delay timeout of %dms",
                        cmd->rsc_id, cmd->action, cmd->start_delay);
            return TRUE;
        }
        rsc->pending_ops = g_list_remove_link(rsc->pending_ops, first);
        g_list_free_1(first);

#ifdef PCMK__TIME_USE_CGT
        get_current_time(&(cmd->t_run), &(cmd->t_first_run));
#endif
        cmd->epoch_last_run = time(NULL);
    }

    if (!cmd) {
        pcmk__trace("Nothing further to do for %s", rsc->rsc_id);
        return TRUE;
    }

    rsc->active = cmd;          /* only one op at a time for a rsc */
    if (cmd->interval_ms) {
        rsc->recurring_ops = g_list_append(rsc->recurring_ops, cmd);
    }

    log_execute(cmd);

    if (pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        execute_stonith_action(rsc, cmd);
    } else {
        execute_nonstonith_action(rsc, cmd);
    }

    return TRUE;
}

void
execd_free_rsc(gpointer data)
{
    GList *gIter = NULL;
    lrmd_rsc_t *rsc = data;
    bool is_fencing_rsc = pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH,
                                       pcmk__str_casei);

    gIter = rsc->pending_ops;
    while (gIter != NULL) {
        GList *next = gIter->next;
        lrmd_cmd_t *cmd = gIter->data;

        /* command was never executed */
        cmd->result.execution_status = PCMK_EXEC_CANCELLED;
        cmd_finalize(cmd, NULL);

        gIter = next;
    }
    /* frees list, but not list elements. */
    g_list_free(rsc->pending_ops);

    gIter = rsc->recurring_ops;
    while (gIter != NULL) {
        GList *next = gIter->next;
        lrmd_cmd_t *cmd = gIter->data;

        if (is_fencing_rsc) {
            cmd->result.execution_status = PCMK_EXEC_CANCELLED;
            /* If a fencing resource's recurring operation is in-flight, just
             * mark it as cancelled. It is not safe to finalize/free the cmd
             * until the fencer API says it has either completed or timed out.
             */
            if (rsc->active != cmd) {
                cmd_finalize(cmd, NULL);
            }
        } else {
            /* This command is already handed off to service library,
             * let service library cancel it and tell us via the callback
             * when it is cancelled. The rsc can be safely destroyed
             * even if we are waiting for the cancel result */
            services_action_cancel(rsc->rsc_id,
                                   normalize_action_name(rsc, cmd->action),
                                   cmd->interval_ms);
        }

        gIter = next;
    }
    /* frees list, but not list elements. */
    g_list_free(rsc->recurring_ops);

    free(rsc->rsc_id);
    free(rsc->class);
    free(rsc->provider);
    free(rsc->type);
    mainloop_destroy_trigger(rsc->work);

    free(rsc);
}

int
execd_process_signon(pcmk__client_t *client, xmlNode *request, int call_id,
                     xmlNode **reply)
{
    int rc = pcmk_rc_ok;
    time_t now = time(NULL);
    const char *protocol_version = pcmk__xe_get(request,
                                                PCMK__XA_LRMD_PROTOCOL_VERSION);
    const char *start_state = pcmk__env_option(PCMK__ENV_NODE_START_STATE);

    if (pcmk__compare_versions(protocol_version,
                               LRMD_COMPATIBLE_PROTOCOL) < 0) {
        pcmk__err("Cluster API version must be greater than or equal to "
                  LRMD_COMPATIBLE_PROTOCOL " , not %s",
                  protocol_version);
        rc = EPROTO;
    }

    if (pcmk__xe_attr_is_true(request, PCMK__XA_LRMD_IS_IPC_PROVIDER)) {
#ifdef PCMK__COMPILE_REMOTE
        if ((client->remote != NULL)
            && pcmk__is_set(client->flags,
                            pcmk__client_tls_handshake_complete)) {
            const char *op = pcmk__xe_get(request, PCMK__XA_LRMD_OP);

            // This is a remote connection from a cluster node's controller
            ipc_proxy_add_provider(client);

            /* @TODO Allowing multiple proxies makes no sense given that clients
             * have no way to choose between them. Maybe always use the most
             * recent one and switch any existing IPC connections to use it,
             * by iterating over ipc_clients here, and if client->id doesn't
             * match the client's userdata, replace the userdata with the new
             * ID. After the iteration, call lrmd_remote_client_destroy() on any
             * of the replaced values in ipc_providers.
             */

            /* If this was a register operation, also ask for new schema files but
             * only if it's supported by the protocol version.
             */
            if (pcmk__str_eq(op, CRM_OP_REGISTER, pcmk__str_none) &&
                LRMD_SUPPORTS_SCHEMA_XFER(protocol_version)) {
                remoted_request_cib_schema_files();
            }
        } else {
            rc = EACCES;
        }
#else
        rc = EPROTONOSUPPORT;
#endif
    }

    pcmk__assert(reply != NULL);

    *reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    pcmk__xe_set(*reply, PCMK__XA_LRMD_OP, CRM_OP_REGISTER);
    pcmk__xe_set(*reply, PCMK__XA_LRMD_CLIENTID, client->id);
    pcmk__xe_set(*reply, PCMK__XA_LRMD_PROTOCOL_VERSION, LRMD_PROTOCOL_VERSION);
    pcmk__xe_set_time(*reply, PCMK__XA_UPTIME, now - start_time);

    if (start_state) {
        pcmk__xe_set(*reply, PCMK__XA_NODE_START_STATE, start_state);
    }

    return rc;
}

void
execd_process_rsc_register(pcmk__client_t *client, uint32_t id, xmlNode *request)
{
    lrmd_rsc_t *rsc = build_rsc_from_xml(request);
    lrmd_rsc_t *dup = g_hash_table_lookup(rsc_list, rsc->rsc_id);

    if (dup &&
        pcmk__str_eq(rsc->class, dup->class, pcmk__str_casei) &&
        pcmk__str_eq(rsc->provider, dup->provider, pcmk__str_casei) &&
        pcmk__str_eq(rsc->type, dup->type, pcmk__str_casei)) {

        pcmk__notice("Ignoring duplicate registration of '%s'", rsc->rsc_id);
        execd_free_rsc(rsc);
        return;
    }

    g_hash_table_replace(rsc_list, rsc->rsc_id, rsc);
    pcmk__info("Cached agent information for '%s'", rsc->rsc_id);
}

int
execd_process_get_rsc_info(xmlNode *request, int call_id, xmlNode **reply)
{
    int rc = pcmk_rc_ok;
    xmlNode *rsc_xml = pcmk__xpath_find_one(request->doc,
                                            "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    const char *rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);
    lrmd_rsc_t *rsc = NULL;

    if (rsc_id == NULL) {
        rc = ENODEV;
    } else {
        rsc = g_hash_table_lookup(rsc_list, rsc_id);
        if (rsc == NULL) {
            pcmk__info("Agent information for '%s' not in cache", rsc_id);
            rc = ENODEV;
        }
    }

    CRM_LOG_ASSERT(reply != NULL);

    *reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    if (rsc) {
        pcmk__xe_set(*reply, PCMK__XA_LRMD_RSC_ID, rsc->rsc_id);
        pcmk__xe_set(*reply, PCMK__XA_LRMD_CLASS, rsc->class);
        pcmk__xe_set(*reply, PCMK__XA_LRMD_PROVIDER, rsc->provider);
        pcmk__xe_set(*reply, PCMK__XA_LRMD_TYPE, rsc->type);
    }

    return rc;
}

int
execd_process_rsc_unregister(pcmk__client_t *client, xmlNode *request)
{
    int rc = pcmk_rc_ok;
    lrmd_rsc_t *rsc = NULL;
    xmlNode *rsc_xml = pcmk__xpath_find_one(request->doc,
                                            "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    const char *rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);

    if (!rsc_id) {
        return ENODEV;
    }

    rsc = g_hash_table_lookup(rsc_list, rsc_id);
    if (rsc == NULL) {
        pcmk__info("Ignoring unregistration of resource '%s', which is not "
                   "registered", rsc_id);
        return pcmk_rc_ok;
    }

    if (rsc->active) {
        /* let the caller know there are still active ops on this rsc to watch for */
        pcmk__trace("Operation (%p) still in progress for unregistered "
                    "resource %s", rsc->active, rsc_id);
        rc = EINPROGRESS;
    }

    g_hash_table_remove(rsc_list, rsc_id);

    return rc;
}

int
execd_process_rsc_exec(pcmk__client_t *client, xmlNode *request)
{
    lrmd_rsc_t *rsc = NULL;
    lrmd_cmd_t *cmd = NULL;
    xmlNode *rsc_xml = pcmk__xpath_find_one(request->doc,
                                            "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    const char *rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);

    if (!rsc_id) {
        return EINVAL;
    }

    if (!(rsc = g_hash_table_lookup(rsc_list, rsc_id))) {
        pcmk__info("Resource '%s' not found (%d active resources)", rsc_id,
                   g_hash_table_size(rsc_list));
        return ENODEV;
    }

    cmd = create_lrmd_cmd(request, client);

    /* Don't reference cmd after handing it off to be scheduled.
     * The cmd could get merged and freed. */
    schedule_lrmd_cmd(rsc, cmd);

    return pcmk_rc_ok;
}

static int
cancel_op(const char *rsc_id, const char *action, guint interval_ms)
{
    GList *gIter = NULL;
    lrmd_rsc_t *rsc = g_hash_table_lookup(rsc_list, rsc_id);

    /* How to cancel an action.
     * 1. Check pending ops list, if it hasn't been handed off
     *    to the service library or stonith recurring list remove
     *    it there and that will stop it.
     * 2. If it isn't in the pending ops list, then it's either a
     *    recurring op in the stonith recurring list, or the service
     *    library's recurring list.  Stop it there
     * 3. If not found in any lists, then this operation has either
     *    been executed already and is not a recurring operation, or
     *    never existed.
     */
    if (!rsc) {
        return ENODEV;
    }

    for (gIter = rsc->pending_ops; gIter != NULL; gIter = gIter->next) {
        lrmd_cmd_t *cmd = gIter->data;

        if (action_matches(cmd, action, interval_ms)) {
            cmd->result.execution_status = PCMK_EXEC_CANCELLED;
            cmd_finalize(cmd, rsc);
            return pcmk_rc_ok;
        }
    }

    if (pcmk__str_eq(rsc->class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        /* The service library does not handle stonith operations.
         * We have to handle recurring stonith operations ourselves. */
        for (gIter = rsc->recurring_ops; gIter != NULL; gIter = gIter->next) {
            lrmd_cmd_t *cmd = gIter->data;

            if (action_matches(cmd, action, interval_ms)) {
                cmd->result.execution_status = PCMK_EXEC_CANCELLED;
                if (rsc->active != cmd) {
                    cmd_finalize(cmd, rsc);
                }
                return pcmk_rc_ok;
            }
        }
    } else if (services_action_cancel(rsc_id,
                                      normalize_action_name(rsc, action),
                                      interval_ms) == TRUE) {
        /* The service library will tell the action_complete callback function
         * this action was cancelled, which will destroy the cmd and remove
         * it from the recurring_op list. Do not do that in this function
         * if the service library says it cancelled it. */
        return pcmk_rc_ok;
    }

    return EOPNOTSUPP;
}

static void
cancel_all_recurring(lrmd_rsc_t * rsc, const char *client_id)
{
    GList *cmd_list = NULL;
    GList *cmd_iter = NULL;

    /* Notice a copy of each list is created when concat is called.
     * This prevents odd behavior from occurring when the cmd_list
     * is iterated through later on.  It is possible the cancel_op
     * function may end up modifying the recurring_ops and pending_ops
     * lists.  If we did not copy those lists, our cmd_list iteration
     * could get messed up.*/
    if (rsc->recurring_ops) {
        cmd_list = g_list_concat(cmd_list, g_list_copy(rsc->recurring_ops));
    }
    if (rsc->pending_ops) {
        cmd_list = g_list_concat(cmd_list, g_list_copy(rsc->pending_ops));
    }
    if (!cmd_list) {
        return;
    }

    for (cmd_iter = cmd_list; cmd_iter; cmd_iter = cmd_iter->next) {
        lrmd_cmd_t *cmd = cmd_iter->data;

        if (cmd->interval_ms == 0) {
            continue;
        }

        if (client_id && !pcmk__str_eq(cmd->client_id, client_id, pcmk__str_casei)) {
            continue;
        }

        cancel_op(rsc->rsc_id, cmd->action, cmd->interval_ms);
    }
    /* frees only the copied list data, not the cmds */
    g_list_free(cmd_list);
}

int
execd_process_rsc_cancel(pcmk__client_t *client, xmlNode *request)
{
    xmlNode *rsc_xml = pcmk__xpath_find_one(request->doc,
                                            "//" PCMK__XE_LRMD_RSC,
                                            LOG_ERR);
    const char *rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);
    const char *action = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ACTION);
    guint interval_ms = 0;

    pcmk__xe_get_guint(rsc_xml, PCMK__XA_LRMD_RSC_INTERVAL, &interval_ms);

    if (!rsc_id || !action) {
        return EINVAL;
    }

    return cancel_op(rsc_id, action, interval_ms);
}

static void
add_recurring_op_xml(xmlNode *reply, lrmd_rsc_t *rsc)
{
    xmlNode *rsc_xml = pcmk__xe_create(reply, PCMK__XE_LRMD_RSC);

    pcmk__xe_set(rsc_xml, PCMK__XA_LRMD_RSC_ID, rsc->rsc_id);
    for (GList *item = rsc->recurring_ops; item != NULL; item = item->next) {
        lrmd_cmd_t *cmd = item->data;
        xmlNode *op_xml = pcmk__xe_create(rsc_xml, PCMK__XE_LRMD_RSC_OP);

        pcmk__xe_set(op_xml, PCMK__XA_LRMD_RSC_ACTION,
                     pcmk__s(cmd->real_action, cmd->action));
        pcmk__xe_set_guint(op_xml, PCMK__XA_LRMD_RSC_INTERVAL,
                           cmd->interval_ms);
        pcmk__xe_set_int(op_xml, PCMK__XA_LRMD_TIMEOUT, cmd->timeout_orig);
    }
}

int
execd_process_get_recurring(xmlNode *request, int call_id, xmlNode **reply)
{
    int rc = pcmk_rc_ok;
    const char *rsc_id = NULL;
    lrmd_rsc_t *rsc = NULL;
    xmlNode *rsc_xml = NULL;

    // Resource ID is optional
    rsc_xml = pcmk__xe_first_child(request, PCMK__XE_LRMD_CALLDATA, NULL, NULL);
    if (rsc_xml) {
        rsc_xml = pcmk__xe_first_child(rsc_xml, PCMK__XE_LRMD_RSC, NULL, NULL);
    }
    if (rsc_xml) {
        rsc_id = pcmk__xe_get(rsc_xml, PCMK__XA_LRMD_RSC_ID);
    }

    // If resource ID is specified, resource must exist
    if (rsc_id != NULL) {
        rsc = g_hash_table_lookup(rsc_list, rsc_id);
        if (rsc == NULL) {
            pcmk__info("Resource '%s' not found (%d active resources)", rsc_id,
                       g_hash_table_size(rsc_list));
            rc = ENODEV;
        }
    }

    CRM_LOG_ASSERT(reply != NULL);

    *reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);

    // If resource ID is not specified, check all resources
    if (rsc_id == NULL) {
        GHashTableIter iter;
        char *key = NULL;

        g_hash_table_iter_init(&iter, rsc_list);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                      (gpointer *) &rsc)) {
            add_recurring_op_xml(*reply, rsc);
        }
    } else if (rsc) {
        add_recurring_op_xml(*reply, rsc);
    }

    return rc;
}
