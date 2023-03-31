/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <regex.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/lrmd.h>           // lrmd_event_data_t, lrmd_rsc_info_t, etc.
#include <crm/services.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules.h>
#include <crm/lrmd_internal.h>

#include <pacemaker-internal.h>
#include <pacemaker-controld.h>

#define START_DELAY_THRESHOLD 5 * 60 * 1000
#define MAX_LRM_REG_FAILS 30

struct delete_event_s {
    int rc;
    const char *rsc;
    lrm_state_t *lrm_state;
};

static gboolean is_rsc_active(lrm_state_t * lrm_state, const char *rsc_id);
static gboolean build_active_RAs(lrm_state_t * lrm_state, xmlNode * rsc_list);
static gboolean stop_recurring_actions(gpointer key, gpointer value, gpointer user_data);

static lrmd_event_data_t *construct_op(const lrm_state_t *lrm_state,
                                       const xmlNode *rsc_op,
                                       const char *rsc_id,
                                       const char *operation);
static void do_lrm_rsc_op(lrm_state_t *lrm_state, lrmd_rsc_info_t *rsc,
                          xmlNode *msg, struct ra_metadata_s *md);

static gboolean lrm_state_verify_stopped(lrm_state_t * lrm_state, enum crmd_fsa_state cur_state,
                                         int log_level);

static void
lrm_connection_destroy(void)
{
    if (pcmk_is_set(controld_globals.fsa_input_register, R_LRM_CONNECTED)) {
        crm_crit("Connection to executor failed");
        register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
        controld_clear_fsa_input_flags(R_LRM_CONNECTED);

    } else {
        crm_info("Disconnected from executor");
    }

}

static char *
make_stop_id(const char *rsc, int call_id)
{
    return crm_strdup_printf("%s:%d", rsc, call_id);
}

static void
copy_instance_keys(gpointer key, gpointer value, gpointer user_data)
{
    if (strstr(key, CRM_META "_") == NULL) {
        g_hash_table_replace(user_data, strdup((const char *)key), strdup((const char *)value));
    }
}

static void
copy_meta_keys(gpointer key, gpointer value, gpointer user_data)
{
    if (strstr(key, CRM_META "_") != NULL) {
        g_hash_table_replace(user_data, strdup((const char *)key), strdup((const char *)value));
    }
}

/*!
 * \internal
 * \brief Remove a recurring operation from a resource's history
 *
 * \param[in,out] history  Resource history to modify
 * \param[in]     op       Operation to remove
 *
 * \return TRUE if the operation was found and removed, FALSE otherwise
 */
static gboolean
history_remove_recurring_op(rsc_history_t *history, const lrmd_event_data_t *op)
{
    GList *iter;

    for (iter = history->recurring_op_list; iter != NULL; iter = iter->next) {
        lrmd_event_data_t *existing = iter->data;

        if ((op->interval_ms == existing->interval_ms)
            && pcmk__str_eq(op->rsc_id, existing->rsc_id, pcmk__str_none)
            && pcmk__str_eq(op->op_type, existing->op_type, pcmk__str_casei)) {

            history->recurring_op_list = g_list_delete_link(history->recurring_op_list, iter);
            lrmd_free_event(existing);
            return TRUE;
        }
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Free all recurring operations in resource history
 *
 * \param[in,out] history  Resource history to modify
 */
static void
history_free_recurring_ops(rsc_history_t *history)
{
    GList *iter;

    for (iter = history->recurring_op_list; iter != NULL; iter = iter->next) {
        lrmd_free_event(iter->data);
    }
    g_list_free(history->recurring_op_list);
    history->recurring_op_list = NULL;
}

/*!
 * \internal
 * \brief Free resource history
 *
 * \param[in,out] history  Resource history to free
 */
void
history_free(gpointer data)
{
    rsc_history_t *history = (rsc_history_t*)data;

    if (history->stop_params) {
        g_hash_table_destroy(history->stop_params);
    }

    /* Don't need to free history->rsc.id because it's set to history->id */
    free(history->rsc.type);
    free(history->rsc.standard);
    free(history->rsc.provider);

    lrmd_free_event(history->failed);
    lrmd_free_event(history->last);
    free(history->id);
    history_free_recurring_ops(history);
    free(history);
}

static void
update_history_cache(lrm_state_t * lrm_state, lrmd_rsc_info_t * rsc, lrmd_event_data_t * op)
{
    int target_rc = 0;
    rsc_history_t *entry = NULL;

    if (op->rsc_deleted) {
        crm_debug("Purged history for '%s' after %s", op->rsc_id, op->op_type);
        controld_delete_resource_history(op->rsc_id, lrm_state->node_name,
                                         NULL, crmd_cib_smart_opt());
        return;
    }

    if (pcmk__str_eq(op->op_type, RSC_NOTIFY, pcmk__str_casei)) {
        return;
    }

    crm_debug("Updating history for '%s' with %s op", op->rsc_id, op->op_type);

    entry = g_hash_table_lookup(lrm_state->resource_history, op->rsc_id);
    if (entry == NULL && rsc) {
        entry = calloc(1, sizeof(rsc_history_t));
        entry->id = strdup(op->rsc_id);
        g_hash_table_insert(lrm_state->resource_history, entry->id, entry);

        entry->rsc.id = entry->id;
        entry->rsc.type = strdup(rsc->type);
        entry->rsc.standard = strdup(rsc->standard);
        pcmk__str_update(&entry->rsc.provider, rsc->provider);

    } else if (entry == NULL) {
        crm_info("Resource %s no longer exists, not updating cache", op->rsc_id);
        return;
    }

    entry->last_callid = op->call_id;
    target_rc = rsc_op_expected_rc(op);
    if (op->op_status == PCMK_EXEC_CANCELLED) {
        if (op->interval_ms > 0) {
            crm_trace("Removing cancelled recurring op: " PCMK__OP_FMT,
                      op->rsc_id, op->op_type, op->interval_ms);
            history_remove_recurring_op(entry, op);
            return;
        } else {
            crm_trace("Skipping " PCMK__OP_FMT " rc=%d, status=%d",
                      op->rsc_id, op->op_type, op->interval_ms, op->rc,
                      op->op_status);
        }

    } else if (did_rsc_op_fail(op, target_rc)) {
        /* Store failed monitors here, otherwise the block below will cause them
         * to be forgotten when a stop happens.
         */
        if (entry->failed) {
            lrmd_free_event(entry->failed);
        }
        entry->failed = lrmd_copy_event(op);

    } else if (op->interval_ms == 0) {
        if (entry->last) {
            lrmd_free_event(entry->last);
        }
        entry->last = lrmd_copy_event(op);

        if (op->params && pcmk__strcase_any_of(op->op_type, CRMD_ACTION_START,
                                               CRMD_ACTION_RELOAD,
                                               CRMD_ACTION_RELOAD_AGENT,
                                               CRMD_ACTION_STATUS, NULL)) {
            if (entry->stop_params) {
                g_hash_table_destroy(entry->stop_params);
            }
            entry->stop_params = pcmk__strkey_table(free, free);

            g_hash_table_foreach(op->params, copy_instance_keys, entry->stop_params);
        }
    }

    if (op->interval_ms > 0) {
        /* Ensure there are no duplicates */
        history_remove_recurring_op(entry, op);

        crm_trace("Adding recurring op: " PCMK__OP_FMT,
                  op->rsc_id, op->op_type, op->interval_ms);
        entry->recurring_op_list = g_list_prepend(entry->recurring_op_list, lrmd_copy_event(op));

    } else if (entry->recurring_op_list && !pcmk__str_eq(op->op_type, RSC_STATUS, pcmk__str_casei)) {
        crm_trace("Dropping %d recurring ops because of: " PCMK__OP_FMT,
                  g_list_length(entry->recurring_op_list), op->rsc_id,
                  op->op_type, op->interval_ms);
        history_free_recurring_ops(entry);
    }
}

/*!
 * \internal
 * \brief Send a direct OK ack for a resource task
 *
 * \param[in] lrm_state  LRM connection
 * \param[in] input      Input message being ack'ed
 * \param[in] rsc_id     ID of affected resource
 * \param[in] rsc        Affected resource (if available)
 * \param[in] task       Operation task being ack'ed
 * \param[in] ack_host   Name of host to send ack to
 * \param[in] ack_sys    IPC system name to ack
 */
static void
send_task_ok_ack(const lrm_state_t *lrm_state, const ha_msg_input_t *input,
                 const char *rsc_id, const lrmd_rsc_info_t *rsc,
                 const char *task, const char *ack_host, const char *ack_sys)
{
    lrmd_event_data_t *op = construct_op(lrm_state, input->xml, rsc_id, task);

    lrmd__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
    controld_ack_event_directly(ack_host, ack_sys, rsc, op, rsc_id);
    lrmd_free_event(op);
}

static inline const char *
op_node_name(lrmd_event_data_t *op)
{
    return pcmk__s(op->remote_nodename, controld_globals.our_nodename);
}

void
lrm_op_callback(lrmd_event_data_t * op)
{
    CRM_CHECK(op != NULL, return);
    switch (op->type) {
        case lrmd_event_disconnect:
            if (op->remote_nodename == NULL) {
                /* If this is the local executor IPC connection, set the right
                 * bits in the controller when the connection goes down.
                 */
                lrm_connection_destroy();
            }
            break;

        case lrmd_event_exec_complete:
            {
                lrm_state_t *lrm_state = lrm_state_find(op_node_name(op));

                CRM_ASSERT(lrm_state != NULL);
                process_lrm_event(lrm_state, op, NULL, NULL);
            }
            break;

        default:
            break;
    }
}

static void
try_local_executor_connect(long long action, fsa_data_t *msg_data,
                           lrm_state_t *lrm_state)
{
    int rc = pcmk_rc_ok;

    crm_debug("Connecting to the local executor");

    // If we can connect, great
    rc = controld_connect_local_executor(lrm_state);
    if (rc == pcmk_rc_ok) {
        controld_set_fsa_input_flags(R_LRM_CONNECTED);
        crm_info("Connection to the local executor established");
        return;
    }

    // Otherwise, if we can try again, set a timer to do so
    if (lrm_state->num_lrm_register_fails < MAX_LRM_REG_FAILS) {
        crm_warn("Failed to connect to the local executor %d time%s "
                 "(%d max): %s", lrm_state->num_lrm_register_fails,
                 pcmk__plural_s(lrm_state->num_lrm_register_fails),
                 MAX_LRM_REG_FAILS, pcmk_rc_str(rc));
        controld_start_wait_timer();
        crmd_fsa_stall(FALSE);
        return;
    }

    // Otherwise give up
    crm_err("Failed to connect to the executor the max allowed "
            "%d time%s: %s", lrm_state->num_lrm_register_fails,
            pcmk__plural_s(lrm_state->num_lrm_register_fails),
            pcmk_rc_str(rc));
    register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
}

/*	 A_LRM_CONNECT	*/
void
do_lrm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    /* This only pertains to local executor connections. Remote connections are
     * handled as resources within the scheduler. Connecting and disconnecting
     * from remote executor instances is handled differently.
     */

    lrm_state_t *lrm_state = NULL;

    if (controld_globals.our_nodename == NULL) {
        return; /* Nothing to do */
    }
    lrm_state = lrm_state_find_or_create(controld_globals.our_nodename);
    if (lrm_state == NULL) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        return;
    }

    if (action & A_LRM_DISCONNECT) {
        if (lrm_state_verify_stopped(lrm_state, cur_state, LOG_INFO) == FALSE) {
            if (action == A_LRM_DISCONNECT) {
                crmd_fsa_stall(FALSE);
                return;
            }
        }

        controld_clear_fsa_input_flags(R_LRM_CONNECTED);
        crm_info("Disconnecting from the executor");
        lrm_state_disconnect(lrm_state);
        lrm_state_reset_tables(lrm_state, FALSE);
        crm_notice("Disconnected from the executor");
    }

    if (action & A_LRM_CONNECT) {
        try_local_executor_connect(action, msg_data, lrm_state);
    }

    if (action & ~(A_LRM_CONNECT | A_LRM_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action),
                __func__);
    }
}

static gboolean
lrm_state_verify_stopped(lrm_state_t * lrm_state, enum crmd_fsa_state cur_state, int log_level)
{
    int counter = 0;
    gboolean rc = TRUE;
    const char *when = "lrm disconnect";

    GHashTableIter gIter;
    const char *key = NULL;
    rsc_history_t *entry = NULL;
    active_op_t *pending = NULL;

    crm_debug("Checking for active resources before exit");

    if (cur_state == S_TERMINATE) {
        log_level = LOG_ERR;
        when = "shutdown";

    } else if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        when = "shutdown... waiting";
    }

    if ((lrm_state->active_ops != NULL) && lrm_state_is_connected(lrm_state)) {
        guint removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                                    stop_recurring_actions,
                                                    lrm_state);
        guint nremaining = g_hash_table_size(lrm_state->active_ops);

        if (removed || nremaining) {
            crm_notice("Stopped %u recurring operation%s at %s (%u remaining)",
                       removed, pcmk__plural_s(removed), when, nremaining);
        }
    }

    if (lrm_state->active_ops != NULL) {
        g_hash_table_iter_init(&gIter, lrm_state->active_ops);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&pending)) {
            /* Ignore recurring actions in the shutdown calculations */
            if (pending->interval_ms == 0) {
                counter++;
            }
        }
    }

    if (counter > 0) {
        do_crm_log(log_level, "%d pending executor operation%s at %s",
                   counter, pcmk__plural_s(counter), when);

        if ((cur_state == S_TERMINATE)
            || !pcmk_is_set(controld_globals.fsa_input_register,
                            R_SENT_RSC_STOP)) {
            g_hash_table_iter_init(&gIter, lrm_state->active_ops);
            while (g_hash_table_iter_next(&gIter, (gpointer*)&key, (gpointer*)&pending)) {
                do_crm_log(log_level, "Pending action: %s (%s)", key, pending->op_key);
            }

        } else {
            rc = FALSE;
        }
        return rc;
    }

    if (lrm_state->resource_history == NULL) {
        return rc;
    }

    if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        /* At this point we're not waiting, we're just shutting down */
        when = "shutdown";
    }

    counter = 0;
    g_hash_table_iter_init(&gIter, lrm_state->resource_history);
    while (g_hash_table_iter_next(&gIter, NULL, (gpointer*)&entry)) {
        if (is_rsc_active(lrm_state, entry->id) == FALSE) {
            continue;
        }

        counter++;
        if (log_level == LOG_ERR) {
            crm_info("Found %s active at %s", entry->id, when);
        } else {
            crm_trace("Found %s active at %s", entry->id, when);
        }
        if (lrm_state->active_ops != NULL) {
            GHashTableIter hIter;

            g_hash_table_iter_init(&hIter, lrm_state->active_ops);
            while (g_hash_table_iter_next(&hIter, (gpointer*)&key, (gpointer*)&pending)) {
                if (pcmk__str_eq(entry->id, pending->rsc_id, pcmk__str_none)) {
                    crm_notice("%sction %s (%s) incomplete at %s",
                               pending->interval_ms == 0 ? "A" : "Recurring a",
                               key, pending->op_key, when);
                }
            }
        }
    }

    if (counter) {
        crm_err("%d resource%s active at %s",
                counter, (counter == 1)? " was" : "s were", when);
    }

    return rc;
}

static gboolean
is_rsc_active(lrm_state_t * lrm_state, const char *rsc_id)
{
    rsc_history_t *entry = NULL;

    entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
    if (entry == NULL || entry->last == NULL) {
        return FALSE;
    }

    crm_trace("Processing %s: %s.%d=%d", rsc_id, entry->last->op_type,
              entry->last->interval_ms, entry->last->rc);
    if (entry->last->rc == PCMK_OCF_OK && pcmk__str_eq(entry->last->op_type, CRMD_ACTION_STOP, pcmk__str_casei)) {
        return FALSE;

    } else if (entry->last->rc == PCMK_OCF_OK
               && pcmk__str_eq(entry->last->op_type, CRMD_ACTION_MIGRATE, pcmk__str_casei)) {
        // A stricter check is too complex ... leave that to the scheduler
        return FALSE;

    } else if (entry->last->rc == PCMK_OCF_NOT_RUNNING) {
        return FALSE;

    } else if ((entry->last->interval_ms == 0)
               && (entry->last->rc == PCMK_OCF_NOT_CONFIGURED)) {
        /* Badly configured resources can't be reliably stopped */
        return FALSE;
    }

    return TRUE;
}

static gboolean
build_active_RAs(lrm_state_t * lrm_state, xmlNode * rsc_list)
{
    GHashTableIter iter;
    rsc_history_t *entry = NULL;

    g_hash_table_iter_init(&iter, lrm_state->resource_history);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&entry)) {

        GList *gIter = NULL;
        xmlNode *xml_rsc = create_xml_node(rsc_list, XML_LRM_TAG_RESOURCE);

        crm_xml_add(xml_rsc, XML_ATTR_ID, entry->id);
        crm_xml_add(xml_rsc, XML_ATTR_TYPE, entry->rsc.type);
        crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, entry->rsc.standard);
        crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, entry->rsc.provider);

        if (entry->last && entry->last->params) {
            const char *container = g_hash_table_lookup(entry->last->params, CRM_META"_"XML_RSC_ATTR_CONTAINER);
            if (container) {
                crm_trace("Resource %s is a part of container resource %s", entry->id, container);
                crm_xml_add(xml_rsc, XML_RSC_ATTR_CONTAINER, container);
            }
        }
        controld_add_resource_history_xml(xml_rsc, &(entry->rsc), entry->failed,
                                          lrm_state->node_name);
        controld_add_resource_history_xml(xml_rsc, &(entry->rsc), entry->last,
                                          lrm_state->node_name);
        for (gIter = entry->recurring_op_list; gIter != NULL; gIter = gIter->next) {
            controld_add_resource_history_xml(xml_rsc, &(entry->rsc), gIter->data,
                                              lrm_state->node_name);
        }
    }

    return FALSE;
}

xmlNode *
controld_query_executor_state(void)
{
    xmlNode *xml_state = NULL;
    xmlNode *xml_data = NULL;
    xmlNode *rsc_list = NULL;
    crm_node_t *peer = NULL;
    lrm_state_t *lrm_state = lrm_state_find(controld_globals.our_nodename);

    if (!lrm_state) {
        crm_err("Could not find executor state for node %s",
                controld_globals.our_nodename);
        return NULL;
    }

    peer = crm_get_peer_full(0, lrm_state->node_name, CRM_GET_PEER_ANY);
    CRM_CHECK(peer != NULL, return NULL);

    xml_state = create_node_state_update(peer,
                                         node_update_cluster|node_update_peer,
                                         NULL, __func__);
    if (xml_state == NULL) {
        return NULL;
    }

    xml_data = create_xml_node(xml_state, XML_CIB_TAG_LRM);
    crm_xml_add(xml_data, XML_ATTR_ID, peer->uuid);
    rsc_list = create_xml_node(xml_data, XML_LRM_TAG_RESOURCES);

    /* Build a list of active (not always running) resources */
    build_active_RAs(lrm_state, rsc_list);

    crm_log_xml_trace(xml_state, "Current executor state");

    return xml_state;
}

/*!
 * \internal
 * \brief Map standard Pacemaker return code to operation status and OCF code
 *
 * \param[out] event  Executor event whose status and return code should be set
 * \param[in]  rc     Standard Pacemaker return code
 */
void
controld_rc2event(lrmd_event_data_t *event, int rc)
{
    /* This is called for cleanup requests from controller peers/clients, not
     * for resource actions, so no exit reason is needed.
     */
    switch (rc) {
        case pcmk_rc_ok:
            lrmd__set_result(event, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            break;
        case EACCES:
            lrmd__set_result(event, PCMK_OCF_INSUFFICIENT_PRIV,
                             PCMK_EXEC_ERROR, NULL);
            break;
        default:
            lrmd__set_result(event, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_ERROR,
                             NULL);
            break;
    }
}

/*!
 * \internal
 * \brief Trigger a new transition after CIB status was deleted
 *
 * If a CIB status delete was not expected (as part of the transition graph),
 * trigger a new transition by updating the (arbitrary) "last-lrm-refresh"
 * cluster property.
 *
 * \param[in] from_sys  IPC name that requested the delete
 * \param[in] rsc_id    Resource whose status was deleted (for logging only)
 */
void
controld_trigger_delete_refresh(const char *from_sys, const char *rsc_id)
{
    if (!pcmk__str_eq(from_sys, CRM_SYSTEM_TENGINE, pcmk__str_casei)) {
        char *now_s = crm_strdup_printf("%lld", (long long) time(NULL));

        crm_debug("Triggering a refresh after %s cleaned %s", from_sys, rsc_id);
        cib__update_node_attr(controld_globals.logger_out,
                              controld_globals.cib_conn, cib_none,
                              XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                              "last-lrm-refresh", now_s, NULL, NULL);
        free(now_s);
    }
}

static void
notify_deleted(lrm_state_t * lrm_state, ha_msg_input_t * input, const char *rsc_id, int rc)
{
    lrmd_event_data_t *op = NULL;
    const char *from_sys = crm_element_value(input->msg, F_CRM_SYS_FROM);
    const char *from_host = crm_element_value(input->msg, F_CRM_HOST_FROM);

    crm_info("Notifying %s on %s that %s was%s deleted",
             from_sys, (from_host? from_host : "localhost"), rsc_id,
             ((rc == pcmk_ok)? "" : " not"));
    op = construct_op(lrm_state, input->xml, rsc_id, CRMD_ACTION_DELETE);
    controld_rc2event(op, pcmk_legacy2rc(rc));
    controld_ack_event_directly(from_host, from_sys, NULL, op, rsc_id);
    lrmd_free_event(op);
    controld_trigger_delete_refresh(from_sys, rsc_id);
}

static gboolean
lrm_remove_deleted_rsc(gpointer key, gpointer value, gpointer user_data)
{
    struct delete_event_s *event = user_data;
    struct pending_deletion_op_s *op = value;

    if (pcmk__str_eq(event->rsc, op->rsc, pcmk__str_none)) {
        notify_deleted(event->lrm_state, op->input, event->rsc, event->rc);
        return TRUE;
    }
    return FALSE;
}

static gboolean
lrm_remove_deleted_op(gpointer key, gpointer value, gpointer user_data)
{
    const char *rsc = user_data;
    active_op_t *pending = value;

    if (pcmk__str_eq(rsc, pending->rsc_id, pcmk__str_none)) {
        crm_info("Removing op %s:%d for deleted resource %s",
                 pending->op_key, pending->call_id, rsc);
        return TRUE;
    }
    return FALSE;
}

static void
delete_rsc_entry(lrm_state_t *lrm_state, ha_msg_input_t *input,
                 const char *rsc_id, GHashTableIter *rsc_iter, int rc,
                 const char *user_name, bool from_cib)
{
    struct delete_event_s event;

    CRM_CHECK(rsc_id != NULL, return);

    if (rc == pcmk_ok) {
        char *rsc_id_copy = strdup(rsc_id);

        if (rsc_iter) {
            g_hash_table_iter_remove(rsc_iter);
        } else {
            g_hash_table_remove(lrm_state->resource_history, rsc_id_copy);
        }

        if (from_cib) {
            controld_delete_resource_history(rsc_id_copy, lrm_state->node_name,
                                             user_name, crmd_cib_smart_opt());
        }
        g_hash_table_foreach_remove(lrm_state->active_ops,
                                    lrm_remove_deleted_op, rsc_id_copy);
        free(rsc_id_copy);
    }

    if (input) {
        notify_deleted(lrm_state, input, rsc_id, rc);
    }

    event.rc = rc;
    event.rsc = rsc_id;
    event.lrm_state = lrm_state;
    g_hash_table_foreach_remove(lrm_state->deletion_ops, lrm_remove_deleted_rsc, &event);
}

static inline gboolean
last_failed_matches_op(rsc_history_t *entry, const char *op, guint interval_ms)
{
    if (entry == NULL) {
        return FALSE;
    }
    if (op == NULL) {
        return TRUE;
    }
    return (pcmk__str_eq(op, entry->failed->op_type, pcmk__str_casei)
            && (interval_ms == entry->failed->interval_ms));
}

/*!
 * \internal
 * \brief Clear a resource's last failure
 *
 * Erase a resource's last failure on a particular node from both the
 * LRM resource history in the CIB, and the resource history remembered
 * for the LRM state.
 *
 * \param[in] rsc_id      Resource name
 * \param[in] node_name   Node name
 * \param[in] operation   If specified, only clear if matching this operation
 * \param[in] interval_ms If operation is specified, it has this interval
 */
void
lrm_clear_last_failure(const char *rsc_id, const char *node_name,
                       const char *operation, guint interval_ms)
{
    lrm_state_t *lrm_state = lrm_state_find(node_name);

    if (lrm_state == NULL) {
        return;
    }
    if (lrm_state->resource_history != NULL) {
        rsc_history_t *entry = g_hash_table_lookup(lrm_state->resource_history,
                                                   rsc_id);

        if (last_failed_matches_op(entry, operation, interval_ms)) {
            lrmd_free_event(entry->failed);
            entry->failed = NULL;
        }
    }
}

/* Returns: gboolean - cancellation is in progress */
static gboolean
cancel_op(lrm_state_t * lrm_state, const char *rsc_id, const char *key, int op, gboolean remove)
{
    int rc = pcmk_ok;
    char *local_key = NULL;
    active_op_t *pending = NULL;

    CRM_CHECK(op != 0, return FALSE);
    CRM_CHECK(rsc_id != NULL, return FALSE);
    if (key == NULL) {
        local_key = make_stop_id(rsc_id, op);
        key = local_key;
    }
    pending = g_hash_table_lookup(lrm_state->active_ops, key);

    if (pending) {
        if (remove && !pcmk_is_set(pending->flags, active_op_remove)) {
            controld_set_active_op_flags(pending, active_op_remove);
            crm_debug("Scheduling %s for removal", key);
        }

        if (pcmk_is_set(pending->flags, active_op_cancelled)) {
            crm_debug("Operation %s already cancelled", key);
            free(local_key);
            return FALSE;
        }
        controld_set_active_op_flags(pending, active_op_cancelled);

    } else {
        crm_info("No pending op found for %s", key);
        free(local_key);
        return FALSE;
    }

    crm_debug("Cancelling op %d for %s (%s)", op, rsc_id, key);
    rc = lrm_state_cancel(lrm_state, pending->rsc_id, pending->op_type,
                          pending->interval_ms);
    if (rc == pcmk_ok) {
        crm_debug("Op %d for %s (%s): cancelled", op, rsc_id, key);
        free(local_key);
        return TRUE;
    }

    crm_debug("Op %d for %s (%s): Nothing to cancel", op, rsc_id, key);
    /* The caller needs to make sure the entry is
     * removed from the active operations list
     *
     * Usually by returning TRUE inside the worker function
     * supplied to g_hash_table_foreach_remove()
     *
     * Not removing the entry from active operations will block
     * the node from shutting down
     */
    free(local_key);
    return FALSE;
}

struct cancel_data {
    gboolean done;
    gboolean remove;
    const char *key;
    lrmd_rsc_info_t *rsc;
    lrm_state_t *lrm_state;
};

static gboolean
cancel_action_by_key(gpointer key, gpointer value, gpointer user_data)
{
    gboolean remove = FALSE;
    struct cancel_data *data = user_data;
    active_op_t *op = value;

    if (pcmk__str_eq(op->op_key, data->key, pcmk__str_none)) {
        data->done = TRUE;
        remove = !cancel_op(data->lrm_state, data->rsc->id, key, op->call_id, data->remove);
    }
    return remove;
}

static gboolean
cancel_op_key(lrm_state_t * lrm_state, lrmd_rsc_info_t * rsc, const char *key, gboolean remove)
{
    guint removed = 0;
    struct cancel_data data;

    CRM_CHECK(rsc != NULL, return FALSE);
    CRM_CHECK(key != NULL, return FALSE);

    data.key = key;
    data.rsc = rsc;
    data.done = FALSE;
    data.remove = remove;
    data.lrm_state = lrm_state;

    removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                          cancel_action_by_key, &data);
    crm_trace("Removed %u op cache entries, new size: %u",
              removed, g_hash_table_size(lrm_state->active_ops));
    return data.done;
}

/*!
 * \internal
 * \brief Retrieve resource information from LRM
 *
 * \param[in,out]  lrm_state  Executor connection state to use
 * \param[in]      rsc_xml    XML containing resource configuration
 * \param[in]      do_create  If true, register resource if not already
 * \param[out]     rsc_info   Where to store information obtained from executor
 *
 * \retval pcmk_ok   Success (and rsc_info holds newly allocated result)
 * \retval -EINVAL   Required information is missing from arguments
 * \retval -ENOTCONN No active connection to LRM
 * \retval -ENODEV   Resource not found
 * \retval -errno    Error communicating with executor when registering resource
 *
 * \note Caller is responsible for freeing result on success.
 */
static int
get_lrm_resource(lrm_state_t *lrm_state, const xmlNode *rsc_xml,
                 gboolean do_create, lrmd_rsc_info_t **rsc_info)
{
    const char *id = ID(rsc_xml);

    CRM_CHECK(lrm_state && rsc_xml && rsc_info, return -EINVAL);
    CRM_CHECK(id, return -EINVAL);

    if (lrm_state_is_connected(lrm_state) == FALSE) {
        return -ENOTCONN;
    }

    crm_trace("Retrieving resource information for %s from the executor", id);
    *rsc_info = lrm_state_get_rsc_info(lrm_state, id, 0);

    // If resource isn't known by ID, try clone name, if provided
    if (!*rsc_info) {
        const char *long_id = crm_element_value(rsc_xml, XML_ATTR_ID_LONG);

        if (long_id) {
            *rsc_info = lrm_state_get_rsc_info(lrm_state, long_id, 0);
        }
    }

    if ((*rsc_info == NULL) && do_create) {
        const char *class = crm_element_value(rsc_xml, XML_AGENT_ATTR_CLASS);
        const char *provider = crm_element_value(rsc_xml, XML_AGENT_ATTR_PROVIDER);
        const char *type = crm_element_value(rsc_xml, XML_ATTR_TYPE);
        int rc;

        crm_trace("Registering resource %s with the executor", id);
        rc = lrm_state_register_rsc(lrm_state, id, class, provider, type,
                                    lrmd_opt_drop_recurring);
        if (rc != pcmk_ok) {
            fsa_data_t *msg_data = NULL;

            crm_err("Could not register resource %s with the executor on %s: %s "
                    CRM_XS " rc=%d",
                    id, lrm_state->node_name, pcmk_strerror(rc), rc);

            /* Register this as an internal error if this involves the local
             * executor. Otherwise, we're likely dealing with an unresponsive
             * remote node, which is not an FSA failure.
             */
            if (lrm_state_is_local(lrm_state) == TRUE) {
                register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
            }
            return rc;
        }

        *rsc_info = lrm_state_get_rsc_info(lrm_state, id, 0);
    }
    return *rsc_info? pcmk_ok : -ENODEV;
}

static void
delete_resource(lrm_state_t *lrm_state, const char *id, lrmd_rsc_info_t *rsc,
                GHashTableIter *iter, const char *sys, const char *user,
                ha_msg_input_t *request, bool unregister, bool from_cib)
{
    int rc = pcmk_ok;

    crm_info("Removing resource %s from executor for %s%s%s",
             id, sys, (user? " as " : ""), (user? user : ""));

    if (rsc && unregister) {
        rc = lrm_state_unregister_rsc(lrm_state, id, 0);
    }

    if (rc == pcmk_ok) {
        crm_trace("Resource %s deleted from executor", id);
    } else if (rc == -EINPROGRESS) {
        crm_info("Deletion of resource '%s' from executor is pending", id);
        if (request) {
            struct pending_deletion_op_s *op = NULL;
            char *ref = crm_element_value_copy(request->msg, XML_ATTR_REFERENCE);

            op = calloc(1, sizeof(struct pending_deletion_op_s));
            op->rsc = strdup(rsc->id);
            op->input = copy_ha_msg_input(request);
            g_hash_table_insert(lrm_state->deletion_ops, ref, op);
        }
        return;
    } else {
        crm_warn("Could not delete '%s' from executor for %s%s%s: %s "
                 CRM_XS " rc=%d", id, sys, (user? " as " : ""),
                 (user? user : ""), pcmk_strerror(rc), rc);
    }

    delete_rsc_entry(lrm_state, request, id, iter, rc, user, from_cib);
}

static int
get_fake_call_id(lrm_state_t *lrm_state, const char *rsc_id)
{
    int call_id = 999999999;
    rsc_history_t *entry = NULL;

    if(lrm_state) {
        entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
    }

    /* Make sure the call id is greater than the last successful operation,
     * otherwise the failure will not result in a possible recovery of the resource
     * as it could appear the failure occurred before the successful start */
    if (entry) {
        call_id = entry->last_callid + 1;
    }

    if (call_id < 0) {
        call_id = 1;
    }
    return call_id;
}

static void
fake_op_status(lrm_state_t *lrm_state, lrmd_event_data_t *op, int op_status,
               enum ocf_exitcode op_exitcode, const char *exit_reason)
{
    op->call_id = get_fake_call_id(lrm_state, op->rsc_id);
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;
    lrmd__set_result(op, op_exitcode, op_status, exit_reason);
}

static void
force_reprobe(lrm_state_t *lrm_state, const char *from_sys,
              const char *from_host, const char *user_name,
              gboolean is_remote_node, bool reprobe_all_nodes)
{
    GHashTableIter gIter;
    rsc_history_t *entry = NULL;

    crm_info("Clearing resource history on node %s", lrm_state->node_name);
    g_hash_table_iter_init(&gIter, lrm_state->resource_history);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        /* only unregister the resource during a reprobe if it is not a remote connection
         * resource. otherwise unregistering the connection will terminate remote-node
         * membership */
        bool unregister = true;

        if (is_remote_lrmd_ra(NULL, NULL, entry->id)) {
            unregister = false;

            if (reprobe_all_nodes) {
                lrm_state_t *remote_lrm_state = lrm_state_find(entry->id);

                if (remote_lrm_state != NULL) {
                    /* If reprobing all nodes, be sure to reprobe the remote
                     * node before clearing its connection resource
                     */
                    force_reprobe(remote_lrm_state, from_sys, from_host,
                                  user_name, TRUE, reprobe_all_nodes);
                }
            }
        }

        /* Don't delete from the CIB, since we'll delete the whole node's LRM
         * state from the CIB soon
         */
        delete_resource(lrm_state, entry->id, &entry->rsc, &gIter, from_sys,
                        user_name, NULL, unregister, false);
    }

    /* Now delete the copy in the CIB */
    controld_delete_node_state(lrm_state->node_name, controld_section_lrm,
                               cib_scope_local);

    // @COMPAT DCs < 1.1.14 need this deleted (in case it was explicitly false)
    update_attrd(lrm_state->node_name, CRM_OP_PROBED, NULL, user_name, is_remote_node);
}

/*!
 * \internal
 * \brief Fail a requested action without actually executing it
 *
 * For an action that can't be executed, process it similarly to an actual
 * execution result, with specified error status (except for notify actions,
 * which will always be treated as successful).
 *
 * \param[in,out] lrm_state    Executor connection that action is for
 * \param[in]     action       Action XML from request
 * \param[in]     rc           Desired return code to use
 * \param[in]     op_status    Desired operation status to use
 * \param[in]     exit_reason  Human-friendly detail, if error
 */
static void
synthesize_lrmd_failure(lrm_state_t *lrm_state, const xmlNode *action,
                        int op_status, enum ocf_exitcode rc,
                        const char *exit_reason)
{
    lrmd_event_data_t *op = NULL;
    const char *operation = crm_element_value(action, XML_LRM_ATTR_TASK);
    const char *target_node = crm_element_value(action, XML_LRM_ATTR_TARGET);
    xmlNode *xml_rsc = find_xml_node(action, XML_CIB_TAG_RESOURCE, TRUE);

    if ((xml_rsc == NULL) || (ID(xml_rsc) == NULL)) {
        /* @TODO Should we do something else, like direct ack? */
        crm_info("Can't fake %s failure (%d) on %s without resource configuration",
                 crm_element_value(action, XML_LRM_ATTR_TASK_KEY), rc,
                 target_node);
        return;

    } else if(operation == NULL) {
        /* This probably came from crm_resource -C, nothing to do */
        crm_info("Can't fake %s failure (%d) on %s without operation",
                 ID(xml_rsc), rc, target_node);
        return;
    }

    op = construct_op(lrm_state, action, ID(xml_rsc), operation);

    if (pcmk__str_eq(operation, RSC_NOTIFY, pcmk__str_casei)) { // Notifications can't fail
        fake_op_status(lrm_state, op, PCMK_EXEC_DONE, PCMK_OCF_OK, NULL);
    } else {
        fake_op_status(lrm_state, op, op_status, rc, exit_reason);
    }

    crm_info("Faking " PCMK__OP_FMT " result (%d) on %s",
             op->rsc_id, op->op_type, op->interval_ms, op->rc, target_node);

    // Process the result as if it came from the LRM
    process_lrm_event(lrm_state, op, NULL, action);
    lrmd_free_event(op);
}

/*!
 * \internal
 * \brief Get target of an LRM operation (replacing \p NULL with local node
 *        name)
 *
 * \param[in] xml  LRM operation data XML
 *
 * \return LRM operation target node name (local node or Pacemaker Remote node)
 */
static const char *
lrm_op_target(const xmlNode *xml)
{
    const char *target = NULL;

    if (xml) {
        target = crm_element_value(xml, XML_LRM_ATTR_TARGET);
    }
    if (target == NULL) {
        target = controld_globals.our_nodename;
    }
    return target;
}

static void
fail_lrm_resource(xmlNode *xml, lrm_state_t *lrm_state, const char *user_name,
                  const char *from_host, const char *from_sys)
{
    lrmd_event_data_t *op = NULL;
    lrmd_rsc_info_t *rsc = NULL;
    xmlNode *xml_rsc = find_xml_node(xml, XML_CIB_TAG_RESOURCE, TRUE);

    CRM_CHECK(xml_rsc != NULL, return);

    /* The executor simply executes operations and reports the results, without
     * any concept of success or failure, so to fail a resource, we must fake
     * what a failure looks like.
     *
     * To do this, we create a fake executor operation event for the resource,
     * and pass that event to the executor client callback so it will be
     * processed as if it came from the executor.
     */
    op = construct_op(lrm_state, xml, ID(xml_rsc), "asyncmon");

    free((char*) op->user_data);
    op->user_data = NULL;
    op->interval_ms = 0;

    if (user_name && !pcmk__is_privileged(user_name)) {
        crm_err("%s does not have permission to fail %s", user_name, ID(xml_rsc));
        fake_op_status(lrm_state, op, PCMK_EXEC_ERROR,
                       PCMK_OCF_INSUFFICIENT_PRIV,
                       "Unprivileged user cannot fail resources");
        controld_ack_event_directly(from_host, from_sys, NULL, op, ID(xml_rsc));
        lrmd_free_event(op);
        return;
    }


    if (get_lrm_resource(lrm_state, xml_rsc, TRUE, &rsc) == pcmk_ok) {
        crm_info("Failing resource %s...", rsc->id);
        fake_op_status(lrm_state, op, PCMK_EXEC_DONE, PCMK_OCF_UNKNOWN_ERROR,
                       "Simulated failure");
        process_lrm_event(lrm_state, op, NULL, xml);
        op->rc = PCMK_OCF_OK; // The request to fail the resource succeeded
        lrmd_free_rsc_info(rsc);

    } else {
        crm_info("Cannot find/create resource in order to fail it...");
        crm_log_xml_warn(xml, "bad input");
        fake_op_status(lrm_state, op, PCMK_EXEC_ERROR, PCMK_OCF_UNKNOWN_ERROR,
                       "Cannot fail unknown resource");
    }

    controld_ack_event_directly(from_host, from_sys, NULL, op, ID(xml_rsc));
    lrmd_free_event(op);
}

static void
handle_reprobe_op(lrm_state_t *lrm_state, const char *from_sys,
                  const char *from_host, const char *user_name,
                  gboolean is_remote_node, bool reprobe_all_nodes)
{
    crm_notice("Forcing the status of all resources to be redetected");
    force_reprobe(lrm_state, from_sys, from_host, user_name, is_remote_node,
                  reprobe_all_nodes);

    if (!pcmk__strcase_any_of(from_sys, CRM_SYSTEM_PENGINE, CRM_SYSTEM_TENGINE, NULL)) {

        xmlNode *reply = create_request(CRM_OP_INVOKE_LRM, NULL, from_host,
                                        from_sys, CRM_SYSTEM_LRMD,
                                        controld_globals.our_uuid);

        crm_debug("ACK'ing re-probe from %s (%s)", from_sys, from_host);

        if (relay_message(reply, TRUE) == FALSE) {
            crm_log_xml_err(reply, "Unable to route reply");
        }
        free_xml(reply);
    }
}

static bool do_lrm_cancel(ha_msg_input_t *input, lrm_state_t *lrm_state,
              lrmd_rsc_info_t *rsc, const char *from_host, const char *from_sys)
{
    char *op_key = NULL;
    char *meta_key = NULL;
    int call = 0;
    const char *call_id = NULL;
    const char *op_task = NULL;
    guint interval_ms = 0;
    gboolean in_progress = FALSE;
    xmlNode *params = find_xml_node(input->xml, XML_TAG_ATTRS, TRUE);

    CRM_CHECK(params != NULL, return FALSE);

    meta_key = crm_meta_name(XML_LRM_ATTR_TASK);
    op_task = crm_element_value(params, meta_key);
    free(meta_key);
    CRM_CHECK(op_task != NULL, return FALSE);

    meta_key = crm_meta_name(XML_LRM_ATTR_INTERVAL_MS);
    if (crm_element_value_ms(params, meta_key, &interval_ms) != pcmk_ok) {
        free(meta_key);
        return FALSE;
    }
    free(meta_key);

    op_key = pcmk__op_key(rsc->id, op_task, interval_ms);

    meta_key = crm_meta_name(XML_LRM_ATTR_CALLID);
    call_id = crm_element_value(params, meta_key);
    free(meta_key);

    crm_debug("Scheduler requested op %s (call=%s) be cancelled",
              op_key, (call_id? call_id : "NA"));
    pcmk__scan_min_int(call_id, &call, 0);
    if (call == 0) {
        // Normal case when the scheduler cancels a recurring op
        in_progress = cancel_op_key(lrm_state, rsc, op_key, TRUE);

    } else {
        // Normal case when the scheduler cancels an orphan op
        in_progress = cancel_op(lrm_state, rsc->id, NULL, call, TRUE);
    }

    // Acknowledge cancellation operation if for a remote connection resource
    if (!in_progress || is_remote_lrmd_ra(NULL, NULL, rsc->id)) {
        char *op_id = make_stop_id(rsc->id, call);

        if (is_remote_lrmd_ra(NULL, NULL, rsc->id) == FALSE) {
            crm_info("Nothing known about operation %d for %s", call, op_key);
        }
        controld_delete_action_history_by_key(rsc->id, lrm_state->node_name,
                                              op_key, call);
        send_task_ok_ack(lrm_state, input, rsc->id, rsc, op_task,
                         from_host, from_sys);

        /* needed at least for cancellation of a remote operation */
        if (lrm_state->active_ops != NULL) {
            g_hash_table_remove(lrm_state->active_ops, op_id);
        }
        free(op_id);

    } else {
        /* No ack is needed since abcdaa8, but peers with older versions
         * in a rolling upgrade need one. We didn't bump the feature set
         * at that commit, so we can only compare against the previous
         * CRM version (3.0.8). If any peers have feature set 3.0.9 but
         * not abcdaa8, they will time out waiting for the ack (no
         * released versions of Pacemaker are affected).
         */
        const char *peer_version = crm_element_value(params, XML_ATTR_CRM_VERSION);

        if (compare_version(peer_version, "3.0.8") <= 0) {
            crm_info("Sending compatibility ack for %s cancellation to %s (CRM version %s)",
                     op_key, from_host, peer_version);
            send_task_ok_ack(lrm_state, input, rsc->id, rsc, op_task,
                             from_host, from_sys);
        }
    }

    free(op_key);
    return TRUE;
}

static void
do_lrm_delete(ha_msg_input_t *input, lrm_state_t *lrm_state,
              lrmd_rsc_info_t *rsc, const char *from_sys, const char *from_host,
              bool crm_rsc_delete, const char *user_name)
{
    bool unregister = true;
    int cib_rc = controld_delete_resource_history(rsc->id, lrm_state->node_name,
                                                  user_name,
                                                  cib_dryrun|cib_sync_call);

    if (cib_rc != pcmk_rc_ok) {
        lrmd_event_data_t *op = NULL;

        op = construct_op(lrm_state, input->xml, rsc->id, CRMD_ACTION_DELETE);

        /* These are resource clean-ups, not actions, so no exit reason is
         * needed.
         */
        lrmd__set_result(op, pcmk_rc2ocf(cib_rc), PCMK_EXEC_ERROR, NULL);
        controld_ack_event_directly(from_host, from_sys, NULL, op, rsc->id);
        lrmd_free_event(op);
        return;
    }

    if (crm_rsc_delete && is_remote_lrmd_ra(NULL, NULL, rsc->id)) {
        unregister = false;
    }

    delete_resource(lrm_state, rsc->id, rsc, NULL, from_sys,
                    user_name, input, unregister, true);
}

// User data for asynchronous metadata execution
struct metadata_cb_data {
    lrmd_rsc_info_t *rsc;   // Copy of resource information
    xmlNode *input_xml;     // Copy of FSA input XML
};

static struct metadata_cb_data *
new_metadata_cb_data(lrmd_rsc_info_t *rsc, xmlNode *input_xml)
{
    struct metadata_cb_data *data = NULL;

    data = calloc(1, sizeof(struct metadata_cb_data));
    CRM_ASSERT(data != NULL);
    data->input_xml = copy_xml(input_xml);
    data->rsc = lrmd_copy_rsc_info(rsc);
    return data;
}

static void
free_metadata_cb_data(struct metadata_cb_data *data)
{
    lrmd_free_rsc_info(data->rsc);
    free_xml(data->input_xml);
    free(data);
}

/*!
 * \internal
 * \brief Execute an action after metadata has been retrieved
 *
 * \param[in] pid        Ignored
 * \param[in] result     Result of metadata action
 * \param[in] user_data  Metadata callback data
 */
static void
metadata_complete(int pid, const pcmk__action_result_t *result, void *user_data)
{
    struct metadata_cb_data *data = (struct metadata_cb_data *) user_data;

    struct ra_metadata_s *md = NULL;
    lrm_state_t *lrm_state = lrm_state_find(lrm_op_target(data->input_xml));

    if ((lrm_state != NULL) && pcmk__result_ok(result)) {
        md = controld_cache_metadata(lrm_state->metadata_cache, data->rsc,
                                     result->action_stdout);
    }
    do_lrm_rsc_op(lrm_state, data->rsc, data->input_xml, md);
    free_metadata_cb_data(data);
}

/*	 A_LRM_INVOKE	*/
void
do_lrm_invoke(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    lrm_state_t *lrm_state = NULL;
    const char *crm_op = NULL;
    const char *from_sys = NULL;
    const char *from_host = NULL;
    const char *operation = NULL;
    ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
    const char *user_name = NULL;
    const char *target_node = lrm_op_target(input->xml);
    gboolean is_remote_node = FALSE;
    bool crm_rsc_delete = FALSE;

    // Message routed to the local node is targeting a specific, non-local node
    is_remote_node = !pcmk__str_eq(target_node, controld_globals.our_nodename,
                                   pcmk__str_casei);

    lrm_state = lrm_state_find(target_node);
    if ((lrm_state == NULL) && is_remote_node) {
        crm_err("Failing action because local node has never had connection to remote node %s",
                target_node);
        synthesize_lrmd_failure(NULL, input->xml, PCMK_EXEC_NOT_CONNECTED,
                                PCMK_OCF_UNKNOWN_ERROR,
                                "Local node has no connection to remote");
        return;
    }
    CRM_ASSERT(lrm_state != NULL);

    user_name = pcmk__update_acl_user(input->msg, F_CRM_USER, NULL);
    crm_op = crm_element_value(input->msg, F_CRM_TASK);
    from_sys = crm_element_value(input->msg, F_CRM_SYS_FROM);
    if (!pcmk__str_eq(from_sys, CRM_SYSTEM_TENGINE, pcmk__str_none)) {
        from_host = crm_element_value(input->msg, F_CRM_HOST_FROM);
    }

    if (pcmk__str_eq(crm_op, CRM_OP_LRM_DELETE, pcmk__str_none)) {
        if (!pcmk__str_eq(from_sys, CRM_SYSTEM_TENGINE, pcmk__str_none)) {
            crm_rsc_delete = TRUE; // from crm_resource
        }
        operation = CRMD_ACTION_DELETE;

    } else if (input->xml != NULL) {
        operation = crm_element_value(input->xml, XML_LRM_ATTR_TASK);
    }

    CRM_CHECK(!pcmk__str_empty(crm_op) || !pcmk__str_empty(operation), return);

    crm_trace("'%s' execution request from %s as %s user",
              pcmk__s(crm_op, operation),
              pcmk__s(from_sys, "unknown subsystem"),
              pcmk__s(user_name, "current"));

    if (pcmk__str_eq(crm_op, CRM_OP_LRM_FAIL, pcmk__str_none)) {
        fail_lrm_resource(input->xml, lrm_state, user_name, from_host,
                          from_sys);

    } else if (pcmk__str_eq(crm_op, CRM_OP_LRM_REFRESH, pcmk__str_none)) {
        /* @COMPAT This can only be sent by crm_resource --refresh on a
         * Pacemaker Remote node running Pacemaker 1.1.9, which is extremely
         * unlikely. It previously would cause the controller to re-write its
         * resource history to the CIB. Just ignore it.
         */
        crm_notice("Ignoring refresh request from Pacemaker Remote 1.1.9 node");

    // @COMPAT DCs <1.1.14 in a rolling upgrade might schedule this op
    } else if (pcmk__str_eq(operation, CRM_OP_PROBED, pcmk__str_none)) {
        update_attrd(lrm_state->node_name, CRM_OP_PROBED, XML_BOOLEAN_TRUE,
                     user_name, is_remote_node);

    } else if (pcmk__str_eq(crm_op, CRM_OP_REPROBE, pcmk__str_none)
               || pcmk__str_eq(operation, CRM_OP_REPROBE, pcmk__str_none)) {
        const char *raw_target = NULL;

        if (input->xml != NULL) {
            // For CRM_OP_REPROBE, a NULL target means we're targeting all nodes
            raw_target = crm_element_value(input->xml, XML_LRM_ATTR_TARGET);
        }
        handle_reprobe_op(lrm_state, from_sys, from_host, user_name,
                          is_remote_node, (raw_target == NULL));

    } else if (operation != NULL) {
        lrmd_rsc_info_t *rsc = NULL;
        xmlNode *xml_rsc = find_xml_node(input->xml, XML_CIB_TAG_RESOURCE, TRUE);
        gboolean create_rsc = !pcmk__str_eq(operation, CRMD_ACTION_DELETE,
                                            pcmk__str_none);
        int rc;

        // We can't return anything meaningful without a resource ID
        CRM_CHECK(xml_rsc && ID(xml_rsc), return);

        rc = get_lrm_resource(lrm_state, xml_rsc, create_rsc, &rsc);
        if (rc == -ENOTCONN) {
            synthesize_lrmd_failure(lrm_state, input->xml,
                                    PCMK_EXEC_NOT_CONNECTED,
                                    PCMK_OCF_UNKNOWN_ERROR,
                                    "Not connected to remote executor");
            return;

        } else if ((rc < 0) && !create_rsc) {
            /* Delete of malformed or nonexistent resource
             * (deleting something that does not exist is a success)
             */
            crm_notice("Not registering resource '%s' for a %s event "
                       CRM_XS " get-rc=%d (%s) transition-key=%s",
                       ID(xml_rsc), operation,
                       rc, pcmk_strerror(rc), ID(input->xml));
            delete_rsc_entry(lrm_state, input, ID(xml_rsc), NULL, pcmk_ok,
                             user_name, true);
            return;

        } else if (rc == -EINVAL) {
            // Resource operation on malformed resource
            crm_err("Invalid resource definition for %s", ID(xml_rsc));
            crm_log_xml_warn(input->msg, "invalid resource");
            synthesize_lrmd_failure(lrm_state, input->xml, PCMK_EXEC_ERROR,
                                    PCMK_OCF_NOT_CONFIGURED, // fatal error
                                    "Invalid resource definition");
            return;

        } else if (rc < 0) {
            // Error communicating with the executor
            crm_err("Could not register resource '%s' with executor: %s "
                    CRM_XS " rc=%d",
                    ID(xml_rsc), pcmk_strerror(rc), rc);
            crm_log_xml_warn(input->msg, "failed registration");
            synthesize_lrmd_failure(lrm_state, input->xml, PCMK_EXEC_ERROR,
                                    PCMK_OCF_INVALID_PARAM, // hard error
                                    "Could not register resource with executor");
            return;
        }

        if (pcmk__str_eq(operation, CRMD_ACTION_CANCEL, pcmk__str_none)) {
            if (!do_lrm_cancel(input, lrm_state, rsc, from_host, from_sys)) {
                crm_log_xml_warn(input->xml, "Bad command");
            }

        } else if (pcmk__str_eq(operation, CRMD_ACTION_DELETE, pcmk__str_none)) {
            do_lrm_delete(input, lrm_state, rsc, from_sys, from_host,
                          crm_rsc_delete, user_name);

        } else {
            struct ra_metadata_s *md = NULL;

            /* Getting metadata from cache is OK except for start actions --
             * always refresh from the agent for those, in case the resource
             * agent was updated.
             *
             * @TODO Only refresh metadata for starts if the agent actually
             * changed (using something like inotify, or a hash or modification
             * time of the agent executable).
             */
            if (strcmp(operation, CRMD_ACTION_START) != 0) {
                md = controld_get_rsc_metadata(lrm_state, rsc,
                                               controld_metadata_from_cache);
            }

            if ((md == NULL) && crm_op_needs_metadata(rsc->standard,
                                                      operation)) {
                /* Most likely, we'll need the agent metadata to record the
                 * pending operation and the operation result. Get it now rather
                 * than wait until then, so the metadata action doesn't eat into
                 * the real action's timeout.
                 *
                 * @TODO Metadata is retrieved via direct execution of the
                 * agent, which has a couple of related issues: the executor
                 * should execute agents, not the controller; and metadata for
                 * Pacemaker Remote nodes should be collected on those nodes,
                 * not locally.
                 */
                struct metadata_cb_data *data = NULL;

                data = new_metadata_cb_data(rsc, input->xml);
                crm_info("Retrieving metadata for %s (%s%s%s:%s) asynchronously",
                         rsc->id, rsc->standard,
                         ((rsc->provider == NULL)? "" : ":"),
                         ((rsc->provider == NULL)? "" : rsc->provider),
                         rsc->type);
                (void) lrmd__metadata_async(rsc, metadata_complete,
                                            (void *) data);
            } else {
                do_lrm_rsc_op(lrm_state, rsc, input->xml, md);
            }
        }

        lrmd_free_rsc_info(rsc);

    } else {
        crm_err("Invalid execution request: unknown command '%s' (bug?)",
                crm_op);
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

static lrmd_event_data_t *
construct_op(const lrm_state_t *lrm_state, const xmlNode *rsc_op,
             const char *rsc_id, const char *operation)
{
    lrmd_event_data_t *op = NULL;
    const char *op_delay = NULL;
    const char *op_timeout = NULL;
    GHashTable *params = NULL;

    xmlNode *primitive = NULL;
    const char *class = NULL;

    const char *transition = NULL;

    CRM_ASSERT(rsc_id && operation);

    op = lrmd_new_event(rsc_id, operation, 0);
    op->type = lrmd_event_exec_complete;
    op->timeout = 0;
    op->start_delay = 0;
    lrmd__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);

    if (rsc_op == NULL) {
        CRM_LOG_ASSERT(pcmk__str_eq(CRMD_ACTION_STOP, operation, pcmk__str_casei));
        op->user_data = NULL;
        /* the stop_all_resources() case
         * by definition there is no DC (or they'd be shutting
         *   us down).
         * So we should put our version here.
         */
        op->params = pcmk__strkey_table(free, free);

        g_hash_table_insert(op->params, strdup(XML_ATTR_CRM_VERSION), strdup(CRM_FEATURE_SET));

        crm_trace("Constructed %s op for %s", operation, rsc_id);
        return op;
    }

    params = xml2list(rsc_op);
    g_hash_table_remove(params, CRM_META "_op_target_rc");

    op_delay = crm_meta_value(params, XML_OP_ATTR_START_DELAY);
    pcmk__scan_min_int(op_delay, &op->start_delay, 0);

    op_timeout = crm_meta_value(params, XML_ATTR_TIMEOUT);
    pcmk__scan_min_int(op_timeout, &op->timeout, 0);

    if (pcmk__guint_from_hash(params, CRM_META "_" XML_LRM_ATTR_INTERVAL_MS, 0,
                              &(op->interval_ms)) != pcmk_rc_ok) {
        op->interval_ms = 0;
    }

    /* If this is a start action with the special expire_attrs meta-attribute
     * set to false (or missing entirely), go ahead and clear the purge bit from
     * the connection resource's flags.
     */
    if (!crm_is_true(crm_meta_value(params, PCMK_META_EXPIRE_ATTRS))) {
        lrm_state_t *connection_rsc = lrm_state_find(rsc_id);

        if (connection_rsc && connection_rsc->remote_ra_data) {
            remote_ra_clear_purge_attrs(connection_rsc);
        }
    }

    /* Use pcmk_monitor_timeout instead of meta timeout for stonith
       recurring monitor, if set */
    primitive = find_xml_node(rsc_op, XML_CIB_TAG_RESOURCE, FALSE);
    class = crm_element_value(primitive, XML_AGENT_ATTR_CLASS);

    if (pcmk_is_set(pcmk_get_ra_caps(class), pcmk_ra_cap_fence_params)
            && pcmk__str_eq(operation, CRMD_ACTION_STATUS, pcmk__str_casei)
            && (op->interval_ms > 0)) {

        op_timeout = g_hash_table_lookup(params, "pcmk_monitor_timeout");
        if (op_timeout != NULL) {
            op->timeout = crm_get_msec(op_timeout);
        }
    }

    if (!pcmk__str_eq(operation, RSC_STOP, pcmk__str_casei)) {
        op->params = params;

    } else {
        rsc_history_t *entry = NULL;

        if (lrm_state) {
            entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
        }

        /* If we do not have stop parameters cached, use
         * whatever we are given */
        if (!entry || !entry->stop_params) {
            op->params = params;
        } else {
            /* Copy the cached parameter list so that we stop the resource
             * with the old attributes, not the new ones */
            op->params = pcmk__strkey_table(free, free);

            g_hash_table_foreach(params, copy_meta_keys, op->params);
            g_hash_table_foreach(entry->stop_params, copy_instance_keys, op->params);
            g_hash_table_destroy(params);
            params = NULL;
        }
    }

    /* sanity */
    if (op->timeout <= 0) {
        op->timeout = op->interval_ms;
    }
    if (op->start_delay < 0) {
        op->start_delay = 0;
    }

    transition = crm_element_value(rsc_op, XML_ATTR_TRANSITION_KEY);
    CRM_CHECK(transition != NULL, return op);

    op->user_data = strdup(transition);

    if (op->interval_ms != 0) {
        if (pcmk__strcase_any_of(operation, CRMD_ACTION_START, CRMD_ACTION_STOP, NULL)) {
            crm_err("Start and Stop actions cannot have an interval: %u",
                    op->interval_ms);
            op->interval_ms = 0;
        }
    }

    crm_trace("Constructed %s op for %s: interval=%u",
              operation, rsc_id, op->interval_ms);

    return op;
}

/*!
 * \internal
 * \brief Send a (synthesized) event result
 *
 * Reply with a synthesized event result directly, as opposed to going through
 * the executor.
 *
 * \param[in]     to_host  Host to send result to
 * \param[in]     to_sys   IPC name to send result (NULL for transition engine)
 * \param[in]     rsc      Type information about resource the result is for
 * \param[in,out] op       Event with result to send
 * \param[in]     rsc_id   ID of resource the result is for
 */
void
controld_ack_event_directly(const char *to_host, const char *to_sys,
                            const lrmd_rsc_info_t *rsc, lrmd_event_data_t *op,
                            const char *rsc_id)
{
    xmlNode *reply = NULL;
    xmlNode *update, *iter;
    crm_node_t *peer = NULL;

    CRM_CHECK(op != NULL, return);
    if (op->rsc_id == NULL) {
        CRM_ASSERT(rsc_id != NULL);
        op->rsc_id = strdup(rsc_id);
    }
    if (to_sys == NULL) {
        to_sys = CRM_SYSTEM_TENGINE;
    }

    peer = crm_get_peer(0, controld_globals.our_nodename);
    update = create_node_state_update(peer, node_update_none, NULL,
                                      __func__);

    iter = create_xml_node(update, XML_CIB_TAG_LRM);
    crm_xml_add(iter, XML_ATTR_ID, controld_globals.our_uuid);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCE);

    crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

    controld_add_resource_history_xml(iter, rsc, op,
                                      controld_globals.our_nodename);
    reply = create_request(CRM_OP_INVOKE_LRM, update, to_host, to_sys, CRM_SYSTEM_LRMD, NULL);

    crm_log_xml_trace(update, "[direct ACK]");

    crm_debug("ACK'ing resource op " PCMK__OP_FMT " from %s: %s",
              op->rsc_id, op->op_type, op->interval_ms, op->user_data,
              crm_element_value(reply, XML_ATTR_REFERENCE));

    if (relay_message(reply, TRUE) == FALSE) {
        crm_log_xml_err(reply, "Unable to route reply");
    }

    free_xml(update);
    free_xml(reply);
}

gboolean
verify_stopped(enum crmd_fsa_state cur_state, int log_level)
{
    gboolean res = TRUE;
    GList *lrm_state_list = lrm_state_get_list();
    GList *state_entry;

    for (state_entry = lrm_state_list; state_entry != NULL; state_entry = state_entry->next) {
        lrm_state_t *lrm_state = state_entry->data;

        if (!lrm_state_verify_stopped(lrm_state, cur_state, log_level)) {
            /* keep iterating through all even when false is returned */
            res = FALSE;
        }
    }

    controld_set_fsa_input_flags(R_SENT_RSC_STOP);
    g_list_free(lrm_state_list); lrm_state_list = NULL;
    return res;
}

struct stop_recurring_action_s {
    lrmd_rsc_info_t *rsc;
    lrm_state_t *lrm_state;
};

static gboolean
stop_recurring_action_by_rsc(gpointer key, gpointer value, gpointer user_data)
{
    gboolean remove = FALSE;
    struct stop_recurring_action_s *event = user_data;
    active_op_t *op = value;

    if ((op->interval_ms != 0)
        && pcmk__str_eq(op->rsc_id, event->rsc->id, pcmk__str_none)) {

        crm_debug("Cancelling op %d for %s (%s)", op->call_id, op->rsc_id, (char*)key);
        remove = !cancel_op(event->lrm_state, event->rsc->id, key, op->call_id, FALSE);
    }

    return remove;
}

static gboolean
stop_recurring_actions(gpointer key, gpointer value, gpointer user_data)
{
    gboolean remove = FALSE;
    lrm_state_t *lrm_state = user_data;
    active_op_t *op = value;

    if (op->interval_ms != 0) {
        crm_info("Cancelling op %d for %s (%s)", op->call_id, op->rsc_id,
                 (const char *) key);
        remove = !cancel_op(lrm_state, op->rsc_id, key, op->call_id, FALSE);
    }

    return remove;
}

/*!
 * \internal
 * \brief Check whether recurring actions should be cancelled before an action
 *
 * \param[in] rsc_id       Resource that action is for
 * \param[in] action       Action being performed
 * \param[in] interval_ms  Operation interval of \p action (in milliseconds)
 *
 * \return true if recurring actions should be cancelled, otherwise false
 */
static bool
should_cancel_recurring(const char *rsc_id, const char *action, guint interval_ms)
{
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id) && (interval_ms == 0)
        && (strcmp(action, CRMD_ACTION_MIGRATE) == 0)) {
        /* Don't stop monitoring a migrating Pacemaker Remote connection
         * resource until the entire migration has completed. We must detect if
         * the connection is unexpectedly severed, even during a migration.
         */
        return false;
    }

    // Cancel recurring actions before changing resource state
    return (interval_ms == 0)
            && !pcmk__str_any_of(action, CRMD_ACTION_STATUS, CRMD_ACTION_NOTIFY,
                                 NULL);
}

/*!
 * \internal
 * \brief Check whether an action should not be performed at this time
 *
 * \param[in] operation  Action to be performed
 *
 * \return Readable description of why action should not be performed,
 *         or NULL if it should be performed
 */
static const char *
should_nack_action(const char *action)
{
    if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)
        && pcmk__str_eq(action, RSC_START, pcmk__str_none)) {

        register_fsa_input(C_SHUTDOWN, I_SHUTDOWN, NULL);
        return "Not attempting start due to shutdown in progress";
    }

    switch (controld_globals.fsa_state) {
        case S_NOT_DC:
        case S_POLICY_ENGINE:   // Recalculating
        case S_TRANSITION_ENGINE:
            break;
        default:
            if (!pcmk__str_eq(action, CRMD_ACTION_STOP, pcmk__str_none)) {
                return "Controller cannot attempt actions at this time";
            }
            break;
    }
    return NULL;
}

static void
do_lrm_rsc_op(lrm_state_t *lrm_state, lrmd_rsc_info_t *rsc, xmlNode *msg,
              struct ra_metadata_s *md)
{
    int rc;
    int call_id = 0;
    char *op_id = NULL;
    lrmd_event_data_t *op = NULL;
    fsa_data_t *msg_data = NULL;
    const char *transition = NULL;
    const char *operation = NULL;
    const char *nack_reason = NULL;

    CRM_CHECK((rsc != NULL) && (msg != NULL), return);

    operation = crm_element_value(msg, XML_LRM_ATTR_TASK);
    CRM_CHECK(!pcmk__str_empty(operation), return);

    transition = crm_element_value(msg, XML_ATTR_TRANSITION_KEY);
    if (pcmk__str_empty(transition)) {
        crm_log_xml_err(msg, "Missing transition number");
    }

    if (lrm_state == NULL) {
        // This shouldn't be possible, but provide a failsafe just in case
        crm_err("Cannot execute %s of %s: No executor connection "
                CRM_XS " transition_key=%s",
                operation, rsc->id, pcmk__s(transition, ""));
        synthesize_lrmd_failure(NULL, msg, PCMK_EXEC_INVALID,
                                PCMK_OCF_UNKNOWN_ERROR,
                                "No executor connection");
        return;
    }

    if (pcmk__str_any_of(operation, CRMD_ACTION_RELOAD,
                         CRMD_ACTION_RELOAD_AGENT, NULL)) {
        /* Pre-2.1.0 DCs will schedule reload actions only, and 2.1.0+ DCs
         * will schedule reload-agent actions only. In either case, we need
         * to map that to whatever the resource agent actually supports.
         * Default to the OCF 1.1 name.
         */
        if ((md != NULL)
            && pcmk_is_set(md->ra_flags, ra_supports_legacy_reload)) {
            operation = CRMD_ACTION_RELOAD;
        } else {
            operation = CRMD_ACTION_RELOAD_AGENT;
        }
    }

    op = construct_op(lrm_state, msg, rsc->id, operation);
    CRM_CHECK(op != NULL, return);

    if (should_cancel_recurring(rsc->id, operation, op->interval_ms)) {
        guint removed = 0;
        struct stop_recurring_action_s data;

        data.rsc = rsc;
        data.lrm_state = lrm_state;
        removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                              stop_recurring_action_by_rsc,
                                              &data);

        if (removed) {
            crm_debug("Stopped %u recurring operation%s in preparation for "
                      PCMK__OP_FMT, removed, pcmk__plural_s(removed),
                      rsc->id, operation, op->interval_ms);
        }
    }

    /* now do the op */
    crm_notice("Requesting local execution of %s operation for %s on %s "
               CRM_XS " transition_key=%s op_key=" PCMK__OP_FMT,
               crm_action_str(op->op_type, op->interval_ms), rsc->id, lrm_state->node_name,
               pcmk__s(transition, ""), rsc->id, operation, op->interval_ms);

    nack_reason = should_nack_action(operation);
    if (nack_reason != NULL) {
        crm_notice("Discarding attempt to perform action %s on %s in state %s "
                   "(shutdown=%s)", operation, rsc->id,
                   fsa_state2string(controld_globals.fsa_state),
                   pcmk__btoa(pcmk_is_set(controld_globals.fsa_input_register,
                                          R_SHUTDOWN)));

        lrmd__set_result(op, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_INVALID,
                         nack_reason);
        controld_ack_event_directly(NULL, NULL, rsc, op, rsc->id);
        lrmd_free_event(op);
        free(op_id);
        return;
    }

    controld_record_pending_op(lrm_state->node_name, rsc, op);

    op_id = pcmk__op_key(rsc->id, op->op_type, op->interval_ms);

    if (op->interval_ms > 0) {
        /* cancel it so we can then restart it without conflict */
        cancel_op_key(lrm_state, rsc, op_id, FALSE);
    }

    rc = controld_execute_resource_agent(lrm_state, rsc->id, op->op_type,
                                         op->user_data, op->interval_ms,
                                         op->timeout, op->start_delay,
                                         op->params, &call_id);
    if (rc == pcmk_rc_ok) {
        /* record all operations so we can wait
         * for them to complete during shutdown
         */
        char *call_id_s = make_stop_id(rsc->id, call_id);
        active_op_t *pending = NULL;

        pending = calloc(1, sizeof(active_op_t));
        crm_trace("Recording pending op: %d - %s %s", call_id, op_id, call_id_s);

        pending->call_id = call_id;
        pending->interval_ms = op->interval_ms;
        pending->op_type = strdup(operation);
        pending->op_key = strdup(op_id);
        pending->rsc_id = strdup(rsc->id);
        pending->start_time = time(NULL);
        pcmk__str_update(&pending->user_data, op->user_data);
        if (crm_element_value_epoch(msg, XML_CONFIG_ATTR_SHUTDOWN_LOCK,
                                    &(pending->lock_time)) != pcmk_ok) {
            pending->lock_time = 0;
        }
        g_hash_table_replace(lrm_state->active_ops, call_id_s, pending);

        if ((op->interval_ms > 0)
            && (op->start_delay > START_DELAY_THRESHOLD)) {
            int target_rc = PCMK_OCF_OK;

            crm_info("Faking confirmation of %s: execution postponed for over 5 minutes", op_id);
            decode_transition_key(op->user_data, NULL, NULL, NULL, &target_rc);
            lrmd__set_result(op, target_rc, PCMK_EXEC_DONE, NULL);
            controld_ack_event_directly(NULL, NULL, rsc, op, rsc->id);
        }

        pending->params = op->params;
        op->params = NULL;

    } else if (lrm_state_is_local(lrm_state)) {
        crm_err("Could not initiate %s action for resource %s locally: %s "
                CRM_XS " rc=%d", operation, rsc->id, pcmk_rc_str(rc), rc);
        fake_op_status(lrm_state, op, PCMK_EXEC_NOT_CONNECTED,
                       PCMK_OCF_UNKNOWN_ERROR, pcmk_rc_str(rc));
        process_lrm_event(lrm_state, op, NULL, NULL);
        register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

    } else {
        crm_err("Could not initiate %s action for resource %s remotely on %s: "
                "%s " CRM_XS " rc=%d",
                operation, rsc->id, lrm_state->node_name, pcmk_rc_str(rc), rc);
        fake_op_status(lrm_state, op, PCMK_EXEC_NOT_CONNECTED,
                       PCMK_OCF_UNKNOWN_ERROR, pcmk_rc_str(rc));
        process_lrm_event(lrm_state, op, NULL, NULL);
    }

    free(op_id);
    lrmd_free_event(op);
}

void
do_lrm_event(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input cur_input, fsa_data_t * msg_data)
{
    CRM_CHECK(FALSE, return);
}

static char *
unescape_newlines(const char *string)
{
    char *pch = NULL;
    char *ret = NULL;
    static const char *escaped_newline = "\\n";

    if (!string) {
        return NULL;
    }

    ret = strdup(string);
    pch = strstr(ret, escaped_newline);
    while (pch != NULL) {
        /* Replace newline escape pattern with actual newline (and a space so we
         * don't have to shuffle the rest of the buffer)
         */
        pch[0] = '\n';
        pch[1] = ' ';
        pch = strstr(pch, escaped_newline);
    }

    return ret;
}

static bool
did_lrm_rsc_op_fail(lrm_state_t *lrm_state, const char * rsc_id,
                    const char * op_type, guint interval_ms)
{
    rsc_history_t *entry = NULL;

    CRM_CHECK(lrm_state != NULL, return FALSE);
    CRM_CHECK(rsc_id != NULL, return FALSE);
    CRM_CHECK(op_type != NULL, return FALSE);

    entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
    if (entry == NULL || entry->failed == NULL) {
        return FALSE;
    }

    if (pcmk__str_eq(entry->failed->rsc_id, rsc_id, pcmk__str_none)
        && pcmk__str_eq(entry->failed->op_type, op_type, pcmk__str_casei)
        && entry->failed->interval_ms == interval_ms) {
        return TRUE;
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Log the result of an executor action (actual or synthesized)
 *
 * \param[in] op         Executor action to log result for
 * \param[in] op_key     Operation key for action
 * \param[in] node_name  Name of node action was performed on, if known
 * \param[in] confirmed  Whether to log that graph action was confirmed
 */
static void
log_executor_event(const lrmd_event_data_t *op, const char *op_key,
                   const char *node_name, gboolean confirmed)
{
    int log_level = LOG_ERR;
    GString *str = g_string_sized_new(100); // reasonable starting size

    pcmk__g_strcat(str,
                   "Result of ", crm_action_str(op->op_type, op->interval_ms),
                   " operation for ", op->rsc_id, NULL);

    if (node_name != NULL) {
        pcmk__g_strcat(str, " on ", node_name, NULL);
    }

    switch (op->op_status) {
        case PCMK_EXEC_DONE:
            log_level = LOG_NOTICE;
            pcmk__g_strcat(str, ": ", services_ocf_exitcode_str(op->rc), NULL);
            break;

        case PCMK_EXEC_TIMEOUT:
            pcmk__g_strcat(str,
                           ": ", pcmk_exec_status_str(op->op_status), " after ",
                           pcmk__readable_interval(op->timeout), NULL);
            break;

        case PCMK_EXEC_CANCELLED:
            log_level = LOG_INFO;
	    /* order of __attribute__ and Fall through comment is IMPORTANT!
	     * do not change it without proper testing with both clang and gcc
	     * in multiple versions.
	     * the clang check allows to build with all versions of clang.
	     * the has_c_attribute check is to workaround a bug in clang version
	     * in rhel7. has_attribute would happily return "YES SIR WE GOT IT"
	     * and fail the build the next line.
	     */
#ifdef __clang__
#ifdef __has_c_attribute
#if __has_attribute(fallthrough)
	    __attribute__((fallthrough));
#endif
#endif
#endif
            // Fall through
        default:
            pcmk__g_strcat(str, ": ", pcmk_exec_status_str(op->op_status),
                           NULL);
    }

    if ((op->exit_reason != NULL)
        && ((op->op_status != PCMK_EXEC_DONE) || (op->rc != PCMK_OCF_OK))) {

        pcmk__g_strcat(str, " (", op->exit_reason, ")", NULL);
    }

    g_string_append(str, " " CRM_XS);
    g_string_append_printf(str, " graph action %sconfirmed; call=%d key=%s",
                           (confirmed? "" : "un"), op->call_id, op_key);
    if (op->op_status == PCMK_EXEC_DONE) {
        g_string_append_printf(str, " rc=%d", op->rc);
    }

    do_crm_log(log_level, "%s", str->str);
    g_string_free(str, TRUE);

    /* The services library has already logged the output at info or debug
     * level, so just raise to notice if it looks like a failure.
     */
    if ((op->output != NULL) && (op->rc != PCMK_OCF_OK)) {
        char *prefix = crm_strdup_printf(PCMK__OP_FMT "@%s output",
                                         op->rsc_id, op->op_type,
                                         op->interval_ms, node_name);

        crm_log_output(LOG_NOTICE, prefix, op->output);
        free(prefix);
    }
}

void
process_lrm_event(lrm_state_t *lrm_state, lrmd_event_data_t *op,
                  active_op_t *pending, const xmlNode *action_xml)
{
    char *op_id = NULL;
    char *op_key = NULL;

    gboolean remove = FALSE;
    gboolean removed = FALSE;
    bool need_direct_ack = FALSE;
    lrmd_rsc_info_t *rsc = NULL;
    const char *node_name = NULL;

    CRM_CHECK(op != NULL, return);
    CRM_CHECK(op->rsc_id != NULL, return);

    // Remap new status codes for older DCs
    if (compare_version(controld_globals.dc_version, "3.2.0") < 0) {
        switch (op->op_status) {
            case PCMK_EXEC_NOT_CONNECTED:
                lrmd__set_result(op, PCMK_OCF_CONNECTION_DIED,
                                 PCMK_EXEC_ERROR, op->exit_reason);
                break;
            case PCMK_EXEC_INVALID:
                lrmd__set_result(op, CRM_DIRECT_NACK_RC, PCMK_EXEC_ERROR,
                                 op->exit_reason);
                break;
            default:
                break;
        }
    }

    op_id = make_stop_id(op->rsc_id, op->call_id);
    op_key = pcmk__op_key(op->rsc_id, op->op_type, op->interval_ms);

    // Get resource info if available (from executor state or action XML)
    if (lrm_state) {
        rsc = lrm_state_get_rsc_info(lrm_state, op->rsc_id, 0);
    }
    if ((rsc == NULL) && action_xml) {
        xmlNode *xml = find_xml_node(action_xml, XML_CIB_TAG_RESOURCE, TRUE);

        const char *standard = crm_element_value(xml, XML_AGENT_ATTR_CLASS);
        const char *provider = crm_element_value(xml, XML_AGENT_ATTR_PROVIDER);
        const char *type = crm_element_value(xml, XML_ATTR_TYPE);

        if (standard && type) {
            crm_info("%s agent information not cached, using %s%s%s:%s from action XML",
                     op->rsc_id, standard,
                     (provider? ":" : ""), (provider? provider : ""), type);
            rsc = lrmd_new_rsc_info(op->rsc_id, standard, provider, type);
        } else {
            crm_err("Can't process %s result because %s agent information not cached or in XML",
                    op_key, op->rsc_id);
        }
    }

    // Get node name if available (from executor state or action XML)
    if (lrm_state) {
        node_name = lrm_state->node_name;
    } else if (action_xml) {
        node_name = crm_element_value(action_xml, XML_LRM_ATTR_TARGET);
    }

    if(pending == NULL) {
        remove = TRUE;
        if (lrm_state) {
            pending = g_hash_table_lookup(lrm_state->active_ops, op_id);
        }
    }

    if (op->op_status == PCMK_EXEC_ERROR) {
        switch(op->rc) {
            case PCMK_OCF_NOT_RUNNING:
            case PCMK_OCF_RUNNING_PROMOTED:
            case PCMK_OCF_DEGRADED:
            case PCMK_OCF_DEGRADED_PROMOTED:
                // Leave it to the TE/scheduler to decide if this is an error
                op->op_status = PCMK_EXEC_DONE;
                break;
            default:
                /* Nothing to do */
                break;
        }
    }

    if (op->op_status != PCMK_EXEC_CANCELLED) {
        /* We might not record the result, so directly acknowledge it to the
         * originator instead, so it doesn't time out waiting for the result
         * (especially important if part of a transition).
         */
        need_direct_ack = TRUE;

        if (controld_action_is_recordable(op->op_type)) {
            if (node_name && rsc) {
                // We should record the result, and happily, we can
                time_t lock_time = (pending == NULL)? 0 : pending->lock_time;

                controld_update_resource_history(node_name, rsc, op, lock_time);
                need_direct_ack = FALSE;

            } else if (op->rsc_deleted) {
                /* We shouldn't record the result (likely the resource was
                 * refreshed, cleaned, or removed while this operation was
                 * in flight).
                 */
                crm_notice("Not recording %s result in CIB because "
                           "resource information was removed since it was initiated",
                           op_key);
            } else {
                /* This shouldn't be possible; the executor didn't consider the
                 * resource deleted, but we couldn't find resource or node
                 * information.
                 */
                crm_err("Unable to record %s result in CIB: %s", op_key,
                        (node_name? "No resource information" : "No node name"));
            }
        }

    } else if (op->interval_ms == 0) {
        /* A non-recurring operation was cancelled. Most likely, the
         * never-initiated action was removed from the executor's pending
         * operations list upon resource removal.
         */
        need_direct_ack = TRUE;

    } else if (pending == NULL) {
        /* This recurring operation was cancelled, but was not pending. No
         * transition actions are waiting on it, nothing needs to be done.
         */

    } else if (op->user_data == NULL) {
        /* This recurring operation was cancelled and pending, but we don't
         * have a transition key. This should never happen.
         */
        crm_err("Recurring operation %s was cancelled without transition information",
                op_key);

    } else if (pcmk_is_set(pending->flags, active_op_remove)) {
        /* This recurring operation was cancelled (by us) and pending, and we
         * have been waiting for it to finish.
         */
        if (lrm_state) {
            controld_delete_action_history(op);
        }

        /* Directly acknowledge failed recurring actions here. The above call to
         * controld_delete_action_history() will not erase any corresponding
         * last_failure entry, which means that the DC won't confirm the
         * cancellation via process_op_deletion(), and the transition would
         * otherwise wait for the action timer to pop.
         */
        if (did_lrm_rsc_op_fail(lrm_state, pending->rsc_id,
                                pending->op_type, pending->interval_ms)) {
            need_direct_ack = TRUE;
        }

    } else if (op->rsc_deleted) {
        /* This recurring operation was cancelled (but not by us, and the
         * executor does not have resource information, likely due to resource
         * cleanup, refresh, or removal) and pending.
         */
        crm_debug("Recurring op %s was cancelled due to resource deletion",
                  op_key);
        need_direct_ack = TRUE;

    } else {
        /* This recurring operation was cancelled (but not by us, likely by the
         * executor before stopping the resource) and pending. We don't need to
         * do anything special.
         */
    }

    if (need_direct_ack) {
        controld_ack_event_directly(NULL, NULL, NULL, op, op->rsc_id);
    }

    if(remove == FALSE) {
        /* The caller will do this afterwards, but keep the logging consistent */
        removed = TRUE;

    } else if (lrm_state && ((op->interval_ms == 0)
                             || (op->op_status == PCMK_EXEC_CANCELLED))) {

        gboolean found = g_hash_table_remove(lrm_state->active_ops, op_id);

        if (op->interval_ms != 0) {
            removed = TRUE;
        } else if (found) {
            removed = TRUE;
            crm_trace("Op %s (call=%d, stop-id=%s, remaining=%u): Confirmed",
                      op_key, op->call_id, op_id,
                      g_hash_table_size(lrm_state->active_ops));
        }
    }

    log_executor_event(op, op_key, node_name, removed);

    if (lrm_state) {
        if (!pcmk__str_eq(op->op_type, RSC_METADATA, pcmk__str_casei)) {
            crmd_alert_resource_op(lrm_state->node_name, op);
        } else if (rsc && (op->rc == PCMK_OCF_OK)) {
            char *metadata = unescape_newlines(op->output);

            controld_cache_metadata(lrm_state->metadata_cache, rsc, metadata);
            free(metadata);
        }
    }

    if (op->rsc_deleted) {
        crm_info("Deletion of resource '%s' complete after %s", op->rsc_id, op_key);
        if (lrm_state) {
            delete_rsc_entry(lrm_state, NULL, op->rsc_id, NULL, pcmk_ok, NULL,
                             true);
        }
    }

    /* If a shutdown was escalated while operations were pending,
     * then the FSA will be stalled right now... allow it to continue
     */
    controld_trigger_fsa();
    if (lrm_state && rsc) {
        update_history_cache(lrm_state, rsc, op);
    }

    lrmd_free_rsc_info(rsc);
    free(op_key);
    free(op_id);
}
