/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/services.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <regex.h>
#include <crm/pengine/rules.h>

#define START_DELAY_THRESHOLD 5 * 60 * 1000
#define MAX_LRM_REG_FAILS 30

#define s_if_plural(i) (((i) == 1)? "" : "s")

struct delete_event_s {
    int rc;
    const char *rsc;
    lrm_state_t *lrm_state;
};

static gboolean is_rsc_active(lrm_state_t * lrm_state, const char *rsc_id);
static gboolean build_active_RAs(lrm_state_t * lrm_state, xmlNode * rsc_list);
static gboolean stop_recurring_actions(gpointer key, gpointer value, gpointer user_data);
static int delete_rsc_status(lrm_state_t * lrm_state, const char *rsc_id, int call_options,
                             const char *user_name);

static lrmd_event_data_t *construct_op(lrm_state_t * lrm_state, xmlNode * rsc_op,
                                       const char *rsc_id, const char *operation);
static void do_lrm_rsc_op(lrm_state_t * lrm_state, lrmd_rsc_info_t * rsc, const char *operation,
                          xmlNode * msg, xmlNode * request);

void send_direct_ack(const char *to_host, const char *to_sys,
                     lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, const char *rsc_id);

static gboolean lrm_state_verify_stopped(lrm_state_t * lrm_state, enum crmd_fsa_state cur_state,
                                         int log_level);
static int do_update_resource(const char *node_name, lrmd_rsc_info_t * rsc, lrmd_event_data_t * op);

static void
lrm_connection_destroy(void)
{
    if (is_set(fsa_input_register, R_LRM_CONNECTED)) {
        crm_crit("LRM Connection failed");
        register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
        clear_bit(fsa_input_register, R_LRM_CONNECTED);

    } else {
        crm_info("LRM Connection disconnected");
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

        if ((op->interval == existing->interval)
            && crm_str_eq(op->rsc_id, existing->rsc_id, TRUE)
            && safe_str_eq(op->op_type, existing->op_type)) {

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
        delete_rsc_status(lrm_state, op->rsc_id, cib_quorum_override, NULL);
        return;
    }

    if (safe_str_eq(op->op_type, RSC_NOTIFY)) {
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
        if (rsc->provider) {
            entry->rsc.provider = strdup(rsc->provider);
        } else {
            entry->rsc.provider = NULL;
        }

    } else if (entry == NULL) {
        crm_info("Resource %s no longer exists, not updating cache", op->rsc_id);
        return;
    }

    entry->last_callid = op->call_id;
    target_rc = rsc_op_expected_rc(op);
    if (op->op_status == PCMK_LRM_OP_CANCELLED) {
        if (op->interval > 0) {
            crm_trace("Removing cancelled recurring op: %s_%s_%d", op->rsc_id, op->op_type,
                      op->interval);
            history_remove_recurring_op(entry, op);
            return;
        } else {
            crm_trace("Skipping %s_%s_%d rc=%d, status=%d", op->rsc_id, op->op_type, op->interval,
                      op->rc, op->op_status);
        }

    } else if (did_rsc_op_fail(op, target_rc)) {
        /* Store failed monitors here, otherwise the block below will cause them
         * to be forgotten when a stop happens.
         */
        if (entry->failed) {
            lrmd_free_event(entry->failed);
        }
        entry->failed = lrmd_copy_event(op);

    } else if (op->interval == 0) {
        if (entry->last) {
            lrmd_free_event(entry->last);
        }
        entry->last = lrmd_copy_event(op);

        if (op->params &&
            (safe_str_eq(CRMD_ACTION_START, op->op_type) ||
             safe_str_eq("reload", op->op_type) ||
             safe_str_eq(CRMD_ACTION_STATUS, op->op_type))) {

            if (entry->stop_params) {
                g_hash_table_destroy(entry->stop_params);
            }
            entry->stop_params = crm_str_table_new();

            g_hash_table_foreach(op->params, copy_instance_keys, entry->stop_params);
        }
    }

    if (op->interval > 0) {
        /* Ensure there are no duplicates */
        history_remove_recurring_op(entry, op);

        crm_trace("Adding recurring op: %s_%s_%d", op->rsc_id, op->op_type, op->interval);
        entry->recurring_op_list = g_list_prepend(entry->recurring_op_list, lrmd_copy_event(op));

    } else if (entry->recurring_op_list && safe_str_eq(op->op_type, RSC_STATUS) == FALSE) {
        crm_trace("Dropping %d recurring ops because of: %s_%s_%d",
                  g_list_length(entry->recurring_op_list), op->rsc_id,
                  op->op_type, op->interval);
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
send_task_ok_ack(lrm_state_t *lrm_state, ha_msg_input_t *input,
                 const char *rsc_id, lrmd_rsc_info_t *rsc, const char *task,
                 const char *ack_host, const char *ack_sys)
{
    lrmd_event_data_t *op = construct_op(lrm_state, input->xml, rsc_id, task);

    op->rc = PCMK_OCF_OK;
    op->op_status = PCMK_LRM_OP_DONE;
    send_direct_ack(ack_host, ack_sys, rsc, op, rsc_id);
    lrmd_free_event(op);
}

void
lrm_op_callback(lrmd_event_data_t * op)
{
    const char *nodename = NULL;
    lrm_state_t *lrm_state = NULL;

    CRM_CHECK(op != NULL, return);

    /* determine the node name for this connection. */
    nodename = op->remote_nodename ? op->remote_nodename : fsa_our_uname;

    if (op->type == lrmd_event_disconnect && (safe_str_eq(nodename, fsa_our_uname))) {
        /* if this is the local lrmd ipc connection, set the right bits in the
         * crmd when the connection goes down */
        lrm_connection_destroy();
        return;
    } else if (op->type != lrmd_event_exec_complete) {
        /* we only need to process execution results */
        return;
    }

    lrm_state = lrm_state_find(nodename);
    CRM_ASSERT(lrm_state != NULL);

    process_lrm_event(lrm_state, op, NULL);
}

/*	 A_LRM_CONNECT	*/
void
do_lrm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    /* This only pertains to local lrmd connections.  Remote connections are handled as
     * resources within the pengine.  Connecting and disconnecting from remote lrmd instances
     * handled differently than the local. */

    lrm_state_t *lrm_state = NULL;

    if(fsa_our_uname == NULL) {
        return; /* Nothing to do */
    }
    lrm_state = lrm_state_find_or_create(fsa_our_uname);
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

        clear_bit(fsa_input_register, R_LRM_CONNECTED);
        crm_info("Disconnecting from the LRM");
        lrm_state_disconnect(lrm_state);
        lrm_state_reset_tables(lrm_state, FALSE);
        crm_notice("Disconnected from the LRM");
    }

    if (action & A_LRM_CONNECT) {
        int ret = pcmk_ok;

        crm_debug("Connecting to the LRM");
        ret = lrm_state_ipc_connect(lrm_state);

        if (ret != pcmk_ok) {
            if (lrm_state->num_lrm_register_fails < MAX_LRM_REG_FAILS) {
                crm_warn("Failed to connect to the LRM %d time%s (%d max)",
                         lrm_state->num_lrm_register_fails,
                         s_if_plural(lrm_state->num_lrm_register_fails),
                         MAX_LRM_REG_FAILS);

                crm_timer_start(wait_timer);
                crmd_fsa_stall(FALSE);
                return;
            }
        }

        if (ret != pcmk_ok) {
            crm_err("Failed to connect to the LRM the max allowed %d time%s",
                    lrm_state->num_lrm_register_fails,
                    s_if_plural(lrm_state->num_lrm_register_fails));
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            return;
        }

        set_bit(fsa_input_register, R_LRM_CONNECTED);
        crm_info("LRM connection established");
    }

    if (action & ~(A_LRM_CONNECT | A_LRM_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action), __FUNCTION__);
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
    struct recurring_op_s *pending = NULL;

    crm_debug("Checking for active resources before exit");

    if (cur_state == S_TERMINATE) {
        log_level = LOG_ERR;
        when = "shutdown";

    } else if (is_set(fsa_input_register, R_SHUTDOWN)) {
        when = "shutdown... waiting";
    }

    if (lrm_state->pending_ops && lrm_state_is_connected(lrm_state) == TRUE) {
        guint removed = g_hash_table_foreach_remove(
            lrm_state->pending_ops, stop_recurring_actions, lrm_state);
        guint nremaining = g_hash_table_size(lrm_state->pending_ops);

        if (removed || nremaining) {
            crm_notice("Stopped %u recurring operation%s at %s (%u remaining)",
                       removed, s_if_plural(removed), when, nremaining);
        }
    }

    if (lrm_state->pending_ops) {
        g_hash_table_iter_init(&gIter, lrm_state->pending_ops);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&pending)) {
            /* Ignore recurring actions in the shutdown calculations */
            if (pending->interval == 0) {
                counter++;
            }
        }
    }

    if (counter > 0) {
        do_crm_log(log_level, "%d pending LRM operation%s at %s",
                   counter, s_if_plural(counter), when);

        if (cur_state == S_TERMINATE || !is_set(fsa_input_register, R_SENT_RSC_STOP)) {
            g_hash_table_iter_init(&gIter, lrm_state->pending_ops);
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

    if (is_set(fsa_input_register, R_SHUTDOWN)) {
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
        if (lrm_state->pending_ops) {
            GHashTableIter hIter;

            g_hash_table_iter_init(&hIter, lrm_state->pending_ops);
            while (g_hash_table_iter_next(&hIter, (gpointer*)&key, (gpointer*)&pending)) {
                if (crm_str_eq(entry->id, pending->rsc_id, TRUE)) {
                    crm_notice("%sction %s (%s) incomplete at %s",
                               pending->interval == 0 ? "A" : "Recurring a",
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

static char *
build_parameter_list(const lrmd_event_data_t *op,
                     const struct ra_metadata_s *metadata,
                     xmlNode *result, enum ra_param_flags_e param_type,
                     bool invert_for_xml)
{
    int len = 0;
    int max = 0;
    char *list = NULL;
    GList *iter = NULL;

    /* Newer resource agents support the "private" parameter attribute to
     * indicate sensitive parameters. For backward compatibility with older
     * agents, this list is used if the agent doesn't specify any as "private".
     */
    const char *secure_terms[] = {
        "password",
        "passwd",
        "user",
    };

    if (is_not_set(metadata->ra_flags, ra_uses_private)
        && (param_type == ra_param_private)) {

        max = DIMOF(secure_terms);
    }

    for (iter = metadata->ra_params; iter != NULL; iter = iter->next) {
        struct ra_param_s *param = (struct ra_param_s *) iter->data;
        bool accept = FALSE;

        if (is_set(param->rap_flags, param_type)) {
            accept = TRUE;

        } else if (max) {
            for (int lpc = 0; lpc < max; lpc++) {
                if (safe_str_eq(secure_terms[lpc], param->rap_name)) {
                    accept = TRUE;
                    break;
                }
            }
        }

        if (accept) {
            int start = len;

            crm_trace("Attr %s is %s", param->rap_name, ra_param_flag2text(param_type));

            len += strlen(param->rap_name) + 2; // include spaces around
            list = realloc_safe(list, len + 1); // include null terminator

            // spaces before and after make parsing simpler
            sprintf(list + start, " %s ", param->rap_name);

        } else {
            crm_trace("Rejecting %s for %s", param->rap_name, ra_param_flag2text(param_type));
        }

        if (result && (invert_for_xml? !accept : accept)) {
            const char *v = g_hash_table_lookup(op->params, param->rap_name);

            if (v != NULL) {
                crm_trace("Adding attr %s=%s to the xml result", param->rap_name, v);
                crm_xml_add(result, param->rap_name, v);
            }
        }
    }

    return list;
}

static void
append_restart_list(lrmd_event_data_t *op, struct ra_metadata_s *metadata,
                    xmlNode *update, const char *version)
{
    char *list = NULL;
    char *digest = NULL;
    xmlNode *restart = NULL;

    CRM_LOG_ASSERT(op->params != NULL);

    if (op->interval > 0) {
        /* monitors are not reloadable */
        return;
    }

    if (is_set(metadata->ra_flags, ra_supports_reload)) {
        restart = create_xml_node(NULL, XML_TAG_PARAMS);
        /* Add any parameters with unique="1" to the "op-force-restart" list.
         *
         * (Currently, we abuse "unique=0" to indicate reloadability. This is
         * nonstandard and should eventually be replaced once the OCF standard
         * is updated with something better.)
         */
        list = build_parameter_list(op, metadata, restart, ra_param_unique,
                                    FALSE);

    } else {
        /* Resource does not support reloads */
        return;
    }

    digest = calculate_operation_digest(restart, version);
    /* Add "op-force-restart" and "op-restart-digest" to indicate the resource supports reload,
     * no matter if it actually supports any parameters with unique="1"). */
    crm_xml_add(update, XML_LRM_ATTR_OP_RESTART, list? list: "");
    crm_xml_add(update, XML_LRM_ATTR_RESTART_DIGEST, digest);

    crm_trace("%s: %s, %s", op->rsc_id, digest, list);
    crm_log_xml_trace(restart, "restart digest source");

    free_xml(restart);
    free(digest);
    free(list);
}

static void
append_secure_list(lrmd_event_data_t *op, struct ra_metadata_s *metadata,
                   xmlNode *update, const char *version)
{
    char *list = NULL;
    char *digest = NULL;
    xmlNode *secure = NULL;

    CRM_LOG_ASSERT(op->params != NULL);

    /*
     * To keep XML_LRM_ATTR_OP_SECURE short, we want it to contain the
     * secure parameters but XML_LRM_ATTR_SECURE_DIGEST to be based on
     * the insecure ones
     */
    secure = create_xml_node(NULL, XML_TAG_PARAMS);
    list = build_parameter_list(op, metadata, secure, ra_param_private, TRUE);

    if (list != NULL) {
        digest = calculate_operation_digest(secure, version);
        crm_xml_add(update, XML_LRM_ATTR_OP_SECURE, list);
        crm_xml_add(update, XML_LRM_ATTR_SECURE_DIGEST, digest);

        crm_trace("%s: %s, %s", op->rsc_id, digest, list);
        crm_log_xml_trace(secure, "secure digest source");
    } else {
        crm_trace("%s: no secure parameters", op->rsc_id);
    }

    free_xml(secure);
    free(digest);
    free(list);
}

static gboolean
build_operation_update(xmlNode * parent, lrmd_rsc_info_t * rsc, lrmd_event_data_t * op,
                       const char *node_name, const char *src)
{
    int target_rc = 0;
    xmlNode *xml_op = NULL;
    struct ra_metadata_s *metadata = NULL;
    const char *caller_version = NULL;
    lrm_state_t *lrm_state = NULL;

    if (op == NULL) {
        return FALSE;
    }

    target_rc = rsc_op_expected_rc(op);

    /* there is a small risk in formerly mixed clusters that it will
     * be sub-optimal.
     *
     * however with our upgrade policy, the update we send should
     * still be completely supported anyway
     */
    caller_version = g_hash_table_lookup(op->params, XML_ATTR_CRM_VERSION);
    CRM_LOG_ASSERT(caller_version != NULL);

    if(caller_version == NULL) {
        caller_version = CRM_FEATURE_SET;
    }

    crm_trace("Building %s operation update with originator version: %s", op->rsc_id, caller_version);
    xml_op = create_operation_update(parent, op, caller_version, target_rc, fsa_our_uname, src, LOG_DEBUG);
    if (xml_op == NULL) {
        return TRUE;
    }

    if ((rsc == NULL) || (op == NULL) || (op->params == NULL)
        || !crm_op_needs_metadata(rsc->standard, op->op_type)) {

        crm_trace("No digests needed for %s action on %s (params=%p rsc=%p)",
                  op->op_type, op->rsc_id, op->params, rsc);
        return TRUE;
    }

    lrm_state = lrm_state_find(node_name);
    if (lrm_state == NULL) {
        crm_warn("Cannot calculate digests for operation %s_%s_%d because we have no LRM connection to %s",
                 op->rsc_id, op->op_type, op->interval, node_name);
        return TRUE;
    }

    metadata = metadata_cache_get(lrm_state->metadata_cache, rsc);
    if (metadata == NULL) {
        /* For now, we always collect resource agent meta-data via a local,
         * synchronous, direct execution of the agent. This has multiple issues:
         * the lrmd should execute agents, not the crmd; meta-data for
         * Pacemaker Remote nodes should be collected on those nodes, not
         * locally; and the meta-data call shouldn't eat into the timeout of the
         * real action being performed.
         *
         * These issues are planned to be addressed by having the PE schedule
         * a meta-data cache check at the beginning of each transition. Once
         * that is working, this block will only be a fallback in case the
         * initial collection fails.
         */
        char *metadata_str = NULL;

        int rc = lrm_state_get_metadata(lrm_state, rsc->standard,
                                        rsc->provider, rsc->type,
                                        &metadata_str, 0);

        if (rc != pcmk_ok) {
            crm_warn("Failed to get metadata for %s (%s:%s:%s)",
                     rsc->id, rsc->standard, rsc->provider, rsc->type);
            return TRUE;
        }

        metadata = metadata_cache_update(lrm_state->metadata_cache, rsc,
                                         metadata_str);
        free(metadata_str);
        if (metadata == NULL) {
            crm_warn("Failed to update metadata for %s (%s:%s:%s)",
                     rsc->id, rsc->standard, rsc->provider, rsc->type);
            return TRUE;
        }
    }

#if ENABLE_VERSIONED_ATTRS
    crm_xml_add(xml_op, XML_ATTR_RA_VERSION, metadata->ra_version);
#endif

    crm_trace("Including additional digests for %s::%s:%s", rsc->standard, rsc->provider, rsc->type);
    append_restart_list(op, metadata, xml_op, caller_version);
    append_secure_list(op, metadata, xml_op, caller_version);

    return TRUE;
}

static gboolean
is_rsc_active(lrm_state_t * lrm_state, const char *rsc_id)
{
    rsc_history_t *entry = NULL;

    entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
    if (entry == NULL || entry->last == NULL) {
        return FALSE;
    }

    crm_trace("Processing %s: %s.%d=%d",
              rsc_id, entry->last->op_type, entry->last->interval, entry->last->rc);
    if (entry->last->rc == PCMK_OCF_OK && safe_str_eq(entry->last->op_type, CRMD_ACTION_STOP)) {
        return FALSE;

    } else if (entry->last->rc == PCMK_OCF_OK
               && safe_str_eq(entry->last->op_type, CRMD_ACTION_MIGRATE)) {
        /* a stricter check is too complex...
         * leave that to the PE
         */
        return FALSE;

    } else if (entry->last->rc == PCMK_OCF_NOT_RUNNING) {
        return FALSE;

    } else if (entry->last->interval == 0 && entry->last->rc == PCMK_OCF_NOT_CONFIGURED) {
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
        build_operation_update(xml_rsc, &(entry->rsc), entry->failed, lrm_state->node_name, __FUNCTION__);
        build_operation_update(xml_rsc, &(entry->rsc), entry->last, lrm_state->node_name, __FUNCTION__);
        for (gIter = entry->recurring_op_list; gIter != NULL; gIter = gIter->next) {
            build_operation_update(xml_rsc, &(entry->rsc), gIter->data, lrm_state->node_name, __FUNCTION__);
        }
    }

    return FALSE;
}

static xmlNode *
do_lrm_query_internal(lrm_state_t *lrm_state, int update_flags)
{
    xmlNode *xml_state = NULL;
    xmlNode *xml_data = NULL;
    xmlNode *rsc_list = NULL;
    crm_node_t *peer = NULL;

    peer = crm_get_peer_full(0, lrm_state->node_name, CRM_GET_PEER_ANY);
    CRM_CHECK(peer != NULL, return NULL);

    xml_state = create_node_state_update(peer, update_flags, NULL,
                                         __FUNCTION__);
    if (xml_state == NULL) {
        return NULL;
    }

    xml_data = create_xml_node(xml_state, XML_CIB_TAG_LRM);
    crm_xml_add(xml_data, XML_ATTR_ID, peer->uuid);
    rsc_list = create_xml_node(xml_data, XML_LRM_TAG_RESOURCES);

    /* Build a list of active (not always running) resources */
    build_active_RAs(lrm_state, rsc_list);

    crm_log_xml_trace(xml_state, "Current state of the LRM");

    return xml_state;
}

xmlNode *
do_lrm_query(gboolean is_replace, const char *node_name)
{
    lrm_state_t *lrm_state = lrm_state_find(node_name);

    if (!lrm_state) {
        crm_err("Could not query lrm state for lrmd node %s", node_name);
        return NULL;
    }
    return do_lrm_query_internal(lrm_state,
                                 node_update_cluster|node_update_peer);
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

    if (rc == pcmk_ok) {
        op->op_status = PCMK_LRM_OP_DONE;
        op->rc = PCMK_OCF_OK;
    } else {
        op->op_status = PCMK_LRM_OP_ERROR;
        op->rc = PCMK_OCF_UNKNOWN_ERROR;
    }

    send_direct_ack(from_host, from_sys, NULL, op, rsc_id);
    lrmd_free_event(op);

    if (safe_str_neq(from_sys, CRM_SYSTEM_TENGINE)) {
        /* this isn't expected - trigger a new transition */
        time_t now = time(NULL);
        char *now_s = crm_itoa(now);

        crm_debug("Triggering a refresh after %s deleted %s from the LRM", from_sys, rsc_id);

        update_attr_delegate(fsa_cib_conn, cib_none, XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                             "last-lrm-refresh", now_s, FALSE, NULL, NULL);

        free(now_s);
    }
}

static gboolean
lrm_remove_deleted_rsc(gpointer key, gpointer value, gpointer user_data)
{
    struct delete_event_s *event = user_data;
    struct pending_deletion_op_s *op = value;

    if (crm_str_eq(event->rsc, op->rsc, TRUE)) {
        notify_deleted(event->lrm_state, op->input, event->rsc, event->rc);
        return TRUE;
    }
    return FALSE;
}

static gboolean
lrm_remove_deleted_op(gpointer key, gpointer value, gpointer user_data)
{
    const char *rsc = user_data;
    struct recurring_op_s *pending = value;

    if (crm_str_eq(rsc, pending->rsc_id, TRUE)) {
        crm_info("Removing op %s:%d for deleted resource %s",
                 pending->op_key, pending->call_id, rsc);
        return TRUE;
    }
    return FALSE;
}

/*
 * Remove the rsc from the CIB
 *
 * Avoids refreshing the entire LRM section of this host
 */
#define rsc_template "//"XML_CIB_TAG_STATE"[@uname='%s']//"XML_LRM_TAG_RESOURCE"[@id='%s']"

static int
delete_rsc_status(lrm_state_t * lrm_state, const char *rsc_id, int call_options,
                  const char *user_name)
{
    char *rsc_xpath = NULL;
    int rc = pcmk_ok;

    CRM_CHECK(rsc_id != NULL, return -ENXIO);

    rsc_xpath = crm_strdup_printf(rsc_template, lrm_state->node_name, rsc_id);

    rc = cib_internal_op(fsa_cib_conn, CIB_OP_DELETE, NULL, rsc_xpath,
                         NULL, NULL, call_options | cib_xpath, user_name);

    free(rsc_xpath);
    return rc;
}

static void
delete_rsc_entry(lrm_state_t * lrm_state, ha_msg_input_t * input, const char *rsc_id,
                 GHashTableIter * rsc_gIter, int rc, const char *user_name)
{
    struct delete_event_s event;

    CRM_CHECK(rsc_id != NULL, return);

    if (rc == pcmk_ok) {
        char *rsc_id_copy = strdup(rsc_id);

        if (rsc_gIter)
            g_hash_table_iter_remove(rsc_gIter);
        else
            g_hash_table_remove(lrm_state->resource_history, rsc_id_copy);
        crm_debug("sync: Sending delete op for %s", rsc_id_copy);
        delete_rsc_status(lrm_state, rsc_id_copy, cib_quorum_override, user_name);

        g_hash_table_foreach_remove(lrm_state->pending_ops, lrm_remove_deleted_op, rsc_id_copy);
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

/*!
 * \internal
 * \brief Erase an LRM history entry from the CIB, given the operation data
 *
 * \param[in] lrm_state  LRM state of the desired node
 * \param[in] op         Operation whose history should be deleted
 */
static void
erase_lrm_history_by_op(lrm_state_t *lrm_state, lrmd_event_data_t *op)
{
    xmlNode *xml_top = NULL;

    CRM_CHECK(op != NULL, return);

    xml_top = create_xml_node(NULL, XML_LRM_TAG_RSC_OP);
    crm_xml_add_int(xml_top, XML_LRM_ATTR_CALLID, op->call_id);
    crm_xml_add(xml_top, XML_ATTR_TRANSITION_KEY, op->user_data);

    if (op->interval > 0) {
        char *op_id = generate_op_key(op->rsc_id, op->op_type, op->interval);

        /* Avoid deleting last_failure too (if it was a result of this recurring op failing) */
        crm_xml_add(xml_top, XML_ATTR_ID, op_id);
        free(op_id);
    }

    crm_debug("Erasing LRM resource history for %s_%s_%d (call=%d)",
              op->rsc_id, op->op_type, op->interval, op->call_id);

    fsa_cib_conn->cmds->remove(fsa_cib_conn, XML_CIB_TAG_STATUS, xml_top,
                               cib_quorum_override);

    crm_log_xml_trace(xml_top, "op:cancel");
    free_xml(xml_top);
}

/* Define xpath to find LRM resource history entry by node and resource */
#define XPATH_HISTORY                                   \
    "/" XML_TAG_CIB "/" XML_CIB_TAG_STATUS              \
    "/" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='%s']"  \
    "/" XML_CIB_TAG_LRM "/" XML_LRM_TAG_RESOURCES       \
    "/" XML_LRM_TAG_RESOURCE "[@" XML_ATTR_ID "='%s']"  \
    "/" XML_LRM_TAG_RSC_OP

/* ... and also by operation key */
#define XPATH_HISTORY_ID XPATH_HISTORY \
    "[@" XML_ATTR_ID "='%s']"

/* ... and also by operation key and operation call ID */
#define XPATH_HISTORY_CALL XPATH_HISTORY \
    "[@" XML_ATTR_ID "='%s' and @" XML_LRM_ATTR_CALLID "='%d']"

/* ... and also by operation key and original operation key */
#define XPATH_HISTORY_ORIG XPATH_HISTORY \
    "[@" XML_ATTR_ID "='%s' and @" XML_LRM_ATTR_TASK_KEY "='%s']"

/*!
 * \internal
 * \brief Erase an LRM history entry from the CIB, given operation identifiers
 *
 * \param[in] lrm_state  LRM state of the node to clear history for
 * \param[in] rsc_id     Name of resource to clear history for
 * \param[in] key        Operation key of operation to clear history for
 * \param[in] orig_op    If specified, delete only if it has this original op
 * \param[in] call_id    If specified, delete entry only if it has this call ID
 */
static void
erase_lrm_history_by_id(lrm_state_t *lrm_state, const char *rsc_id,
                        const char *key, const char *orig_op, int call_id)
{
    char *op_xpath = NULL;

    CRM_CHECK((rsc_id != NULL) && (key != NULL), return);

    if (call_id > 0) {
        op_xpath = crm_strdup_printf(XPATH_HISTORY_CALL,
                                     lrm_state->node_name, rsc_id, key,
                                     call_id);

    } else if (orig_op) {
        op_xpath = crm_strdup_printf(XPATH_HISTORY_ORIG,
                                     lrm_state->node_name, rsc_id, key,
                                     orig_op);
    } else {
        op_xpath = crm_strdup_printf(XPATH_HISTORY_ID,
                                     lrm_state->node_name, rsc_id, key);
    }

    crm_debug("Erasing LRM resource history for %s on %s (call=%d)",
              key, rsc_id, call_id);
    fsa_cib_conn->cmds->remove(fsa_cib_conn, op_xpath, NULL,
                               cib_quorum_override | cib_xpath);
    free(op_xpath);
}

static inline gboolean
last_failed_matches_op(rsc_history_t *entry, const char *op, int interval)
{
    if (entry == NULL) {
        return FALSE;
    }
    if (op == NULL) {
        return TRUE;
    }
    return (safe_str_eq(op, entry->failed->op_type)
            && (interval == entry->failed->interval));
}

/*!
 * \internal
 * \brief Clear a resource's last failure
 *
 * Erase a resource's last failure on a particular node from both the
 * LRM resource history in the CIB, and the resource history remembered
 * for the LRM state.
 *
 * \param[in] rsc_id     Resource name
 * \param[in] node_name  Node name
 * \param[in] operation  If specified, only clear if matching this operation
 * \param[in] interval   If operation is specified, it has this interval in ms
 */
void
lrm_clear_last_failure(const char *rsc_id, const char *node_name,
                       const char *operation, int interval)
{
    char *op_key = NULL;
    char *orig_op_key = NULL;
    lrm_state_t *lrm_state = NULL;

    lrm_state = lrm_state_find(node_name);
    if (lrm_state == NULL) {
        return;
    }

    /* Erase from CIB */
    op_key = generate_op_key(rsc_id, "last_failure", 0);
    if (operation) {
        orig_op_key = generate_op_key(rsc_id, operation, interval);
    }
    erase_lrm_history_by_id(lrm_state, rsc_id, op_key, orig_op_key, 0);
    free(op_key);
    free(orig_op_key);

    /* Remove from memory */
    if (lrm_state->resource_history) {
        rsc_history_t *entry = g_hash_table_lookup(lrm_state->resource_history,
                                                   rsc_id);

        if (last_failed_matches_op(entry, operation, interval)) {
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
    struct recurring_op_s *pending = NULL;

    CRM_CHECK(op != 0, return FALSE);
    CRM_CHECK(rsc_id != NULL, return FALSE);
    if (key == NULL) {
        local_key = make_stop_id(rsc_id, op);
        key = local_key;
    }
    pending = g_hash_table_lookup(lrm_state->pending_ops, key);

    if (pending) {
        if (remove && pending->remove == FALSE) {
            pending->remove = TRUE;
            crm_debug("Scheduling %s for removal", key);
        }

        if (pending->cancelled) {
            crm_debug("Operation %s already cancelled", key);
            free(local_key);
            return FALSE;
        }

        pending->cancelled = TRUE;

    } else {
        crm_info("No pending op found for %s", key);
        free(local_key);
        return FALSE;
    }

    crm_debug("Cancelling op %d for %s (%s)", op, rsc_id, key);
    rc = lrm_state_cancel(lrm_state, pending->rsc_id, pending->op_type, pending->interval);
    if (rc == pcmk_ok) {
        crm_debug("Op %d for %s (%s): cancelled", op, rsc_id, key);
        free(local_key);
        return TRUE;
    }

    crm_debug("Op %d for %s (%s): Nothing to cancel", op, rsc_id, key);
    /* The caller needs to make sure the entry is
     * removed from the pending_ops list
     *
     * Usually by returning TRUE inside the worker function
     * supplied to g_hash_table_foreach_remove()
     *
     * Not removing the entry from pending_ops will block
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
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (crm_str_eq(op->op_key, data->key, TRUE)) {
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

    removed = g_hash_table_foreach_remove(lrm_state->pending_ops, cancel_action_by_key, &data);
    crm_trace("Removed %u op cache entries, new size: %u",
              removed, g_hash_table_size(lrm_state->pending_ops));
    return data.done;
}

/*!
 * \internal
 * \brief Retrieve resource information from LRM
 *
 * \param[in]  lrm_state LRM connection to use
 * \param[in]  rsc_xml   XML containing resource configuration
 * \param[in]  do_create If true, register resource with LRM if not already
 * \param[out] rsc_info  Where to store resource information obtained from LRM
 *
 * \retval pcmk_ok   Success (and rsc_info holds newly allocated result)
 * \retval -EINVAL   Required information is missing from arguments
 * \retval -ENOTCONN No active connection to LRM
 * \retval -ENODEV   Resource not found
 * \retval -errno    Error communicating with lrmd when registering resource
 *
 * \note Caller is responsible for freeing result on success.
 */
static int
get_lrm_resource(lrm_state_t *lrm_state, xmlNode *rsc_xml, gboolean do_create,
                 lrmd_rsc_info_t **rsc_info)
{
    const char *id = ID(rsc_xml);

    CRM_CHECK(lrm_state && rsc_xml && rsc_info, return -EINVAL);
    CRM_CHECK(id, return -EINVAL);

    if (lrm_state_is_connected(lrm_state) == FALSE) {
        return -ENOTCONN;
    }

    crm_trace("Retrieving resource information for %s from the LRM", id);
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

        crm_trace("Registering resource %s with LRM", id);
        rc = lrm_state_register_rsc(lrm_state, id, class, provider, type,
                                    lrmd_opt_drop_recurring);
        if (rc != pcmk_ok) {
            fsa_data_t *msg_data = NULL;

            crm_err("Could not register resource %s with LRM on %s: %s "
                    CRM_XS " rc=%d",
                    id, lrm_state->node_name, pcmk_strerror(rc), rc);

            /* Register this as an internal error if this involves the local
             * lrmd. Otherwise, we're likely dealing with an unresponsive remote
             * node, which is not an FSA failure.
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
delete_resource(lrm_state_t * lrm_state,
                const char *id,
                lrmd_rsc_info_t * rsc,
                GHashTableIter * gIter,
                const char *sys,
                const char *host,
                const char *user,
                ha_msg_input_t * request,
                gboolean unregister)
{
    int rc = pcmk_ok;

    crm_info("Removing resource %s for %s (%s) on %s", id, sys, user ? user : "internal", host);

    if (rsc && unregister) {
        rc = lrm_state_unregister_rsc(lrm_state, id, 0);
    }

    if (rc == pcmk_ok) {
        crm_trace("Resource '%s' deleted", id);
    } else if (rc == -EINPROGRESS) {
        crm_info("Deletion of resource '%s' pending", id);
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
        crm_warn("Deletion of resource '%s' for %s (%s) on %s failed: %d",
                 id, sys, user ? user : "internal", host, rc);
    }

    delete_rsc_entry(lrm_state, request, id, gIter, rc, user);
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
               enum ocf_exitcode op_exitcode)
{
    op->call_id = get_fake_call_id(lrm_state, op->rsc_id);
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;
    op->op_status = op_status;
    op->rc = op_exitcode;
}

static void
force_reprobe(lrm_state_t *lrm_state, const char *from_sys,
              const char *from_host, const char *user_name,
              gboolean is_remote_node)
{
    GHashTableIter gIter;
    rsc_history_t *entry = NULL;

    crm_info("Clearing resource history on node %s", lrm_state->node_name);
    g_hash_table_iter_init(&gIter, lrm_state->resource_history);
    while (g_hash_table_iter_next(&gIter, NULL, (void **)&entry)) {
        /* only unregister the resource during a reprobe if it is not a remote connection
         * resource. otherwise unregistering the connection will terminate remote-node
         * membership */
        gboolean unregister = TRUE;

        if (is_remote_lrmd_ra(NULL, NULL, entry->id)) {
            lrm_state_t *remote_lrm_state = lrm_state_find(entry->id);
            if (remote_lrm_state) {
                /* when forcing a reprobe, make sure to clear remote node before
                 * clearing the remote node's connection resource */ 
                force_reprobe(remote_lrm_state, from_sys, from_host, user_name, TRUE);
            }
            unregister = FALSE;
        }

        delete_resource(lrm_state, entry->id, &entry->rsc, &gIter, from_sys, from_host,
                        user_name, NULL, unregister);
    }

    /* Now delete the copy in the CIB */
    erase_status_tag(lrm_state->node_name, XML_CIB_TAG_LRM, cib_scope_local);

    /* And finally, _delete_ the value in attrd
     * Setting it to FALSE results in the PE sending us back here again
     */
    update_attrd(lrm_state->node_name, CRM_OP_PROBED, NULL, user_name, is_remote_node);
}

static void
synthesize_lrmd_failure(lrm_state_t *lrm_state, xmlNode *action, int rc) 
{
    lrmd_event_data_t *op = NULL;
    lrmd_rsc_info_t *rsc_info = NULL;
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

    if (safe_str_eq(operation, RSC_NOTIFY)) { // Notifications can't fail
        fake_op_status(lrm_state, op, PCMK_LRM_OP_DONE, PCMK_OCF_OK);
    } else {
        fake_op_status(lrm_state, op, PCMK_LRM_OP_ERROR, rc);
    }

    crm_info("Faking %s_%s_%d result (%d) on %s",
             op->rsc_id, op->op_type, op->interval, op->rc, target_node);

    /* Process the result as if it came from the LRM, if possible
     * (i.e. resource info can be obtained from the lrm_state).
     */
    if (lrm_state) {
        rsc_info = lrm_state_get_rsc_info(lrm_state, op->rsc_id, 0);
    }
    if (rsc_info) {
        process_lrm_event(lrm_state, op, NULL);

    } else {
        /* If we can't process the result normally, at least write it to the CIB
         * if possible, so the PE can act on it.
         */
        char *standard = crm_element_value_copy(xml_rsc, XML_AGENT_ATTR_CLASS);
        char *provider = crm_element_value_copy(xml_rsc, XML_AGENT_ATTR_PROVIDER);
        char *type = crm_element_value_copy(xml_rsc, XML_ATTR_TYPE);

        if (standard && type) {
            rsc_info = lrmd_new_rsc_info(op->rsc_id, standard, provider, type);
            do_update_resource(target_node, rsc_info, op);
            lrmd_free_rsc_info(rsc_info);
        } else {
            // @TODO Should we direct ack?
            crm_info("Can't fake %s failure (%d) on %s without resource standard and type",
                     crm_element_value(action, XML_LRM_ATTR_TASK_KEY), rc,
                     target_node);
        }
    }
    lrmd_free_event(op);
}

/*!
 * \internal
 * \brief Get target of an LRM operation
 *
 * \param[in] xml  LRM operation data XML
 *
 * \return LRM operation target node name (local node or Pacemaker Remote node)
 */
static const char *
lrm_op_target(xmlNode *xml)
{
    const char *target = NULL;

    if (xml) {
        target = crm_element_value(xml, XML_LRM_ATTR_TARGET);
    }
    if (target == NULL) {
        target = fsa_our_uname;
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

    /* The lrmd simply executes operations and reports the results, without any
     * concept of success or failure, so to fail a resource, we must fake what a
     * failure looks like.
     *
     * To do this, we create a fake lrmd operation event for the resource, and
     * pass that event to the lrmd client callback so it will be processed as if
     * it came from the lrmd.
     */
    op = construct_op(lrm_state, xml, ID(xml_rsc), "asyncmon");
    fake_op_status(lrm_state, op, PCMK_LRM_OP_DONE, PCMK_OCF_UNKNOWN_ERROR);

    free((char*) op->user_data);
    op->user_data = NULL;
    op->interval = 0;

#if ENABLE_ACL
    if (user_name && is_privileged(user_name) == FALSE) {
        crm_err("%s does not have permission to fail %s", user_name, ID(xml_rsc));
        send_direct_ack(from_host, from_sys, NULL, op, ID(xml_rsc));
        lrmd_free_event(op);
        return;
    }
#endif

    if (get_lrm_resource(lrm_state, xml_rsc, TRUE, &rsc) == pcmk_ok) {
        crm_info("Failing resource %s...", rsc->id);
        process_lrm_event(lrm_state, op, NULL);
        op->op_status = PCMK_LRM_OP_DONE;
        op->rc = PCMK_OCF_OK;
        lrmd_free_rsc_info(rsc);

    } else {
        crm_info("Cannot find/create resource in order to fail it...");
        crm_log_xml_warn(xml, "bad input");
    }

    send_direct_ack(from_host, from_sys, NULL, op, ID(xml_rsc));
    lrmd_free_event(op);
}

static void
handle_refresh_op(lrm_state_t *lrm_state, const char *user_name,
                  const char *from_host, const char *from_sys)
{
    int rc = pcmk_ok;
    xmlNode *fragment = do_lrm_query_internal(lrm_state, node_update_all);

    fsa_cib_update(XML_CIB_TAG_STATUS, fragment, cib_quorum_override, rc, user_name);
    crm_info("Forced a local LRM refresh: call=%d", rc);

    if (safe_str_neq(CRM_SYSTEM_CRMD, from_sys)) {
        xmlNode *reply = create_request(CRM_OP_INVOKE_LRM, fragment, from_host,
                                        from_sys, CRM_SYSTEM_LRMD,
                                        fsa_our_uuid);

        crm_debug("ACK'ing refresh from %s (%s)", from_sys, from_host);

        if (relay_message(reply, TRUE) == FALSE) {
            crm_log_xml_err(reply, "Unable to route reply");
        }
        free_xml(reply);
    }

    free_xml(fragment);
}

static void
handle_query_op(xmlNode *msg, lrm_state_t *lrm_state)
{
    xmlNode *data = do_lrm_query_internal(lrm_state, node_update_all);
    xmlNode *reply = create_reply(msg, data);

    if (relay_message(reply, TRUE) == FALSE) {
        crm_err("Unable to route reply");
        crm_log_xml_err(reply, "reply");
    }
    free_xml(reply);
    free_xml(data);
}

static void
handle_reprobe_op(lrm_state_t *lrm_state, const char *from_sys,
                  const char *from_host, const char *user_name,
                  gboolean is_remote_node)
{
    crm_notice("Forcing the status of all resources to be redetected");
    force_reprobe(lrm_state, from_sys, from_host, user_name, is_remote_node);

    if (safe_str_neq(CRM_SYSTEM_PENGINE, from_sys)
        && safe_str_neq(CRM_SYSTEM_TENGINE, from_sys)) {

        xmlNode *reply = create_request(CRM_OP_INVOKE_LRM, NULL, from_host,
                                        from_sys, CRM_SYSTEM_LRMD,
                                        fsa_our_uuid);

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
    const char *op_interval = NULL;
    gboolean in_progress = FALSE;
    xmlNode *params = find_xml_node(input->xml, XML_TAG_ATTRS, TRUE);

    CRM_CHECK(params != NULL, return FALSE);

    meta_key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
    op_interval = crm_element_value(params, meta_key);
    free(meta_key);
    CRM_CHECK(op_interval != NULL, return FALSE);

    meta_key = crm_meta_name(XML_LRM_ATTR_TASK);
    op_task = crm_element_value(params, meta_key);
    free(meta_key);
    CRM_CHECK(op_task != NULL, return FALSE);

    meta_key = crm_meta_name(XML_LRM_ATTR_CALLID);
    call_id = crm_element_value(params, meta_key);
    free(meta_key);

    op_key = generate_op_key(rsc->id, op_task, crm_parse_int(op_interval, "0"));

    crm_debug("PE requested op %s (call=%s) be cancelled",
              op_key, (call_id? call_id : "NA"));
    call = crm_parse_int(call_id, "0");
    if (call == 0) {
        /* the normal case when the PE cancels a recurring op */
        in_progress = cancel_op_key(lrm_state, rsc, op_key, TRUE);

    } else {
        /* the normal case when the PE cancels an orphan op */
        in_progress = cancel_op(lrm_state, rsc->id, NULL, call, TRUE);
    }

    // Acknowledge cancellation operation if for a remote connection resource
    if (!in_progress || is_remote_lrmd_ra(NULL, NULL, rsc->id)) {
        char *op_id = make_stop_id(rsc->id, call);

        if (is_remote_lrmd_ra(NULL, NULL, rsc->id) == FALSE) {
            crm_info("Nothing known about operation %d for %s", call, op_key);
        }
        erase_lrm_history_by_id(lrm_state, rsc->id, op_key, NULL, call);
        send_task_ok_ack(lrm_state, input, rsc->id, rsc, op_task,
                         from_host, from_sys);

        /* needed at least for cancellation of a remote operation */
        g_hash_table_remove(lrm_state->pending_ops, op_id);
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
    gboolean unregister = TRUE;

#if ENABLE_ACL
    int cib_rc = delete_rsc_status(lrm_state, rsc->id,
                                   cib_dryrun|cib_sync_call, user_name);

    if (cib_rc != pcmk_ok) {
        lrmd_event_data_t *op = NULL;

        crm_err("Could not delete resource status of %s for %s (user %s) on %s: %s"
                CRM_XS " rc=%d",
                rsc->id, from_sys, (user_name? user_name : "unknown"),
                from_host, pcmk_strerror(cib_rc), cib_rc);

        op = construct_op(lrm_state, input->xml, rsc->id, CRMD_ACTION_DELETE);
        op->op_status = PCMK_LRM_OP_ERROR;

        if (cib_rc == -EACCES) {
            op->rc = PCMK_OCF_INSUFFICIENT_PRIV;
        } else {
            op->rc = PCMK_OCF_UNKNOWN_ERROR;
        }
        send_direct_ack(from_host, from_sys, NULL, op, rsc->id);
        lrmd_free_event(op);
        lrmd_free_rsc_info(rsc);
        return;
    }
#endif

    if (crm_rsc_delete && is_remote_lrmd_ra(NULL, NULL, rsc->id)) {
        unregister = FALSE;
    }

    delete_resource(lrm_state, rsc->id, rsc, NULL, from_sys, from_host,
                    user_name, input, unregister);
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
    const char *target_node = NULL;
    gboolean is_remote_node = FALSE;
    bool crm_rsc_delete = FALSE;

    target_node = lrm_op_target(input->xml);
    is_remote_node = safe_str_neq(target_node, fsa_our_uname);

    lrm_state = lrm_state_find(target_node);
    if ((lrm_state == NULL) && is_remote_node) {
        crm_err("Failing action because local node has never had connection to remote node %s",
                target_node);
        synthesize_lrmd_failure(NULL, input->xml, PCMK_OCF_CONNECTION_DIED);
        return;
    }
    CRM_ASSERT(lrm_state != NULL);

#if ENABLE_ACL
    user_name = crm_acl_get_set_user(input->msg, F_CRM_USER, NULL);
    crm_trace("LRM command from user '%s'", user_name);
#endif

    crm_op = crm_element_value(input->msg, F_CRM_TASK);
    from_sys = crm_element_value(input->msg, F_CRM_SYS_FROM);
    if (safe_str_neq(from_sys, CRM_SYSTEM_TENGINE)) {
        from_host = crm_element_value(input->msg, F_CRM_HOST_FROM);
    }
    crm_trace("LRM %s command from %s", crm_op, from_sys);

    if (safe_str_eq(crm_op, CRM_OP_LRM_DELETE)) {
        crm_rsc_delete = TRUE; // Only crm_resource uses this op
        operation = CRMD_ACTION_DELETE;

    } else if (safe_str_eq(crm_op, CRM_OP_LRM_FAIL)) {
        fail_lrm_resource(input->xml, lrm_state, user_name, from_host,
                          from_sys);
        return;

    } else if (input->xml != NULL) {
        operation = crm_element_value(input->xml, XML_LRM_ATTR_TASK);
    }

    if (safe_str_eq(crm_op, CRM_OP_LRM_REFRESH)) {
        handle_refresh_op(lrm_state, user_name, from_host, from_sys);

    } else if (safe_str_eq(crm_op, CRM_OP_LRM_QUERY)) {
        handle_query_op(input->msg, lrm_state);

    } else if (safe_str_eq(operation, CRM_OP_PROBED)) {
        update_attrd(lrm_state->node_name, CRM_OP_PROBED, XML_BOOLEAN_TRUE,
                     user_name, is_remote_node);

    } else if (safe_str_eq(operation, CRM_OP_REPROBE)
               || safe_str_eq(crm_op, CRM_OP_REPROBE)) {
        handle_reprobe_op(lrm_state, from_sys, from_host, user_name,
                          is_remote_node);

    } else if (operation != NULL) {
        lrmd_rsc_info_t *rsc = NULL;
        xmlNode *xml_rsc = find_xml_node(input->xml, XML_CIB_TAG_RESOURCE, TRUE);
        gboolean create_rsc = safe_str_neq(operation, CRMD_ACTION_DELETE);
        int rc;

        // We can't return anything meaningful without a resource ID
        CRM_CHECK(xml_rsc && ID(xml_rsc), return);

        rc = get_lrm_resource(lrm_state, xml_rsc, create_rsc, &rsc);
        if (rc == -ENOTCONN) {
            synthesize_lrmd_failure(lrm_state, input->xml,
                                    PCMK_OCF_CONNECTION_DIED);
            return;

        } else if (!create_rsc) {
            /* Delete of malformed or nonexistent resource
             * (deleting something that does not exist is a success)
             */
            crm_notice("Not registering resource '%s' for a %s event "
                       CRM_XS " get-rc=%d (%s) transition-key=%s",
                       ID(xml_rsc), operation,
                       rc, pcmk_strerror(rc), ID(input->xml));
            delete_rsc_entry(lrm_state, input, ID(xml_rsc), NULL, pcmk_ok,
                             user_name);
            send_task_ok_ack(lrm_state, input, ID(xml_rsc), NULL, operation,
                             from_host, from_sys);
            return;

        } else if (rc == -EINVAL) {
            // Resource operation on malformed resource
            crm_err("Invalid resource definition for %s", ID(xml_rsc));
            crm_log_xml_warn(input->msg, "invalid resource");
            synthesize_lrmd_failure(lrm_state, input->xml,
                                    PCMK_OCF_NOT_CONFIGURED); // fatal error
            return;

        } else if (rc < 0) {
            // Error communicating with lrmd
            crm_err("Could not register resource '%s' with lrmd: %s " CRM_XS " rc=%d",
                    ID(xml_rsc), pcmk_strerror(rc), rc);
            crm_log_xml_warn(input->msg, "failed registration");
            synthesize_lrmd_failure(lrm_state, input->xml,
                                    PCMK_OCF_INVALID_PARAM); // hard error
            return;
        }

        if (safe_str_eq(operation, CRMD_ACTION_CANCEL)) {
            if (!do_lrm_cancel(input, lrm_state, rsc, from_host, from_sys)) {
                crm_log_xml_warn(input->xml, "Bad command");
            }

        } else if (safe_str_eq(operation, CRMD_ACTION_DELETE)) {
            do_lrm_delete(input, lrm_state, rsc, from_sys, from_host,
                          crm_rsc_delete, user_name);

        } else {
            do_lrm_rsc_op(lrm_state, rsc, operation, input->xml, input->msg);
        }

        lrmd_free_rsc_info(rsc);

    } else {
        crm_err("Cannot perform operation %s of unknown type", crm_str(crm_op));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

static lrmd_event_data_t *
construct_op(lrm_state_t * lrm_state, xmlNode * rsc_op, const char *rsc_id, const char *operation)
{
    lrmd_event_data_t *op = NULL;
    const char *op_delay = NULL;
    const char *op_timeout = NULL;
    const char *op_interval = NULL;
    GHashTable *params = NULL;

    const char *transition = NULL;

    CRM_ASSERT(rsc_id && operation);

    op = calloc(1, sizeof(lrmd_event_data_t));
    CRM_ASSERT(op != NULL);

    op->type = lrmd_event_exec_complete;
    op->op_type = strdup(operation);
    op->op_status = PCMK_LRM_OP_PENDING;
    op->rc = -1;
    op->rsc_id = strdup(rsc_id);
    op->interval = 0;
    op->timeout = 0;
    op->start_delay = 0;

    if (rsc_op == NULL) {
        CRM_LOG_ASSERT(safe_str_eq(CRMD_ACTION_STOP, operation));
        op->user_data = NULL;
        /* the stop_all_resources() case
         * by definition there is no DC (or they'd be shutting
         *   us down).
         * So we should put our version here.
         */
        op->params = crm_str_table_new();

        g_hash_table_insert(op->params, strdup(XML_ATTR_CRM_VERSION), strdup(CRM_FEATURE_SET));

        crm_trace("Constructed %s op for %s", operation, rsc_id);
        return op;
    }

    params = xml2list(rsc_op);
    g_hash_table_remove(params, CRM_META "_op_target_rc");

    op_delay = crm_meta_value(params, XML_OP_ATTR_START_DELAY);
    op_timeout = crm_meta_value(params, XML_ATTR_TIMEOUT);
    op_interval = crm_meta_value(params, XML_LRM_ATTR_INTERVAL);

    op->interval = crm_parse_int(op_interval, "0");
    op->timeout = crm_parse_int(op_timeout, "0");
    op->start_delay = crm_parse_int(op_delay, "0");

#if ENABLE_VERSIONED_ATTRS
    // Resolve any versioned parameters
    if (lrm_state && safe_str_neq(op->op_type, RSC_METADATA)
        && safe_str_neq(op->op_type, CRMD_ACTION_DELETE)
        && !is_remote_lrmd_ra(NULL, NULL, rsc_id)) {

        // Resource info *should* already be cached, so we don't get lrmd call
        lrmd_rsc_info_t *rsc = lrm_state_get_rsc_info(lrm_state, rsc_id, 0);
        struct ra_metadata_s *metadata;

        metadata = metadata_cache_get(lrm_state->metadata_cache, rsc);
        if (metadata) {
            xmlNode *versioned_attrs = NULL;
            GHashTable *hash = NULL;
            char *key = NULL;
            char *value = NULL;
            GHashTableIter iter;

            versioned_attrs = first_named_child(rsc_op, XML_TAG_OP_VER_ATTRS);
            hash = pe_unpack_versioned_parameters(versioned_attrs, metadata->ra_version);
            g_hash_table_iter_init(&iter, hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
                g_hash_table_iter_steal(&iter);
                g_hash_table_replace(params, key, value);
            }
            g_hash_table_destroy(hash);

            versioned_attrs = first_named_child(rsc_op, XML_TAG_OP_VER_META);
            hash = pe_unpack_versioned_parameters(versioned_attrs, metadata->ra_version);
            g_hash_table_iter_init(&iter, hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
                g_hash_table_replace(params, crm_meta_name(key), strdup(value));

                if (safe_str_eq(key, XML_ATTR_TIMEOUT)) {
                    op->timeout = crm_parse_int(value, "0");
                } else if (safe_str_eq(key, XML_OP_ATTR_START_DELAY)) {
                    op->start_delay = crm_parse_int(value, "0");
                }
            }
            g_hash_table_destroy(hash);

            versioned_attrs = first_named_child(rsc_op, XML_TAG_RSC_VER_ATTRS);
            hash = pe_unpack_versioned_parameters(versioned_attrs, metadata->ra_version);
            g_hash_table_iter_init(&iter, hash);
            while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
                g_hash_table_iter_steal(&iter);
                g_hash_table_replace(params, key, value);
            }
            g_hash_table_destroy(hash);
        }

        lrmd_free_rsc_info(rsc);
    }
#endif

    if (safe_str_neq(operation, RSC_STOP)) {
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
            op->params = crm_str_table_new();

            g_hash_table_foreach(params, copy_meta_keys, op->params);
            g_hash_table_foreach(entry->stop_params, copy_instance_keys, op->params);
            g_hash_table_destroy(params);
            params = NULL;
        }
    }

    /* sanity */
    if (op->interval < 0) {
        op->interval = 0;
    }
    if (op->timeout <= 0) {
        op->timeout = op->interval;
    }
    if (op->start_delay < 0) {
        op->start_delay = 0;
    }

    transition = crm_element_value(rsc_op, XML_ATTR_TRANSITION_KEY);
    CRM_CHECK(transition != NULL, return op);

    op->user_data = strdup(transition);

    if (op->interval != 0) {
        if (safe_str_eq(operation, CRMD_ACTION_START)
            || safe_str_eq(operation, CRMD_ACTION_STOP)) {
            crm_err("Start and Stop actions cannot have an interval: %d", op->interval);
            op->interval = 0;
        }
    }

    crm_trace("Constructed %s op for %s: interval=%d", operation, rsc_id, op->interval);

    return op;
}

void
send_direct_ack(const char *to_host, const char *to_sys,
                lrmd_rsc_info_t * rsc, lrmd_event_data_t * op, const char *rsc_id)
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

    peer = crm_get_peer(0, fsa_our_uname);
    update = create_node_state_update(peer, node_update_none, NULL,
                                      __FUNCTION__);

    iter = create_xml_node(update, XML_CIB_TAG_LRM);
    crm_xml_add(iter, XML_ATTR_ID, fsa_our_uuid);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCE);

    crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

    build_operation_update(iter, rsc, op, fsa_our_uname, __FUNCTION__);
    reply = create_request(CRM_OP_INVOKE_LRM, update, to_host, to_sys, CRM_SYSTEM_LRMD, NULL);

    crm_log_xml_trace(update, "ACK Update");

    crm_debug("ACK'ing resource op %s_%s_%d from %s: %s",
              op->rsc_id, op->op_type, op->interval, op->user_data,
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

    set_bit(fsa_input_register, R_SENT_RSC_STOP);
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
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (op->interval != 0 && crm_str_eq(op->rsc_id, event->rsc->id, TRUE)) {
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
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    if (op->interval != 0) {
        crm_info("Cancelling op %d for %s (%s)", op->call_id, op->rsc_id, key);
        remove = !cancel_op(lrm_state, op->rsc_id, key, op->call_id, FALSE);
    }

    return remove;
}

static void
record_pending_op(const char *node_name, lrmd_rsc_info_t *rsc, lrmd_event_data_t *op)
{
    const char *record_pending = NULL;

    CRM_CHECK(node_name != NULL, return);
    CRM_CHECK(rsc != NULL, return);
    CRM_CHECK(op != NULL, return);

    if ((op->op_type == NULL) || (op->params == NULL)
        || safe_str_eq(op->op_type, CRMD_ACTION_CANCEL)
        || safe_str_eq(op->op_type, CRMD_ACTION_DELETE)) {
        return;
    }

    // defaults to true
    record_pending = crm_meta_value(op->params, XML_OP_ATTR_PENDING);
    if (record_pending && !crm_is_true(record_pending)) {
        return;
    }

    op->call_id = -1;
    op->op_status = PCMK_LRM_OP_PENDING;
    op->rc = PCMK_OCF_UNKNOWN;

    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

    /* write a "pending" entry to the CIB, inhibit notification */
    crm_debug("Recording pending op %s_%s_%d on %s in the CIB",
              op->rsc_id, op->op_type, op->interval, node_name);

    do_update_resource(node_name, rsc, op);
}

static void
do_lrm_rsc_op(lrm_state_t * lrm_state, lrmd_rsc_info_t * rsc, const char *operation, xmlNode * msg,
              xmlNode * request)
{
    int call_id = 0;
    char *op_id = NULL;
    lrmd_event_data_t *op = NULL;
    lrmd_key_value_t *params = NULL;
    fsa_data_t *msg_data = NULL;
    const char *transition = NULL;
    gboolean stop_recurring = FALSE;
    bool send_nack = FALSE;

    CRM_CHECK(rsc != NULL, return);
    CRM_CHECK(operation != NULL, return);

    if (msg != NULL) {
        transition = crm_element_value(msg, XML_ATTR_TRANSITION_KEY);
        if (transition == NULL) {
            crm_log_xml_err(msg, "Missing transition number");
        }
    }

    op = construct_op(lrm_state, msg, rsc->id, operation);
    CRM_CHECK(op != NULL, return);

    if (is_remote_lrmd_ra(NULL, NULL, rsc->id)
        && op->interval == 0
        && strcmp(operation, CRMD_ACTION_MIGRATE) == 0) {

        /* pcmk remote connections are a special use case.
         * We never ever want to stop monitoring a connection resource until
         * the entire migration has completed. If the connection is unexpectedly
         * severed, even during a migration, this is an event we must detect.*/
        stop_recurring = FALSE;

    } else if (op->interval == 0
        && strcmp(operation, CRMD_ACTION_STATUS) != 0
        && strcmp(operation, CRMD_ACTION_NOTIFY) != 0) {

        /* stop any previous monitor operations before changing the resource state */
        stop_recurring = TRUE;
    }

    if (stop_recurring == TRUE) {
        guint removed = 0;
        struct stop_recurring_action_s data;

        data.rsc = rsc;
        data.lrm_state = lrm_state;
        removed = g_hash_table_foreach_remove(
            lrm_state->pending_ops, stop_recurring_action_by_rsc, &data);

        if (removed) {
            crm_debug("Stopped %u recurring operation%s in preparation for %s_%s_%d",
                      removed, s_if_plural(removed), rsc->id, operation, op->interval);
        }
    }

    /* now do the op */
    crm_info("Performing key=%s op=%s_%s_%d", transition, rsc->id, operation, op->interval);

    if (is_set(fsa_input_register, R_SHUTDOWN) && safe_str_eq(operation, RSC_START)) {
        register_fsa_input(C_SHUTDOWN, I_SHUTDOWN, NULL);
        send_nack = TRUE;

    } else if (fsa_state != S_NOT_DC
               && fsa_state != S_POLICY_ENGINE /* Recalculating */
               && fsa_state != S_TRANSITION_ENGINE
               && safe_str_neq(operation, CRMD_ACTION_STOP)) {
        send_nack = TRUE;
    }

    if(send_nack) {
        crm_notice("Discarding attempt to perform action %s on %s in state %s (shutdown=%s)",
                   operation, rsc->id, fsa_state2string(fsa_state),
                   is_set(fsa_input_register, R_SHUTDOWN)?"true":"false");

        op->rc = CRM_DIRECT_NACK_RC;
        op->op_status = PCMK_LRM_OP_ERROR;
        send_direct_ack(NULL, NULL, rsc, op, rsc->id);
        lrmd_free_event(op);
        free(op_id);
        return;
    }

    record_pending_op(lrm_state->node_name, rsc, op);

    op_id = generate_op_key(rsc->id, op->op_type, op->interval);

    if (op->interval > 0) {
        /* cancel it so we can then restart it without conflict */
        cancel_op_key(lrm_state, rsc, op_id, FALSE);
    }

    if (op->params) {
        char *key = NULL;
        char *value = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, op->params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            params = lrmd_key_value_add(params, key, value);
        }
    }

    call_id = lrm_state_exec(lrm_state,
                             rsc->id,
                             op->op_type,
                             op->user_data, op->interval, op->timeout, op->start_delay, params);

    if (call_id <= 0 && lrm_state_is_local(lrm_state)) {
        crm_err("Operation %s on %s failed: %d", operation, rsc->id, call_id);
        register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);

    } else if (call_id <= 0) {
        crm_err("Operation %s on resource %s failed to execute on remote node %s: %d",
                operation, rsc->id, lrm_state->node_name, call_id);
        fake_op_status(lrm_state, op, PCMK_LRM_OP_DONE, PCMK_OCF_UNKNOWN_ERROR);
        process_lrm_event(lrm_state, op, NULL);

    } else {
        /* record all operations so we can wait
         * for them to complete during shutdown
         */
        char *call_id_s = make_stop_id(rsc->id, call_id);
        struct recurring_op_s *pending = NULL;

        pending = calloc(1, sizeof(struct recurring_op_s));
        crm_trace("Recording pending op: %d - %s %s", call_id, op_id, call_id_s);

        pending->call_id = call_id;
        pending->interval = op->interval;
        pending->op_type = strdup(operation);
        pending->op_key = strdup(op_id);
        pending->rsc_id = strdup(rsc->id);
        pending->start_time = time(NULL);
        pending->user_data = strdup(op->user_data);
        g_hash_table_replace(lrm_state->pending_ops, call_id_s, pending);

        if (op->interval > 0 && op->start_delay > START_DELAY_THRESHOLD) {
            char *uuid = NULL;
            int dummy = 0, target_rc = 0;

            crm_info("Faking confirmation of %s: execution postponed for over 5 minutes", op_id);

            decode_transition_key(op->user_data, &uuid, &dummy, &dummy, &target_rc);
            free(uuid);

            op->rc = target_rc;
            op->op_status = PCMK_LRM_OP_DONE;
            send_direct_ack(NULL, NULL, rsc, op, rsc->id);
        }

        pending->params = op->params;
        op->params = NULL;
    }

    free(op_id);
    lrmd_free_event(op);
    return;
}

int last_resource_update = 0;

static void
cib_rsc_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    switch (rc) {
        case pcmk_ok:
        case -pcmk_err_diff_failed:
        case -pcmk_err_diff_resync:
            crm_trace("Resource update %d complete: rc=%d", call_id, rc);
            break;
        default:
            crm_warn("Resource update %d failed: (rc=%d) %s", call_id, rc, pcmk_strerror(rc));
    }

    if (call_id == last_resource_update) {
        last_resource_update = 0;
        trigger_fsa(fsa_source);
    }
}

static int
do_update_resource(const char *node_name, lrmd_rsc_info_t * rsc, lrmd_event_data_t * op)
{
/*
  <status>
  <nodes_status id=uname>
  <lrm>
  <lrm_resources>
  <lrm_resource id=...>
  </...>
*/
    int rc = pcmk_ok;
    xmlNode *update, *iter = NULL;
    int call_opt = crmd_cib_smart_opt();
    const char *uuid = NULL;

    CRM_CHECK(op != NULL, return 0);

    iter = create_xml_node(iter, XML_CIB_TAG_STATUS);
    update = iter;
    iter = create_xml_node(iter, XML_CIB_TAG_STATE);

    if (safe_str_eq(node_name, fsa_our_uname)) {
        uuid = fsa_our_uuid;

    } else {
        /* remote nodes uuid and uname are equal */
        uuid = node_name;
        crm_xml_add(iter, XML_NODE_IS_REMOTE, "true");
    }

    CRM_LOG_ASSERT(uuid != NULL);
    if(uuid == NULL) {
        rc = -EINVAL;
        goto done;
    }

    crm_xml_add(iter, XML_ATTR_UUID,  uuid);
    crm_xml_add(iter, XML_ATTR_UNAME, node_name);
    crm_xml_add(iter, XML_ATTR_ORIGIN, __FUNCTION__);

    iter = create_xml_node(iter, XML_CIB_TAG_LRM);
    crm_xml_add(iter, XML_ATTR_ID, uuid);

    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCES);
    iter = create_xml_node(iter, XML_LRM_TAG_RESOURCE);
    crm_xml_add(iter, XML_ATTR_ID, op->rsc_id);

    build_operation_update(iter, rsc, op, node_name, __FUNCTION__);

    if (rsc) {
        const char *container = NULL;

        crm_xml_add(iter, XML_ATTR_TYPE, rsc->type);
        crm_xml_add(iter, XML_AGENT_ATTR_CLASS, rsc->standard);
        crm_xml_add(iter, XML_AGENT_ATTR_PROVIDER, rsc->provider);

        if (op->params) {
            container = g_hash_table_lookup(op->params, CRM_META"_"XML_RSC_ATTR_CONTAINER);
        }
        if (container) {
            crm_trace("Resource %s is a part of container resource %s", op->rsc_id, container);
            crm_xml_add(iter, XML_RSC_ATTR_CONTAINER, container);
        }

    } else {
        crm_warn("Resource %s no longer exists in the lrmd", op->rsc_id);
        send_direct_ack(NULL, NULL, rsc, op, op->rsc_id);
        goto cleanup;
    }

    crm_log_xml_trace(update, __FUNCTION__);

    /* make it an asynchronous call and be done with it
     *
     * Best case:
     *   the resource state will be discovered during
     *   the next signup or election.
     *
     * Bad case:
     *   we are shutting down and there is no DC at the time,
     *   but then why were we shutting down then anyway?
     *   (probably because of an internal error)
     *
     * Worst case:
     *   we get shot for having resources "running" when the really weren't
     *
     * the alternative however means blocking here for too long, which
     * isn't acceptable
     */
    fsa_cib_update(XML_CIB_TAG_STATUS, update, call_opt, rc, NULL);

    if (rc > 0) {
        last_resource_update = rc;
    }
  done:
    /* the return code is a call number, not an error code */
    crm_trace("Sent resource state update message: %d for %s=%d on %s", rc,
              op->op_type, op->interval, op->rsc_id);
    fsa_register_cib_callback(rc, FALSE, NULL, cib_rsc_callback);

  cleanup:
    free_xml(update);
    return rc;
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
        /* 2 chars for 2 chars, null-termination irrelevant */
        memcpy(pch, "\n ", 2 * sizeof(char));
        pch = strstr(pch, escaped_newline);
    }

    return ret;
}

gboolean
process_lrm_event(lrm_state_t * lrm_state, lrmd_event_data_t * op, struct recurring_op_s *pending)
{
    char *op_id = NULL;
    char *op_key = NULL;

    int update_id = 0;
    gboolean remove = FALSE;
    gboolean removed = FALSE;
    lrmd_rsc_info_t *rsc = NULL;

    CRM_CHECK(op != NULL, return FALSE);
    CRM_CHECK(op->rsc_id != NULL, return FALSE);

    op_id = make_stop_id(op->rsc_id, op->call_id);
    op_key = generate_op_key(op->rsc_id, op->op_type, op->interval);
    rsc = lrm_state_get_rsc_info(lrm_state, op->rsc_id, 0);
    if(pending == NULL) {
        remove = TRUE;
        pending = g_hash_table_lookup(lrm_state->pending_ops, op_id);
    }

    if (op->op_status == PCMK_LRM_OP_ERROR) {
        switch(op->rc) {
            case PCMK_OCF_NOT_RUNNING:
            case PCMK_OCF_RUNNING_MASTER:
            case PCMK_OCF_DEGRADED:
            case PCMK_OCF_DEGRADED_MASTER:
                /* Leave it up to the TE/PE to decide if this is an error */
                op->op_status = PCMK_LRM_OP_DONE;
                break;
            default:
                /* Nothing to do */
                break;
        }
    }

    if (op->op_status != PCMK_LRM_OP_CANCELLED) {
        if (safe_str_eq(op->op_type, RSC_NOTIFY) || safe_str_eq(op->op_type, RSC_METADATA)) {
            /* Keep notify and meta-data ops out of the CIB */
            send_direct_ack(NULL, NULL, NULL, op, op->rsc_id);
        } else {
            update_id = do_update_resource(lrm_state->node_name, rsc, op);
        }
    } else if (op->interval == 0) {
        /* This will occur when "crm resource cleanup" is called while actions are in-flight */
        crm_err("Op %s (call=%d): Cancelled", op_key, op->call_id);
        send_direct_ack(NULL, NULL, NULL, op, op->rsc_id);

    } else if (pending == NULL) {
        /* We don't need to do anything for cancelled ops
         * that are not in our pending op list. There are no
         * transition actions waiting on these operations. */

    } else if (op->user_data == NULL) {
        /* At this point we have a pending entry, but no transition
         * key present in the user_data field. report this */
        crm_err("Op %s (call=%d): No user data", op_key, op->call_id);

    } else if (pending->remove) {
        /* The tengine canceled this op, we have been waiting for the cancel to finish. */
        erase_lrm_history_by_op(lrm_state, op);

    } else if (pending && op->rsc_deleted) {
        /* The tengine initiated this op, but it was cancelled outside of the
         * tengine's control during a resource cleanup/re-probe request. The tengine
         * must be alerted that this operation completed, otherwise the tengine
         * will continue waiting for this update to occur until it is timed out.
         * We don't want this update going to the cib though, so use a direct ack. */
        crm_trace("Op %s (call=%d): cancelled due to rsc deletion", op_key, op->call_id);
        send_direct_ack(NULL, NULL, NULL, op, op->rsc_id);

    } else {
        /* Before a stop is called, no need to direct ack */
        crm_trace("Op %s (call=%d): no delete event required", op_key, op->call_id);
    }

    if(remove == FALSE) {
        /* The caller will do this afterwards, but keep the logging consistent */
        removed = TRUE;

    } else if ((op->interval == 0) && g_hash_table_remove(lrm_state->pending_ops, op_id)) {
        removed = TRUE;
        crm_trace("Op %s (call=%d, stop-id=%s, remaining=%u): Confirmed",
                  op_key, op->call_id, op_id, g_hash_table_size(lrm_state->pending_ops));

    } else if(op->interval != 0 && op->op_status == PCMK_LRM_OP_CANCELLED) {
        removed = TRUE;
        g_hash_table_remove(lrm_state->pending_ops, op_id);
    }

    switch (op->op_status) {
        case PCMK_LRM_OP_CANCELLED:
            crm_info("Result of %s operation for %s on %s: %s "
                     CRM_XS " call=%d key=%s confirmed=%s",
                     crm_action_str(op->op_type, op->interval),
                     op->rsc_id, lrm_state->node_name,
                     services_lrm_status_str(op->op_status),
                     op->call_id, op_key, (removed? "true" : "false"));
            break;

        case PCMK_LRM_OP_DONE:
            do_crm_log(op->interval?LOG_INFO:LOG_NOTICE,
                       "Result of %s operation for %s on %s: %d (%s) "
                       CRM_XS " call=%d key=%s confirmed=%s cib-update=%d",
                       crm_action_str(op->op_type, op->interval),
                       op->rsc_id, lrm_state->node_name,
                       op->rc, services_ocf_exitcode_str(op->rc),
                       op->call_id, op_key, (removed? "true" : "false"),
                       update_id);
            break;

        case PCMK_LRM_OP_TIMEOUT:
            crm_err("Result of %s operation for %s on %s: %s "
                    CRM_XS " call=%d key=%s timeout=%dms",
                    crm_action_str(op->op_type, op->interval),
                    op->rsc_id, lrm_state->node_name,
                    services_lrm_status_str(op->op_status),
                    op->call_id, op_key, op->timeout);
            break;

        default:
            crm_err("Result of %s operation for %s on %s: %s "
                    CRM_XS " call=%d key=%s confirmed=%s status=%d cib-update=%d",
                    crm_action_str(op->op_type, op->interval),
                    op->rsc_id, lrm_state->node_name,
                    services_lrm_status_str(op->op_status), op->call_id, op_key,
                    (removed? "true" : "false"), op->op_status, update_id);
    }

    if (op->output) {
        char *prefix =
            crm_strdup_printf("%s-%s_%s_%d:%d", lrm_state->node_name, op->rsc_id, op->op_type, op->interval, op->call_id);

        if (op->rc) {
            crm_log_output(LOG_NOTICE, prefix, op->output);
        } else {
            crm_log_output(LOG_DEBUG, prefix, op->output);
        }
        free(prefix);
    }

    if (safe_str_neq(op->op_type, RSC_METADATA)) {
        crmd_alert_resource_op(lrm_state->node_name, op);
    } else if (op->rc == PCMK_OCF_OK) {
        char *metadata = unescape_newlines(op->output);

        metadata_cache_update(lrm_state->metadata_cache, rsc, metadata);
        free(metadata);
    }

    if (op->rsc_deleted) {
        crm_info("Deletion of resource '%s' complete after %s", op->rsc_id, op_key);
        delete_rsc_entry(lrm_state, NULL, op->rsc_id, NULL, pcmk_ok, NULL);
    }

    /* If a shutdown was escalated while operations were pending,
     * then the FSA will be stalled right now... allow it to continue
     */
    mainloop_set_trigger(fsa_source);
    update_history_cache(lrm_state, rsc, op);

    lrmd_free_rsc_info(rsc);
    free(op_key);
    free(op_id);

    return TRUE;
}
