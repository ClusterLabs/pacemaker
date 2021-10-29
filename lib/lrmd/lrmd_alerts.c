/*
 * Copyright 2015-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/alerts_internal.h>
#include <crm/lrmd_internal.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

static lrmd_key_value_t *
alert_key2param(lrmd_key_value_t *head, enum pcmk__alert_keys_e name,
                const char *value)
{
    const char **key;

    if (value == NULL) {
        value = "";
    }
    for (key = pcmk__alert_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        head = lrmd_key_value_add(head, *key, value);
    }
    return head;
}

static lrmd_key_value_t *
alert_key2param_int(lrmd_key_value_t *head, enum pcmk__alert_keys_e name,
                    int value)
{
    char *value_s = pcmk__itoa(value);

    head = alert_key2param(head, name, value_s);
    free(value_s);
    return head;
}

static lrmd_key_value_t *
alert_key2param_ms(lrmd_key_value_t *head, enum pcmk__alert_keys_e name,
                   guint value)
{
    char *value_s = crm_strdup_printf("%u", value);

    head = alert_key2param(head, name, value_s);
    free(value_s);
    return head;
}

static void
set_ev_kv(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_key_value_t **head = (lrmd_key_value_t **) user_data;

    if (value) {
        crm_trace("Setting environment variable %s='%s'",
                  (char*)key, (char*)value);
        *head = lrmd_key_value_add(*head, key, value);
    }
}

static lrmd_key_value_t *
alert_envvar2params(lrmd_key_value_t *head, pcmk__alert_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_ev_kv, &head);
    }
    return head;
}

/*
 * We could use g_strv_contains() instead of this function,
 * but that has only been available since glib 2.43.2.
 */
static gboolean
is_target_alert(char **list, const char *value)
{
    int target_list_num = 0;
    gboolean rc = FALSE;

    CRM_CHECK(value != NULL, return FALSE);

    if (list == NULL) {
        return TRUE;
    }

    target_list_num = g_strv_length(list);

    for (int cnt = 0; cnt < target_list_num; cnt++) {
        if (strcmp(list[cnt], value) == 0) {
            rc = TRUE;
            break;
        }
    }
    return rc;
}

/*!
 * \internal
 * \brief Execute alert agents for an event
 *
 * \param[in]     lrmd        Executor connection to use
 * \param[in]     alert_list  Alerts to execute
 * \param[in]     kind        Type of event that is being alerted for
 * \param[in]     attr_name   If pcmk__alert_attribute, the attribute name
 * \param[in,out] params      Environment variables to pass to agents
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alerts failed
 * \retval -2 if all alerts failed
 */
static int
exec_alert_list(lrmd_t *lrmd, GList *alert_list, enum pcmk__alert_flags kind,
                const char *attr_name, lrmd_key_value_t *params)
{
    bool any_success = FALSE, any_failure = FALSE;
    const char *kind_s = pcmk__alert_flag2text(kind);
    pcmk__time_hr_t *now = NULL;
    struct timeval tv_now;
    char timestamp_epoch[20];
    char timestamp_usec[7];

    params = alert_key2param(params, PCMK__alert_key_kind, kind_s);
    params = alert_key2param(params, PCMK__alert_key_version,
                             PACEMAKER_VERSION);

    for (GList *iter = g_list_first(alert_list); iter; iter = g_list_next(iter)) {
        pcmk__alert_t *entry = (pcmk__alert_t *)(iter->data);
        lrmd_key_value_t *copy_params = NULL;
        lrmd_key_value_t *head = NULL;
        int rc;

        if (!pcmk_is_set(entry->flags, kind)) {
            crm_trace("Filtering unwanted %s alert to %s via %s",
                      kind_s, entry->recipient, entry->id);
            continue;
        }

        if ((kind == pcmk__alert_attribute)
            && !is_target_alert(entry->select_attribute_name, attr_name)) {

            crm_trace("Filtering unwanted attribute '%s' alert to %s via %s",
                      attr_name, entry->recipient, entry->id);
            continue;
        }

        if (now == NULL) {
            if (gettimeofday(&tv_now, NULL) == 0) {
                now = pcmk__time_timeval_hr_convert(NULL, &tv_now);
            }
        }
        crm_info("Sending %s alert via %s to %s",
                 kind_s, entry->id, entry->recipient);

        /* Make a copy of the parameters, because each alert will be unique */
        for (head = params; head != NULL; head = head->next) {
            copy_params = lrmd_key_value_add(copy_params, head->key, head->value);
        }

        copy_params = alert_key2param(copy_params, PCMK__alert_key_recipient,
                                      entry->recipient);

        if (now) {
            char *timestamp = pcmk__time_format_hr(entry->tstamp_format, now);

            if (timestamp) {
                copy_params = alert_key2param(copy_params,
                                              PCMK__alert_key_timestamp,
                                              timestamp);
                free(timestamp);
            }

            snprintf(timestamp_epoch, sizeof(timestamp_epoch), "%lld",
                     (long long) tv_now.tv_sec);
            copy_params = alert_key2param(copy_params,
                                          PCMK__alert_key_timestamp_epoch,
                                          timestamp_epoch);
            snprintf(timestamp_usec, sizeof(timestamp_usec), "%06d", now->useconds);
            copy_params = alert_key2param(copy_params,
                                          PCMK__alert_key_timestamp_usec,
                                          timestamp_usec);
        }

        copy_params = alert_envvar2params(copy_params, entry);

        rc = lrmd->cmds->exec_alert(lrmd, entry->id, entry->path,
                                    entry->timeout, copy_params);
        if (rc < 0) {
            crm_err("Could not execute alert %s: %s " CRM_XS " rc=%d",
                    entry->id, pcmk_strerror(rc), rc);
            any_failure = TRUE;
        } else {
            any_success = TRUE;
        }
    }

    if (now) {
        free(now);
    }

    if (any_failure) {
        return (any_success? -1 : -2);
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Send an alert for a node attribute change
 *
 * \param[in] lrmd        Executor connection to use
 * \param[in] alert_list  List of alert agents to execute
 * \param[in] node        Name of node with attribute change
 * \param[in] nodeid      Node ID of node with attribute change
 * \param[in] attr_name   Name of attribute that changed
 * \param[in] attr_value  New value of attribute that changed
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_attribute_alert(lrmd_t *lrmd, GList *alert_list,
                          const char *node, uint32_t nodeid,
                          const char *attr_name, const char *attr_value)
{
    int rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        return -2;
    }

    params = alert_key2param(params, PCMK__alert_key_node, node);
    params = alert_key2param_int(params, PCMK__alert_key_nodeid, nodeid);
    params = alert_key2param(params, PCMK__alert_key_attribute_name, attr_name);
    params = alert_key2param(params, PCMK__alert_key_attribute_value,
                             attr_value);

    rc = exec_alert_list(lrmd, alert_list, pcmk__alert_attribute, attr_name,
                         params);
    lrmd_key_value_freeall(params);
    return rc;
}

/*!
 * \internal
 * \brief Send an alert for a node membership event
 *
 * \param[in] lrmd        Executor connection to use
 * \param[in] alert_list  List of alert agents to execute
 * \param[in] node        Name of node with change
 * \param[in] nodeid      Node ID of node with change
 * \param[in] state       New state of node with change
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_node_alert(lrmd_t *lrmd, GList *alert_list,
                     const char *node, uint32_t nodeid, const char *state)
{
    int rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        return -2;
    }

    params = alert_key2param(params, PCMK__alert_key_node, node);
    params = alert_key2param(params, PCMK__alert_key_desc, state);
    params = alert_key2param_int(params, PCMK__alert_key_nodeid, nodeid);

    rc = exec_alert_list(lrmd, alert_list, pcmk__alert_node, NULL, params);
    lrmd_key_value_freeall(params);
    return rc;
}

/*!
 * \internal
 * \brief Send an alert for a fencing event
 *
 * \param[in] lrmd        Executor connection to use
 * \param[in] alert_list  List of alert agents to execute
 * \param[in] target      Name of fence target node
 * \param[in] task        Type of fencing event that occurred
 * \param[in] desc        Readable description of event
 * \param[in] op_rc       Result of fence action
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_fencing_alert(lrmd_t *lrmd, GList *alert_list,
                        const char *target, const char *task, const char *desc,
                        int op_rc)
{
    int rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        return -2;
    }

    params = alert_key2param(params, PCMK__alert_key_node, target);
    params = alert_key2param(params, PCMK__alert_key_task, task);
    params = alert_key2param(params, PCMK__alert_key_desc, desc);
    params = alert_key2param_int(params, PCMK__alert_key_rc, op_rc);

    rc = exec_alert_list(lrmd, alert_list, pcmk__alert_fencing, NULL, params);
    lrmd_key_value_freeall(params);
    return rc;
}

/*!
 * \internal
 * \brief Send an alert for a resource operation
 *
 * \param[in] lrmd        Executor connection to use
 * \param[in] alert_list  List of alert agents to execute
 * \param[in] node        Name of node that executed operation
 * \param[in] op          Resource operation
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_resource_alert(lrmd_t *lrmd, GList *alert_list,
                         const char *node, lrmd_event_data_t *op)
{
    int rc = pcmk_ok;
    int target_rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        return -2;
    }

    target_rc = rsc_op_expected_rc(op);
    if ((op->interval_ms == 0) && (target_rc == op->rc)
        && pcmk__str_eq(op->op_type, RSC_STATUS, pcmk__str_casei)) {

        /* Don't send alerts for probes with the expected result. Leave it up to
         * the agent whether to alert for 'failed' probes. (Even if we find a
         * resource running, it was probably because someone did a clean-up of
         * the status section.)
         */
        return pcmk_ok;
    }

    params = alert_key2param(params, PCMK__alert_key_node, node);
    params = alert_key2param(params, PCMK__alert_key_rsc, op->rsc_id);
    params = alert_key2param(params, PCMK__alert_key_task, op->op_type);
    params = alert_key2param_ms(params, PCMK__alert_key_interval,
                                op->interval_ms);
    params = alert_key2param_int(params, PCMK__alert_key_target_rc, target_rc);
    params = alert_key2param_int(params, PCMK__alert_key_status, op->op_status);
    params = alert_key2param_int(params, PCMK__alert_key_rc, op->rc);

    /* Reoccurring operations do not set exec_time, so on timeout, set it
     * to the operation timeout since that's closer to the actual value.
     */
    if ((op->op_status == PCMK_EXEC_TIMEOUT) && (op->exec_time == 0)) {
        params = alert_key2param_int(params, PCMK__alert_key_exec_time,
                                     op->timeout);
    } else {
        params = alert_key2param_int(params, PCMK__alert_key_exec_time,
                                     op->exec_time);
    }

    if (op->op_status == PCMK_EXEC_DONE) {
        params = alert_key2param(params, PCMK__alert_key_desc,
                                 services_ocf_exitcode_str(op->rc));
    } else {
        params = alert_key2param(params, PCMK__alert_key_desc,
                                 pcmk_exec_status_str(op->op_status));
    }

    rc = exec_alert_list(lrmd, alert_list, pcmk__alert_resource, NULL, params);
    lrmd_key_value_freeall(params);
    return rc;
}
