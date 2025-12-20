/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/lrmd_internal.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

static lrmd_key_value_t *
alert_key2param(lrmd_key_value_t *head, enum pcmk__alert_keys_e name,
                const char *value)
{
    if (value == NULL) {
        value = "";
    }
    pcmk__trace("Setting alert key %s = '%s'", pcmk__alert_keys[name], value);
    return lrmd_key_value_add(head, pcmk__alert_keys[name], value);
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
    char *value_s = pcmk__assert_asprintf("%u", value);

    head = alert_key2param(head, name, value_s);
    free(value_s);
    return head;
}

static void
set_ev_kv(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_key_value_t **head = (lrmd_key_value_t **) user_data;

    if (value) {
        pcmk__trace("Setting environment variable %s='%s'", (const char*) key,
                    (const char *) value);
        *head = lrmd_key_value_add(*head, key, value);
    }
}

static lrmd_key_value_t *
alert_envvar2params(lrmd_key_value_t *head, const pcmk__alert_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_ev_kv, &head);
    }
    return head;
}

/*!
 * \internal
 * \brief Execute alert agents for an event
 *
 * \param[in,out] lrmd        Executor connection to use
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
exec_alert_list(lrmd_t *lrmd, const GList *alert_list,
                enum pcmk__alert_flags kind, const char *attr_name,
                lrmd_key_value_t *params)
{
    bool any_success = false;
    bool any_failure = false;
    const char *kind_s = pcmk__alert_flag2text(kind);

    struct timespec now_tv = { 0, };
    crm_time_t *now_dt = NULL;
    int now_usec = 0;

    qb_util_timespec_from_epoch_get(&now_tv);
    now_dt = pcmk__copy_timet(now_tv.tv_sec);
    now_usec = now_tv.tv_nsec / QB_TIME_NS_IN_USEC;

    params = alert_key2param(params, PCMK__alert_key_kind, kind_s);
    params = alert_key2param(params, PCMK__alert_key_version,
                             PACEMAKER_VERSION);

    for (const GList *iter = alert_list; iter != NULL; iter = iter->next) {
        const pcmk__alert_t *entry = iter->data;
        lrmd_key_value_t *copy_params = NULL;
        char *str = NULL;
        int rc = pcmk_ok;

        if (!pcmk__is_set(entry->flags, kind)) {
            pcmk__trace("Filtering unwanted %s alert to %s via %s", kind_s,
                        entry->recipient, entry->id);
            continue;
        }

        if (kind == pcmk__alert_attribute) {
            const gchar *const *select_attr_name =
                (const gchar *const *) entry->select_attribute_name;

            if (attr_name == NULL) {
                CRM_LOG_ASSERT(attr_name != NULL);
                continue;
            }

            if ((select_attr_name != NULL)
                && !pcmk__g_strv_contains(select_attr_name, attr_name)) {

                pcmk__trace("Filtering unwanted attribute '%s' alert to %s via "
                            "%s", attr_name, entry->recipient, entry->id);
                continue;
            }
        }

        pcmk__info("Sending %s alert via %s to %s", kind_s, entry->id,
                   entry->recipient);

        /* Make a copy of the parameters, because each alert will be unique */
        for (const lrmd_key_value_t *param = params; param != NULL;
             param = param->next) {

            copy_params = lrmd_key_value_add(copy_params, param->key,
                                             param->value);
        }

        copy_params = alert_key2param(copy_params, PCMK__alert_key_recipient,
                                      entry->recipient);

        str = pcmk__time_format_hr(entry->tstamp_format, now_dt, now_usec);
        if (str != NULL) {
            copy_params = alert_key2param(copy_params,
                                          PCMK__alert_key_timestamp, str);
            free(str);
        }

        str = pcmk__assert_asprintf("%lld", (long long) now_tv.tv_sec);
        copy_params = alert_key2param(copy_params,
                                      PCMK__alert_key_timestamp_epoch, str);
        free(str);

        str = pcmk__assert_asprintf("%06d", now_usec);
        copy_params = alert_key2param(copy_params,
                                      PCMK__alert_key_timestamp_usec, str);
        free(str);

        copy_params = alert_envvar2params(copy_params, entry);

        rc = lrmd->cmds->exec_alert(lrmd, entry->id, entry->path,
                                    entry->timeout, copy_params);
        if (rc < 0) {
            pcmk__err("Could not execute alert %s: %s " QB_XS " rc=%d",
                      entry->id, pcmk_strerror(rc), rc);
            any_failure = true;
        } else {
            any_success = true;
        }
    }

    crm_time_free(now_dt);

    if (any_failure) {
        return (any_success? -1 : -2);
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Send an alert for a node attribute change
 *
 * \param[in,out] lrmd        Executor connection to use
 * \param[in]     alert_list  List of alert agents to execute
 * \param[in]     node        Name of node with attribute change
 * \param[in]     nodeid      Node ID of node with attribute change
 * \param[in]     attr_name   Name of attribute that changed
 * \param[in]     attr_value  New value of attribute that changed
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_attribute_alert(lrmd_t *lrmd, const GList *alert_list,
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
 * \param[in,out] lrmd        Executor connection to use
 * \param[in]     alert_list  List of alert agents to execute
 * \param[in]     node        Name of node with change
 * \param[in]     nodeid      Node ID of node with change
 * \param[in]     state       New state of node with change
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_node_alert(lrmd_t *lrmd, const GList *alert_list,
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
 * \param[in,out] lrmd        Executor connection to use
 * \param[in]     alert_list  List of alert agents to execute
 * \param[in]     target      Name of fence target node
 * \param[in]     task        Type of fencing event that occurred
 * \param[in]     desc        Readable description of event
 * \param[in]     op_rc       Result of fence action
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_fencing_alert(lrmd_t *lrmd, const GList *alert_list,
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
 * \param[in,out] lrmd        Executor connection to use
 * \param[in]     alert_list  List of alert agents to execute
 * \param[in]     node        Name of node that executed operation
 * \param[in]     op          Resource operation
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_resource_alert(lrmd_t *lrmd, const GList *alert_list,
                         const char *node, const lrmd_event_data_t *op)
{
    int rc = pcmk_ok;
    int target_rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        return -2;
    }

    target_rc = rsc_op_expected_rc(op);
    if ((op->interval_ms == 0) && (target_rc == op->rc)
        && pcmk__str_eq(op->op_type, PCMK_ACTION_MONITOR, pcmk__str_casei)) {

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
                                 crm_exit_str((crm_exit_t) op->rc));
    } else {
        params = alert_key2param(params, PCMK__alert_key_desc,
                                 pcmk_exec_status_str(op->op_status));
    }

    rc = exec_alert_list(lrmd, alert_list, pcmk__alert_resource, NULL, params);
    lrmd_key_value_freeall(params);
    return rc;
}
