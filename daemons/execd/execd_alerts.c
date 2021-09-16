/*
 * Copyright 2016-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/alerts_internal.h>
#include <crm/msg_xml.h>

#include "pacemaker-execd.h"

/* Track in-flight alerts so we can wait for them at shutdown */
static GHashTable *inflight_alerts; /* key = call_id, value = timeout */
static gboolean draining_alerts = FALSE;

static inline void
add_inflight_alert(int call_id, int timeout)
{
    if (inflight_alerts == NULL) {
        inflight_alerts = pcmk__intkey_table(NULL);
    }
    pcmk__intkey_table_insert(inflight_alerts, call_id,
                              GINT_TO_POINTER(timeout));
}

static inline void
remove_inflight_alert(int call_id)
{
    if (inflight_alerts != NULL) {
        pcmk__intkey_table_remove(inflight_alerts, call_id);
    }
}

static int
max_inflight_timeout(void)
{
    GHashTableIter iter;
    gpointer timeout;
    int max_timeout = 0;

    if (inflight_alerts) {
        g_hash_table_iter_init(&iter, inflight_alerts);
        while (g_hash_table_iter_next(&iter, NULL, &timeout)) {
            if (GPOINTER_TO_INT(timeout) > max_timeout) {
                max_timeout = GPOINTER_TO_INT(timeout);
            }
        }
    }
    return max_timeout;
}

struct alert_cb_s {
    char *client_id;
    int call_id;
};

static void
alert_complete(svc_action_t *action)
{
    struct alert_cb_s *cb_data = (struct alert_cb_s *) (action->cb_data);

    remove_inflight_alert(cb_data->call_id);
    crm_debug("Alert pid %d for %s completed with rc=%d",
              action->pid, cb_data->client_id, action->rc);

    free(cb_data->client_id);
    free(action->cb_data);
    action->cb_data = NULL;
}

int
process_lrmd_alert_exec(pcmk__client_t *client, uint32_t id, xmlNode *request)
{
    static int alert_sequence_no = 0;

    xmlNode *alert_xml = get_xpath_object("//" F_LRMD_ALERT, request, LOG_ERR);
    const char *alert_id = crm_element_value(alert_xml, F_LRMD_ALERT_ID);
    const char *alert_path = crm_element_value(alert_xml, F_LRMD_ALERT_PATH);
    svc_action_t *action = NULL;
    int alert_timeout = 0;
    int rc = pcmk_ok;
    GHashTable *params = NULL;
    struct alert_cb_s *cb_data = NULL;

    if ((alert_id == NULL) || (alert_path == NULL) ||
        (client == NULL) || (client->id == NULL)) { /* hint static analyzer */
        return -EINVAL;
    }
    if (draining_alerts) {
        return pcmk_ok;
    }

    crm_element_value_int(alert_xml, F_LRMD_TIMEOUT, &alert_timeout);

    crm_info("Executing alert %s for %s", alert_id, client->id);

    params = xml2list(alert_xml);
    pcmk__add_alert_key_int(params, PCMK__alert_key_node_sequence,
                            ++alert_sequence_no);

    cb_data = calloc(1, sizeof(struct alert_cb_s));
    CRM_CHECK(cb_data != NULL,
              rc = -ENOMEM; goto err);

    /* coverity[deref_ptr] False Positive */
    cb_data->client_id = strdup(client->id);
    CRM_CHECK(cb_data->client_id != NULL,
              rc = -ENOMEM; goto err);

    crm_element_value_int(request, F_LRMD_CALLID, &(cb_data->call_id));

    action = services_alert_create(alert_id, alert_path, alert_timeout, params,
                                   alert_sequence_no, cb_data);
    if (action->rc != PCMK_OCF_UNKNOWN) {
        rc = -E2BIG;
        goto err;
    }

    rc = services_action_user(action, CRM_DAEMON_USER);
    if (rc < 0) {
        goto err;
    }

    add_inflight_alert(cb_data->call_id, alert_timeout);
    if (services_alert_async(action, alert_complete) == FALSE) {
        services_action_free(action);
    }
    return pcmk_ok;

err:
    if (cb_data) {
        if (cb_data->client_id) {
            free(cb_data->client_id);
        }
        free(cb_data);
    }
    if (action) {
        services_action_free(action);
    }
    return rc;
}

static bool
drain_check(guint remaining_timeout_ms)
{
    if (inflight_alerts != NULL) {
        guint count = g_hash_table_size(inflight_alerts);

        if (count > 0) {
            crm_trace("%d alerts pending (%.3fs timeout remaining)",
                      count, remaining_timeout_ms / 1000.0);
            return TRUE;
        }
    }
    return FALSE;
}

void
lrmd_drain_alerts(GMainLoop *mloop)
{
    if (inflight_alerts != NULL) {
        guint timer_ms = max_inflight_timeout() + 5000;

        crm_trace("Draining in-flight alerts (timeout %.3fs)",
                  timer_ms / 1000.0);
        draining_alerts = TRUE;
        pcmk_drain_main_loop(mloop, timer_ms, drain_check);
        g_hash_table_destroy(inflight_alerts);
        inflight_alerts = NULL;
    }
}
