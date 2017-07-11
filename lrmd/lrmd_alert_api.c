/*
 * Copyright (C) 2016-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/common/alerts_internal.h>
#include <crm/msg_xml.h>

#include <lrmd_private.h>

struct alert_cb_s {
    char *client_id;
};

static void
alert_complete(svc_action_t *action)
{
    struct alert_cb_s *cb_data = (struct alert_cb_s *) (action->cb_data);

    crm_debug("Alert pid %d for %s completed with rc=%d",
              action->pid, cb_data->client_id, action->rc);

    free(cb_data->client_id);
    free(action->cb_data);
    action->cb_data = NULL;
}

int
process_lrmd_alert_exec(crm_client_t *client, uint32_t id, xmlNode *request)
{
    static int alert_sequence_no = 0;

    xmlNode *alert_xml = get_xpath_object("//" F_LRMD_ALERT, request, LOG_ERR);
    const char *alert_id = crm_element_value(alert_xml, F_LRMD_ALERT_ID);
    const char *alert_path = crm_element_value(alert_xml, F_LRMD_ALERT_PATH);
    svc_action_t *action = NULL;
    int alert_timeout = 0;
    GHashTable *params = NULL;
    struct alert_cb_s *cb_data;

    if ((alert_id == NULL) || (alert_path == NULL)) {
        return -EINVAL;
    }
    crm_element_value_int(alert_xml, F_LRMD_TIMEOUT, &alert_timeout);

    crm_info("Executing alert %s for %s", alert_id, client->id);

    params = xml2list(alert_xml);
    crm_insert_alert_key_int(params, CRM_alert_node_sequence,
                             ++alert_sequence_no);

    cb_data = calloc(1, sizeof(struct alert_cb_s));
    cb_data->client_id = strdup(client->id);

    action = services_alert_create(alert_id, alert_path, alert_timeout, params,
                                   alert_sequence_no, cb_data);

    if (services_alert_async(action, alert_complete) == FALSE) {
        services_action_free(action);
    }
    return pcmk_ok;
}
