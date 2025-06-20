/*
 * Copyright 2012-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/alerts_internal.h>
#include <crm/fencing/internal.h>
#include <crm/lrmd.h>
#include <crm/lrmd_internal.h>
#include <crm/pengine/status.h>
#include <crm/stonith-ng.h>

#include <pacemaker-controld.h>

static GList *crmd_alert_list = NULL;

void
crmd_unpack_alerts(xmlNode *alerts)
{
    pcmk__free_alerts(crmd_alert_list);
    crmd_alert_list = pcmk__unpack_alerts(alerts);
}

void
crmd_alert_node_event(pcmk__node_status_t *node)
{
    lrm_state_t *lrm_state;

    if (crmd_alert_list == NULL) {
        return;
    }

    lrm_state = controld_get_executor_state(NULL, false);
    if (lrm_state == NULL) {
        return;
    }

    lrmd_send_node_alert((lrmd_t *) lrm_state->conn, crmd_alert_list,
                         node->name, node->cluster_layer_id, node->state);
}

void
crmd_alert_fencing_op(stonith_event_t * e)
{
    char *desc;
    lrm_state_t *lrm_state;

    if (crmd_alert_list == NULL) {
        return;
    }

    lrm_state = controld_get_executor_state(NULL, false);
    if (lrm_state == NULL) {
        return;
    }

    desc = stonith__event_description(e);
    lrmd_send_fencing_alert((lrmd_t *) lrm_state->conn, crmd_alert_list,
                            e->target, e->operation, desc, e->result);
    free(desc);
}

void
crmd_alert_resource_op(const char *node, lrmd_event_data_t * op)
{
    lrm_state_t *lrm_state;

    if (crmd_alert_list == NULL) {
        return;
    }

    lrm_state = controld_get_executor_state(NULL, false);
    if (lrm_state == NULL) {
        return;
    }

    lrmd_send_resource_alert((lrmd_t *) lrm_state->conn, crmd_alert_list, node,
                             op);
}
