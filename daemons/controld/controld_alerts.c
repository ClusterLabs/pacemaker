/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/lrmd.h>
#include <crm/lrmd_internal.h>
#include <crm/pengine/rules_internal.h>
#include <crm/pengine/status.h>
#include <crm/stonith-ng.h>

#include <pacemaker-controld.h>

static GList *crmd_alert_list = NULL;

void
crmd_unpack_alerts(xmlNode *alerts)
{
    pe_free_alert_list(crmd_alert_list);
    crmd_alert_list = pe_unpack_alerts(alerts);
}

void
crmd_alert_node_event(crm_node_t *node)
{
    lrm_state_t *lrm_state;

    if (crmd_alert_list == NULL) {
        return;
    }

    lrm_state = lrm_state_find(fsa_our_uname);
    if (lrm_state == NULL) {
        return;
    }

    lrmd_send_node_alert((lrmd_t *) lrm_state->conn, crmd_alert_list,
                         node->uname, node->id, node->state);
}

void
crmd_alert_fencing_op(stonith_event_t * e)
{
    char *desc;
    lrm_state_t *lrm_state;

    if (crmd_alert_list == NULL) {
        return;
    }

    lrm_state = lrm_state_find(fsa_our_uname);
    if (lrm_state == NULL) {
        return;
    }

    desc = crm_strdup_printf("Operation %s of %s by %s for %s@%s: %s (ref=%s)",
                             e->action, e->target,
                             (e->executioner? e->executioner : "<no-one>"),
                             e->client_origin, e->origin,
                             pcmk_strerror(e->result), e->id);

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

    lrm_state = lrm_state_find(fsa_our_uname);
    if (lrm_state == NULL) {
        return;
    }

    lrmd_send_resource_alert((lrmd_t *) lrm_state->conn, crmd_alert_list, node,
                             op);
}
