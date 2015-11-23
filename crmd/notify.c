/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include "notify.h"

char *notify_script = NULL;
char *notify_target = NULL;


static const char *notify_keys[] = 
{
    "CRM_notify_recipient",
    "CRM_notify_node",
    "CRM_notify_nodeid",
    "CRM_notify_rsc",
    "CRM_notify_task",
    "CRM_notify_interval",
    "CRM_notify_desc",
    "CRM_notify_status",
    "CRM_notify_target_rc",
    "CRM_notify_rc",
    "CRM_notify_kind",
    "CRM_notify_version",
};


void
crmd_enable_notifications(const char *script, const char *target)
{
    free(notify_script);
    notify_script = NULL;

    free(notify_target);
    notify_target = NULL;

    if(script == NULL || safe_str_eq(script, "/dev/null")) {
        crm_notice("Notifications disabled");
        return;
    }

    notify_script = strdup(script);
    notify_target = strdup(target);
    crm_notice("Notifications enabled");
}

static void
set_notify_key(const char *name, const char *cvalue, char *value)
{
    int lpc;
    bool found = 0;

    if(cvalue == NULL) {
        cvalue = value;
    }

    for(lpc = 0; lpc < DIMOF(notify_keys); lpc++) {
        if(safe_str_eq(name, notify_keys[lpc])) {
            found = 1;
            crm_trace("Setting notify key %s = '%s'", name, cvalue);
            setenv(name, cvalue, 1);
            break;
        }
    }

    CRM_ASSERT(found != 0);
    free(value);
}

static void crmd_notify_complete(svc_action_t *op) 
{
    if(op->rc == 0) {
        crm_info("Notification %d (%s) complete", op->sequence, op->agent);
    } else {
        crm_warn("Notification %d (%s) failed: %d", op->sequence, op->agent, op->rc);
    }
}

static void
send_notification(const char *kind)
{
    int lpc;
    svc_action_t *notify = NULL;
    static int operations = 0;

    crm_debug("Sending '%s' notification to '%s' via '%s'", kind, notify_target, notify_script);

    set_notify_key("CRM_notify_recipient", notify_target, NULL);
    set_notify_key("CRM_notify_kind", kind, NULL);
    set_notify_key("CRM_notify_version", VERSION, NULL);

    notify = services_action_create_generic(notify_script, NULL);

    notify->timeout = CRMD_NOTIFY_TIMEOUT_MS;
    notify->standard = strdup("event");
    notify->id = strdup(notify_script);
    notify->agent = strdup(notify_script);
    notify->sequence = ++operations;

    if(services_action_async(notify, &crmd_notify_complete) == FALSE) {
        services_action_free(notify);
    }

    for(lpc = 0; lpc < DIMOF(notify_keys); lpc++) {
        unsetenv(notify_keys[lpc]);
    }
}

void crmd_notify_node_event(crm_node_t *node)
{
    if(notify_script == NULL) {
        return;
    }

    set_notify_key("CRM_notify_node", node->uname, NULL);
    set_notify_key("CRM_notify_nodeid", NULL, crm_itoa(node->id));
    set_notify_key("CRM_notify_desc", node->state, NULL);

    send_notification("node");
}

void
crmd_notify_fencing_op(stonith_event_t * e)
{
    char *desc = NULL;

    if (notify_script == NULL) {
        return;
    }

    desc = crm_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                   e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                   e->id);

    set_notify_key("CRM_notify_node", e->target, NULL);
    set_notify_key("CRM_notify_task", e->operation, NULL);
    set_notify_key("CRM_notify_desc", NULL, desc);
    set_notify_key("CRM_notify_rc", NULL, crm_itoa(e->result));

    send_notification("fencing");
}

void
crmd_notify_resource_op(const char *node, lrmd_event_data_t * op)
{
    int target_rc = 0;

    if(notify_script == NULL) {
        return;
    }

    target_rc = rsc_op_expected_rc(op);
    if(op->interval == 0 && target_rc == op->rc && safe_str_eq(op->op_type, RSC_STATUS)) {
        /* Leave it up to the script if they want to notify for
         * 'failed' probes, only swallow ones for which the result was
         * unexpected.
         *
         * Even if we find a resource running, it was probably because
         * someone erased the status section.
         */
        return;
    }

    set_notify_key("CRM_notify_node", node, NULL);

    set_notify_key("CRM_notify_rsc", op->rsc_id, NULL);
    set_notify_key("CRM_notify_task", op->op_type, NULL);
    set_notify_key("CRM_notify_interval", NULL, crm_itoa(op->interval));

    set_notify_key("CRM_notify_target_rc", NULL, crm_itoa(target_rc));
    set_notify_key("CRM_notify_status", NULL, crm_itoa(op->op_status));
    set_notify_key("CRM_notify_rc", NULL, crm_itoa(op->rc));

    if(op->op_status == PCMK_LRM_OP_DONE) {
        set_notify_key("CRM_notify_desc", services_ocf_exitcode_str(op->rc), NULL);
    } else {
        set_notify_key("CRM_notify_desc", services_lrm_status_str(op->op_status), NULL);
    }

    send_notification("resource");
}

