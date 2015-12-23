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
crm_trigger_t *notify_send = NULL;
GList *notify_list;
static int operations = 0;

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

static void
set_notify_key(const char *name, const char *cvalue)
{
    crm_trace("Setting notify key %s = '%s'", name, cvalue);
    setenv(name, cvalue, 1);
}

static void 
set_notify_keys(gpointer key, gpointer value, gpointer user_data)
{
    set_notify_key((char *)key, (char *)value);
}

static void 
unset_notify_keys(gpointer key, gpointer value, gpointer user_data)
{
    crm_trace("Unsetting notify key %s", key);
    unsetenv((char *)key);
}

static void
set_notify_params(GHashTable *params, const char *name, const char *cvalue, char *value)
{
    int lpc;
    bool found = 0;

    if(cvalue == NULL) {
        cvalue = value;
    }

    for(lpc = 0; lpc < DIMOF(notify_keys); lpc++) {
        if(safe_str_eq(name, notify_keys[lpc])) {
            found = 1;
            g_hash_table_insert(params, strdup(name), strdup(cvalue));
            break;
        }
    }

    CRM_ASSERT(found != 0);
    free(value);
}

void 
crmd_notify_clenaup()
{
    GList *l;
    svc_action_t *notify;
    
    for( l = g_list_first(notify_list); l ; l = g_list_next(l)) {
        notify = (svc_action_t *)(l->data);
        if (notify->sequence == 0) {
            notify->sequence = ++operations;

            g_hash_table_foreach(notify->params, set_notify_keys, NULL);

            if (services_action_async(notify, NULL) == FALSE) {
                crm_debug("Notifications Sending : %d failed", notify->sequence);
                services_action_free(notify);
            } else {
                crm_debug("Notifications Sending : %d ", notify->sequence);
            }
            
            g_hash_table_foreach(notify->params, unset_notify_keys, NULL);
        }
    }

    g_list_free(notify_list);
    notify_list = NULL;
    mainloop_destroy_trigger(notify_send);
    notify_send = NULL;
}

static void 
crmd_notify_complete(svc_action_t *op) 
{
    if(op->rc == 0) {
        crm_info("Notification %d (%s) complete", op->sequence, op->agent);
    } else {
        crm_warn("Notification %d (%s) failed: %d", op->sequence, op->agent, op->rc);
    }
    notify_list = g_list_remove(notify_list, op);
    mainloop_set_trigger(notify_send);
    
}

gboolean
crmd_notify_trigger(gpointer user_data)
{
    GList *l;
    svc_action_t *notify;
    
  retry : 
    l = g_list_first(notify_list);
    if (l != NULL) {
        notify = (svc_action_t *)(l->data);

        if (notify->sequence == 0) { 
            notify->sequence = ++operations;

            g_hash_table_foreach(notify->params, set_notify_keys, NULL);

            if(services_action_async(notify, &crmd_notify_complete) == FALSE) {
                crm_debug("Notifications Sending : %d failed", notify->sequence);
                services_action_free(notify);
                notify_list = g_list_remove(notify_list, notify);
                goto retry;
            }

            g_hash_table_foreach(notify->params, unset_notify_keys, NULL);
            crm_debug("Notifications Sending : %d ", notify->sequence);
        } else {
            crm_debug("Notifications Pending : %d ", notify->sequence);
        }
    }
    return TRUE;
}

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

    if (notify_send == NULL) {
        notify_send = mainloop_add_trigger(G_PRIORITY_LOW, crmd_notify_trigger, notify_list);
    }
    crm_notice("Notifications enabled");
}

static void
send_notification(const char *kind, GHashTable *params)
{
    svc_action_t *notify = NULL;

    crm_debug("Sending '%s' notification to '%s' via '%s'", kind, notify_target, notify_script);

    set_notify_params(params, "CRM_notify_recipient", notify_target, NULL);
    set_notify_params(params, "CRM_notify_kind", kind, NULL);
    set_notify_params(params, "CRM_notify_version", VERSION, NULL);

    notify = services_action_create_generic(notify_script, NULL);

    notify->timeout = CRMD_NOTIFY_TIMEOUT_MS;
    notify->standard = strdup("event");
    notify->id = strdup(notify_script);
    notify->agent = strdup(notify_script);

    notify->params = params;

    notify_list = g_list_append(notify_list, notify);

    mainloop_set_trigger(notify_send);
}

void crmd_notify_node_event(crm_node_t *node)
{
    GHashTable *params = NULL;

    if(notify_script == NULL) {
        return;
    }

    params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);

    set_notify_params(params, "CRM_notify_node", node->uname, NULL);
    set_notify_params(params, "CRM_notify_nodeid", NULL, crm_itoa(node->id));
    set_notify_params(params, "CRM_notify_desc", node->state, NULL);

    send_notification("node", params);
}

void
crmd_notify_fencing_op(stonith_event_t * e)
{
    char *desc = NULL;
    GHashTable *params = NULL;

    if (notify_script == NULL) {
        return;
    }

    desc = crm_strdup_printf("Operation %s requested by %s for peer %s: %s (ref=%s)",
                                   e->operation, e->origin, e->target, pcmk_strerror(e->result),
                                   e->id);
    params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);

    set_notify_params(params, "CRM_notify_node", e->target, NULL);
    set_notify_params(params, "CRM_notify_task", e->operation, NULL);
    set_notify_params(params, "CRM_notify_desc", NULL, desc);
    set_notify_params(params, "CRM_notify_rc", NULL, crm_itoa(e->result));

    send_notification("fencing", params);
}

void
crmd_notify_resource_op(const char *node, lrmd_event_data_t * op)
{
    int target_rc = 0;
    GHashTable *params = NULL;

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

    params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                           g_hash_destroy_str, g_hash_destroy_str);

    set_notify_params(params, "CRM_notify_node", node, NULL);

    set_notify_params(params, "CRM_notify_rsc", op->rsc_id, NULL);
    set_notify_params(params, "CRM_notify_task", op->op_type, NULL);
    set_notify_params(params, "CRM_notify_interval", NULL, crm_itoa(op->interval));

    set_notify_params(params, "CRM_notify_target_rc", NULL, crm_itoa(target_rc));
    set_notify_params(params, "CRM_notify_status", NULL, crm_itoa(op->op_status));
    set_notify_params(params, "CRM_notify_rc", NULL, crm_itoa(op->rc));

    if(op->op_status == PCMK_LRM_OP_DONE) {
        set_notify_params(params, "CRM_notify_desc", services_ocf_exitcode_str(op->rc), NULL);
    } else {
        set_notify_params(params, "CRM_notify_desc", services_lrm_status_str(op->op_status), NULL);
    }

    send_notification("resource", params);
}

