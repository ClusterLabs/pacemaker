/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election.h>
#include <internal.h>
#include "attrd_alerts.h"
#include <crm/common/alerts_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/pengine/rules_internal.h>
#include <crm/lrmd_alerts_internal.h>

static GListPtr attrd_alert_list = NULL;

lrmd_t *
attrd_lrmd_connect(int max_attempts, void callback(lrmd_event_data_t * op))
{
    int ret = -ENOTCONN;
    int fails = 0;

    if (!the_lrmd) {
        the_lrmd = lrmd_api_new();
    }
    the_lrmd->cmds->set_callback(the_lrmd, callback);

    while (fails < max_attempts) {
        ret = the_lrmd->cmds->connect(the_lrmd, T_ATTRD, NULL);
        if (ret != pcmk_ok) {
            fails++;
            crm_debug("Could not connect to LRMD, %d tries remaining",
                      (max_attempts - fails));
            /* @TODO We don't want to block here with sleep, but we should wait
             * some time between connection attempts. We could possibly add a
             * timer with a callback, but then we'd likely need an alert queue.
             */
        } else {
            break;
        }
    }

    if (ret != pcmk_ok) {
        if (the_lrmd->cmds->is_connected(the_lrmd)) {
            lrmd_api_delete(the_lrmd);
        }
        the_lrmd = NULL;
    }
    return the_lrmd;
}

static void
config_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    crm_time_t *now = crm_time_new(NULL);
    xmlNode *crmalerts = NULL;

    if (rc != pcmk_ok) {
        crm_err("Local CIB query resulted in an error: %s", pcmk_strerror(rc));
        goto bail;
    }

    crmalerts = output;
    if ((crmalerts) &&
        (crm_element_name(crmalerts)) &&
        (strcmp(crm_element_name(crmalerts), XML_CIB_TAG_ALERTS) != 0)) {
        crmalerts = first_named_child(crmalerts, XML_CIB_TAG_ALERTS);
    }
    if (!crmalerts) {
        crm_err("Local CIB query for " XML_CIB_TAG_ALERTS " section failed");
        goto bail;
    }

    pe_free_alert_list(attrd_alert_list);
    attrd_alert_list = pe_unpack_alerts(crmalerts);

  bail:
    crm_time_free(now);
}

gboolean
attrd_read_options(gpointer user_data)
{
    int call_id;
    
    if (the_cib) {
        call_id = the_cib->cmds->query(the_cib,
            "//" XML_CIB_TAG_ALERTS,
            NULL, cib_xpath | cib_scope_local);

        the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE,
                                              NULL,
                                              "config_query_callback",
                                              config_query_callback, free);

        crm_trace("Querying the CIB... call %d", call_id);
    } else {
        crm_err("Querying the CIB...CIB connection not active");
    }
    return TRUE;
}

void
attrd_cib_updated_cb(const char *event, xmlNode * msg)
{
    int rc = -1;
    int format= 1;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);
    xmlNode *change = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(msg != NULL, return);

    crm_element_value_int(msg, F_CIB_RC, &rc);
    if (rc < pcmk_ok) {
        crm_trace("Filter rc=%d (%s)", rc, pcmk_strerror(rc));
        return;
    }

    crm_element_value_int(patchset, "format", &format);
    if (format == 1) {
        if ((xpathObj = xpath_search(
                 msg,
                 "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_ALERTS
                 )) != NULL) {
            freeXpathObject(xpathObj);
            mainloop_set_trigger(attrd_config_read);
        }
    } else if (format == 2) {
        for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
            const char *xpath = crm_element_value(change, XML_DIFF_PATH);

            if (xpath == NULL) {
                continue;
            }

            if (!strstr(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_ALERTS)) {
                /* this is not a change to an existing alerts section */

                xmlNode *section = NULL;
                const char *name = NULL;

                if ((strcmp(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION) != 0) ||
                    ((section = __xml_first_child(change)) == NULL) ||
                    ((name = crm_element_name(section)) == NULL) ||
                    (strcmp(name, XML_CIB_TAG_ALERTS) != 0)) {
                    /* this is not a newly added alerts section */
                    continue;
                }
            }

            mainloop_set_trigger(attrd_config_read);
            break;
        }

    } else {
        crm_warn("Unknown patch format: %d", format);
    }

}

static int 
exec_alerts(lrmd_t *lrmd, enum crm_alert_flags kind, const char *attribute_name,
            lrmd_key_value_t *params)
{
    int rc = pcmk_ok;
    GListPtr l;
    crm_time_hr_t *now = crm_time_hr_new(NULL);
    
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_kind,
                                               crm_alert_flag2text(kind));
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_version, VERSION);

    for (l = g_list_first(attrd_alert_list); l; l = g_list_next(l)) {
        crm_alert_entry_t *entry = (crm_alert_entry_t *)(l->data);
        char *timestamp;
        lrmd_key_value_t * copy_params = NULL;
        lrmd_key_value_t *head, *p;

        if (is_not_set(entry->flags, kind)) {
            crm_trace("Filtering unwanted %s alert to %s via %s",
                      crm_alert_flag2text(kind), entry->recipient, entry->id);
            continue;
        }

        if ((kind == crm_alert_attribute)
            && !crm_is_target_alert(entry->select_attribute_name, attribute_name)) {

            crm_trace("Filtering unwanted attribute '%s' alert to %s via %s",
                      attribute_name, entry->recipient, entry->id);
            continue;
        }

        crm_info("Sending %s alert via %s to %s",
                 crm_alert_flag2text(kind), entry->id, entry->recipient);

        /* Because there is a parameter to turn into every transmission, Copy a parameter. */
        head = params;
        while (head) {
            p = head->next;
            copy_params = lrmd_key_value_add(copy_params, head->key, head->value);
            head = p;
        }

        timestamp = crm_time_format_hr(entry->tstamp_format, now);

        copy_params = lrmd_key_value_add(copy_params, CRM_ALERT_KEY_PATH, entry->path);
        copy_params = lrmd_set_alert_key_to_lrmd_params(copy_params, CRM_alert_recipient, entry->recipient);
        copy_params = lrmd_set_alert_key_to_lrmd_params(copy_params, CRM_alert_timestamp, timestamp);
        copy_params = lrmd_set_alert_envvar_to_lrmd_params(copy_params, entry);

        rc = lrmd->cmds->exec_alert(lrmd, entry->id, entry->path,
                                    entry->timeout, copy_params);
        if (rc < 0) {
            crm_err("Could not execute alert %s: %s " CRM_XS " rc=%d",
                    entry->id, pcmk_strerror(rc), rc);
        }

        free(timestamp);
    }

    if (now) {
        free(now);
    }

    return rc;
}

static void
attrd_alert_lrm_op_callback(lrmd_event_data_t * op)
{
    CRM_CHECK(op != NULL, return);

    if (op->type == lrmd_event_disconnect) {
        crm_info("Lost connection to LRMD service!");
        if (the_lrmd->cmds->is_connected(the_lrmd)) {
            the_lrmd->cmds->disconnect(the_lrmd);
            lrmd_api_delete(the_lrmd);
        }
        the_lrmd = NULL;
        return;
    } else if (op->type != lrmd_event_exec_complete) {
        return;
    }

    if (op->params != NULL) {
        void *value_tmp1, *value_tmp2;

        value_tmp1 = g_hash_table_lookup(op->params, CRM_ALERT_KEY_PATH);
        if (value_tmp1 != NULL) {
            value_tmp2 = g_hash_table_lookup(op->params, CRM_ALERT_NODE_SEQUENCE);
            if(op->rc == 0) {
                crm_info("Alert %s (%s) complete", value_tmp2, value_tmp1);
            } else {
                crm_warn("Alert %s (%s) failed: %d", value_tmp2, value_tmp1, op->rc);
            }
        }
    }
}

int
attrd_send_alerts(lrmd_t *lrmd, const char *node, uint32_t nodeid,
                  const char *attribute_name, const char *attribute_value)
{
    int ret = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        lrmd = attrd_lrmd_connect(10, attrd_alert_lrm_op_callback);
        if (lrmd == NULL) {
            crm_warn("Cannot send alerts: LRMD connection not active");
            return ret;
        }
    }

    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_node, node);
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_nodeid, crm_itoa(nodeid));
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_attribute_name, attribute_name);
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_attribute_value, attribute_value == NULL ? "null" : attribute_value);

    ret = exec_alerts(lrmd, crm_alert_attribute, attribute_name, params);

    if (params) {
        lrmd_key_value_freeall(params);
    }

    return ret;
}

#if HAVE_ATOMIC_ATTRD
void
set_alert_attribute_value(GHashTable *t, attribute_value_t *v)
{
    attribute_value_t *a_v = NULL;
    a_v = calloc(1, sizeof(attribute_value_t));
    CRM_ASSERT(a_v != NULL);

    a_v->nodeid = v->nodeid;
    a_v->nodename = strdup(v->nodename);

    if (v->current != NULL) {
        a_v->current = strdup(v->current);
    }

    g_hash_table_replace(t, a_v->nodename, a_v);
}

void
send_alert_attributes_value(attribute_t *a, GHashTable *t)
{
    int call_id = 0;
    attribute_value_t *at = NULL;
    GHashTableIter vIter;

    g_hash_table_iter_init(&vIter, t);

    while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & at)) {
        call_id = attrd_send_alerts(the_lrmd, at->nodename, at->nodeid, a->id,
                                    at->current);
        crm_trace("Sent alerts for %s[%s]=%s: call_id=%d nodeid=%d",
                  at->nodename, a->id, at->current, call_id, at->nodeid);
    }
}
#endif
