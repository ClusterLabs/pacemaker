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

static void
attrd_lrmd_callback(lrmd_event_data_t * op)
{
    CRM_CHECK(op != NULL, return);
    switch (op->type) {
        case lrmd_event_disconnect:
            crm_info("Lost connection to LRMD");
            attrd_lrmd_disconnect();
            break;
        default:
            break;
    }
}

lrmd_t *
attrd_lrmd_connect()
{
    int ret = -ENOTCONN;
    int fails = 0;
    const unsigned int max_attempts = 10;

    if (!the_lrmd) {
        the_lrmd = lrmd_api_new();
    }
    the_lrmd->cmds->set_callback(the_lrmd, attrd_lrmd_callback);

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
        attrd_lrmd_disconnect();
    }
    return the_lrmd;
}

void
attrd_lrmd_disconnect() {
    if (the_lrmd) {
        lrmd_t *conn = the_lrmd;

        the_lrmd = NULL; /* in case we're called recursively */
        lrmd_api_delete(conn); /* will disconnect if necessary */
    }
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
    int rc = 0;
    attribute_value_t *at = NULL;
    GHashTableIter vIter;

    g_hash_table_iter_init(&vIter, t);

    while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & at)) {
        rc = lrmd_send_attribute_alert(attrd_alert_list, attrd_lrmd_connect,
                                       at->nodename, at->nodeid, a->id,
                                       at->current);
        crm_trace("Sent alerts for %s[%s]=%s: nodeid=%d rc=%d",
                  a->id, at->nodename, at->current, at->nodeid, rc);
    }
}
#endif
