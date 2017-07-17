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
    xmlNode *crmalerts = NULL;

    if (rc != pcmk_ok) {
        crm_err("Local CIB query resulted in an error: %s", pcmk_strerror(rc));
        return;
    }

    crmalerts = output;
    if (crmalerts && !crm_str_eq(crm_element_name(crmalerts),
                                 XML_CIB_TAG_ALERTS, TRUE)) {
        crmalerts = first_named_child(crmalerts, XML_CIB_TAG_ALERTS);
    }
    if (!crmalerts) {
        crm_err("Local CIB query for " XML_CIB_TAG_ALERTS " section failed");
        return;
    }

    pe_free_alert_list(attrd_alert_list);
    attrd_alert_list = pe_unpack_alerts(crmalerts);
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
    if (crm_patchset_contains_alert(msg, FALSE)) {
        mainloop_set_trigger(attrd_config_read);
    }
}

int
attrd_send_attribute_alert(const char *node, int nodeid,
                           const char *attr, const char *value)
{
    return lrmd_send_attribute_alert(attrd_alert_list, attrd_lrmd_connect,
                                     node, nodeid, attr, value);
}
