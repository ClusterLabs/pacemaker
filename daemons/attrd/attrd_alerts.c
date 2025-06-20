/*
 * Copyright 2015-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/cib_internal.h>
#include <crm/common/xml.h>
#include <crm/lrmd_internal.h>
#include "pacemaker-attrd.h"

static GList *attrd_alert_list = NULL;

static void
attrd_lrmd_callback(lrmd_event_data_t * op)
{
    CRM_CHECK(op != NULL, return);
    switch (op->type) {
        case lrmd_event_disconnect:
            crm_info("Lost connection to executor");
            attrd_lrmd_disconnect();
            break;
        default:
            break;
    }
}

static lrmd_t *
attrd_lrmd_connect(void)
{
    if (the_lrmd == NULL) {
        the_lrmd = lrmd_api_new();
        the_lrmd->cmds->set_callback(the_lrmd, attrd_lrmd_callback);
    }

    if (!the_lrmd->cmds->is_connected(the_lrmd)) {
        const unsigned int max_attempts = 10;
        int ret = -ENOTCONN;

        for (int fails = 0; fails < max_attempts; ++fails) {
            ret = the_lrmd->cmds->connect(the_lrmd, PCMK__VALUE_ATTRD, NULL);
            if (ret == pcmk_ok) {
                break;
            }

            crm_debug("Could not connect to executor, %d tries remaining",
                      (max_attempts - fails));
            /* @TODO We don't want to block here with sleep, but we should wait
             * some time between connection attempts. We could possibly add a
             * timer with a callback, but then we'd likely need an alert queue.
             */
        }

        if (ret != pcmk_ok) {
            attrd_lrmd_disconnect();
        }
    }

    return the_lrmd;
}

void
attrd_lrmd_disconnect(void) {
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

    if (rc == -ENXIO) {
        crm_debug("Local CIB has no alerts section");
        return;
    } else if (rc != pcmk_ok) {
        crm_notice("Could not query local CIB: %s", pcmk_strerror(rc));
        return;
    }

    crmalerts = output;
    if ((crmalerts != NULL) && !pcmk__xe_is(crmalerts, PCMK_XE_ALERTS)) {
        crmalerts = pcmk__xe_first_child(crmalerts, PCMK_XE_ALERTS, NULL, NULL);
    }
    if (!crmalerts) {
        crm_notice("CIB query result has no " PCMK_XE_ALERTS " section");
        return;
    }

    pcmk__free_alerts(attrd_alert_list);
    attrd_alert_list = pcmk__unpack_alerts(crmalerts);
}

gboolean
attrd_read_options(gpointer user_data)
{
    int call_id;

    CRM_CHECK(the_cib != NULL, return TRUE);

    call_id = the_cib->cmds->query(the_cib,
                                   pcmk__cib_abs_xpath_for(PCMK_XE_ALERTS),
                                   NULL, cib_xpath);

    the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE, NULL,
                                          "config_query_callback",
                                          config_query_callback, free);

    crm_trace("Querying the CIB... call %d", call_id);
    return TRUE;
}

int
attrd_send_attribute_alert(const char *node, const char *node_xml_id,
                           const char *attr, const char *value)
{
    uint32_t nodeid = 0U;
    pcmk__node_status_t *node_status = NULL;

    if (attrd_alert_list == NULL) {
        return pcmk_ok;
    }
    node_status = pcmk__search_node_caches(0, node, node_xml_id,
                                           pcmk__node_search_remote
                                           |pcmk__node_search_cluster_member
                                           |pcmk__node_search_cluster_cib);
    if (node_status != NULL) {
        nodeid = node_status->cluster_layer_id;
    }
    return lrmd_send_attribute_alert(attrd_lrmd_connect(), attrd_alert_list,
                                     node, nodeid, attr, value);
}
