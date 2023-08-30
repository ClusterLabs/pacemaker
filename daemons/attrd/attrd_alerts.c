/*
 * Copyright 2015-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/cib_internal.h>
#include <crm/pengine/rules_internal.h>
#include <crm/lrmd_internal.h>
#include "pacemaker-attrd.h"

static GList *attrd_alert_list = NULL;
static GHashTable *alert_attribute_value_table = NULL;

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
            ret = the_lrmd->cmds->connect(the_lrmd, T_ATTRD, NULL);
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
    if ((crmalerts != NULL) && !pcmk__xe_is(crmalerts, XML_CIB_TAG_ALERTS)) {
        crmalerts = first_named_child(crmalerts, XML_CIB_TAG_ALERTS);
    }
    if (!crmalerts) {
        crm_notice("CIB query result has no " XML_CIB_TAG_ALERTS " section");
        return;
    }

    pe_free_alert_list(attrd_alert_list);
    attrd_alert_list = pe_unpack_alerts(crmalerts);
}

gboolean
attrd_read_options(gpointer user_data)
{
    int call_id;

    CRM_CHECK(the_cib != NULL, return TRUE);

    call_id = the_cib->cmds->query(the_cib,
                                   pcmk__cib_abs_xpath_for(XML_CIB_TAG_ALERTS),
                                   NULL, cib_xpath|cib_scope_local);

    the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE, NULL,
                                          "config_query_callback",
                                          config_query_callback, free);

    crm_trace("Querying the CIB... call %d", call_id);
    return TRUE;
}

/*!
 * \internal
 * \brief Record an attribute value to use when sending alerts
 *
 * \param[in] attr_value  Attribute value to record
 *
 * \note The table stores attribute values for at most one attribute at a time.
 */
void
attrd_record_alert_attribute_value(const attribute_value_t *attr_value)
{
    attribute_value_t *copy = attrd_copy_attribute_value(attr_value);

    if (copy == NULL) {
        return;
    }

    if (alert_attribute_value_table == NULL) {
        alert_attribute_value_table =
            pcmk__strikey_table(NULL, attrd_free_attribute_value);
    }
    g_hash_table_insert(alert_attribute_value_table, copy->nodename, copy);
}

/*!
 * \internal
 * \brief Send alerts for attribute value change on one node
 *
 * \param[in] node_name  Name of node with attribute change
 * \param[in] nodeid     Node ID of node with attribute change
 * \param[in] attr       Name of attribute that changed
 * \param[in] value      New value of attribute that changed
 *
 * \retval \c pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 *
 * \todo Use legacy or standard Pacemaker return codes
 */
static int
send_attribute_alerts_one(const char *node_name, int nodeid, const char *attr,
                          const char *value)
{
    if (attrd_alert_list == NULL) {
        return pcmk_ok;
    }
    return lrmd_send_attribute_alert(attrd_lrmd_connect(), attrd_alert_list,
                                     node_name, nodeid, attr, value);
}

/*!
 * \internal
 * \brief Send all alerts for an attribute value change
 *
 * \param[in] attr  Attribute that changed
 */
void
attrd_send_attribute_alerts_all(const attribute_t *attr)
{
    GHashTableIter iter;
    attribute_value_t *attr_value = NULL;

    if (alert_attribute_value_table == NULL) {
        return;
    }

    g_hash_table_iter_init(&iter, alert_attribute_value_table);

    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &attr_value)) {
        int rc = send_attribute_alerts_one(attr_value->nodename,
                                           attr_value->nodeid, attr->id,
                                           attr_value->current);

        crm_trace("%s alert for %s[%s]=%s " CRM_XS " nodeid=%d rc=%d",
                  ((rc == pcmk_ok)? "Sent" : "Failed to send"), attr->id,
                  attr_value->nodename, attr_value->current, attr_value->nodeid,
                  rc);
    }
    g_hash_table_remove_all(alert_attribute_value_table);
}

/*!
 * \internal
 * \brief Free the table of attribute values saved for use when sending alerts
 */
void
attrd_free_alert_attribute_value_table(void)
{
    if (alert_attribute_value_table != NULL) {
        g_hash_table_destroy(alert_attribute_value_table);
        alert_attribute_value_table = NULL;
    }
}
