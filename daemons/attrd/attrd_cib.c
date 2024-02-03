/*
 * Copyright 2013-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <inttypes.h>   // PRIu32
#include <stdbool.h>
#include <stdlib.h>
#include <glib.h>

#include <crm/cib/internal.h>       // cib__*
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>   // pcmk__get_node()

#include "pacemaker-attrd.h"

static int last_cib_op_done = 0;

static void write_attribute(attribute_t *a, bool ignore_delay);

static void
attrd_cib_destroy_cb(gpointer user_data)
{
    cib_t *cib = user_data;

    cib->cmds->signoff(cib);

    if (attrd_shutting_down(false)) {
        crm_info("Disconnected from the CIB manager");

    } else {
        // @TODO This should trigger a reconnect, not a shutdown
        crm_crit("Lost connection to the CIB manager, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}

static void
attrd_cib_updated_cb(const char *event, xmlNode *msg)
{
    const xmlNode *patchset = NULL;
    const char *client_name = NULL;
    bool status_changed = false;

    if (attrd_shutting_down(true)) {
        crm_debug("Ignoring CIB change during shutdown");
        return;
    }

    if (cib__get_notify_patchset(msg, &patchset) != pcmk_rc_ok) {
        return;
    }

    if (cib__element_in_patchset(patchset, PCMK_XE_ALERTS)) {
        mainloop_set_trigger(attrd_config_read);
    }

    status_changed = cib__element_in_patchset(patchset, PCMK_XE_STATUS);

    client_name = crm_element_value(msg, PCMK__XA_CIB_CLIENTNAME);
    if (!cib__client_triggers_refresh(client_name)) {
        /* This change came from a source that ensured the CIB is consistent
         * with our attributes table, so we don't need to write anything out.
         */
        return;
    }

    if (!attrd_election_won()) {
        // Don't write attributes if we're not the writer
        return;
    }

    if (status_changed || cib__element_in_patchset(patchset, PCMK_XE_NODES)) {
        /* An unsafe client modified the PCMK_XE_NODES or PCMK_XE_STATUS
         * section. Write transient attributes to ensure they're up-to-date in
         * the CIB.
         */
        if (client_name == NULL) {
            client_name = crm_element_value(msg, PCMK__XA_CIB_CLIENTID);
        }
        crm_notice("Updating all attributes after %s event triggered by %s",
                   event, pcmk__s(client_name, "(unidentified client)"));

        attrd_write_attributes(attrd_write_all);
    }
}

int
attrd_cib_connect(int max_retry)
{
    static int attempts = 0;

    int rc = -ENOTCONN;

    the_cib = cib_new();
    if (the_cib == NULL) {
        return -ENOTCONN;
    }

    do {
        if (attempts > 0) {
            sleep(attempts);
        }
        attempts++;
        crm_debug("Connection attempt %d to the CIB manager", attempts);
        rc = the_cib->cmds->signon(the_cib, PCMK__VALUE_ATTRD, cib_command);

    } while ((rc != pcmk_ok) && (attempts < max_retry));

    if (rc != pcmk_ok) {
        crm_err("Connection to the CIB manager failed: %s " CRM_XS " rc=%d",
                pcmk_strerror(rc), rc);
        goto cleanup;
    }

    crm_debug("Connected to the CIB manager after %d attempts", attempts);

    rc = the_cib->cmds->set_connection_dnotify(the_cib, attrd_cib_destroy_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set disconnection callback");
        goto cleanup;
    }

    rc = the_cib->cmds->add_notify_callback(the_cib, T_CIB_DIFF_NOTIFY,
                                            attrd_cib_updated_cb);
    if (rc != pcmk_ok) {
        crm_err("Could not set CIB notification callback");
        goto cleanup;
    }

    return pcmk_ok;

cleanup:
    cib__clean_up_connection(&the_cib);
    return -ENOTCONN;
}

void
attrd_cib_disconnect(void)
{
    CRM_CHECK(the_cib != NULL, return);
    the_cib->cmds->del_notify_callback(the_cib, T_CIB_DIFF_NOTIFY,
                                       attrd_cib_updated_cb);
    cib__clean_up_connection(&the_cib);
}

static void
attrd_erase_cb(xmlNode *msg, int call_id, int rc, xmlNode *output,
               void *user_data)
{
    const char *node = pcmk__s((const char *) user_data, "a node");

    if (rc == pcmk_ok) {
        crm_info("Cleared transient node attributes for %s from CIB", node);
    } else {
        crm_err("Unable to clear transient node attributes for %s from CIB: %s",
                node, pcmk_strerror(rc));
    }
}

#define XPATH_TRANSIENT "//" PCMK__XE_NODE_STATE    \
                        "[@" PCMK_XA_UNAME "='%s']" \
                        "/" PCMK__XE_TRANSIENT_ATTRIBUTES

/*!
 * \internal
 * \brief Wipe all transient node attributes for a node from the CIB
 *
 * \param[in] node  Node to clear attributes for
 */
void
attrd_cib_erase_transient_attrs(const char *node)
{
    int call_id = 0;
    char *xpath = NULL;

    CRM_CHECK(node != NULL, return);

    xpath = crm_strdup_printf(XPATH_TRANSIENT, node);

    crm_debug("Clearing transient node attributes for %s from CIB using %s",
              node, xpath);

    call_id = the_cib->cmds->remove(the_cib, xpath, NULL, cib_xpath);
    free(xpath);

    // strdup() is just for logging here, so ignore failure
    the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE,
                                          strdup(node), "attrd_erase_cb",
                                          attrd_erase_cb, free);
}

/*!
 * \internal
 * \brief Prepare the CIB after cluster is connected
 */
void
attrd_cib_init(void)
{
    /* We have no attribute values in memory, so wipe the CIB to match. This is
     * normally done by the DC's controller when this node leaves the cluster, but
     * this handles the case where the node restarted so quickly that the
     * cluster layer didn't notice.
     *
     * \todo If pacemaker-attrd respawns after crashing (see PCMK_ENV_RESPAWNED),
     *       ideally we'd skip this and sync our attributes from the writer.
     *       However, currently we reject any values for us that the writer has, in
     *       attrd_peer_update().
     */
    attrd_cib_erase_transient_attrs(attrd_cluster->uname);

    // Set a trigger for reading the CIB (for the alerts section)
    attrd_config_read = mainloop_add_trigger(G_PRIORITY_HIGH, attrd_read_options, NULL);

    // Always read the CIB at start-up
    mainloop_set_trigger(attrd_config_read);
}

static gboolean
attribute_timer_cb(gpointer data)
{
    attribute_t *a = data;
    crm_trace("Dampen interval expired for %s", a->id);
    attrd_write_or_elect_attribute(a);
    return FALSE;
}

static void
attrd_cib_callback(xmlNode *msg, int call_id, int rc, xmlNode *output, void *user_data)
{
    int level = LOG_ERR;
    GHashTableIter iter;
    const char *peer = NULL;
    attribute_value_t *v = NULL;

    char *name = user_data;
    attribute_t *a = g_hash_table_lookup(attributes, name);

    if(a == NULL) {
        crm_info("Attribute %s no longer exists", name);
        return;
    }

    a->update = 0;
    if (rc == pcmk_ok && call_id < 0) {
        rc = call_id;
    }

    switch (rc) {
        case pcmk_ok:
            level = LOG_INFO;
            last_cib_op_done = call_id;
            if (a->timer && !a->timeout_ms) {
                // Remove temporary dampening for failed writes
                mainloop_timer_del(a->timer);
                a->timer = NULL;
            }
            break;

        case -pcmk_err_diff_failed:    /* When an attr changes while the CIB is syncing */
        case -ETIME:           /* When an attr changes while there is a DC election */
        case -ENXIO:           /* When an attr changes while the CIB is syncing a
                                *   newer config from a node that just came up
                                */
            level = LOG_WARNING;
            break;
    }

    do_crm_log(level, "CIB update %d result for %s: %s " CRM_XS " rc=%d",
               call_id, a->id, pcmk_strerror(rc), rc);

    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, (gpointer *) & peer, (gpointer *) & v)) {
        if (rc == pcmk_ok) {
            crm_info("* Wrote %s[%s]=%s",
                     a->id, peer, pcmk__s(v->requested, "(unset)"));
            pcmk__str_update(&(v->requested), NULL);
        } else {
            do_crm_log(level, "* Could not write %s[%s]=%s",
                       a->id, peer, pcmk__s(v->requested, "(unset)"));
            a->changed = true; // Reattempt write below if we are still writer
        }
    }

    if (a->changed && attrd_election_won()) {
        if (rc == pcmk_ok) {
            /* We deferred a write of a new update because this update was in
             * progress. Write out the new value without additional delay.
             */
            crm_debug("Pending update for %s can be written now", a->id);
            write_attribute(a, false);

        /* We're re-attempting a write because the original failed; delay
         * the next attempt so we don't potentially flood the CIB manager
         * and logs with a zillion attempts per second.
         *
         * @TODO We could elect a new writer instead. However, we'd have to
         * somehow downgrade our vote, and we'd still need something like this
         * if all peers similarly fail to write this attribute (which may
         * indicate a corrupted attribute entry rather than a CIB issue).
         */
        } else if (a->timer) {
            // Attribute has a dampening value, so use that as delay
            if (!mainloop_timer_running(a->timer)) {
                crm_trace("Delayed re-attempted write for %s by %s",
                          name, pcmk__readable_interval(a->timeout_ms));
                mainloop_timer_start(a->timer);
            }
        } else {
            /* Set a temporary dampening of 2 seconds (timer will continue
             * to exist until the attribute's dampening gets set or the
             * write succeeds).
             */
            a->timer = attrd_add_timer(a->id, 2000, a);
            mainloop_timer_start(a->timer);
        }
    }
}

/*!
 * \internal
 * \brief Add a set-attribute update request to the current CIB transaction
 *
 * \param[in] attr     Attribute to update
 * \param[in] attr_id  ID of attribute to update
 * \param[in] node_id  ID of node for which to update attribute value
 * \param[in] set_id   ID of attribute set
 * \param[in] value    New value for attribute
 *
 * \return Standard Pacemaker return code
 */
static int
add_set_attr_update(const attribute_t *attr, const char *attr_id,
                    const char *node_id, const char *set_id, const char *value)
{
    xmlNode *update = create_xml_node(NULL, PCMK__XE_NODE_STATE);
    xmlNode *child = update;
    int rc = ENOMEM;

    if (child == NULL) {
        goto done;
    }
    crm_xml_add(child, PCMK_XA_ID, node_id);

    child = create_xml_node(child, PCMK__XE_TRANSIENT_ATTRIBUTES);
    if (child == NULL) {
        goto done;
    }
    crm_xml_add(child, PCMK_XA_ID, node_id);

    child = create_xml_node(child, attr->set_type);
    if (child == NULL) {
        goto done;
    }
    crm_xml_add(child, PCMK_XA_ID, set_id);

    child = create_xml_node(child, PCMK_XE_NVPAIR);
    if (child == NULL) {
        goto done;
    }
    crm_xml_add(child, PCMK_XA_ID, attr_id);
    crm_xml_add(child, PCMK_XA_NAME, attr->id);
    crm_xml_add(child, PCMK_XA_VALUE, value);

    rc = the_cib->cmds->modify(the_cib, PCMK_XE_STATUS, update,
                               cib_can_create|cib_transaction);
    rc = pcmk_legacy2rc(rc);

done:
    free_xml(update);
    return rc;
}

/*!
 * \internal
 * \brief Add an unset-attribute update request to the current CIB transaction
 *
 * \param[in] attr     Attribute to update
 * \param[in] attr_id  ID of attribute to update
 * \param[in] node_id  ID of node for which to update attribute value
 * \param[in] set_id   ID of attribute set
 *
 * \return Standard Pacemaker return code
 */
static int
add_unset_attr_update(const attribute_t *attr, const char *attr_id,
                      const char *node_id, const char *set_id)
{
    char *xpath = crm_strdup_printf("/" PCMK_XE_CIB
                                    "/" PCMK_XE_STATUS
                                    "/" PCMK__XE_NODE_STATE
                                        "[@" PCMK_XA_ID "='%s']"
                                    "/" PCMK__XE_TRANSIENT_ATTRIBUTES
                                        "[@" PCMK_XA_ID "='%s']"
                                    "/%s[@" PCMK_XA_ID "='%s']"
                                    "/" PCMK_XE_NVPAIR
                                        "[@" PCMK_XA_ID "='%s' "
                                         "and @" PCMK_XA_NAME "='%s']",
                                    node_id, node_id, attr->set_type, set_id,
                                    attr_id, attr->id);

    int rc = the_cib->cmds->remove(the_cib, xpath, NULL,
                                   cib_xpath|cib_transaction);

    free(xpath);
    return pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Add an attribute update request to the current CIB transaction
 *
 * \param[in] attr      Attribute to update
 * \param[in] value     New value for attribute
 * \param[in] node_id   ID of node for which to update attribute value
 *
 * \return Standard Pacemaker return code
 */
static int
add_attr_update(const attribute_t *attr, const char *value, const char *node_id)
{
    char *set_id = attrd_set_id(attr, node_id);
    char *nvpair_id = attrd_nvpair_id(attr, node_id);
    int rc = pcmk_rc_ok;

    if (value == NULL) {
        rc = add_unset_attr_update(attr, nvpair_id, node_id, set_id);
    } else {
        rc = add_set_attr_update(attr, nvpair_id, node_id, set_id, value);
    }
    free(set_id);
    free(nvpair_id);
    return rc;
}

static void
send_alert_attributes_value(attribute_t *a, GHashTable *t)
{
    int rc = 0;
    attribute_value_t *at = NULL;
    GHashTableIter vIter;

    g_hash_table_iter_init(&vIter, t);

    while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & at)) {
        rc = attrd_send_attribute_alert(at->nodename, at->nodeid,
                                        a->id, at->current);
        crm_trace("Sent alerts for %s[%s]=%s: nodeid=%d rc=%d",
                  a->id, at->nodename, at->current, at->nodeid, rc);
    }
}

static void
set_alert_attribute_value(GHashTable *t, attribute_value_t *v)
{
    attribute_value_t *a_v = NULL;
    a_v = calloc(1, sizeof(attribute_value_t));
    CRM_ASSERT(a_v != NULL);

    a_v->nodeid = v->nodeid;
    a_v->nodename = strdup(v->nodename);
    pcmk__str_update(&a_v->current, v->current);

    g_hash_table_replace(t, a_v->nodename, a_v);
}

mainloop_timer_t *
attrd_add_timer(const char *id, int timeout_ms, attribute_t *attr)
{
   return mainloop_timer_add(id, timeout_ms, FALSE, attribute_timer_cb, attr);
}

/*!
 * \internal
 * \brief Write an attribute's values to the CIB if appropriate
 *
 * \param[in,out] a             Attribute to write
 * \param[in]     ignore_delay  If true, write attribute now regardless of any
 *                              configured delay
 */
static void
write_attribute(attribute_t *a, bool ignore_delay)
{
    int private_updates = 0, cib_updates = 0;
    attribute_value_t *v = NULL;
    GHashTableIter iter;
    GHashTable *alert_attribute_value = NULL;
    int rc = pcmk_ok;

    if (a == NULL) {
        return;
    }

    /* If this attribute will be written to the CIB ... */
    if (!stand_alone && !a->is_private) {
        /* Defer the write if now's not a good time */
        if (a->update && (a->update < last_cib_op_done)) {
            crm_info("Write out of '%s' continuing: update %d considered lost",
                     a->id, a->update);
            a->update = 0; // Don't log this message again

        } else if (a->update) {
            crm_info("Write out of '%s' delayed: update %d in progress",
                     a->id, a->update);
            goto done;

        } else if (mainloop_timer_running(a->timer)) {
            if (ignore_delay) {
                mainloop_timer_stop(a->timer);
                crm_debug("Overriding '%s' write delay", a->id);
            } else {
                crm_info("Delaying write of '%s'", a->id);
                goto done;
            }
        }

        // Initiate a transaction for all the peer value updates
        CRM_CHECK(the_cib != NULL, goto done);
        the_cib->cmds->set_user(the_cib, a->user);
        rc = the_cib->cmds->init_transaction(the_cib);
        if (rc != pcmk_ok) {
            crm_err("Failed to write %s (id %s, set %s): Could not initiate "
                    "CIB transaction",
                    a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set_id, "n/a"));
            goto done;
        }
    }

    /* Attribute will be written shortly, so clear changed flag */
    a->changed = false;

    /* We will check all peers' uuids shortly, so initialize this to false */
    a->unknown_peer_uuids = false;

    /* Attribute will be written shortly, so clear forced write flag */
    a->force_write = FALSE;

    /* Make the table for the attribute trap */
    alert_attribute_value = pcmk__strikey_table(NULL,
                                                attrd_free_attribute_value);

    /* Iterate over each peer value of this attribute */
    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &v)) {
        const char *uuid = NULL;

        if (pcmk_is_set(v->flags, attrd_value_remote)) {
            /* If this is a Pacemaker Remote node, the node's UUID is the same
             * as its name, which we already have.
             */
            uuid = v->nodename;

        } else {
            // This will create a cluster node cache entry if none exists
            crm_node_t *peer = pcmk__get_node(v->nodeid, v->nodename, NULL,
                                              pcmk__node_search_any);

            uuid = peer->uuid;

            // Remember peer's node ID if we're just now learning it
            if ((peer->id != 0) && (v->nodeid == 0)) {
                crm_trace("Learned ID %u for node %s", peer->id, v->nodename);
                v->nodeid = peer->id;
            }
        }

        /* If this is a private attribute, no update needs to be sent */
        if (stand_alone || a->is_private) {
            private_updates++;
            continue;
        }

        // Defer write if this is a cluster node that's never been seen
        if (uuid == NULL) {
            a->unknown_peer_uuids = true;
            crm_notice("Cannot update %s[%s]='%s' now because node's UUID is "
                       "unknown (will retry if learned)",
                       a->id, v->nodename, v->current);
            continue;
        }

        // Update this value as part of the CIB transaction we're building
        rc = add_attr_update(a, v->current, uuid);
        if (rc != pcmk_rc_ok) {
            crm_err("Failed to update %s[%s]='%s': %s "
                    CRM_XS " node uuid=%s id=%" PRIu32,
                    a->id, v->nodename, v->current, pcmk_rc_str(rc),
                    uuid, v->nodeid);
            continue;
        }

        crm_debug("Writing %s[%s]=%s (node-state-id=%s node-id=%" PRIu32 ")",
                  a->id, v->nodename, pcmk__s(v->current, "(unset)"),
                  uuid, v->nodeid);
        cib_updates++;

        /* Preservation of the attribute to transmit alert */
        set_alert_attribute_value(alert_attribute_value, v);

        // Save this value so we can log it when write completes
        pcmk__str_update(&(v->requested), v->current);
    }

    if (private_updates) {
        crm_info("Processed %d private change%s for %s, id=%s, set=%s",
                 private_updates, pcmk__plural_s(private_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set_id, "n/a"));
    }
    if (cib_updates > 0) {
        char *id = NULL;

        // Commit transaction
        a->update = the_cib->cmds->end_transaction(the_cib, true, cib_none);

        crm_info("Sent CIB request %d with %d change%s for %s (id %s, set %s)",
                 a->update, cib_updates, pcmk__plural_s(cib_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set_id, "n/a"));

        pcmk__str_update(&id, a->id);
        if (the_cib->cmds->register_callback_full(the_cib, a->update,
                                                  CIB_OP_TIMEOUT_S, FALSE, id,
                                                  "attrd_cib_callback",
                                                  attrd_cib_callback, free)) {
            // Transmit alert of the attribute
            send_alert_attributes_value(a, alert_attribute_value);
        }
    }

done:
    // Discard transaction (if any)
    if (the_cib != NULL) {
        the_cib->cmds->end_transaction(the_cib, false, cib_none);
        the_cib->cmds->set_user(the_cib, NULL);
    }

    if (alert_attribute_value != NULL) {
        g_hash_table_destroy(alert_attribute_value);
    }
}

/*!
 * \internal
 * \brief Write out attributes
 *
 * \param[in] options  Group of enum attrd_write_options
 */
void
attrd_write_attributes(uint32_t options)
{
    GHashTableIter iter;
    attribute_t *a = NULL;

    crm_debug("Writing out %s attributes",
              pcmk_is_set(options, attrd_write_all)? "all" : "changed");
    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & a)) {
        if (!pcmk_is_set(options, attrd_write_all) && a->unknown_peer_uuids) {
            // Try writing this attribute again, in case peer ID was learned
            a->changed = true;
        } else if (a->force_write) {
            /* If the force_write flag is set, write the attribute. */
            a->changed = true;
        }

        if (pcmk_is_set(options, attrd_write_all) || a->changed) {
            bool ignore_delay = pcmk_is_set(options, attrd_write_no_delay);

            if (a->force_write) {
                // Always ignore delay when forced write flag is set
                ignore_delay = true;
            }
            write_attribute(a, ignore_delay);
        } else {
            crm_trace("Skipping unchanged attribute %s", a->id);
        }
    }
}

void
attrd_write_or_elect_attribute(attribute_t *a)
{
    if (attrd_election_won()) {
        write_attribute(a, false);
    } else {
        attrd_start_election_if_needed();
    }
}
