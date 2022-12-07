/*
 * Copyright 2013-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <glib.h>

#include <crm/msg_xml.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

static int last_cib_op_done = 0;

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
        do_crm_log(level, "* %s[%s]=%s", a->id, peer, v->requested);
        free(v->requested);
        v->requested = NULL;
        if (rc != pcmk_ok) {
            a->changed = true; /* Attempt write out again */
        }
    }

    if (a->changed && attrd_election_won()) {
        if (rc == pcmk_ok) {
            /* We deferred a write of a new update because this update was in
             * progress. Write out the new value without additional delay.
             */
            attrd_write_attribute(a, false);

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

static void
build_update_element(xmlNode *parent, attribute_t *a, const char *nodeid, const char *value)
{
    const char *set = NULL;
    xmlNode *xml_obj = NULL;

    xml_obj = create_xml_node(parent, XML_CIB_TAG_STATE);
    crm_xml_add(xml_obj, XML_ATTR_ID, nodeid);

    xml_obj = create_xml_node(xml_obj, XML_TAG_TRANSIENT_NODEATTRS);
    crm_xml_add(xml_obj, XML_ATTR_ID, nodeid);

    if (pcmk__str_eq(a->set_type, XML_TAG_ATTR_SETS, pcmk__str_null_matches)) {
        xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
    } else if (pcmk__str_eq(a->set_type, XML_TAG_UTILIZATION, pcmk__str_none)) {
        xml_obj = create_xml_node(xml_obj, XML_TAG_UTILIZATION);
    } else {
        crm_err("Unknown set type attribute: %s", a->set_type);
    }

    if (a->set_id) {
        crm_xml_set_id(xml_obj, "%s", a->set_id);
    } else {
        crm_xml_set_id(xml_obj, "%s-%s", XML_CIB_TAG_STATUS, nodeid);
    }
    set = ID(xml_obj);

    xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
    if (a->uuid) {
        crm_xml_set_id(xml_obj, "%s", a->uuid);
    } else {
        crm_xml_set_id(xml_obj, "%s-%s", set, a->id);
    }
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, a->id);

    if(value) {
        crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, value);

    } else {
        crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, "");
        crm_xml_add(xml_obj, "__delete__", XML_NVPAIR_ATTR_VALUE);
    }
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

void
attrd_write_attribute(attribute_t *a, bool ignore_delay)
{
    int private_updates = 0, cib_updates = 0;
    xmlNode *xml_top = NULL;
    attribute_value_t *v = NULL;
    GHashTableIter iter;
    enum cib_call_options flags = cib_quorum_override;
    GHashTable *alert_attribute_value = NULL;

    if (a == NULL) {
        return;
    }

    /* If this attribute will be written to the CIB ... */
    if (!a->is_private) {

        /* Defer the write if now's not a good time */
        CRM_CHECK(the_cib != NULL, return);
        if (a->update && (a->update < last_cib_op_done)) {
            crm_info("Write out of '%s' continuing: update %d considered lost", a->id, a->update);
            a->update = 0; // Don't log this message again

        } else if (a->update) {
            crm_info("Write out of '%s' delayed: update %d in progress", a->id, a->update);
            return;

        } else if (mainloop_timer_running(a->timer)) {
            if (ignore_delay) {
                /* 'refresh' forces a write of the current value of all attributes
                 * Cancel any existing timers, we're writing it NOW
                 */
                mainloop_timer_stop(a->timer);
                crm_debug("Write out of '%s': timer is running but ignore delay", a->id);
            } else {
                crm_info("Write out of '%s' delayed: timer is running", a->id);
                return;
            }
        }

        /* Initialize the status update XML */
        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
    }

    /* Attribute will be written shortly, so clear changed flag */
    a->changed = false;

    /* We will check all peers' uuids shortly, so initialize this to false */
    a->unknown_peer_uuids = false;

    /* Attribute will be written shortly, so clear forced write flag */
    a->force_write = FALSE;

    /* Make the table for the attribute trap */
    alert_attribute_value = pcmk__strikey_table(NULL, attrd_free_attribute_value);

    /* Iterate over each peer value of this attribute */
    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & v)) {
        crm_node_t *peer = crm_get_peer_full(v->nodeid, v->nodename, CRM_GET_PEER_ANY);

        /* If the value's peer info does not correspond to a peer, ignore it */
        if (peer == NULL) {
            crm_notice("Cannot update %s[%s]=%s because peer not known",
                       a->id, v->nodename, v->current);
            continue;
        }

        /* If we're just learning the peer's node id, remember it */
        if (peer->id && (v->nodeid == 0)) {
            crm_trace("Learned ID %u for node %s", peer->id, v->nodename);
            v->nodeid = peer->id;
        }

        /* If this is a private attribute, no update needs to be sent */
        if (a->is_private) {
            private_updates++;
            continue;
        }

        /* If the peer is found, but its uuid is unknown, defer write */
        if (peer->uuid == NULL) {
            a->unknown_peer_uuids = true;
            crm_notice("Cannot update %s[%s]=%s because peer UUID not known "
                       "(will retry if learned)",
                       a->id, v->nodename, v->current);
            continue;
        }

        /* Add this value to status update XML */
        crm_debug("Updating %s[%s]=%s (peer known as %s, UUID %s, ID %u/%u)",
                  a->id, v->nodename, v->current,
                  peer->uname, peer->uuid, peer->id, v->nodeid);
        build_update_element(xml_top, a, peer->uuid, v->current);
        cib_updates++;

        /* Preservation of the attribute to transmit alert */
        set_alert_attribute_value(alert_attribute_value, v);

        free(v->requested);
        v->requested = NULL;
        if (v->current) {
            v->requested = strdup(v->current);
        } else {
            /* Older attrd versions don't know about the cib_mixed_update
             * flag so make sure it goes to the local cib which does
             */
            cib__set_call_options(flags, crm_system_name,
                                  cib_mixed_update|cib_scope_local);
        }
    }

    if (private_updates) {
        crm_info("Processed %d private change%s for %s, id=%s, set=%s",
                 private_updates, pcmk__plural_s(private_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set_id, "n/a"));
    }
    if (cib_updates) {
        crm_log_xml_trace(xml_top, __func__);

        a->update = cib_internal_op(the_cib, PCMK__CIB_REQUEST_MODIFY, NULL,
                                    XML_CIB_TAG_STATUS, xml_top, NULL, flags,
                                    a->user);

        crm_info("Sent CIB request %d with %d change%s for %s (id %s, set %s)",
                 a->update, cib_updates, pcmk__plural_s(cib_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set_id, "n/a"));

        the_cib->cmds->register_callback_full(the_cib, a->update,
                                              CIB_OP_TIMEOUT_S, FALSE,
                                              strdup(a->id),
                                              "attrd_cib_callback",
                                              attrd_cib_callback, free);
        /* Transmit alert of the attribute */
        send_alert_attributes_value(a, alert_attribute_value);
    }

    g_hash_table_destroy(alert_attribute_value);
    free_xml(xml_top);
}

void
attrd_write_attributes(bool all, bool ignore_delay)
{
    GHashTableIter iter;
    attribute_t *a = NULL;

    crm_debug("Writing out %s attributes", all? "all" : "changed");
    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & a)) {
        if (!all && a->unknown_peer_uuids) {
            // Try writing this attribute again, in case peer ID was learned
            a->changed = true;
        } else if (a->force_write) {
            /* If the force_write flag is set, write the attribute. */
            a->changed = true;
        }

        if(all || a->changed) {
            /* When forced write flag is set, ignore delay. */
            attrd_write_attribute(a, (a->force_write ? true : ignore_delay));
        } else {
            crm_trace("Skipping unchanged attribute %s", a->id);
        }
    }
}

void
attrd_write_or_elect_attribute(attribute_t *a)
{
    if (attrd_election_won()) {
        attrd_write_attribute(a, false);
    } else {
        attrd_start_election_if_needed();
    }
}
