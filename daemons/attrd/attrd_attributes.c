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

static attribute_t *
attrd_create_attribute(xmlNode *xml)
{
    int dampen = 0;
    const char *value = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    attribute_t *a = calloc(1, sizeof(attribute_t));

    CRM_ASSERT(a != NULL);

    a->id      = crm_element_value_copy(xml, PCMK__XA_ATTR_NAME);
    a->set     = crm_element_value_copy(xml, PCMK__XA_ATTR_SET);
    a->uuid    = crm_element_value_copy(xml, PCMK__XA_ATTR_UUID);
    a->values = pcmk__strikey_table(NULL, attrd_free_attribute_value);

    crm_element_value_int(xml, PCMK__XA_ATTR_IS_PRIVATE, &a->is_private);

    a->user = crm_element_value_copy(xml, PCMK__XA_ATTR_USER);
    crm_trace("Performing all %s operations as user '%s'", a->id, a->user);

    if (value != NULL) {
        dampen = crm_get_msec(value);
    }
    crm_trace("Created attribute %s with %s write delay", a->id,
              (a->timeout_ms == 0)? "no" : pcmk__readable_interval(a->timeout_ms));

    if(dampen > 0) {
        a->timeout_ms = dampen;
        a->timer = attrd_add_timer(a->id, a->timeout_ms, a);
    } else if (dampen < 0) {
        crm_warn("Ignoring invalid delay %s for attribute %s", value, a->id);
    }

    g_hash_table_replace(attributes, a->id, a);
    return a;
}

static int
attrd_update_dampening(attribute_t *a, xmlNode *xml, const char *attr)
{
    const char *dvalue = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    int dampen = 0;

    if (dvalue == NULL) {
        crm_warn("Could not update %s: peer did not specify value for delay",
                 attr);
        return EINVAL;
    }

    dampen = crm_get_msec(dvalue);
    if (dampen < 0) {
        crm_warn("Could not update %s: invalid delay value %dms (%s)",
                 attr, dampen, dvalue);
        return EINVAL;
    }

    if (a->timeout_ms != dampen) {
        mainloop_timer_del(a->timer);
        a->timeout_ms = dampen;
        if (dampen > 0) {
            a->timer = attrd_add_timer(attr, a->timeout_ms, a);
            crm_info("Update attribute %s delay to %dms (%s)",
                     attr, dampen, dvalue);
        } else {
            a->timer = NULL;
            crm_info("Update attribute %s to remove delay", attr);
        }

        /* If dampening changed, do an immediate write-out,
         * otherwise repeated dampening changes would prevent write-outs
         */
        attrd_write_or_elect_attribute(a);
    }

    return pcmk_rc_ok;
}

GHashTable *attributes = NULL;

/*!
 * \internal
 * \brief Create an XML representation of an attribute for use in peer messages
 *
 * \param[in,out] parent      Create attribute XML as child element of this
 * \param[in]     a           Attribute to represent
 * \param[in]     v           Attribute value to represent
 * \param[in]     force_write If true, value should be written even if unchanged
 *
 * \return XML representation of attribute
 */
xmlNode *
attrd_add_value_xml(xmlNode *parent, const attribute_t *a,
                    const attribute_value_t *v, bool force_write)
{
    xmlNode *xml = create_xml_node(parent, __func__);

    crm_xml_add(xml, PCMK__XA_ATTR_NAME, a->id);
    crm_xml_add(xml, PCMK__XA_ATTR_SET, a->set);
    crm_xml_add(xml, PCMK__XA_ATTR_UUID, a->uuid);
    crm_xml_add(xml, PCMK__XA_ATTR_USER, a->user);
    pcmk__xe_add_node(xml, v->nodename, v->nodeid);
    if (v->is_remote != 0) {
        crm_xml_add_int(xml, PCMK__XA_ATTR_IS_REMOTE, 1);
    }
    crm_xml_add(xml, PCMK__XA_ATTR_VALUE, v->current);
    crm_xml_add_int(xml, PCMK__XA_ATTR_DAMPENING, a->timeout_ms / 1000);
    crm_xml_add_int(xml, PCMK__XA_ATTR_IS_PRIVATE, a->is_private);
    crm_xml_add_int(xml, PCMK__XA_ATTR_FORCE, force_write);

    return xml;
}

void
attrd_clear_value_seen(void)
{
    GHashTableIter aIter;
    GHashTableIter vIter;
    attribute_t *a;
    attribute_value_t *v = NULL;

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {
            v->seen = FALSE;
            crm_trace("Clear seen flag %s[%s] = %s.", a->id, v->nodename, v->current);
        }
    }
}

attribute_t *
attrd_populate_attribute(xmlNode *xml, const char *attr)
{
    attribute_t *a = NULL;
    bool update_both = false;

    const char *op = crm_element_value(xml, PCMK__XA_TASK);

    // NULL because PCMK__ATTRD_CMD_SYNC_RESPONSE has no PCMK__XA_TASK
    update_both = pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH,
                               pcmk__str_null_matches);

    // Look up or create attribute entry
    a = g_hash_table_lookup(attributes, attr);
    if (a == NULL) {
        if (update_both || pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_none)) {
            a = attrd_create_attribute(xml);
        } else {
            crm_warn("Could not update %s: attribute not found", attr);
            return NULL;
        }
    }

    // Update attribute dampening
    if (update_both || pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_none)) {
        int rc = attrd_update_dampening(a, xml, attr);

        if (rc != pcmk_rc_ok || !update_both) {
            return NULL;
        }
    }

    return a;
}
