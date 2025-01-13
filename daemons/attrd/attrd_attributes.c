/*
 * Copyright 2013-2025 the Pacemaker project contributors
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

#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

static attribute_t *
attrd_create_attribute(xmlNode *xml)
{
    int is_private = 0;
    long long dampen = 0;
    const char *name = crm_element_value(xml, PCMK__XA_ATTR_NAME);
    const char *set_type = crm_element_value(xml, PCMK__XA_ATTR_SET_TYPE);
    const char *dampen_s = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    attribute_t *a = NULL;

    if (set_type == NULL) {
        set_type = PCMK_XE_INSTANCE_ATTRIBUTES;
    }

    /* Set type is meaningful only when writing to the CIB. Private
     * attributes are not written.
     */
    crm_element_value_int(xml, PCMK__XA_ATTR_IS_PRIVATE, &is_private);
    if (!is_private && !pcmk__str_any_of(set_type,
                                         PCMK_XE_INSTANCE_ATTRIBUTES,
                                         PCMK_XE_UTILIZATION, NULL)) {
        crm_warn("Ignoring attribute %s with invalid set type %s",
                 pcmk__s(name, "(unidentified)"), set_type);
        return NULL;
    }

    a = pcmk__assert_alloc(1, sizeof(attribute_t));

    a->id = pcmk__str_copy(name);
    a->set_type = pcmk__str_copy(set_type);
    a->set_id = crm_element_value_copy(xml, PCMK__XA_ATTR_SET);
    a->user = crm_element_value_copy(xml, PCMK__XA_ATTR_USER);
    a->values = pcmk__strikey_table(NULL, attrd_free_attribute_value);

    if (is_private) {
        attrd_set_attr_flags(a, attrd_attr_is_private);
    }

    if (dampen_s != NULL) {
        dampen = crm_get_msec(dampen_s);
    }

    if (dampen > 0) {
        a->timeout_ms = (int) QB_MIN(dampen, INT_MAX);
        a->timer = attrd_add_timer(a->id, a->timeout_ms, a);
    } else if (dampen < 0) {
        crm_warn("Ignoring invalid delay %s for attribute %s", dampen_s, a->id);
    }

    crm_trace("Created attribute %s with %s write delay and %s CIB user",
              a->id,
              ((dampen > 0)? pcmk__readable_interval(a->timeout_ms) : "no"),
              pcmk__s(a->user, "default"));

    g_hash_table_replace(attributes, a->id, a);
    return a;
}

static int
attrd_update_dampening(attribute_t *a, xmlNode *xml, const char *attr)
{
    const char *dvalue = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    long long dampen = 0;

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
        a->timeout_ms = (int) QB_MIN(dampen, INT_MAX);
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
    xmlNode *xml = pcmk__xe_create(parent, __func__);

    crm_xml_add(xml, PCMK__XA_ATTR_NAME, a->id);
    crm_xml_add(xml, PCMK__XA_ATTR_SET_TYPE, a->set_type);
    crm_xml_add(xml, PCMK__XA_ATTR_SET, a->set_id);
    crm_xml_add(xml, PCMK__XA_ATTR_USER, a->user);
    crm_xml_add(xml, PCMK__XA_ATTR_HOST, v->nodename);

    /* @COMPAT Prior to 2.1.10 and 3.0.1, the node's cluster ID was added
     * instead of its XML ID. For Corosync and Pacemaker Remote nodes, those are
     * the same, but if we ever support node XML IDs that differ from their
     * cluster IDs, we will have to drop support for rolling upgrades from
     * versions before those.
     */
    crm_xml_add(xml, PCMK__XA_ATTR_HOST_ID, attrd_get_node_xml_id(v->nodename));

    crm_xml_add(xml, PCMK__XA_ATTR_VALUE, v->current);
    crm_xml_add_int(xml, PCMK__XA_ATTR_DAMPENING,
                    pcmk__timeout_ms2s(a->timeout_ms));
    crm_xml_add_int(xml, PCMK__XA_ATTR_IS_PRIVATE,
                    pcmk_is_set(a->flags, attrd_attr_is_private));
    crm_xml_add_int(xml, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(v->flags, attrd_value_remote));
    crm_xml_add_int(xml, PCMK__XA_ATTRD_IS_FORCE_WRITE, force_write);

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
            attrd_clear_value_flags(v, attrd_value_from_peer);
        }
    }
}

attribute_t *
attrd_populate_attribute(xmlNode *xml, const char *attr)
{
    attribute_t *a = NULL;
    bool update_both = false;

    const char *op = crm_element_value(xml, PCMK_XA_TASK);

    // NULL because PCMK__ATTRD_CMD_SYNC_RESPONSE has no PCMK_XA_TASK
    update_both = pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH,
                               pcmk__str_null_matches);

    // Look up or create attribute entry
    a = g_hash_table_lookup(attributes, attr);
    if (a == NULL) {
        if (update_both || pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_none)) {
            a = attrd_create_attribute(xml);
            if (a == NULL) {
                return NULL;
            }

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

/*!
 * \internal
 * \brief Get the XML ID used to write out an attribute set
 *
 * \param[in] attr           Attribute to get set ID for
 * \param[in] node_state_id  XML ID of node state that attribute value is for
 *
 * \return Newly allocated string with XML ID to use for \p attr set
 */
char *
attrd_set_id(const attribute_t *attr, const char *node_state_id)
{
    char *set_id = NULL;

    pcmk__assert((attr != NULL) && (node_state_id != NULL));

    if (pcmk__str_empty(attr->set_id)) {
        /* @COMPAT This should really take the set type into account. Currently
         * we use the same XML ID for transient attributes and utilization
         * attributes. It doesn't cause problems because the status section is
         * not limited by the schema in any way, but it's still unfortunate.
         * For backward compatibility reasons, we can't change this.
         */
        set_id = crm_strdup_printf("%s-%s", PCMK_XE_STATUS, node_state_id);
    } else {
        /* @COMPAT When the user specifies a set ID for an attribute, it is the
         * same for every node. That is less than ideal, but again, the schema
         * doesn't enforce anything for the status section. We couldn't change
         * it without allowing the set ID to vary per value rather than per
         * attribute, which would break backward compatibility, pose design
         * challenges, and potentially cause problems in rolling upgrades.
         */
        set_id = pcmk__str_copy(attr->set_id);
    }
    pcmk__xml_sanitize_id(set_id);
    return set_id;
}

/*!
 * \internal
 * \brief Get the XML ID used to write out an attribute value
 *
 * \param[in] attr           Attribute to get value XML ID for
 * \param[in] node_state_id  UUID of node that attribute value is for
 *
 * \return Newly allocated string with XML ID of \p attr value
 */
char *
attrd_nvpair_id(const attribute_t *attr, const char *node_state_id)
{
    char *nvpair_id = NULL;

    if (attr->set_id != NULL) {
        nvpair_id = crm_strdup_printf("%s-%s", attr->set_id, attr->id);

    } else {
        nvpair_id = crm_strdup_printf(PCMK_XE_STATUS "-%s-%s",
                                      node_state_id, attr->id);
    }
    pcmk__xml_sanitize_id(nvpair_id);
    return nvpair_id;
}

/*!
 * \internal
 * \brief Check whether an attribute is one that must be written to the CIB
 *
 * \param[in] a  Attribute to check
 *
 * \return false if we are in standalone mode or \p a is private, otherwise true
 */
bool
attrd_for_cib(const attribute_t *a)
{
    return !stand_alone && (a != NULL)
           && !pcmk_is_set(a->flags, attrd_attr_is_private);
}

/*!
 * \internal
 * \brief Drop NULL attribute values as indicated by given function
 *
 * Drop all NULL node attribute values that a given function indicates should
 * be, based on the XML ID of an element that was removed from the CIB.
 *
 * \param[in] cib_id    ID of XML element that was removed from CIB
 *                      (a name/value pair, an attribute set, or a node state)
 * \param[in] set_type  If not NULL, drop only attributes with this set type
 * \param[in] func      Call this function for every attribute/value
 *                      combination; keep the value if it returns 0, drop
 *                      the value and keep checking the attribute's other
 *                      values if it returns 1, or drop value and stop checking
 *                      the attribute's further values if it returns 2
 */
static void
drop_removed_values(const char *cib_id, const char *set_type,
                    int (*func)(const attribute_t *, const attribute_value_t *,
                                const char *))
{
    attribute_t *a = NULL;
    GHashTableIter attr_iter;
    const char *entry_type = pcmk__s(set_type, "status entry"); // for log

    CRM_CHECK((cib_id != NULL) && (func != NULL), return);

    // Check every attribute ...
    g_hash_table_iter_init(&attr_iter, attributes);
    while (g_hash_table_iter_next(&attr_iter, NULL, (gpointer *) &a)) {
        attribute_value_t *v = NULL;
        GHashTableIter value_iter;

        if (!attrd_for_cib(a)
            || ((set_type != NULL)
                && !pcmk__str_eq(a->set_type, set_type, pcmk__str_none))) {
            continue;
        }

        // Check every value of the attribute ...
        g_hash_table_iter_init(&value_iter, a->values);
        while (g_hash_table_iter_next(&value_iter, NULL, (gpointer *) &v)) {
            int rc = 0;

            if (v->current != NULL) {
                continue;
            }

            if (attrd_get_node_xml_id(v->nodename) == NULL) {
                /* This shouldn't be a significant issue, since we will know the
                 * XML ID if *any* attribute for the node has ever been written.
                 */
                crm_trace("Ignoring %s[%s] after CIB erasure of %s %s because "
                          "its node XML ID is unknown (possibly attribute was "
                          "never written to CIB)",
                          a->id, v->nodename, entry_type, cib_id);
                continue;
            }

            rc = func(a, v, cib_id);
            if (rc > 0) {
                crm_debug("Dropping %s[%s] after CIB erasure of %s %s",
                          a->id, v->nodename, entry_type, cib_id);
                g_hash_table_iter_remove(&value_iter);
                if (rc > 1) {
                    return;
                }
            }
        }
    }
}

/*!
 * \internal
 * \brief Check whether an attribute value has a given XML ID
 *
 * \param[in] a       Attribute being checked
 * \param[in] v       Attribute value being checked
 * \param[in] cib_id  ID of name/value pair element that was removed from CIB
 *
 * \return 2 if value matches XML ID, otherwise 0
 */
static int
nvpair_matches(const attribute_t *a, const attribute_value_t *v,
               const char *cib_id)
{
    char *id = attrd_nvpair_id(a, attrd_get_node_xml_id(v->nodename));

    /* The attribute manager doesn't enforce uniqueness for value XML IDs
     * (schema validation could be disabled), but in practice they should be,
     * so we can stop looping if we find a match.
     */
    int rc = pcmk__str_eq(id, cib_id, pcmk__str_none)? 2 : 0;

    free(id);
    return rc;
}

/*!
 * \internal
 * \brief Drop attribute value corresponding to given removed CIB entry
 *
 * \param[in] cib_id  ID of name/value pair element that was removed from CIB
 */
void
attrd_drop_removed_value(const char *cib_id)
{
    drop_removed_values(cib_id, NULL, nvpair_matches);
}

/*!
 * \internal
 * \brief Check whether an attribute value has a given attribute set ID
 *
 * \param[in] a       Attribute being checked
 * \param[in] v       Attribute value being checked
 * \param[in] cib_id  ID of attribute set that was removed from CIB
 *
 * \return 1 if value matches XML ID, otherwise 0
 */
static int
set_id_matches(const attribute_t *a, const attribute_value_t *v,
               const char *cib_id)
{
    char *id = attrd_set_id(a, attrd_get_node_xml_id(v->nodename));
    int rc = pcmk__str_eq(id, cib_id, pcmk__str_none)? 1: 0;

    free(id);
    return rc;
}

/*!
 * \internal
 * \brief Drop all removed attribute values for an attribute set
 *
 * \param[in] set_type  XML element name of set that was removed
 * \param[in] cib_id    ID of attribute set that was removed from CIB
 */
void
attrd_drop_removed_set(const char *set_type, const char *cib_id)
{
    drop_removed_values(cib_id, set_type, set_id_matches);
}

/*!
 * \internal
 * \brief Check whether an attribute value has a given node state XML ID
 *
 * \param[in] a       Attribute being checked
 * \param[in] v       Attribute value being checked
 * \param[in] cib_id  ID of node state that was removed from CIB
 *
 * \return 1 if value matches removed ID, otherwise 0
 */
static int
node_matches(const attribute_t *a, const attribute_value_t *v,
             const char *cib_id)
{
    if (pcmk__str_eq(cib_id, attrd_get_node_xml_id(v->nodename),
                     pcmk__str_none)) {
        return 1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Drop all removed attribute values for a node
 *
 * \param[in] cib_id  ID of node state that was removed from CIB
 */
void
attrd_drop_removed_values(const char *cib_id)
{
    drop_removed_values(cib_id, NULL, node_matches);
}
