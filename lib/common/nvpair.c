/*
 * Copyright 2004-2019 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

/*
 * This file isolates handling of two types of name/value pairs:
 *
 * - XML attributes (<TAG ... NAME=VALUE ...>)
 * - XML nvpair elements (<nvpair id=ID name=NAME value=VALUE>)
 */

// XML attribute handling

/*!
 * \brief Create an XML attribute with specified name and value
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value on success, \c NULL otherwise
 * \note This does nothing if node, name, or value are \c NULL or empty.
 */
const char *
crm_xml_add(xmlNode *node, const char *name, const char *value)
{
    bool dirty = FALSE;
    xmlAttr *attr = NULL;

    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL, return NULL);

    if (value == NULL) {
        return NULL;
    }
#if XML_PARANOIA_CHECKS
    {
        const char *old_value = NULL;

        old_value = crm_element_value(node, name);

        /* Could be re-setting the same value */
        CRM_CHECK(old_value != value,
                  crm_err("Cannot reset %s with crm_xml_add(%s)", name, value);
                  return value);
    }
#endif

    if (pcmk__tracking_xml_changes(node, FALSE)) {
        const char *old = crm_element_value(node, name);

        if (old == NULL || value == NULL || strcmp(old, value) != 0) {
            dirty = TRUE;
        }
    }

    if (dirty && (pcmk__check_acl(node, name, xpf_acl_create) == FALSE)) {
        crm_trace("Cannot add %s=%s to %s", name, value, node->name);
        return NULL;
    }

    attr = xmlSetProp(node, (const xmlChar *)name, (const xmlChar *)value);
    if (dirty) {
        pcmk__mark_xml_attr_dirty(attr);
    }

    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *)attr->children->content;
}

/*!
 * \brief Replace an XML attribute with specified name and (possibly NULL) value
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value on success, \c NULL otherwise
 * \note This does nothing if node or name is \c NULL or empty.
 */
const char *
crm_xml_replace(xmlNode *node, const char *name, const char *value)
{
    bool dirty = FALSE;
    xmlAttr *attr = NULL;
    const char *old_value = NULL;

    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL && name[0] != 0, return NULL);

    old_value = crm_element_value(node, name);

    /* Could be re-setting the same value */
    CRM_CHECK(old_value != value, return value);

    if (pcmk__check_acl(node, name, xpf_acl_write) == FALSE) {
        /* Create a fake object linked to doc->_private instead? */
        crm_trace("Cannot replace %s=%s to %s", name, value, node->name);
        return NULL;

    } else if (old_value && !value) {
        xml_remove_prop(node, name);
        return NULL;
    }

    if (pcmk__tracking_xml_changes(node, FALSE)) {
        if (!old_value || !value || !strcmp(old_value, value)) {
            dirty = TRUE;
        }
    }

    attr = xmlSetProp(node, (const xmlChar *)name, (const xmlChar *)value);
    if (dirty) {
        pcmk__mark_xml_attr_dirty(attr);
    }
    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *) attr->children->content;
}

/*!
 * \brief Create an XML attribute with specified name and integer value
 *
 * This is like \c crm_xml_add() but taking an integer value.
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value as string on success, \c NULL otherwise
 * \note This does nothing if node or name are \c NULL or empty.
 */
const char *
crm_xml_add_int(xmlNode *node, const char *name, int value)
{
    char *number = crm_itoa(value);
    const char *added = crm_xml_add(node, name, number);

    free(number);
    return added;
}

/*!
 * \brief Create an XML attribute with specified name and unsigned value
 *
 * This is like \c crm_xml_add() but taking a guint value.
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     ms     Attribute value to set
 *
 * \return New value as string on success, \c NULL otherwise
 * \note This does nothing if node or name are \c NULL or empty.
 */
const char *
crm_xml_add_ms(xmlNode *node, const char *name, guint ms)
{
    char *number = crm_strdup_printf("%u", ms);
    const char *added = crm_xml_add(node, name, number);

    free(number);
    return added;
}

/*!
 * \brief Retrieve the value of an XML attribute
 *
 * \param[in] data   XML node to check
 * \param[in] name   Attribute name to check
 *
 * \return Value of specified attribute (may be \c NULL)
 */
const char *
crm_element_value(const xmlNode *data, const char *name)
{
    xmlAttr *attr = NULL;

    if (data == NULL) {
        crm_err("Couldn't find %s in NULL", name ? name : "<null>");
        CRM_LOG_ASSERT(data != NULL);
        return NULL;

    } else if (name == NULL) {
        crm_err("Couldn't find NULL in %s", crm_element_name(data));
        return NULL;
    }

    /* The first argument to xmlHasProp() has always been const,
     * but libxml2 <2.9.2 didn't declare that, so cast it
     */
    attr = xmlHasProp((xmlNode *) data, (const xmlChar *)name);
    if (!attr || !attr->children) {
        return NULL;
    }
    return (const char *) attr->children->content;
}

/*!
 * \brief Retrieve the integer value of an XML attribute
 *
 * This is like \c crm_element_value() but returning the value as an integer.
 *
 * \param[in] data   XML node to check
 * \param[in] name   Attribute name to check
 *
 * \return Integer value of specified attribute on success, -1 otherwise
 */
int
crm_element_value_int(const xmlNode *data, const char *name, int *dest)
{
    const char *value = NULL;

    CRM_CHECK(dest != NULL, return -1);
    value = crm_element_value(data, name);
    if (value) {
        *dest = crm_int_helper(value, NULL);
        return 0;
    }
    return -1;
}

int
crm_element_value_const_int(const xmlNode * data, const char *name, int *dest)
{
    return crm_element_value_int((xmlNode *) data, name, dest);
}

const char *
crm_element_value_const(const xmlNode * data, const char *name)
{
    return crm_element_value((xmlNode *) data, name);
}

/*!
 * \brief Retrieve the value of XML second/microsecond attributes as time
 *
 * This is like \c crm_element_value() but returning value as a struct timeval.
 *
 * \param[in]  xml        XML to parse
 * \param[in]  name_sec   Name of XML attribute for seconds
 * \param[in]  name_usec  Name of XML attribute for microseconds
 * \param[out] dest       Where to store result
 *
 * \return \c pcmk_ok on success, -errno on error
 * \note Values default to 0 if XML or XML attribute does not exist
 */
int
crm_element_value_timeval(const xmlNode *xml, const char *name_sec,
                          const char *name_usec, struct timeval *dest)
{
    const char *value_s = NULL;
    long long value_i = 0;

    CRM_CHECK(dest != NULL, return -EINVAL);
    dest->tv_sec = 0;
    dest->tv_usec = 0;

    if (xml == NULL) {
        return 0;
    }

    // Parse seconds
    value_s = crm_element_value(xml, name_sec);
    if (value_s) {
        value_i = crm_parse_ll(value_s, NULL);
        if (errno) {
            return -errno;
        }
        dest->tv_sec = (time_t) value_i;
    }

    // Parse microseconds
    value_s = crm_element_value(xml, name_usec);
    if (value_s) {
        value_i = crm_parse_ll(value_s, NULL);
        if (errno) {
            return -errno;
        }
        dest->tv_usec = (suseconds_t) value_i;
    }
    return 0;
}

/*!
 * \brief Retrieve a copy of the value of an XML attribute
 *
 * This is like \c crm_element_value() but allocating new memory for the result.
 *
 * \param[in] data   XML node to check
 * \param[in] name   Attribute name to check
 *
 * \return Value of specified attribute (may be \c NULL)
 * \note The caller is responsible for freeing the result.
 */
char *
crm_element_value_copy(const xmlNode *data, const char *name)
{
    char *value_copy = NULL;
    const char *value = crm_element_value(data, name);

    if (value != NULL) {
        value_copy = strdup(value);
    }
    return value_copy;
}

/*!
 * \brief Add hash table entry to XML as (possibly legacy) name/value
 *
 * Suitable for \c g_hash_table_foreach(), this function takes a hash table key
 * and value, with an XML node passed as user data, and adds an XML attribute
 * with the specified name and value if it does not already exist. If the key
 * name starts with a digit, this will instead add a \<param name=NAME
 * value=VALUE/> child to the XML (for legacy compatibility with heartbeat).
 *
 * \param[in] key        Key of hash table entry
 * \param[in] value      Value of hash table entry
 * \param[in] user_data  XML node
 */
void
hash2smartfield(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;

    if (isdigit(name[0])) {
        xmlNode *tmp = create_xml_node(xml_node, XML_TAG_PARAM);

        crm_xml_add(tmp, XML_NVPAIR_ATTR_NAME, name);
        crm_xml_add(tmp, XML_NVPAIR_ATTR_VALUE, s_value);

    } else if (crm_element_value(xml_node, name) == NULL) {
        crm_xml_add(xml_node, name, s_value);
        crm_trace("dumped: %s=%s", name, s_value);

    } else {
        crm_trace("duplicate: %s=%s", name, s_value);
    }
}

/*!
 * \brief Set XML attribute based on hash table entry
 *
 * Suitable for \c g_hash_table_foreach(), this function takes a hash table key
 * and value, with an XML node passed as user data, and adds an XML attribute
 * with the specified name and value if it does not already exist.
 *
 * \param[in] key        Key of hash table entry
 * \param[in] value      Value of hash table entry
 * \param[in] user_data  XML node
 */
void
hash2field(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;

    if (crm_element_value(xml_node, name) == NULL) {
        crm_xml_add(xml_node, name, s_value);

    } else {
        crm_trace("duplicate: %s=%s", name, s_value);
    }
}

/*!
 * \brief Set XML attribute based on hash table entry, as meta-attribute name
 *
 * Suitable for \c g_hash_table_foreach(), this function takes a hash table key
 * and value, with an XML node passed as user data, and adds an XML attribute
 * with the meta-attribute version of the specified name and value if it does
 * not already exist and if the name does not appear to be cluster-internal.
 *
 * \param[in] key        Key of hash table entry
 * \param[in] value      Value of hash table entry
 * \param[in] user_data  XML node
 */
void
hash2metafield(gpointer key, gpointer value, gpointer user_data)
{
    char *crm_name = NULL;

    if (key == NULL || value == NULL) {
        return;
    }

    /* Filter out cluster-generated attributes that contain a '#' or ':'
     * (like fail-count and last-failure).
     */
    for (crm_name = key; *crm_name; ++crm_name) {
        if ((*crm_name == '#') || (*crm_name == ':')) {
            return;
        }
    }

    crm_name = crm_meta_name(key);
    hash2field(crm_name, value, user_data);
    free(crm_name);
}

// nvpair handling

/*!
 * \brief Create an XML name/value pair
 *
 * \param[in] parent  If not \c NULL, make new XML node a child of this one
 * \param[in] id      If not \c NULL, use this as ID (otherwise auto-generate)
 * \param[in] name    Name to use
 * \param[in] value   Value to use
 *
 * \return New XML object on success, \c NULL otherwise
 */
xmlNode *
crm_create_nvpair_xml(xmlNode *parent, const char *id, const char *name,
                      const char *value)
{
    xmlNode *nvp;

    /* id can be NULL so we auto-generate one, and name can be NULL if this
     * will be used to delete a name/value pair by ID, but both can't be NULL
     */
    CRM_CHECK(id || name, return NULL);

    nvp = create_xml_node(parent, XML_CIB_TAG_NVPAIR);
    CRM_CHECK(nvp, return NULL);

    if (id) {
        crm_xml_add(nvp, XML_ATTR_ID, id);
    } else {
        const char *parent_id = ID(parent);

        crm_xml_set_id(nvp, "%s-%s",
                       (parent_id? parent_id : XML_CIB_TAG_NVPAIR), name);
    }
    crm_xml_add(nvp, XML_NVPAIR_ATTR_NAME, name);
    crm_xml_add(nvp, XML_NVPAIR_ATTR_VALUE, value);
    return nvp;
}

/*!
 * \brief Add XML nvpair element based on hash table entry
 *
 * Suitable for \c g_hash_table_foreach(), this function takes a hash table key
 * and value, with an XML node passed as the user data, and adds an \c nvpair
 * XML element with the specified name and value.
 *
 * \param[in] key        Key of hash table entry
 * \param[in] value      Value of hash table entry
 * \param[in] user_data  XML node
 */
void
hash2nvpair(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;
    xmlNode *xml_node = user_data;

    crm_create_nvpair_xml(xml_node, name, name, s_value);
    crm_trace("dumped: name=%s value=%s", name, s_value);
}

/*!
 * \brief Retrieve XML attributes as a hash table
 *
 * Given an XML element, this will look for any \<attributes> element child,
 * creating a hash table of (newly allocated string) name/value pairs taken
 * first from the attributes element's NAME=VALUE XML attributes, and then
 * from any \<param name=NAME value=VALUE> children of attributes.
 *
 * \param[in]  XML node to parse
 *
 * \return Hash table with name/value pairs
 * \note It is the caller's responsibility to free the result using
 *       \c g_hash_table_destroy().
 */
GHashTable *
xml2list(xmlNode *parent)
{
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;
    xmlNode *nvpair_list = NULL;
    GHashTable *nvpair_hash = crm_str_table_new();

    CRM_CHECK(parent != NULL, return nvpair_hash);

    nvpair_list = find_xml_node(parent, XML_TAG_ATTRS, FALSE);
    if (nvpair_list == NULL) {
        crm_trace("No attributes in %s", crm_element_name(parent));
        crm_log_xml_trace(parent, "No attributes for resource op");
    }

    crm_log_xml_trace(nvpair_list, "Unpacking");

    for (pIter = pcmk__first_xml_attr(nvpair_list); pIter != NULL;
         pIter = pIter->next) {

        const char *p_name = (const char *)pIter->name;
        const char *p_value = pcmk__xml_attr_value(pIter);

        crm_trace("Added %s=%s", p_name, p_value);

        g_hash_table_insert(nvpair_hash, strdup(p_name), strdup(p_value));
    }

    for (child = __xml_first_child(nvpair_list); child != NULL;
         child = __xml_next(child)) {

        if (strcmp((const char *)child->name, XML_TAG_PARAM) == 0) {
            const char *key = crm_element_value(child, XML_NVPAIR_ATTR_NAME);
            const char *value = crm_element_value(child, XML_NVPAIR_ATTR_VALUE);

            crm_trace("Added %s=%s", key, value);
            if (key != NULL && value != NULL) {
                g_hash_table_insert(nvpair_hash, strdup(key), strdup(value));
            }
        }
    }

    return nvpair_hash;
}
