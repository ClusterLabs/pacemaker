/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdint.h>         // UINT32_MAX
#include <inttypes.h>       // PRIu32
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include "crmcommon_private.h"

/*
 * This file isolates handling of various kinds of name/value pairs:
 *
 * - pcmk_nvpair_t data type
 * - name=value strings
 * - XML nvpair elements (<nvpair id=ID name=NAME value=VALUE>)
 * - Instance attributes and meta-attributes (for resources and actions)
 */

// pcmk_nvpair_t handling

/*!
 * \internal
 * \brief Allocate a new name/value pair
 *
 * \param[in] name   New name (required)
 * \param[in] value  New value
 *
 * \return Newly allocated name/value pair
 * \note The caller is responsible for freeing the result with
 *       \c pcmk__free_nvpair().
 */
static pcmk_nvpair_t *
pcmk__new_nvpair(const char *name, const char *value)
{
    pcmk_nvpair_t *nvpair = NULL;

    pcmk__assert(name);

    nvpair = pcmk__assert_alloc(1, sizeof(pcmk_nvpair_t));

    nvpair->name = pcmk__str_copy(name);
    nvpair->value = pcmk__str_copy(value);
    return nvpair;
}

/*!
 * \internal
 * \brief Free a name/value pair
 *
 * \param[in,out] nvpair  Name/value pair to free
 */
static void
pcmk__free_nvpair(gpointer data)
{
    if (data) {
        pcmk_nvpair_t *nvpair = data;

        free(nvpair->name);
        free(nvpair->value);
        free(nvpair);
    }
}

/*!
 * \brief Prepend a name/value pair to a list
 *
 * \param[in,out] nvpairs  List to modify
 * \param[in]     name     New entry's name
 * \param[in]     value    New entry's value
 *
 * \return New head of list
 * \note The caller is responsible for freeing the list with
 *       \c pcmk_free_nvpairs().
 */
GSList *
pcmk_prepend_nvpair(GSList *nvpairs, const char *name, const char *value)
{
    return g_slist_prepend(nvpairs, pcmk__new_nvpair(name, value));
}

/*!
 * \brief Free a list of name/value pairs
 *
 * \param[in,out] list  List to free
 */
void
pcmk_free_nvpairs(GSList *nvpairs)
{
    g_slist_free_full(nvpairs, pcmk__free_nvpair);
}


// name=value string handling

/*!
 * \internal
 * \brief Extract the name and value from an input string formatted as "name=value".
 * If unable to extract them, they are returned as NULL.
 *
 * \param[in]  input The input string, likely from the command line
 * \param[out] name  Everything before the first '=' in the input string
 * \param[out] value Everything after the first '=' in the input string
 *
 * \return 2 if both name and value could be extracted, 1 if only one could, and
 *         and error code otherwise
 */
int
pcmk__scan_nvpair(const char *input, char **name, char **value)
{
#ifdef HAVE_SSCANF_M
    *name = NULL;
    *value = NULL;
    if (sscanf(input, "%m[^=]=%m[^\n]", name, value) <= 0) {
        return -pcmk_err_bad_nvpair;
    }
#else
    char *sep = NULL;
    *name = NULL;
    *value = NULL;

    sep = strstr(optarg, "=");
    if (sep == NULL) {
        return -pcmk_err_bad_nvpair;
    }

    *name = strndup(input, sep-input);

    if (*name == NULL) {
        return -ENOMEM;
    }

    /* If the last char in optarg is =, the user gave no
     * value for the option.  Leave it as NULL.
     */
    if (*(sep+1) != '\0') {
        *value = strdup(sep+1);

        if (*value == NULL) {
            return -ENOMEM;
        }
    }
#endif

    if (*name != NULL && *value != NULL) {
        return 2;
    } else if (*name != NULL || *value != NULL) {
        return 1;
    } else {
        return -pcmk_err_bad_nvpair;
    }
}

/*!
 * \internal
 * \brief Format a name/value pair.
 *
 * Units can optionally be provided for the value.  Note that unlike most
 * formatting functions, this one returns the formatted string.  It is
 * assumed that the most common use of this function will be to build up
 * a string to be output as part of other functions.
 *
 * \note The caller is responsible for freeing the return value after use.
 *
 * \param[in]     name  The name of the nvpair.
 * \param[in]     value The value of the nvpair.
 * \param[in]     units Optional units for the value, or NULL.
 *
 * \return Newly allocated string with name/value pair
 */
char *
pcmk__format_nvpair(const char *name, const char *value, const char *units)
{
    return crm_strdup_printf("%s=\"%s%s\"", name, value, units ? units : "");
}

/*!
 * \brief Safely add hash table entry to XML as attribute or name-value pair
 *
 * Suitable for \c g_hash_table_foreach(), this function takes a hash table key
 * and value, with an XML node passed as user data, and adds an XML attribute
 * with the specified name and value if it does not already exist. If the key
 * name starts with a digit, then it's not a valid XML attribute name. In that
 * case, this will instead add a <tt><param name=NAME value=VALUE/></tt> child
 * to the XML.
 *
 * \param[in]     key        Key of hash table entry
 * \param[in]     value      Value of hash table entry
 * \param[in,out] user_data  XML node
 */
void
hash2smartfield(gpointer key, gpointer value, gpointer user_data)
{
    /* @TODO Generate PCMK__XE_PARAM nodes for all keys that aren't valid XML
     * attribute names (not just those that start with digits), or possibly for
     * all keys to simplify parsing.
     *
     * Consider either deprecating as public API or exposing PCMK__XE_PARAM.
     * PCMK__XE_PARAM is currently private because it doesn't appear in any
     * output that Pacemaker generates.
     */
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;

    if (isdigit(name[0])) {
        xmlNode *tmp = pcmk__xe_create(xml_node, PCMK__XE_PARAM);

        crm_xml_add(tmp, PCMK_XA_NAME, name);
        crm_xml_add(tmp, PCMK_XA_VALUE, s_value);

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
 * \param[in]     key        Key of hash table entry
 * \param[in]     value      Value of hash table entry
 * \param[in,out] user_data  XML node
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
 * \param[in]     key        Key of hash table entry
 * \param[in]     value      Value of hash table entry
 * \param[in,out] user_data  XML node
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
 * \param[in,out] parent  If not \c NULL, make new XML node a child of this one
 * \param[in]     id      Set this as XML ID (or NULL to auto-generate)
 * \param[in]     name    Name to use
 * \param[in]     value   Value to use
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

    nvp = pcmk__xe_create(parent, PCMK_XE_NVPAIR);

    if (id) {
        crm_xml_add(nvp, PCMK_XA_ID, id);
    } else {
        pcmk__xe_set_id(nvp, "%s-%s",
                        pcmk__s(pcmk__xe_id(parent), PCMK_XE_NVPAIR), name);
    }
    crm_xml_add(nvp, PCMK_XA_NAME, name);
    crm_xml_add(nvp, PCMK_XA_VALUE, value);
    return nvp;
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
xml2list(const xmlNode *parent)
{
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;
    xmlNode *nvpair_list = NULL;
    GHashTable *nvpair_hash = pcmk__strkey_table(free, free);

    CRM_CHECK(parent != NULL, return nvpair_hash);

    nvpair_list = pcmk__xe_first_child(parent, PCMK__XE_ATTRIBUTES, NULL, NULL);
    if (nvpair_list == NULL) {
        crm_trace("No attributes in %s", parent->name);
        crm_log_xml_trace(parent, "No attributes for resource op");
    }

    crm_log_xml_trace(nvpair_list, "Unpacking");

    for (pIter = pcmk__xe_first_attr(nvpair_list); pIter != NULL;
         pIter = pIter->next) {

        const char *p_name = (const char *)pIter->name;
        const char *p_value = pcmk__xml_attr_value(pIter);

        crm_trace("Added %s=%s", p_name, p_value);

        pcmk__insert_dup(nvpair_hash, p_name, p_value);
    }

    for (child = pcmk__xe_first_child(nvpair_list, PCMK__XE_PARAM, NULL, NULL);
         child != NULL; child = pcmk__xe_next_same(child)) {

        const char *key = crm_element_value(child, PCMK_XA_NAME);
        const char *value = crm_element_value(child, PCMK_XA_VALUE);

        crm_trace("Added %s=%s", key, value);
        if (key != NULL && value != NULL) {
            pcmk__insert_dup(nvpair_hash, key, value);
        }
    }

    return nvpair_hash;
}

// Meta-attribute handling

/*!
 * \brief Get the environment variable equivalent of a meta-attribute name
 *
 * \param[in] attr_name  Name of meta-attribute
 *
 * \return Newly allocated string for \p attr_name with "CRM_meta_" prefix and
 *         underbars instead of dashes
 * \note This asserts on an invalid argument or memory allocation error, so
 *       callers can assume the result is non-NULL. The caller is responsible
 *       for freeing the result using free().
 */
char *
crm_meta_name(const char *attr_name)
{
    char *env_name = NULL;

    pcmk__assert(!pcmk__str_empty(attr_name));

    env_name = crm_strdup_printf(CRM_META "_%s", attr_name);
    for (char *c = env_name; *c != '\0'; ++c) {
        if (*c == '-') {
            *c = '_';
        }
    }
    return env_name;
}

/*!
 * \brief Get the value of a meta-attribute
 *
 * Get the value of a meta-attribute from a hash table whose keys are
 * meta-attribute environment variable names (as crm_meta_name() would
 * create, like pcmk__graph_action_t:params, not pcmk_resource_t:meta).
 *
 * \param[in] meta       Hash table of meta-attributes
 * \param[in] attr_name  Name of meta-attribute to get
 *
 * \return Value of given meta-attribute
 */
const char *
crm_meta_value(GHashTable *meta, const char *attr_name)
{
    if ((meta != NULL) && (attr_name != NULL)) {
        char *key = crm_meta_name(attr_name);
        const char *value = g_hash_table_lookup(meta, key);

        free(key);
        return value;
    }
    return NULL;
}

gint
pcmk__cmp_nvpair_blocks(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const xmlNode *pair_a = a;
    const xmlNode *pair_b = b;
    const pcmk__nvpair_unpack_t *unpack_data = user_data;

    int score_a = 0;
    int score_b = 0;
    int rc = pcmk_rc_ok;

    /* If we're overwriting values, we want to process blocks from
     * lowest priority to highest, so higher-priority values overwrite
     * lower-priority ones. If we're not overwriting values, we want to process
     * from highest priority to lowest.
     */
    const gint a_is_higher = unpack_data->overwrite? 1 : -1;
    const gint b_is_higher = -a_is_higher;

    if (a == NULL && b == NULL) {
        return 0;
    } else if (a == NULL) {
        return b_is_higher;
    } else if (b == NULL) {
        return a_is_higher;
    }

    if (pcmk__str_eq(pcmk__xe_id(pair_a), unpack_data->first_id,
                     pcmk__str_none)) {
        return a_is_higher;

    } else if (pcmk__str_eq(pcmk__xe_id(pair_b), unpack_data->first_id,
                            pcmk__str_none)) {
        return b_is_higher;
    }

    rc = pcmk__xe_get_score(pair_a, PCMK_XA_SCORE, &score_a, 0);
    if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
        pcmk__config_warn("Using 0 as %s score because '%s' "
                          "is not a valid score: %s",
                          pcmk__xe_id(pair_a),
                          crm_element_value(pair_a, PCMK_XA_SCORE),
                          pcmk_rc_str(rc));
    }

    rc = pcmk__xe_get_score(pair_b, PCMK_XA_SCORE, &score_b, 0);
    if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
        pcmk__config_warn("Using 0 as %s score because '%s' "
                          "is not a valid score: %s",
                          pcmk__xe_id(pair_b),
                          crm_element_value(pair_b, PCMK_XA_SCORE),
                          pcmk_rc_str(rc));
    }

    if (score_a < score_b) {
        return b_is_higher;
    } else if (score_a > score_b) {
        return a_is_higher;
    }
    return 0;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/nvpair_compat.h>

static gint
pcmk__compare_nvpair(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const pcmk_nvpair_t *pair_a = a;
    const pcmk_nvpair_t *pair_b = b;

    pcmk__assert((pair_a != NULL) && (pair_a->name != NULL)
                 && (pair_b != NULL) && (pair_b->name != NULL));

    rc = strcmp(pair_a->name, pair_b->name);
    if (rc < 0) {
        return -1;
    } else if (rc > 0) {
        return 1;
    }
    return 0;
}

GSList *
pcmk_sort_nvpairs(GSList *list)
{
    return g_slist_sort(list, pcmk__compare_nvpair);
}

GSList *
pcmk_xml_attrs2nvpairs(const xmlNode *xml)
{
    GSList *result = NULL;

    for (xmlAttrPtr iter = pcmk__xe_first_attr(xml); iter != NULL;
         iter = iter->next) {

        result = pcmk_prepend_nvpair(result,
                                     (const char *) iter->name,
                                     (const char *) pcmk__xml_attr_value(iter));
    }
    return result;
}

static void
pcmk__nvpair_add_xml_attr(gpointer data, gpointer user_data)
{
    pcmk_nvpair_t *pair = data;
    xmlNode *parent = user_data;

    crm_xml_add(parent, pair->name, pair->value);
}

void
pcmk_nvpairs2xml_attrs(GSList *list, xmlNode *xml)
{
    g_slist_foreach(list, pcmk__nvpair_add_xml_attr, xml);
}

void
hash2nvpair(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;
    xmlNode *xml_node = user_data;

    crm_create_nvpair_xml(xml_node, name, name, s_value);
    crm_trace("dumped: name=%s value=%s", name, s_value);
}

// LCOV_EXCL_STOP
// End deprecated API
