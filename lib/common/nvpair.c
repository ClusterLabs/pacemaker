/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>         // UINT32_MAX
#include <inttypes.h>       // PRIu32
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>           // gchar, gint, etc.
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
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
 * \brief Extract the name and value from a string formatted as "name=value"
 *
 * \param[in]  input  Input string, likely from the command line
 * \param[out] name   Everything before the first \c '=' in the input string
 * \param[out] value  Everything after the first \c '=' in the input string
 *
 * \return Standard Pacemaker return code
 *
 * \note On success, the caller is responsible for freeing \p *name and
 *       \p *value using \c g_free(). On failure, nothing is allocated.
 */
int
pcmk__scan_nvpair(const gchar *input, gchar **name, gchar **value)
{
    /* @COMPAT Consider rejecting leading (and possibly trailing) whitespace in
     * value and stripping outer quotes from value (for example,
     * using g_shell_unquote()). This would affect stonith_admin and
     * crm_resource and would simplify remoted_spawn_pidone()'s helpers.
     */
    gchar **nvpair = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert(input != NULL);
    pcmk__assert((name != NULL) && (*name == NULL));
    pcmk__assert((value != NULL) && (*value == NULL));

    nvpair = g_strsplit(input, "=", 2);

    // Check whether nvpair is well-formed: two tokens and non-empty name
    if ((g_strv_length(nvpair) != 2) || pcmk__str_empty(nvpair[0])) {
        rc = pcmk_rc_bad_nvpair;
        goto done;
    }

    // name and value take ownership of the strings in nvpair
    *name = nvpair[0];
    *value = nvpair[1];
    nvpair[0] = NULL;
    nvpair[1] = NULL;

done:
    g_strfreev(nvpair);
    return rc;
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
    return pcmk__assert_asprintf("%s=\"%s%s\"", name, value,
                                 pcmk__s(units, ""));
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

        pcmk__xe_set(tmp, PCMK_XA_NAME, name);
        pcmk__xe_set(tmp, PCMK_XA_VALUE, s_value);

    } else if (pcmk__xe_get(xml_node, name) == NULL) {
        pcmk__xe_set(xml_node, name, s_value);
        pcmk__trace("dumped: %s=%s", name, s_value);

    } else {
        pcmk__trace("duplicate: %s=%s", name, s_value);
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

    if (pcmk__xe_get(xml_node, name) == NULL) {
        pcmk__xe_set(xml_node, name, s_value);

    } else {
        pcmk__trace("duplicate: %s=%s", name, s_value);
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
        pcmk__xe_set(nvp, PCMK_XA_ID, id);
    } else {
        pcmk__xe_set_id(nvp, "%s-%s",
                        pcmk__s(pcmk__xe_id(parent), PCMK_XE_NVPAIR), name);
    }
    pcmk__xe_set(nvp, PCMK_XA_NAME, name);
    pcmk__xe_set(nvp, PCMK_XA_VALUE, value);
    return nvp;
}

/*!
 * \internal
 * \brief Add an attribute to a hash table of name-value pairs
 *
 * Insert a copy of the attribute's name as the key and a copy of the
 * attribute's value as the value.
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  Name-value pair table (<tt>GHashTable *</tt>)
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 */
static bool
add_attr_to_nvpair_table(const xmlAttr *attr, void *user_data)
{
    GHashTable *table = user_data;
    const char *name = (const char *) attr->name;
    const char *value = pcmk__xml_attr_value(attr);

    pcmk__insert_dup(table, name, value);
    return true;
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
    xmlNode *nvpair_list = NULL;
    GHashTable *nvpair_hash = pcmk__strkey_table(free, free);

    CRM_CHECK(parent != NULL, return nvpair_hash);

    nvpair_list = pcmk__xe_first_child(parent, PCMK__XE_ATTRIBUTES, NULL, NULL);
    if (nvpair_list == NULL) {
        pcmk__trace("No attributes in %s", parent->name);
        pcmk__log_xml_trace(parent, "No attributes for resource op");
    }

    pcmk__log_xml_trace(nvpair_list, "Unpacking");

    pcmk__xe_foreach_const_attr(nvpair_list, add_attr_to_nvpair_table,
                                nvpair_hash);

    for (child = pcmk__xe_first_child(nvpair_list, PCMK__XE_PARAM, NULL, NULL);
         child != NULL; child = pcmk__xe_next(child, PCMK__XE_PARAM)) {

        const char *key = pcmk__xe_get(child, PCMK_XA_NAME);
        const char *value = pcmk__xe_get(child, PCMK_XA_VALUE);

        pcmk__trace("Added %s=%s", key, value);
        if (key != NULL && value != NULL) {
            pcmk__insert_dup(nvpair_hash, key, value);
        }
    }

    return nvpair_hash;
}

/*!
 * \internal
 * \brief Unpack a single nvpair XML element into a hash table
 *
 * \param[in]     nvpair    XML nvpair element to unpack
 * \param[in,out] userdata  Unpack data
 *
 * \return pcmk_rc_ok (to always proceed to next nvpair)
 */
static int
unpack_nvpair(xmlNode *nvpair, void *userdata)
{
    pcmk__nvpair_unpack_t *unpack_data = userdata;

    const char *name = NULL;
    const char *value = NULL;
    const char *old_value = NULL;
    const xmlNode *ref_nvpair = pcmk__xe_resolve_idref(nvpair, NULL);

    if (ref_nvpair == NULL) {
        /* Not possible with schema validation enabled (error already
         * logged)
         */
        return pcmk_rc_ok;
    }

    name = pcmk__xe_get(ref_nvpair, PCMK_XA_NAME);
    value = pcmk__xe_get(ref_nvpair, PCMK_XA_VALUE);
    if ((name == NULL) || (value == NULL)) {
        return pcmk_rc_ok; // Not possible with schema validation enabled
    }

    old_value = g_hash_table_lookup(unpack_data->values, name);

    if (pcmk__str_eq(value, "#default", pcmk__str_casei)) {
        // @COMPAT Deprecated since 2.1.8
        pcmk__config_warn("Support for setting meta-attributes (such as "
                          "%s) to the explicit value '#default' is "
                          "deprecated and will be removed in a future "
                          "release", name);
        if (old_value != NULL) {
            g_hash_table_remove(unpack_data->values, name);
        }

    } else if ((old_value == NULL) || unpack_data->overwrite) {
        pcmk__trace("Setting %s=\"%s\" (was %s)", name, value,
                    pcmk__s(old_value, "unset"));
        pcmk__insert_dup(unpack_data->values, name, value);
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Unpack an XML block of nvpair elements into a hash table,
 *        evaluated for any rule
 *
 * \param[in]     data       XML block to unpack
 * \param[in,out] user_data  Unpack data
 *
 * \note This is suitable for use as a GList iterator function
 */
void
pcmk__unpack_nvpair_block(gpointer data, gpointer user_data)
{
    xmlNode *pair = data;
    pcmk__nvpair_unpack_t *unpack_data = user_data;

    xmlNode *rule_xml = NULL;

    pcmk__assert((pair != NULL) && (unpack_data != NULL)
                 && (unpack_data->values != NULL));

    rule_xml = pcmk__xe_first_child(pair, PCMK_XE_RULE, NULL, NULL);
    if ((rule_xml != NULL)
        && (pcmk_evaluate_rule(rule_xml, &(unpack_data->rule_input),
                               unpack_data->next_change) != pcmk_rc_ok)) {
        return;
    }

    pcmk__trace("Adding name/value pairs from %s %s overwrite",
                pcmk__xe_id(pair),
                (unpack_data->overwrite? "with" : "without"));
    if (pcmk__xe_is(pair->children, PCMK__XE_ATTRIBUTES)) {
        pair = pair->children;
    }
    pcmk__xe_foreach_child(pair, PCMK_XE_NVPAIR, unpack_nvpair, unpack_data);
}

/*!
 * \brief Unpack nvpair blocks contained by an XML element into a hash table,
 *        evaluated for any rules
 *
 * \param[in]  xml           XML element containing blocks of nvpair elements
 * \param[in]  element_name  If not NULL, only unpack blocks of this element
 * \param[in]  first_id      If not NULL, process block with this ID first
 * \param[in]  rule_input    Values used to evaluate rule criteria
 * \param[out] values        Where to store extracted name/value pairs
 * \param[out] next_change   If not NULL, set to when evaluation will next
 *                           change, if sooner than its current value
 */
void
pcmk_unpack_nvpair_blocks(const xmlNode *xml, const char *element_name,
                          const char *first_id,
                          const pcmk_rule_input_t *rule_input,
                          GHashTable *values, crm_time_t *next_change)
{
    GList *blocks = pcmk__xe_dereference_children(xml, element_name);

    if (blocks != NULL) {
        pcmk__nvpair_unpack_t data = {
            .values = values,
            .first_id = first_id,
            .rule_input = {
                .now = NULL,
            },
            .overwrite = false,
            .next_change = next_change,
        };

        if (rule_input != NULL) {
            data.rule_input = *rule_input;
        }
        blocks = g_list_sort_with_data(blocks, pcmk__cmp_nvpair_blocks, &data);
        g_list_foreach(blocks, pcmk__unpack_nvpair_block, &data);
        g_list_free(blocks);
    }
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

    env_name = pcmk__assert_asprintf(CRM_META "_%s", attr_name);
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

/*!
 * \internal
 * \brief Compare processing order of two XML blocks of name/value pairs
 *
 * \param[in] a          First XML block to compare
 * \param[in] b          Second XML block to compare
 * \param[in] user_data  pcmk__nvpair_unpack_t with first_id (whether a
 *                       particular XML ID should have priority) and overwrite
 *                       (whether later-processed blocks will overwrite values
 *                       from earlier ones) set as desired
 *
 * \return Standard comparison return code (a negative value if \p a should sort
 *         first, a positive value if \p b should sort first, and 0 if they
 *         should sort equally)
 * \note This is suitable for use as a GList sorting function.
 */
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
    const gint a_is_higher = ((unpack_data != NULL)
                              && unpack_data->overwrite)? 1 : -1;
    const gint b_is_higher = -a_is_higher;

    /* NULL values have lowest priority, regardless of the other's score
     * (it won't be possible in practice anyway, this is just a failsafe)
     */
    if (a == NULL) {
        return (b == NULL)? 0 : b_is_higher;

    } else if (b == NULL) {
        return a_is_higher;
    }

    /* A particular XML ID can be specified as having highest priority
     * regardless of score (schema validation, if enabled, prevents two blocks
     * from having the same ID, so we can ignore handling that case
     * specifically)
     */
    if ((unpack_data != NULL) && (unpack_data->first_id != NULL)) {
        if (pcmk__str_eq(pcmk__xe_id(pair_a), unpack_data->first_id,
                         pcmk__str_none)) {
            return a_is_higher;

        } else if (pcmk__str_eq(pcmk__xe_id(pair_b), unpack_data->first_id,
                                pcmk__str_none)) {
            return b_is_higher;
        }
    }

    // Otherwise, check the scores

    rc = pcmk__xe_get_score(pair_a, PCMK_XA_SCORE, &score_a, 0);
    if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
        pcmk__config_warn("Using 0 as %s score because '%s' "
                          "is not a valid score: %s",
                          pcmk__xe_id(pair_a),
                          pcmk__xe_get(pair_a, PCMK_XA_SCORE), pcmk_rc_str(rc));
    }

    rc = pcmk__xe_get_score(pair_b, PCMK_XA_SCORE, &score_b, 0);
    if (rc != pcmk_rc_ok) { // Not possible with schema validation enabled
        pcmk__config_warn("Using 0 as %s score because '%s' "
                          "is not a valid score: %s",
                          pcmk__xe_id(pair_b),
                          pcmk__xe_get(pair_b, PCMK_XA_SCORE), pcmk_rc_str(rc));
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

    pcmk__xe_set(parent, pair->name, pair->value);
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
    pcmk__trace("dumped: name=%s value=%s", name, s_value);
}

// LCOV_EXCL_STOP
// End deprecated API
