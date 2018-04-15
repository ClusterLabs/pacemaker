/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef CRM_COMMON_XML__H
#  define CRM_COMMON_XML__H

/**
 * \file
 * \brief Wrappers for and extensions to libxml2
 * \ingroup core
 */

#  include <stdio.h>
#  include <sys/types.h>
#  include <unistd.h>

#  include <stdlib.h>
#  include <errno.h>
#  include <fcntl.h>

#  include <crm/crm.h>

#  include <libxml/tree.h>
#  include <libxml/xpath.h>

/* Define compression parameters for IPC messages
 *
 * Compression costs a LOT, so we don't want to do it unless we're hitting
 * message limits. Currently, we use 128KB as the threshold, because higher
 * values don't play well with the heartbeat stack. With an earlier limit of
 * 10KB, compressing 184 of 1071 messages accounted for 23% of the total CPU
 * used by the cib.
 */
#  define CRM_BZ2_BLOCKS		4
#  define CRM_BZ2_WORK		20
#  define CRM_BZ2_THRESHOLD	128 * 1024

#  define XML_PARANOIA_CHECKS 0

gboolean add_message_xml(xmlNode * msg, const char *field, xmlNode * xml);
xmlNode *get_message_xml(xmlNode * msg, const char *field);
GHashTable *xml2list(xmlNode * parent);

xmlNode *crm_create_nvpair_xml(xmlNode *parent, const char *id,
                               const char *name, const char *value);

void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
void hash2field(gpointer key, gpointer value, gpointer user_data);
void hash2metafield(gpointer key, gpointer value, gpointer user_data);
void hash2smartfield(gpointer key, gpointer value, gpointer user_data);

xmlDoc *getDocPtr(xmlNode * node);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesn't work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything.
 *
 */
void copy_in_properties(xmlNode * target, xmlNode * src);
void expand_plus_plus(xmlNode * target, const char *name, const char *value);
void fix_plus_plus_recursive(xmlNode * target);

/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
xmlNode *create_xml_node(xmlNode * parent, const char *name);

/*
 * Make a copy of name and value and use the copied memory to create
 * an attribute for node.
 *
 * If node, name or value are NULL, nothing is done.
 *
 * If name or value are an empty string, nothing is done.
 *
 * Returns FALSE on failure and TRUE on success.
 *
 */
const char *crm_xml_add(xmlNode * node, const char *name, const char *value);

const char *crm_xml_replace(xmlNode * node, const char *name, const char *value);

const char *crm_xml_add_int(xmlNode * node, const char *name, int value);

/*!
 * \brief Add a boolean attribute to an XML object
 *
 * Add an attribute with the value XML_BOOLEAN_TRUE or XML_BOOLEAN_FALSE
 * as appropriate to an XML object.
 *
 * \param[in,out] node   XML object to add attribute to
 * \param[in]     name   Name of attribute to add
 * \param[in]     value  Boolean whose value will be tested
 *
 * \return Pointer to newly created XML attribute's content, or NULL on error
 */
static inline const char *
crm_xml_add_boolean(xmlNode *node, const char *name, gboolean value)
{
    return crm_xml_add(node, name, (value? "true" : "false"));
}

/*
 * Unlink the node and set its doc pointer to NULL so free_xml()
 * will act appropriately
 */
void unlink_xml_node(xmlNode * node);

/*
 *
 */
void purge_diff_markers(xmlNode * a_node);

/*
 * Returns a deep copy of src_node
 *
 */
xmlNode *copy_xml(xmlNode * src_node);

/*
 * Add a copy of xml_node to new_parent
 */
xmlNode *add_node_copy(xmlNode * new_parent, xmlNode * xml_node);

int add_node_nocopy(xmlNode * parent, const char *name, xmlNode * child);

/*
 * XML I/O Functions
 *
 * Whitespace between tags is discarded.
 */
xmlNode *filename2xml(const char *filename);

xmlNode *stdin2xml(void);

xmlNode *string2xml(const char *input);

int write_xml_fd(xmlNode * xml_node, const char *filename, int fd, gboolean compress);
int write_xml_file(xmlNode * xml_node, const char *filename, gboolean compress);

char *dump_xml_formatted(xmlNode * msg);
/* Also dump the text node with xml_log_option_text enabled */ 
char *dump_xml_formatted_with_text(xmlNode * msg);

char *dump_xml_unformatted(xmlNode * msg);

/*
 * Diff related Functions
 */
xmlNode *diff_xml_object(xmlNode * left, xmlNode * right, gboolean suppress);

xmlNode *subtract_xml_object(xmlNode * parent, xmlNode * left, xmlNode * right,
                             gboolean full, gboolean * changed, const char *marker);

gboolean can_prune_leaf(xmlNode * xml_node);

void print_xml_diff(FILE * where, xmlNode * diff);

gboolean apply_xml_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);

/*
 * Searching & Modifying
 */
xmlNode *find_xml_node(xmlNode * cib, const char *node_path, gboolean must_find);

xmlNode *find_entity(xmlNode * parent, const char *node_name, const char *id);

void xml_remove_prop(xmlNode * obj, const char *name);

gboolean replace_xml_child(xmlNode * parent, xmlNode * child, xmlNode * update,
                           gboolean delete_only);

gboolean update_xml_child(xmlNode * child, xmlNode * to_update);

int find_xml_children(xmlNode ** children, xmlNode * root,
                      const char *tag, const char *field, const char *value,
                      gboolean search_matches);

int crm_element_value_int(xmlNode * data, const char *name, int *dest);
char *crm_element_value_copy(xmlNode * data, const char *name);
int crm_element_value_const_int(const xmlNode * data, const char *name, int *dest);
const char *crm_element_value_const(const xmlNode * data, const char *name);
xmlNode *get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level);
xmlNode *get_xpath_object_relative(const char *xpath, xmlNode * xml_obj, int error_level);

static inline const char *
crm_element_name(xmlNode *xml)
{
    return xml? (const char *)(xml->name) : NULL;
}

const char *crm_element_value(xmlNode * data, const char *name);

/*!
 * \brief Copy an element from one XML object to another
 *
 * \param[in]     obj1     Source XML
 * \param[in,out] obj2     Destination XML
 * \param[in]     element  Name of element to copy
 *
 * \return Pointer to copied value (from source)
 */
static inline const char *
crm_copy_xml_element(xmlNode *obj1, xmlNode *obj2, const char *element)
{
    const char *value = crm_element_value(obj1, element);

    crm_xml_add(obj2, element, value);
    return value;
}

void xml_validate(const xmlNode * root);

gboolean xml_has_children(const xmlNode * root);

char *calculate_on_disk_digest(xmlNode * local_cib);
char *calculate_operation_digest(xmlNode * local_cib, const char *version);
char *calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                                     const char *version);

/* schema-related functions (from schemas.c) */
gboolean validate_xml(xmlNode * xml_blob, const char *validation, gboolean to_logs);
gboolean validate_xml_verbose(xmlNode * xml_blob);

/*!
 * \brief Update CIB XML to most recent schema version
 *
 * "Update" means either actively employ XSLT-based transformation(s)
 * (if intermediate product to transform valid per its declared schema version,
 * transformation available, proceeded successfully with a result valid per
 * expectated newer schema version), or just try to bump the marked validating
 * schema until all gradually rising schema versions attested or the first
 * such attempt subsequently fails to validate.   Which of the two styles will
 * be used depends on \p transform parameter (positive/negative, respectively).
 *
 * \param[in,out] xml_blob   XML tree representing CIB, may be swapped with
 *                           an "updated" one
 * \param[out]    best       The highest configuration version (per its index
 *                           in the global schemas table) it was possible to
 *                           reach during the update steps while ensuring
 *                           the validity of the result; if no validation
 *                           success was observed against possibly multiple
 *                           schemas, the value is less or equal the result
 *                           of <tt>get_schema_version</tt> applied on the
 *                           input \p xml_blob value (unless that function
 *                           maps it to -1, then 0 would be used instead)
 * \param[in]     max        When \p transform is positive, this allows to
 *                           set upper boundary schema (per its index in the
 *                           global schemas table) beyond which its forbidden
 *                           to update by the means of XSLT transformation
 * \param[in]     transform  Whether to employ XSLT-based transformation so
 *                           as allow overcoming possible incompatibilities
 *                           between major schema versions (see above)
 * \param[in]     to_logs    If true, output notable progress info to
 *                           internal log streams; if false, to stderr
 *
 * \return <tt>pcmk_ok</tt> if no non-recoverable error encountered (up to
 *         caller to evaluate if the update satisfies the requirements
 *         per returned \p best value), negative value carrying the reason
 *         otherwise
 */
int update_validation(xmlNode **xml_blob, int *best, int max,
                      gboolean transform, gboolean to_logs);

int get_schema_version(const char *name);
const char *get_schema_name(int version);
const char *xml_latest_schema(void);
gboolean cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs);

void crm_xml_init(void);
void crm_xml_cleanup(void);

static inline xmlNode *
__xml_first_child(xmlNode * parent)
{
    xmlNode *child = NULL;

    if (parent) {
        child = parent->children;
        while (child && child->type == XML_TEXT_NODE) {
            child = child->next;
        }
    }
    return child;
}

static inline xmlNode *
__xml_next(xmlNode * child)
{
    if (child) {
        child = child->next;
        while (child && child->type == XML_TEXT_NODE) {
            child = child->next;
        }
    }
    return child;
}

static inline xmlNode *
__xml_first_child_element(xmlNode * parent)
{
    xmlNode *child = NULL;

    if (parent) {
        child = parent->children;
    }

    while (child) {
        if(child->type == XML_ELEMENT_NODE) {
            return child;
        }
        child = child->next;
    }
    return NULL;
}

static inline xmlNode *
__xml_next_element(xmlNode * child)
{
    while (child) {
        child = child->next;
        if(child && child->type == XML_ELEMENT_NODE) {
            return child;
        }
    }
    return NULL;
}

void free_xml(xmlNode * child);

xmlNode *first_named_child(xmlNode * parent, const char *name);
xmlNode *crm_next_same_xml(xmlNode *sibling);

xmlNode *sorted_xml(xmlNode * input, xmlNode * parent, gboolean recursive);
xmlXPathObjectPtr xpath_search(xmlNode * xml_top, const char *path);
void crm_foreach_xpath_result(xmlNode *xml, const char *xpath,
                              void (*helper)(xmlNode*, void*), void *user_data);
xmlNode *expand_idref(xmlNode * input, xmlNode * top);

void freeXpathObject(xmlXPathObjectPtr xpathObj);
xmlNode *getXpathResult(xmlXPathObjectPtr xpathObj, int index);
void dedupXpathResults(xmlXPathObjectPtr xpathObj);

static inline int numXpathResults(xmlXPathObjectPtr xpathObj)
{
    if(xpathObj == NULL || xpathObj->nodesetval == NULL) {
        return 0;
    }
    return xpathObj->nodesetval->nodeNr;
}

bool xml_acl_enabled(xmlNode *xml);
void xml_acl_disable(xmlNode *xml);
bool xml_acl_denied(xmlNode *xml); /* Part or all of a change was rejected */
bool xml_acl_filtered_copy(const char *user, xmlNode* acl_source, xmlNode *xml, xmlNode ** result);

bool xml_tracking_changes(xmlNode * xml);
bool xml_document_dirty(xmlNode *xml);
void xml_track_changes(xmlNode * xml, const char *user, xmlNode *acl_source, bool enforce_acls);
void xml_calculate_changes(xmlNode * old, xmlNode * new); /* For comparing two documents after the fact */
void xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml);
void xml_accept_changes(xmlNode * xml);
void xml_log_changes(uint8_t level, const char *function, xmlNode *xml);
void xml_log_patchset(uint8_t level, const char *function, xmlNode *xml);
bool xml_patch_versions(xmlNode *patchset, int add[3], int del[3]);

xmlNode *xml_create_patchset(
    int format, xmlNode *source, xmlNode *target, bool *config, bool manage_version);
int xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version);

void patchset_process_digest(xmlNode *patch, xmlNode *source, xmlNode *target, bool with_digest);

void save_xml_to_file(xmlNode * xml, const char *desc, const char *filename);
char *xml_get_path(xmlNode *xml);

char * crm_xml_escape(const char *text);
void crm_xml_sanitize_id(char *id);
void crm_xml_set_id(xmlNode *xml, const char *format, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));

/*!
 * \brief xmlNode destructor which can be used in glib collections
 */
void crm_destroy_xml(gpointer data);

#endif
