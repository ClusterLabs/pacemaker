/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
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

/* Encryption costs a LOT, don't do it unless we're hitting message limits
 *
 * For now, use 256k as the lower size, which means we can have 4 big data fields
 *  before we hit heartbeat's message limit
 *
 * The previous limit was 10k, compressing 184 of 1071 messages accounted for 23%
 *  of the total CPU used by the cib
 */
#  define CRM_BZ2_BLOCKS		4
#  define CRM_BZ2_WORK		20
#  define CRM_BZ2_THRESHOLD	128 * 1024

#  define XML_PARANOIA_CHECKS 0

gboolean add_message_xml(xmlNode * msg, const char *field, xmlNode * xml);
xmlNode *get_message_xml(xmlNode * msg, const char *field);
GHashTable *xml2list(xmlNode * parent);

void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
void hash2field(gpointer key, gpointer value, gpointer user_data);
void hash2metafield(gpointer key, gpointer value, gpointer user_data);
void hash2smartfield(gpointer key, gpointer value, gpointer user_data);

xmlDoc *getDocPtr(xmlNode * node);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesnt work the way *I* would expect it to.
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

char *dump_xml_unformatted(xmlNode * msg);

/*
 * Diff related Functions
 */
xmlNode *diff_xml_object(xmlNode * left, xmlNode * right, gboolean suppress);

xmlNode *subtract_xml_object(xmlNode * parent, xmlNode * left, xmlNode * right,
                             gboolean full, gboolean * changed, const char *marker);

gboolean can_prune_leaf(xmlNode * xml_node);

void print_xml_diff(FILE * where, xmlNode * diff);
void log_xml_diff(uint8_t log_level, xmlNode * diff, const char *function);

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

#  define crm_element_name(xml) (xml)?(const char *)(xml)->name:NULL

const char *crm_element_value(xmlNode * data, const char *name);

void xml_validate(const xmlNode * root);

gboolean xml_has_children(const xmlNode * root);

char *calculate_on_disk_digest(xmlNode * local_cib);
char *calculate_operation_digest(xmlNode * local_cib, const char *version);
char *calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                                     const char *version);

gboolean validate_xml(xmlNode * xml_blob, const char *validation, gboolean to_logs);
gboolean validate_xml_verbose(xmlNode * xml_blob);
int update_validation(xmlNode ** xml_blob, int *best, gboolean transform, gboolean to_logs);
int get_schema_version(const char *name);
const char *get_schema_name(int version);

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

void free_xml(xmlNode * child);

xmlNode *first_named_child(xmlNode * parent, const char *name);

xmlNode *sorted_xml(xmlNode * input, xmlNode * parent, gboolean recursive);
xmlXPathObjectPtr xpath_search(xmlNode * xml_top, const char *path);
gboolean cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs);
xmlNode *expand_idref(xmlNode * input, xmlNode * top);

void freeXpathObject(xmlXPathObjectPtr xpathObj);
xmlNode *getXpathResult(xmlXPathObjectPtr xpathObj, int index);

static inline int numXpathResults(xmlXPathObjectPtr xpathObj)
{
    if(xpathObj == NULL || xpathObj->nodesetval == NULL) {
        return 0;
    }
    return xpathObj->nodesetval->nodeNr;
}

void xml_track_changes(xmlNode * xml);
void xml_accept_changes(xmlNode * xml);


#endif
