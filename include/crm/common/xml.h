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

#  include <stdio.h>
#  include <sys/types.h>
#  include <unistd.h>

#  include <stdlib.h>
#  include <errno.h>
#  include <fcntl.h>

#  include <crm/crm.h>
#  include <ha_msg.h>

#  include <libxml/tree.h>
#  include <libxml/xpath.h>
typedef xmlNode crm_data_t;

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

extern gboolean add_message_xml(xmlNode * msg, const char *field, xmlNode * xml);
extern xmlNode *get_message_xml(xmlNode * msg, const char *field);
extern GHashTable *xml2list(xmlNode * parent);

#  if CRM_DEPRECATED_SINCE_2_0_3
extern GHashTable *xml2list_202(xmlNode * parent);
#  endif
extern void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
extern void hash2field(gpointer key, gpointer value, gpointer user_data);
extern void hash2metafield(gpointer key, gpointer value, gpointer user_data);
extern void hash2smartfield(gpointer key, gpointer value, gpointer user_data);

extern xmlDoc *getDocPtr(xmlNode *node);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesnt work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything. 
 *
 */
extern void copy_in_properties(xmlNode * target, xmlNode * src);
extern void expand_plus_plus(xmlNode * target, const char *name, const char *value);
extern void fix_plus_plus_recursive(xmlNode * target);

void free_xml_from_parent(xmlNode * parent, xmlNode * a_node);

#  define zap_xml_from_parent(parent, xml_obj) free_xml_from_parent(parent, xml_obj); xml_obj = NULL

/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
extern xmlNode *create_xml_node(xmlNode * parent, const char *name);

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
extern const char *crm_xml_add(xmlNode * node, const char *name, const char *value);

extern const char *crm_xml_replace(xmlNode * node, const char *name, const char *value);

extern const char *crm_xml_add_int(xmlNode * node, const char *name, int value);

/*
 * Unlink the node and set its doc pointer to NULL so free_xml()
 * will act appropriately
 */
extern void unlink_xml_node(xmlNode * node);

/*
 * 
 */
extern void purge_diff_markers(xmlNode * a_node);

/*
 * Returns a deep copy of src_node
 *
 */
extern xmlNode *copy_xml(xmlNode * src_node);

/*
 * Add a copy of xml_node to new_parent
 */
extern xmlNode *add_node_copy(xmlNode * new_parent, xmlNode * xml_node);

extern int add_node_nocopy(xmlNode * parent, const char *name, xmlNode * child);

/*
 * XML I/O Functions
 *
 * Whitespace between tags is discarded.
 */
extern xmlNode *filename2xml(const char *filename);

extern xmlNode *stdin2xml(void);

extern xmlNode *string2xml(const char *input);

extern int write_xml_file(xmlNode * xml_node, const char *filename, gboolean compress);

extern char *dump_xml_formatted(xmlNode * msg);

extern char *dump_xml_unformatted(xmlNode * msg);

/*
 * Diff related Functions
 */
extern xmlNode *diff_xml_object(xmlNode * left, xmlNode * right, gboolean suppress);

extern xmlNode *subtract_xml_object(xmlNode * parent, xmlNode * left, xmlNode * right,
                                    gboolean full, const char *marker);

extern gboolean can_prune_leaf(xmlNode * xml_node);

extern void print_xml_diff(FILE * where, xmlNode * diff);
extern void log_xml_diff(unsigned int log_level, xmlNode * diff, const char *function);

extern gboolean apply_xml_diff(xmlNode * old, xmlNode * diff, xmlNode ** new);

/*
 * Searching & Modifying
 */
extern xmlNode *find_xml_node(xmlNode * cib, const char *node_path, gboolean must_find);

extern xmlNode *find_entity(xmlNode * parent, const char *node_name, const char *id);

extern void xml_remove_prop(xmlNode * obj, const char *name);

extern gboolean replace_xml_child(xmlNode * parent, xmlNode * child, xmlNode * update,
                                  gboolean delete_only);

extern gboolean update_xml_child(xmlNode * child, xmlNode * to_update);

extern int find_xml_children(xmlNode ** children, xmlNode * root,
                             const char *tag, const char *field, const char *value,
                             gboolean search_matches);

extern int crm_element_value_int(xmlNode * data, const char *name, int *dest);
extern char *crm_element_value_copy(xmlNode * data, const char *name);
extern int crm_element_value_const_int(const xmlNode *data, const char *name, int *dest);
extern const char *crm_element_value_const(const xmlNode * data, const char *name);
extern xmlNode *get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level);
extern xmlNode *get_xpath_object_relative(const char *xpath, xmlNode * xml_obj, int error_level);

#  define crm_element_name(xml) (xml)?(const char *)(xml)->name:NULL

extern const char *crm_element_value(xmlNode * data, const char *name);

extern void xml_validate(const xmlNode * root);

extern gboolean xml_has_children(const xmlNode * root);

/* For ABI compatability with version < 1.1.4 */
extern char *calculate_xml_digest(xmlNode * local_cib, gboolean sort, gboolean do_filter);

extern char *calculate_on_disk_digest(xmlNode * local_cib);
extern char *calculate_operation_digest(xmlNode * local_cib, const char *version);
extern char *calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                                            const char *version);

extern gboolean validate_xml(xmlNode * xml_blob, const char *validation, gboolean to_logs);
extern gboolean validate_xml_verbose(xmlNode * xml_blob);
extern int update_validation(xmlNode ** xml_blob, int *best, gboolean transform, gboolean to_logs);
extern int get_schema_version(const char *name);
extern const char *get_schema_name(int version);
extern void crm_xml_cleanup(void);

#  if XML_PARANOIA_CHECKS
#    define crm_validate_data(obj) xml_validate(obj)
#  else
#    define crm_validate_data(obj) CRM_LOG_ASSERT(obj != NULL)
#  endif

static inline xmlNode *
__xml_first_child(xmlNode * parent)
{
    xmlNode *child = NULL;

    if (parent) {
        child = parent->children;
        while (child && child->type != XML_ELEMENT_NODE) {
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
        while (child && child->type != XML_ELEMENT_NODE) {
            child = child->next;
        }
    }
    return child;
}

/* These two child iterator macros are no longer to be used
 * They exist for compatability reasons and will be removed in a
 * future release
 */
#  define xml_child_iter(parent, child, code) do {			\
	if(parent != NULL) {						\
		xmlNode *child = NULL;					\
		xmlNode *__crm_xml_iter = parent->children;		\
		while(__crm_xml_iter != NULL) {				\
			child = __crm_xml_iter;				\
			__crm_xml_iter = __crm_xml_iter->next;		\
			if(child->type == XML_ELEMENT_NODE) {		\
			    code;					\
			}						\
		}							\
	}								\
    } while(0)

#  define xml_child_iter_filter(parent, child, filter, code) do {	\
	if(parent != NULL) {						\
	    xmlNode *child = NULL;					\
	    xmlNode *__crm_xml_iter = parent->children;			\
	    while(__crm_xml_iter != NULL) {				\
		child = __crm_xml_iter;					\
		__crm_xml_iter = __crm_xml_iter->next;			\
		if(child->type == XML_ELEMENT_NODE) {			\
		    if(filter == NULL					\
		       || crm_str_eq(filter, (const char *)child->name, TRUE)) { \
			code;						\
		    }							\
		}							\
	    }								\
	}								\
    } while(0)

#  define xml_prop_iter(parent, prop_name, prop_value, code) do {	\
	if(parent != NULL) {						\
	    xmlAttrPtr prop_iter = parent->properties;			\
	    const char *prop_name = NULL;				\
	    const char *prop_value = NULL;				\
	    while(prop_iter != NULL) {					\
		prop_name = (const char *)prop_iter->name;		\
		prop_value = crm_element_value(parent, prop_name);	\
		prop_iter = prop_iter->next;				\
		if(prop_name) {						\
		    code;						\
		}							\
	    }								\
	}								\
    } while(0)

#  define xml_prop_name_iter(parent, prop_name, code) do {		\
	if(parent != NULL) {						\
	    xmlAttrPtr prop_iter = parent->properties;			\
	    const char *prop_name = NULL;				\
	    while(prop_iter != NULL) {					\
		prop_name = (const char *)prop_iter->name;		\
		prop_iter = prop_iter->next;				\
		if(prop_name) {						\
		    code;						\
		}							\
	    }								\
	}								\
    } while(0)

#  define free_xml(a_node) do {						\
	if((a_node) != NULL) {						\
	    xmlNode *a_doc_top = NULL;					\
	    xmlDoc *a_doc = (a_node)->doc;				\
	    if (a_doc != NULL) {					\
		a_doc_top = xmlDocGetRootElement(a_doc);		\
	    }								\
	    if(a_doc != NULL && a_doc_top == (a_node)) {		\
		xmlFreeDoc(a_doc);					\
									\
	    } else {							\
		/* make sure the node is unlinked first */		\
		xmlUnlinkNode(a_node);					\
		xmlFreeNode(a_node);					\
	    }								\
	}								\
    } while(0)

extern xmlNode *first_named_child(xmlNode * parent, const char *name);

extern xmlNode *convert_ipc_message(IPC_Message * msg, const char *field);
extern xmlNode *convert_ha_message(xmlNode * parent, HA_Message * msg, const char *field);

extern HA_Message *convert_xml_message(xmlNode * msg);
extern xmlNode *sorted_xml(xmlNode * input, xmlNode * parent, gboolean recursive);
extern xmlXPathObjectPtr xpath_search(xmlNode * xml_top, const char *path);
extern gboolean cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs);
extern xmlNode *expand_idref(xmlNode * input, xmlNode * top);

extern xmlNode *getXpathResult(xmlXPathObjectPtr xpathObj, int index);

#endif
