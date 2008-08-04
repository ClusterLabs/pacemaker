/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CRM_COMMON_XML__H
#define CRM_COMMON_XML__H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <ha_msg.h>

#include <libxml/tree.h> 
#include <libxml/xpath.h>
typedef xmlNode crm_data_t;

#define CRM_BZ2_BLOCKS		4
#define CRM_BZ2_WORK		20
#define CRM_BZ2_THRESHOLD	10 * 1024

#define XML_PARANOIA_CHECKS 0

extern gboolean add_message_xml(
	xmlNode *msg, const char *field, xmlNode *xml);
extern xmlNode *get_message_xml(xmlNode *msg, const char *field);
extern GHashTable *xml2list(xmlNode *parent);
#if CRM_DEPRECATED_SINCE_2_0_3
extern GHashTable *xml2list_202(xmlNode *parent);
#endif
extern void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
extern void hash2field(gpointer key, gpointer value, gpointer user_data);
extern void hash2metafield(gpointer key, gpointer value, gpointer user_data);
extern void hash2smartfield(gpointer key, gpointer value, gpointer user_data);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesnt work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything. 
 *
 */
extern void copy_in_properties(xmlNode *target, xmlNode *src);
extern void expand_plus_plus(xmlNode* target, const char *name, const char *value);
extern void fix_plus_plus_recursive(xmlNode* target);

/*
 * Find a child named search_path[i] at level i in the XML fragment where i=0
 * is an immediate child of <i>root</i>.
 *
 * Terminate with success if i == len, or search_path[i] == NULL.
 *
 * On success, returns the sub-fragment described by search_path.
 * On failure, returns NULL.
 */
extern xmlNode *find_xml_node_nested(
	xmlNode *root, const char **search_path, int len);


/*
 * Find a child named search_path[i] at level i in the XML fragment where i=0
 * is an immediate child of <i>root</i>.
 *
 * Once the last child specified by node_path is found, find the value
 * of attr_name.
 *
 * If <i>error<i> is set to TRUE, then it is an error for the attribute not
 * to be found and the function will log accordingly.
 *
 * On success, returns the value of attr_name.
 * On failure, returns NULL.
 */
extern const char *get_xml_attr_nested(xmlNode *parent,
				       const char **node_path, int length,
				       const char *attr_name, gboolean error);


void free_xml_from_parent(xmlNode *parent, xmlNode *a_node);
#define zap_xml_from_parent(parent, xml_obj) free_xml_from_parent(parent, xml_obj); xml_obj = NULL


/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
extern xmlNode *create_xml_node(xmlNode *parent, const char *name);

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
extern const char *crm_xml_add(
	xmlNode *node, const char *name, const char *value);

extern const char *crm_xml_replace(
	xmlNode *node, const char *name, const char *value);

extern const char *crm_xml_add_int(
	xmlNode* node, const char *name, int value);

/*
 * Unlink the node and set its doc pointer to NULL so free_xml()
 * will act appropriately
 */
extern void unlink_xml_node(xmlNode *node);

/*
 * 
 */
extern void purge_diff_markers(xmlNode *a_node);

/*
 * Returns a deep copy of src_node
 *
 */
extern xmlNode *copy_xml(xmlNode *src_node);

/*
 * Add a copy of xml_node to new_parent
 */
extern xmlNode *add_node_copy(
	xmlNode *new_parent, xmlNode *xml_node);

extern int add_node_nocopy(xmlNode *parent, const char *name, xmlNode *child);


/*
 * XML I/O Functions
 *
 * Whitespace between tags is discarded.
 */
extern xmlNode *filename2xml(const char *filename);

extern xmlNode *stdin2xml(void);

extern xmlNode *string2xml(const char *input);

extern int write_xml_file(
	xmlNode *xml_node, const char *filename, gboolean compress);

extern char *dump_xml_formatted(xmlNode *msg);

extern char *dump_xml_unformatted(xmlNode *msg);

extern void print_xml_formatted(
	int log_level, const char *function,
	xmlNode *an_xml_node, const char *text);

/*
 * Diff related Functions
 */ 
extern xmlNode *diff_xml_object(
	xmlNode *left, xmlNode *right, gboolean suppress);

extern void print_xml_diff(FILE *where, xmlNode *diff);
extern void log_xml_diff(unsigned int log_level, xmlNode *diff, const char *function);

extern gboolean apply_xml_diff(
	xmlNode *old, xmlNode *diff, xmlNode **new);


/*
 * Searching & Modifying
 */
extern xmlNode *find_xml_node(
	xmlNode *cib, const char * node_path, gboolean must_find);

extern xmlNode *find_entity(
	xmlNode *parent, const char *node_name, const char *id);

extern xmlNode *subtract_xml_object(
	xmlNode *left, xmlNode *right, const char *marker);

extern int add_xml_object(
	xmlNode *parent, xmlNode *target, xmlNode *update);

extern void xml_remove_prop(xmlNode *obj, const char *name);

extern gboolean replace_xml_child(
	xmlNode *parent, xmlNode *child, xmlNode *update, gboolean delete_only);

extern gboolean update_xml_child(xmlNode *child, xmlNode *to_update);

extern int find_xml_children(
	xmlNode **children, xmlNode *root,
	const char *tag, const char *field, const char *value,
	gboolean search_matches);

extern int crm_element_value_int(xmlNode *data, const char *name, int *dest);
extern char *crm_element_value_copy(xmlNode *data, const char *name);
extern const char *crm_element_value_const(const xmlNode *data, const char *name);
extern xmlNode *get_xpath_object(const char *xpath, xmlNode *xml_obj, int error_level);

static inline const char *crm_element_name(const xmlNode *data)
{
    return (data ? (const char *)data->name : NULL);
}

static inline const char *
crm_element_value(xmlNode *data, const char *name)
{
    xmlAttr *attr = NULL;
    
    if(data == NULL) {
	crm_err("Couldn't find %s in NULL", name?name:"<null>");
	return NULL;

    } else if(name == NULL) {
	crm_err("Couldn't find NULL in %s", crm_element_name(data));
	return NULL;
    }
    
    attr = xmlHasProp(data, (const xmlChar*)name);
    if(attr == NULL || attr->children == NULL) {
	return NULL;
    }
    return (const char*)attr->children->content;
}


extern void xml_validate(const xmlNode *root);

extern gboolean xml_has_children(const xmlNode *root);	 		

extern char *calculate_xml_digest(xmlNode *local_cib, gboolean sort, gboolean do_filter);

extern gboolean validate_xml(xmlNode *xml_blob, const char *validation, gboolean to_logs);
extern int update_validation(xmlNode **xml_blob, int *best, gboolean transform, gboolean to_logs);
extern int get_schema_version(const char *name);
extern const char *get_schema_name(int version);

#if XML_PARANOIA_CHECKS
#  define crm_validate_data(obj) xml_validate(obj)
#else
#  define crm_validate_data(obj) CRM_DEV_ASSERT(obj != NULL)
#endif

#  define xml_child_iter(parent, child, code) do {			\
	if(parent != NULL) {						\
		xmlNode *child = NULL;				\
		xmlNode *__crm_xml_iter = parent->children;		\
		while(__crm_xml_iter != NULL) {				\
			child = __crm_xml_iter;				\
			__crm_xml_iter = __crm_xml_iter->next;		\
			if(child) {					\
			    code;					\
			}						\
		}							\
	} else {							\
		crm_debug_4("Parent of loop was NULL");			\
	}								\
    } while(0)

#  define xml_child_iter_filter(parent, child, filter, code) do {	\
	if(parent != NULL) {						\
	    xmlNode *child = NULL;					\
	    xmlNode *__crm_xml_iter = parent->children;		\
	    while(__crm_xml_iter != NULL) {				\
		child = __crm_xml_iter;					\
		__crm_xml_iter = __crm_xml_iter->next;			\
		if(filter == NULL					\
		   || crm_str_eq(filter, (const char *)child->name, TRUE)) { \
		    code;						\
		}							\
	    }								\
	} else {							\
	    crm_debug_4("Parent of loop was NULL");			\
	}								\
    } while(0)

#  define xml_prop_iter(parent, prop_name, prop_value, code) do {	\
	if(parent != NULL) {						\
	    xmlAttrPtr prop_iter = parent->properties;			\
	    const char *prop_name = NULL;				\
	    const char *prop_value = NULL;				\
	    while(prop_iter != NULL) {					\
		prop_name = (const char *)prop_iter->name;		\
		prop_value = crm_element_value(parent, prop_name);\
		prop_iter = prop_iter->next;				\
		if(prop_name) {						\
		    code;						\
		}							\
	    }								\
	} else {							\
	    crm_debug_4("Parent of loop was NULL");			\
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
		if(a_doc != NULL) {					\
		    crm_err("Line %d: Attempted to free XML (%s) from within an xmlDocPtr (%s/%p)", \
			    __LINE__, crm_element_name(a_node), crm_element_name(a_doc_top), a_doc); \
		}							\
		/* make sure the node is unlinked first */		\
		xmlUnlinkNode(a_node);					\
		xmlFreeNode(a_node);					\
	    }								\
	}								\
    } while(0)


extern xmlNode *first_named_child(xmlNode *parent, const char *name);

extern xmlNode *convert_ipc_message(IPC_Message *msg, const char *field);
extern xmlNode *convert_ha_message(xmlNode *parent, HA_Message *msg, const char *field);

extern HA_Message *convert_xml_message(xmlNode *msg);
extern xmlNode *sorted_xml(xmlNode *input, xmlNode *parent, gboolean recursive);
extern xmlXPathObjectPtr xpath_search(xmlNode *xml_top, const char *path);
extern gboolean cli_config_update(xmlNode **xml);
extern xmlNode *expand_idref(xmlNode *input);

#endif
