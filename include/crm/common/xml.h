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

#include <ha_msg.h>
#include <clplumbing/cl_log.h> 

/* #define USE_LIBXML 1 */
#if CRM_DEV_BUILD
#  define XML_PARANOIA_CHECKS 1
#else
#  define XML_PARANOIA_CHECKS 0
#endif

#ifdef USE_LIBXML
#  include <libxml/tree.h> 
   typedef xmlNode crm_data_t;
#else
   typedef struct ha_msg crm_data_t;
#endif

extern gboolean add_message_xml(
	HA_Message *msg, const char *field, const crm_data_t *xml);
extern crm_data_t *get_message_xml(HA_Message *msg, const char *field);
extern GHashTable *xml2list(crm_data_t *parent);
#if CRM_DEPRECATED_SINCE_2_0_3
extern GHashTable *xml2list_202(crm_data_t *parent);
#endif
extern void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
extern void hash2field(gpointer key, gpointer value, gpointer user_data);
extern void hash2metafield(gpointer key, gpointer value, gpointer user_data);

extern gboolean do_id_check(crm_data_t *xml_obj, GHashTable *id_hash,
			    gboolean silent_add, gboolean silent_rename);

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesnt work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything. 
 *
 */
extern void copy_in_properties(crm_data_t *target, const crm_data_t *src);
extern void expand_plus_plus(crm_data_t* target, const char *name, const char *value);
extern void fix_plus_plus_recursive(crm_data_t* target);

/*
 * Find a child named search_path[i] at level i in the XML fragment where i=0
 * is an immediate child of <i>root</i>.
 *
 * Terminate with success if i == len, or search_path[i] == NULL.
 *
 * On success, returns the sub-fragment described by search_path.
 * On failure, returns NULL.
 */
extern crm_data_t *find_xml_node_nested(
	crm_data_t *root, const char **search_path, int len);


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
extern const char *get_xml_attr_nested(crm_data_t *parent,
				       const char **node_path, int length,
				       const char *attr_name, gboolean error);

#define free_xml(a_node) do {				\
		if(a_node != NULL) {			\
			crm_validate_data(a_node);	\
			ha_msg_del(a_node);		\
		}					\
	} while(0)

void free_xml_from_parent(crm_data_t *parent, crm_data_t *a_node);
#define zap_xml_from_parent(parent, xml_obj) free_xml_from_parent(parent, xml_obj); xml_obj = NULL


/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
extern crm_data_t *create_xml_node(crm_data_t *parent, const char *name);

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
	crm_data_t *node, const char *name, const char *value);

extern const char *crm_xml_add_int(
	crm_data_t* node, const char *name, int value);

/*
 * Unlink the node and set its doc pointer to NULL so free_xml()
 * will act appropriately
 */
extern void unlink_xml_node(crm_data_t *node);

/*
 * Set a timestamp attribute on a_node
 */
extern void add_xml_tstamp(crm_data_t *a_node);

/*
 * 
 */
extern void purge_diff_markers(crm_data_t *a_node);

/*
 * Returns a deep copy of src_node
 *
 */
extern crm_data_t *copy_xml(const crm_data_t *src_node);

/*
 * Add a copy of xml_node to new_parent
 */
extern crm_data_t *add_node_copy(
	crm_data_t *new_parent, const crm_data_t *xml_node);

extern int add_node_nocopy(crm_data_t *parent, const char *name, crm_data_t *child);


/*
 * XML I/O Functions
 *
 * Whitespace between tags is discarded.
 */
extern crm_data_t *file2xml(FILE *input, gboolean compressed);

extern crm_data_t *stdin2xml(void);

extern crm_data_t *string2xml(const char *input);

extern int write_xml_file(
	crm_data_t *xml_node, const char *filename, gboolean compress);

extern char *dump_xml_formatted(const crm_data_t *msg);

extern char *dump_xml_unformatted(const crm_data_t *msg);

extern void print_xml_formatted(
	int log_level, const char *function,
	const crm_data_t *an_xml_node, const char *text);

/*
 * Diff related Functions
 */ 
extern crm_data_t *diff_xml_object(
	crm_data_t *left, crm_data_t *right, gboolean suppress);

extern void log_xml_diff(unsigned int log_level, crm_data_t *diff, const char *function);

extern gboolean apply_xml_diff(
	crm_data_t *old, crm_data_t *diff, crm_data_t **new);


/*
 * Searching & Modifying
 */
extern crm_data_t *find_xml_node(
	crm_data_t *cib, const char * node_path, gboolean must_find);

extern crm_data_t *find_entity(
	crm_data_t *parent, const char *node_name, const char *id);

extern crm_data_t *subtract_xml_object(
	crm_data_t *left, crm_data_t *right, const char *marker);

extern int add_xml_object(
	crm_data_t *parent, crm_data_t *target, const crm_data_t *update);

extern void xml_remove_prop(crm_data_t *obj, const char *name);

extern gboolean replace_xml_child(
	crm_data_t *parent, crm_data_t *child, crm_data_t *update, gboolean delete_only);

extern gboolean update_xml_child(crm_data_t *child, crm_data_t *to_update);

extern int find_xml_children(
	crm_data_t **children, crm_data_t *root,
	const char *tag, const char *field, const char *value,
	gboolean search_matches);

/*
 *
 */
extern const char *crm_element_value(const crm_data_t *data, const char *name);
extern char *crm_element_value_copy(const crm_data_t *data, const char *name);

extern const char *crm_element_name(const crm_data_t *data);

extern void xml_validate(const crm_data_t *root);

extern gboolean xml_has_children(const crm_data_t *root);	 		

extern char *calculate_xml_digest(crm_data_t *local_cib, gboolean sort, gboolean do_filter);

extern gboolean validate_with_dtd(
	crm_data_t *xml_blob, gboolean to_logs, const char *dtd_file);

#if XML_PARANOIA_CHECKS
#  define crm_validate_data(obj) xml_validate(obj)
#else
#  define crm_validate_data(obj) CRM_DEV_ASSERT(obj != NULL)
#endif

#define xml_child_iter(parent, child, loop_code)			\
	if(parent != NULL) {						\
		int __counter = 0;					\
		crm_data_t *child = NULL;				\
		crm_validate_data(parent);				\
		for (__counter = 0; __counter < parent->nfields; __counter++) { \
			if(parent->types[__counter] != FT_STRUCT	\
			   && parent->types[__counter] != FT_UNCOMPRESS) { \
				continue;				\
			}						\
			child = (crm_data_t*)parent->values[__counter]; \
			if(child == NULL) {				\
				crm_debug_4("Skipping %s == NULL",	\
					  parent->names[__counter]);	\
			} else {					\
				loop_code;				\
			}						\
		}							\
	} else {							\
		crm_debug_4("Parent of loop was NULL");			\
	}

#define xml_child_iter_filter(parent, child, filter, loop_code)		\
	if(parent != NULL) {						\
		int __counter = 0;					\
		crm_data_t *child = NULL;				\
		crm_validate_data(parent);				\
		for (__counter = 0; __counter < parent->nfields; __counter++) { \
			if(parent->types[__counter] != FT_STRUCT	\
			   && parent->types[__counter] != FT_UNCOMPRESS) { \
				continue;				\
			}						\
			child = (crm_data_t*)parent->values[__counter]; \
			if(child == NULL) {				\
				crm_debug_4("Skipping %s == NULL",	\
					  parent->names[__counter]);	\
			} else if(filter == NULL/*constant condition*/	\
				  || safe_str_eq(filter, parent->names[__counter])) { \
				loop_code;				\
			} else {					\
				crm_debug_4("Skipping <%s../>",		\
					  parent->names[__counter]);	\
			}						\
		}							\
	} else {							\
		crm_debug_4("Parent of loop was NULL");			\
	}

#define xml_prop_iter(parent, prop_name, prop_value, code) if(parent != NULL) { \
		const char *prop_name = NULL;				\
		const char *prop_value = NULL;				\
		int __counter = 0;					\
		crm_validate_data(parent);				\
		crm_debug_5("Searching %d fields", parent->nfields);	\
		for (__counter = 0; __counter < parent->nfields; __counter++) { \
			crm_debug_5("Searching field %d", __counter);	\
			prop_name = (const char*)parent->names[__counter]; \
			if(parent->types[__counter] != FT_STRING) {	\
				continue;				\
			} else if(prop_name[0] == '_'			\
				  && prop_name[1] == '_') {		\
				continue;				\
			}						\
			prop_value = (const char*)parent->values[__counter]; \
			code;						\
		}							\
	} else {							\
		crm_debug_4("Parent of loop was NULL");			\
	}

#endif
