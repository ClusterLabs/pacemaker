/* $Id: xml.h,v 1.4 2004/09/04 10:40:10 andrew Exp $ */
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

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h> 
#include <libxml/tree.h> 

/*
 * Replacement function for xmlCopyPropList which at the very least,
 * doesnt work the way *I* would expect it to.
 *
 * Copy all the attributes/properties from src into target.
 *
 * Not recursive, does not return anything. 
 *
 */
extern void copy_in_properties(xmlNodePtr target, xmlNodePtr src);

/*
 * Find a child named search_path[i] at level i in the XML fragment where i=0
 * is an immediate child of <i>root</i>.
 *
 * Terminate with success if i == len, or search_path[i] == NULL.
 *
 * On success, returns the sub-fragment described by search_path.
 * On failure, returns NULL.
 */
extern xmlNodePtr find_xml_node_nested(
	xmlNodePtr root, const char **search_path, int len);


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
extern const char *get_xml_attr_nested(xmlNodePtr parent,
				       const char **node_path, int length,
				       const char *attr_name, gboolean error);

/*
 * Free the XML "stuff" associated with a_node
 *
 * If a_node is part of a document, free the whole thing
 *
 * Otherwise, unlink it from its current location and free everything
 * from there down.
 *
 * Wont barf on NULL.
 *
 */
extern void free_xml(xmlNodePtr a_node);

/*
 * Create a node named "name" as a child of "parent"
 * If parent is NULL, creates an unconnected node.
 *
 * Returns the created node
 *
 */
extern xmlNodePtr create_xml_node(xmlNodePtr parent, const char *name);

/*
 * Make a copy of name and value and use the copied memory to create
 * an attribute for node.
 *
 * If node, name or value are NULL, nothing is done.
 *
 * If name or value are an empty string, nothing is done.
 *
 * Returns NULL on failure and the attribute created on success.
 *
 */
extern xmlAttrPtr set_xml_property_copy(xmlNodePtr node,
					const xmlChar *name,
					const xmlChar *value);

/*
 * Unlink the node and set its doc pointer to NULL so free_xml()
 * will act appropriately
 */
extern void unlink_xml_node(xmlNodePtr node);

/*
 * Set a timestamp attribute on a_node
 */
extern void set_node_tstamp(xmlNodePtr a_node);

/*
 * Returns a deep copy of src_node
 *
 * Either calls xmlCopyNode() or a home grown alternative (based on
 * XML_TRACE being defined) that does more logging...
 * helpful when part of the XML document has been freed :)
 */
extern xmlNodePtr copy_xml_node_recursive(xmlNodePtr src_node);

/*
 * Add a copy of xml_node to new_parent
 */
extern xmlNodePtr add_node_copy(xmlNodePtr new_parent, xmlNodePtr xml_node);


/*
 * Read in the contents of a pre-opened file descriptor (until EOF) and
 * produce an XML fragment (it will have an attached document).
 *
 * input will need to be closed on completion.
 *
 * Whitespace between tags is discarded.
 *
 */
extern xmlNodePtr file2xml(FILE *input);

/*
 * Read in the contents of a string and produce an XML fragment (it will
 * have an attached document).
 *
 * input will need to be freed on completion.
 *
 * Whitespace between tags is discarded.
 *
 */
extern xmlNodePtr string2xml(const char *input);


/* convience "wrapper" functions */
extern xmlNodePtr find_xml_node(xmlNodePtr cib, const char * node_path);

extern xmlNodePtr find_entity(xmlNodePtr parent,
			      const char *node_name,
			      const char *id,
			      gboolean siblings);

extern const char *get_xml_attr(xmlNodePtr parent,
				const char *node_name, const char *attr_name,
				gboolean error);

extern xmlNodePtr set_xml_attr(xmlNodePtr parent,
			       const char *node_name,
			       const char *attr_name,
			       const char *attr_value,
			       gboolean create);

extern int write_xml_file(xmlNodePtr xml_node, const char *filename);

extern char *dump_xml_formatted(xmlNodePtr msg);

extern void print_xml_formatted(xmlNodePtr an_xml_node, const char *text);

#define xml_child_iter(a,b,c,d) if(a != NULL) {			\
		xmlNodePtr b = a->children;				\
		while(b != NULL) {					\
			if(c == NULL || safe_str_eq(c, b->name)) {	\
				d;					\
			}						\
			b=b->next;					\
		}							\
	} else {							\
		crm_trace("Parent of loop was NULL");			\
	}

/* 			} else {					\ */
/* 				crm_debug("Ignoring node %s (filter %s)", \ */
/* 					  b->name, (const char*)c);	\ */

#endif
