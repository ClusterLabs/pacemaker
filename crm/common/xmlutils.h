/* $Id: xmlutils.h,v 1.10 2004/03/26 13:01:13 andrew Exp $ */
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
#ifndef XMLUTILS_H
#define XMLUTILS_H

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 
#include <libxml/tree.h> 

extern void copy_in_properties(xmlNodePtr target, xmlNodePtr src);

extern xmlNodePtr find_xml_node(xmlNodePtr cib,
				const char * node_path);

extern xmlNodePtr find_entity(xmlNodePtr parent,
			      const char *node_name,
			      const char *id,
			      gboolean siblings);

extern xmlNodePtr find_entity_nested(xmlNodePtr parent,
				     const char *node_name,
				     const char *elem_filter_name,
				     const char *elem_filter_value,
				     const char *id,
				     gboolean siblings);

extern xmlNodePtr find_xml_node_nested(xmlNodePtr root,
				       const char **search_path,
				       int len);

extern char * dump_xml(xmlNodePtr msg);

extern char * dump_xml_node(xmlNodePtr msg, gboolean whole_doc);

extern void free_xml(xmlNodePtr a_node);

extern void xml_message_debug(xmlNodePtr msg, const char *text);

extern xmlNodePtr create_xml_node(xmlNodePtr parent, const char *name);

extern xmlAttrPtr set_xml_property_copy(xmlNodePtr node,
					const xmlChar *name,
					const xmlChar *value);

extern void unlink_xml_node(xmlNodePtr node);

extern void set_node_tstamp(xmlNodePtr a_node);

extern xmlNodePtr copy_xml_node_recursive(xmlNodePtr src_node,
					  int recursive);

extern xmlNodePtr add_node_copy(xmlNodePtr new_parent,
				xmlNodePtr xml_node);

extern xmlNodePtr file2xml(FILE *input);
extern xmlNodePtr string2xml(const char *input);

extern const char *get_xml_attr(xmlNodePtr parent,
				const char *node_name, const char *attr_name,
				gboolean error);
extern const char *get_xml_attr_nested(xmlNodePtr parent,
				       const char **node_path, int length,
				       const char *attr_name, gboolean error);

extern xmlNodePtr set_xml_attr(xmlNodePtr parent,
			       const char *node_name,
			       const char *attr_name,
			       const char *attr_value,
			       gboolean create);

extern xmlNodePtr set_xml_attr_nested(xmlNodePtr parent,
				      const char **node_path, int length,
				      const char *attr_name,
				      const char *attr_value,
				      gboolean create);

#endif
