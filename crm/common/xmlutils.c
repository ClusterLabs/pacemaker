/* $Id: xmlutils.c,v 1.19 2004/03/26 13:01:12 andrew Exp $ */
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

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm/crm.h>
#include <xmlutils.h>
#include <crm/msg_xml.h>

#include <crm/dmalloc_wrapper.h>

/* int		xmlGetDocCompressMode	(xmlDocPtr doc); */
/* void		xmlSetDocCompressMode	(xmlDocPtr doc, */
/* 					 int mode); */
/* int		xmlGetCompressMode	(void); */
/* void		xmlSetCompressMode	(int mode); */

xmlNodePtr
find_xml_node_nested(xmlNodePtr root, const char **search_path, int len)
{
	int	j;
	FNIN();

	if (root == NULL) {
		CRM_DEBUG("Will never find anything in NULL :)");
		FNRET(NULL);
	}

	if(search_path == NULL) {
		CRM_DEBUG("Will never find NULL :)");
		FNRET(NULL);
	}
	
	
#ifdef XML_TRACE
	CRM_DEBUG("looking for...");
	for (j=0; j < len; ++j) {
		if (search_path[j] == NULL) break;
		CRM_DEBUG2(" --> (%s).", search_path[j]);
	}
#endif
	
	xmlNodePtr child = root->children, lastMatch = NULL;
	for (j=0; j < len; ++j) {
		gboolean is_found = FALSE;
		if (search_path[j] == NULL) {
			len = j; /* a NULL also means stop searching */
			break;
		}
		
		while(child != NULL) {
			const char * child_name = (const char*)child->name;
#ifdef XML_TRACE
			CRM_DEBUG3("comparing (%s) with (%s).",
				   search_path[j],
				   child->name);
#endif
			if (strcmp(child_name, search_path[j]) == 0) {
				lastMatch = child;
				child = lastMatch->children;
#ifdef XML_TRACE
				CRM_DEBUG3("found node (%s) @line (%ld).",
					   search_path[j],
					   xmlGetLineNo(child));
#endif
				is_found = TRUE;
				break;
			}
			child = child->next;
		}
		if (is_found == FALSE) {
#ifdef XML_TRACE
			CRM_DEBUG2(
				"No more siblings left... %s cannot be found.",
				search_path[j]);
#endif
			break;
		}
	}

	if (j == len
	    && lastMatch != NULL
	    && strcmp(lastMatch->name, search_path[j-1]) == 0) {
#ifdef XML_TRACE
		CRM_DEBUG2("returning node (%s).",
			   xmlGetNodePath(lastMatch));
#endif
		FNRET(lastMatch);
	}

	cl_log(LOG_WARNING,
	       "Could not find the full path to the node you specified."
	       "  Closest point was node (%s).",
	       xmlGetNodePath(lastMatch));

	FNRET(NULL);
    
}


const char *
get_xml_attr(xmlNodePtr parent,
	     const char *node_name, const char *attr_name,
	     gboolean error)
{

	if(node_name == NULL) {
		// get it from the current node
		return get_xml_attr_nested(parent, NULL, 0, attr_name, error);
	}
	return get_xml_attr_nested(parent, &node_name, 1, attr_name, error);

}


const char *
get_xml_attr_nested(xmlNodePtr parent,
		    const char **node_path, int length,
		    const char *attr_name, gboolean error)
{
	const char *attr_value = NULL;
	xmlNodePtr attr_parent = NULL;
	
	if(parent == NULL) {
		cl_log(LOG_ERR, "Can not find attribute in NULL parent");
		return NULL;
	} 

	if(attr_name || strlen(attr_name) == 0) {
		cl_log(LOG_ERR, "Can not find attribute with no name");
		return NULL;
	}
	
	if(length == 0) {
		attr_parent = parent;
		
	} else {
		attr_parent = find_xml_node_nested(parent, node_path, length);
		if(attr_parent == NULL && error) {
			cl_log(LOG_ERR, "No node at the path you specified.");
			return NULL;
		}
	}
	
	attr_value = xmlGetProp(attr_parent, attr_name);
	if((attr_value == NULL || strlen(attr_value) == 0) && error) {
		cl_log(LOG_ERR,
		       "No value present for %s at %s",
		       attr_name, xmlGetNodePath(attr_parent));
		return NULL;
	}
	
	return attr_value;
}

xmlNodePtr
set_xml_attr(xmlNodePtr parent,
	     const char *node_name,
	     const char *attr_name,
	     const char *attr_value,
	     gboolean create)
{

	if(node_name == NULL) {
		// set it on the current node
		return set_xml_attr_nested(parent, NULL, 0,
					   attr_name, attr_value, create);
	}
	return set_xml_attr_nested(parent, &node_name, 1,
				   attr_name, attr_value, create);

}


xmlNodePtr
set_xml_attr_nested(xmlNodePtr parent,
		    const char **node_path, int length,
		    const char *attr_name,
		    const char *attr_value,
		    gboolean create)
{
	xmlAttrPtr result        = NULL;
	xmlNodePtr attr_parent   = NULL;
	xmlNodePtr create_parent = NULL;
	
	if(parent == NULL && create == FALSE) {
		cl_log(LOG_ERR, "Can not set attribute in NULL parent");
		return NULL;
	} 

	if(attr_name || strlen(attr_name) == 0) {
		cl_log(LOG_ERR, "Can not set attribute with no name");
		return NULL;
	}


	if(length == 0 && parent != NULL) {
		attr_parent = parent;

	} else if(length == 0 || node_path == NULL
		  || *node_path == NULL || strlen(*node_path) == 0) {
		cl_log(LOG_ERR, "Can not create parent to set attribute on");
		return NULL;
		
	} else {
		attr_parent = find_xml_node_nested(parent, node_path, length);
	}
	
	if(create && attr_parent == NULL) {
		int j = 0;
		attr_parent = parent;
		for (j=0; j < length; ++j) {
			if (node_path[j] == NULL) {
				break;
			}
			
			xmlNodePtr tmp =
				find_xml_node(attr_parent, node_path[j]);

			if(tmp == NULL) {
				attr_parent = create_xml_node(attr_parent,
							      node_path[j]);
				if(j==0) {
					create_parent = attr_parent;
				}
				
			} else {
				attr_parent = tmp;
			}
		}
		
	} else if(attr_parent == NULL) {
		cl_log(LOG_ERR, "Can not find parent to set attribute on");
		return NULL;
		
	}
	
	result = set_xml_property_copy(attr_parent, attr_name, attr_value);
	if(result == NULL) {
		cl_log(LOG_WARNING,
		       "Could not set %s=%s at %s",
		       attr_name, attr_value, xmlGetNodePath(attr_parent));
	}

	if(create_parent != NULL) {
		return create_parent;
	}
	
	return parent;
}



xmlNodePtr
find_xml_node(xmlNodePtr root, const char * search_path)
{
	if(root == NULL) return NULL;
	return find_xml_node_nested(root, &search_path, 1);
}

xmlNodePtr
find_entity(xmlNodePtr parent,
	    const char *node_name,
	    const char *id,
	    gboolean siblings)
{
	return find_entity_nested(parent,
				  node_name,
				  NULL,
				  NULL,
				  id,
				  siblings);
}

xmlNodePtr
find_entity_nested(xmlNodePtr parent,
		   const char *node_name,
		   const char *elem_filter_name,
		   const char *elem_filter_value,
		   const char *id,
		   gboolean siblings)
{
	xmlNodePtr child;
	FNIN();
#ifdef XML_TRACE
	cl_log(LOG_DEBUG, "Looking for %s elem with id=%s.", node_name, id);
#endif
	while(parent != NULL) {
#ifdef XML_TRACE
		CRM_DEBUG2("examining (%s).", xmlGetNodePath(parent));
#endif
		child = parent->children;
	
		while(child != NULL) {
#ifdef XML_TRACE
			CRM_DEBUG2("looking for (%s) [name].", node_name);
#endif
			if (node_name != NULL
			    && strcmp(child->name, node_name) != 0) {    
#ifdef XML_TRACE
				CRM_DEBUG3(
					"skipping entity (%s=%s) [node_name].",
					xmlGetNodePath(child), child->name);
#endif
				break;
			} else if (elem_filter_name != NULL
				   && elem_filter_value != NULL) {
				const char* child_value = (const char*)
					xmlGetProp(child, elem_filter_name);
				
#ifdef XML_TRACE
				cl_log(LOG_DEBUG,
				       "comparing (%s) with (%s) [attr_value].",
				       child_value, elem_filter_value);
#endif
				if (strcmp(child_value, elem_filter_value)) {
#ifdef XML_TRACE
					CRM_DEBUG2("skipping entity (%s) [attr_value].",
						   xmlGetNodePath(child));
#endif
					break;
				}
			}
		
#ifdef XML_TRACE
			cl_log(LOG_DEBUG,
			       "looking for entity (%s) in %s.",
			       id, xmlGetNodePath(child));
#endif
			while(child != NULL) {
#ifdef XML_TRACE
				cl_log(LOG_DEBUG,
				       "looking for entity (%s) in %s.",
				       id, xmlGetNodePath(child));
#endif
				xmlChar *child_id = xmlGetProp(child, "id");
				if (child_id == NULL) {
					cl_log(LOG_CRIT,
					       "Entity (%s) has id=NULL..."
					       "Cib not valid!",
					       xmlGetNodePath(child));
				} else if (strcmp(id, child_id) == 0) {
#ifdef XML_TRACE
					CRM_DEBUG2("found entity (%s).", id);
#endif
					FNRET(child);
				}   
				child = child->next;
			}
		}

		if (siblings == TRUE) {
#ifdef XML_TRACE
			CRM_DEBUG("Nothing yet... checking siblings");	    
#endif
			parent = parent->next;
		} else
			parent = NULL;
	}
	cl_log(LOG_INFO,
	       "Couldnt find anything appropriate for %s elem with id=%s.",
	       node_name, id);	    
	FNRET(NULL);
}


void
copy_in_properties(xmlNodePtr target, xmlNodePtr src)
{
	if(src == NULL) {
		cl_log(LOG_WARNING, "No node to copy properties from");
	} else if (src->properties == NULL) {
		cl_log(LOG_INFO, "No properties to copy");
	} else if (target == NULL) {
		cl_log(LOG_WARNING, "No node to copy properties into");
	} else {
#ifndef USE_BUGGY_LIBXML
		xmlAttrPtr prop_iter = NULL;
		FNIN();
		
		prop_iter = src->properties;
		while(prop_iter != NULL) {
			const char *local_prop_name = prop_iter->name;
			const char *local_prop_value =
				xmlGetProp(src, local_prop_name);
			
			set_xml_property_copy(target,
					      local_prop_name,
					      local_prop_value);
			
			prop_iter = prop_iter->next;
		}
#else
		xmlCopyPropList(target, src->properties);
#endif
	}
	
	FNOUT();
}

char * 
dump_xml(xmlNodePtr msg)
{
	FNIN();
	FNRET(dump_xml_node(msg, FALSE));
}

void
xml_message_debug(xmlNodePtr msg, const char *text)
{
	FNIN();
	char *msg_buffer = dump_xml_node(msg, FALSE);
	CRM_DEBUG3("%s: %s",
		   text==NULL?"<null>":text,
		   msg_buffer==NULL?"<null>":msg_buffer);
	ha_free(msg_buffer);
	FNOUT();
}

char * 
dump_xml_node(xmlNodePtr msg, gboolean whole_doc)
{
	int lpc = 0;
	int msg_size = -1;
	FNIN();

	xmlChar *xml_message = NULL;
	if (msg == NULL) FNRET(NULL);

	xmlInitParser();

	if (whole_doc) {
		if (msg->doc == NULL) {
			xmlDocPtr foo = xmlNewDoc("1.0");
			xmlDocSetRootElement(foo, msg);
			xmlSetTreeDoc(msg,foo);
		}
		xmlDocDumpMemory(msg->doc, &xml_message, &msg_size);
	} else {
#ifdef XML_TRACE
		CRM_DEBUG2("mem used by xml: %d", xmlMemUsed());
#endif    
		xmlMemoryDump ();
	
		xmlBufferPtr xml_buffer = xmlBufferCreate();
		msg_size = xmlNodeDump(xml_buffer, msg->doc, msg, 0, 0);

		xml_message =
			(xmlChar*)ha_strdup(xmlBufferContent(xml_buffer)); 
		xmlBufferFree(xml_buffer);

		if (!xml_message) {
			cl_log(LOG_ERR,
			       "memory allocation failed in dump_xml_node()");
		}
	}

	// HA wont send messages with newlines in them.
	for(; xml_message != NULL && lpc < msg_size; lpc++)
		if (xml_message[lpc] == '\n')
			xml_message[lpc] = ' ';
    
	FNRET((char*)xml_message); 
}

xmlNodePtr
add_node_copy(xmlNodePtr new_parent, xmlNodePtr xml_node)
{
	xmlNodePtr node_copy = NULL;
	
	FNIN();

	if(xml_node != NULL && new_parent != NULL) {
		node_copy = copy_xml_node_recursive(xml_node, 1);
		xmlAddChild(new_parent, node_copy);

	} else if(xml_node == NULL) {
		cl_log(LOG_ERR, "Could not add copy of NULL node");

	} else {
		cl_log(LOG_ERR, "Could not add copy of node to NULL parent");
	}
	
	FNRET(node_copy);
}

xmlAttrPtr
set_xml_property_copy(xmlNodePtr node,
		      const xmlChar *name,
		      const xmlChar *value)
{
	const char *parent_name = NULL;
	const char *local_name = NULL;
	const char *local_value = NULL;

	xmlAttrPtr ret_value = NULL;
	FNIN();

	if(node != NULL) {
		parent_name = node->name;
	}

	
#ifdef XML_TRACE
	CRM_DEBUG4("[%s] Setting %s to %s", parent_name, name, value);
#endif
	if (name == NULL || strlen(name) <= 0)
		ret_value = NULL;
	else if(node == NULL)
		ret_value = NULL;
	else if (value == NULL || strlen(value) <= 0)
		ret_value = NULL;
	else {
		local_value = ha_strdup(value);
		local_name = ha_strdup(name);
		ret_value = xmlSetProp(node, local_name, local_value);
	}
	
	FNRET(ret_value);
}

xmlNodePtr
create_xml_node(xmlNodePtr parent, const char *name)
{
	const char *local_name = NULL;
	const char *parent_name = NULL;
	xmlNodePtr ret_value = NULL;
	FNIN();

	if (name == NULL)
		ret_value = NULL;
	else {
		local_name = ha_strdup(name);

		if(parent == NULL) 
			ret_value = xmlNewNode(NULL, local_name);
		else {
			parent_name = parent->name;
			ret_value =
				xmlNewChild(parent, NULL, local_name, NULL);
		}
	}

#ifdef XML_TRACE
	CRM_DEBUG3("Created node [%s [%s]]", parent_name, local_name);
#endif
	FNRET(ret_value);
}

void
unlink_xml_node(xmlNodePtr node)
{
	xmlUnlinkNode(node);
	/* this helps us with frees and really should be being done by
	 * the library call
	 */
	node->doc = NULL;
}

void
free_xml(xmlNodePtr a_node)
{
	FNIN();
	if (a_node == NULL)
		; // nothing to do
	else if (a_node->doc != NULL)
		xmlFreeDoc(a_node->doc);
	else
	{
		/* make sure the node is unlinked first */
		xmlUnlinkNode(a_node);

#if 0
	/* set a new doc, wont delete without one? */
		xmlDocPtr foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, a_node);
		xmlSetTreeDoc(a_node,foo);
		xmlFreeDoc(foo);
#else
		xmlFreeNode(a_node);
#endif
	}
	
	FNOUT();
}

void
set_node_tstamp(xmlNodePtr a_node)
{
	char *since_epoch = (char*)ha_malloc(128*(sizeof(char)));
	FNIN();
	sprintf(since_epoch, "%ld", (unsigned long)time(NULL));
	set_xml_property_copy(a_node, XML_ATTR_TSTAMP, since_epoch);
	ha_free(since_epoch);
}


xmlNodePtr
copy_xml_node_recursive(xmlNodePtr src_node, int recursive)
{
#if XML_TRACE
	const char *local_name = NULL;
	xmlNodePtr local_node = NULL, node_iter = NULL, local_child = NULL;
	xmlAttrPtr prop_iter = NULL;

	FNIN();
	
	if(src_node != NULL && src_node->name != NULL) {
		local_node = create_xml_node(NULL, src_node->name);

		prop_iter = src_node->properties;
		while(prop_iter != NULL) {
			const char *local_prop_name = prop_iter->name;
			const char *local_prop_value =
				xmlGetProp(src_node, local_prop_name);

			set_xml_property_copy(local_node,
					      local_prop_name,
					      local_prop_value);
			
			prop_iter = prop_iter->next;
			
		}

		node_iter = src_node->children;
		while(node_iter != NULL) {
			local_child = copy_xml_node_recursive(node_iter, 1);
			if(local_child != NULL) {
				xmlAddChild(local_node, local_child);
				CRM_DEBUG3("Copied node [%s [%s]", local_name, local_child->name);
			} 				
			node_iter = node_iter->next;
		}

		CRM_DEBUG2("Returning [%s]", local_node->name);
		FNRET(local_node);
	}

	CRM_DEBUG("Returning null");
	FNRET(NULL);
#else
	return xmlCopyNode(src_node, recursive);
#endif
}


xmlNodePtr
string2xml(const char *input)
{
	char ch = 0;
	int lpc = 0, input_len = strlen(input);
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	
	for(lpc = 0; (lpc < input_len) && more; lpc++) {
		ch = input[lpc];
		switch(ch) {
			case EOF: 
			case 0:
				ch = 0;
				more = FALSE; 
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '>':
			case '<':
				inTag = TRUE;
				if(ch == '>') inTag = FALSE;
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '\n':
			case '\t':
			case ' ':
				ch = ' ';
				if(inTag) {
					xmlBufferAdd(xml_buffer, &ch, 1);
				} 
				break;
			default:
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
		}
	}

	
	xmlNodePtr xml_object = NULL;
	const char *the_xml = xmlBufferContent(xml_buffer);
	xmlDocPtr doc = xmlParseMemory(the_xml, strlen(the_xml));
	if (doc == NULL) {
		cl_log(LOG_ERR, "Malformed XML [xml=%s]", the_xml);
		return NULL;
	}
	xml_object = xmlDocGetRootElement(doc);

	xml_message_debug(xml_object, "Created fragment");

	return xml_object;
}

xmlNodePtr
file2xml(FILE *input)
{
	char ch = 0;
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	
	while (more) {
		ch = fgetc(input);
//		cl_log(LOG_DEBUG, "Got [%c]", ch);
		switch(ch) {
			case EOF: 
			case 0:
				ch = 0;
				more = FALSE; 
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '>':
			case '<':
				inTag = TRUE;
				if(ch == '>') inTag = FALSE;
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
			case '\n':
			case '\t':
			case ' ':
				ch = ' ';
				if(inTag) {
					xmlBufferAdd(xml_buffer, &ch, 1);
				} 
				break;
			default:
				xmlBufferAdd(xml_buffer, &ch, 1);
				break;
		}
	}

	
	xmlNodePtr xml_object = NULL;
	const char *the_xml = xmlBufferContent(xml_buffer);
	xmlDocPtr doc = xmlParseMemory(the_xml, strlen(the_xml));
	if (doc == NULL) {
		cl_log(LOG_ERR, "Malformed XML [xml=%s]", the_xml);
		return NULL;
	}
	xml_object = xmlDocGetRootElement(doc);

	xml_message_debug(xml_object, "Created fragment");

	return xml_object;
}
