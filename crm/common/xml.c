/* $Id: xml.c,v 1.7 2004/07/30 15:31:05 andrew Exp $ */
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

#include <sys/param.h>
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
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/dmalloc_wrapper.h>

void dump_array(int log_level, const char *message,
		const char **array, int depth);


xmlNodePtr
find_xml_node_nested(xmlNodePtr root, const char **search_path, int len)
{
	int	j;
	xmlNodePtr child;
	xmlNodePtr lastMatch;
	

	if (root == NULL) {
		return NULL;
	}

	if(search_path == NULL) {
		crm_trace("Will never find NULL");
		return NULL;
	}
	
	
	dump_array(LOG_TRACE,
		   "Looking for.",
		   search_path, len);
	child = root->children, lastMatch = NULL;
	for (j=0; j < len; ++j) {
		gboolean is_found = FALSE;
		if (search_path[j] == NULL) {
			len = j; /* a NULL also means stop searching */
			break;
		}
		
		while(child != NULL) {
			const char * child_name = (const char*)child->name;
			crm_trace("comparing (%s) with (%s).",
				   search_path[j],
				   child->name);
			if (strcmp(child_name, search_path[j]) == 0) {
				lastMatch = child;
				child = lastMatch->children;
				crm_trace("found node (%s) @line (%ld).",
					   search_path[j],
					   xmlGetLineNo(child));
				is_found = TRUE;
				break;
			}
			child = child->next;
		}
		if (is_found == FALSE) {
			crm_trace("No more siblings left... %s cannot be found.",
				search_path[j]);
			break;
		}
	}

	if (j == len
	    && lastMatch != NULL
	    && strcmp(lastMatch->name, search_path[j-1]) == 0) {
		crm_trace("returning node (%s).",
			   xmlGetNodePath(lastMatch));
		return lastMatch;
	}

	dump_array(LOG_WARNING,
		   "Could not find the full path to the node you specified.",
		   search_path, len);

	crm_warn("Closest point was node (%s) starting from %s.",
	       xmlGetNodePath(lastMatch), root?root->name:NULL);

	return NULL;
    
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
		crm_err("Can not find attribute %s in NULL parent",
		       attr_name);
		return NULL;
	} 

	if(attr_name == NULL || strlen(attr_name) == 0) {
		crm_err("Can not find attribute with no name in %s",
		       xmlGetNodePath(parent));
		return NULL;
	}
	
	if(length == 0) {
		attr_parent = parent;
		
	} else {
		attr_parent = find_xml_node_nested(parent, node_path, length);
		if(attr_parent == NULL && error) {
			crm_err("No node at the path you specified.");
			return NULL;
		}
	}
	
	attr_value = xmlGetProp(attr_parent, attr_name);
	if((attr_value == NULL || strlen(attr_value) == 0) && error) {
		crm_err(
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
	xmlNodePtr tmp;

	if(parent == NULL && create == FALSE) {
		crm_err("Can not set attribute in NULL parent");
		return NULL;
	} 

	if(attr_name == NULL || strlen(attr_name) == 0) {
		crm_err("Can not set attribute to %s with no name",
		       attr_value);
		return NULL;
	}


	if(length == 0 && parent != NULL) {
		attr_parent = parent;

	} else if(length == 0 || node_path == NULL
		  || *node_path == NULL || strlen(*node_path) == 0) {
		crm_err(
		       "Can not create parent to set attribute %s=%s on",
		       attr_name, attr_value);
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
			
			tmp =
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
		crm_err("Can not find parent to set attribute on");
		return NULL;
		
	}
	
	result = set_xml_property_copy(attr_parent, attr_name, attr_value);
	if(result == NULL) {
		crm_warn(
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
	xmlChar *child_id = NULL;
	
	crm_trace("Looking for %s elem with id=%s.", node_name, id);
	while(parent != NULL) {
		crm_trace("examining (%s).", xmlGetNodePath(parent));
		child = parent->children;
	
		while(child != NULL) {
			crm_trace("looking for (%s) [name].", node_name);
			if (node_name != NULL
			    && strcmp(child->name, node_name) != 0) {    
				crm_trace(
					"skipping entity (%s=%s) [node_name].",
					xmlGetNodePath(child), child->name);
				break;
			} else if (elem_filter_name != NULL
				   && elem_filter_value != NULL) {
				const char* child_value = (const char*)
					xmlGetProp(child, elem_filter_name);
				
				crm_trace(
				       "comparing (%s) with (%s) [attr_value].",
				       child_value, elem_filter_value);
				if (strcmp(child_value, elem_filter_value)) {
					crm_trace("skipping entity (%s) [attr_value].",
						   xmlGetNodePath(child));
					break;
				}
			}
		
			crm_trace(
			       "looking for entity (%s) in %s.",
			       id, xmlGetNodePath(child));
			while(child != NULL) {
				crm_trace(
				       "looking for entity (%s) in %s.",
				       id, xmlGetNodePath(child));
				child_id = xmlGetProp(child, XML_ATTR_ID);

				if (child_id == NULL) {
					crm_crit(
					       "Entity (%s) has id=NULL..."
					       "Cib not valid!",
					       xmlGetNodePath(child));
				} else if (strcmp(id, child_id) == 0) {
					crm_trace("found entity (%s).", id);
					return child;
				}   
				child = child->next;
			}
		}

		if (siblings == TRUE) {
			crm_trace("Nothing yet... checking siblings");	    
			parent = parent->next;
		} else
			parent = NULL;
	}
	crm_info(
	       "Couldnt find anything appropriate for %s elem with id=%s.",
	       node_name, id);	    
	return NULL;
}


void
copy_in_properties(xmlNodePtr target, xmlNodePtr src)
{
	if(src == NULL) {
		crm_err("No node to copy properties from");
	} else if (src->properties == NULL) {
		crm_info("No properties to copy");
	} else if (target == NULL) {
		crm_err("No node to copy properties into");
	} else {
#ifndef USE_BUGGY_LIBXML
		xmlAttrPtr prop_iter = NULL;
		
		
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
	
	return;
}

char * 
dump_xml(xmlNodePtr msg)
{
	
	return dump_xml_node(msg, FALSE);
}

void
xml_message_debug(xmlNodePtr msg, const char *text)
{
	char *msg_buffer;

	
	if(msg == NULL) {
		crm_verbose("%s: %s",
		   text==NULL?"<null>":text,"<null>");
		
		return;
	}
	
	msg_buffer = dump_xml_node(msg, FALSE);
	crm_verbose("%s: %s",
		   text==NULL?"<null>":text,
		   msg_buffer==NULL?"<null>":msg_buffer);
	crm_free(msg_buffer);
	return;
}

char * 
dump_xml_node(xmlNodePtr msg, gboolean whole_doc)
{
	int lpc = 0;
	int msg_size = -1;
	xmlChar *xml_message = NULL;
	xmlBufferPtr xml_buffer;

	
	if (msg == NULL) return NULL;

	xmlInitParser();

	if (whole_doc) {
		if (msg->doc == NULL) {
			xmlDocPtr foo = xmlNewDoc("1.0");
			xmlDocSetRootElement(foo, msg);
			xmlSetTreeDoc(msg,foo);
		}
		xmlDocDumpMemory(msg->doc, &xml_message, &msg_size);
	} else {
		crm_trace("mem used by xml: %d", xmlMemUsed());
		xmlMemoryDump ();
	
		xml_buffer = xmlBufferCreate();
		msg_size = xmlNodeDump(xml_buffer, msg->doc, msg, 0, 0);

		xml_message =
			(xmlChar*)crm_strdup(xmlBufferContent(xml_buffer)); 
		xmlBufferFree(xml_buffer);

		if (!xml_message) {
			crm_err(
			       "memory allocation failed in dump_xml_node()");
		}
	}

	xmlCleanupParser();
	
	// HA wont send messages with newlines in them.
	for(; xml_message != NULL && lpc < msg_size; lpc++)
		if (xml_message[lpc] == '\n')
			xml_message[lpc] = ' ';
    
	return (char*)xml_message; 
}

xmlNodePtr
add_node_copy(xmlNodePtr new_parent, xmlNodePtr xml_node)
{
	xmlNodePtr node_copy = NULL;

	if(xml_node != NULL && new_parent != NULL) {
		node_copy = copy_xml_node_recursive(xml_node);
		xmlAddChild(new_parent, node_copy);

	} else if(xml_node == NULL) {
		crm_err("Could not add copy of NULL node");

	} else {
		crm_err("Could not add copy of node to NULL parent");
	}
	
	return node_copy;
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
	

	if(node != NULL) {
		parent_name = node->name;
	}

	
	crm_trace("[%s] Setting %s to %s", parent_name, name, value);
	if (name == NULL || strlen(name) <= 0) {
		ret_value = NULL;
		
	} else if(node == NULL) {
		ret_value = NULL;
		
	} else if (value == NULL || strlen(value) <= 0) {
		ret_value = NULL;
		xmlUnsetProp(node, local_name);
		
	} else {
		local_value = crm_strdup(value);
		local_name = crm_strdup(name);
		ret_value = xmlSetProp(node, local_name, local_value);
	}
	
	return ret_value;
}

xmlNodePtr
create_xml_node(xmlNodePtr parent, const char *name)
{
	const char *local_name = NULL;
	const char *parent_name = NULL;
	xmlNodePtr ret_value = NULL;
	

	if (name == NULL || strlen(name) < 1) {
		ret_value = NULL;
	} else {
		local_name = crm_strdup(name);

		if(parent == NULL) 
			ret_value = xmlNewNode(NULL, local_name);
		else {
			parent_name = parent->name;
			ret_value =
				xmlNewChild(parent, NULL, local_name, NULL);
		}
	}

	crm_trace("Created node [%s [%s]]", parent_name, local_name);
	return ret_value;
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
	
	if (a_node == NULL)
		; // nothing to do
	else if (a_node->doc != NULL)
		xmlFreeDoc(a_node->doc);
	else
	{
		/* make sure the node is unlinked first */
		xmlUnlinkNode(a_node);
		xmlFreeNode(a_node);
	}
	
	return;
}

void
set_node_tstamp(xmlNodePtr a_node)
{
	char *since_epoch = (char*)crm_malloc(128*(sizeof(char)));
	
	sprintf(since_epoch, "%ld", (unsigned long)time(NULL));
	set_xml_property_copy(a_node, XML_ATTR_TSTAMP, since_epoch);
	crm_free(since_epoch);
}

xmlNodePtr
find_entity_recursive(xmlNodePtr xml_node,
		      const char *node_name,
		      const char *elem_filter_name,
		      const char *elem_filter_value,
		      const char *id,
		      gboolean all)
{
	gboolean match = TRUE;
	xmlNodePtr local_node = NULL, node_iter = NULL, local_child = NULL;
	if(xml_node == NULL) {
		return NULL;
	}
	
	if(node_name != NULL
	   && safe_str_neq((const char *)xml_node->name, node_name)) {
		crm_devel("entity (%s) did not match node->name %s.",
			  xmlGetNodePath(xml_node), xml_node->name);
		match = FALSE;
	}

	if(match
	   && id != NULL
	   && safe_str_neq((const char*)xmlGetProp(xml_node, XML_ATTR_ID), id)) {
		crm_devel("entity (%s) did not match id %s.",
			  xmlGetNodePath(xml_node), id);
		match = FALSE;
	}

	// check if any other filters apply
	if (match && elem_filter_name != NULL && elem_filter_value != NULL) {
		const char* child_value = (const char*)
			xmlGetProp(xml_node, elem_filter_name);
		
		crm_devel("comparing (%s) with (%s) [attr_value].",
			  child_value, elem_filter_value);

		if (safe_str_neq(child_value, elem_filter_value)) {
			crm_devel("skipping entity (%s) [attr_value].",
				  xmlGetNodePath(xml_node));
			match = FALSE;
		}
	}

	if(match) {
		crm_devel("xml node (%s) matched", xmlGetNodePath(xml_node));
		return copy_xml_node_recursive(xml_node);

	} else if(xml_node != NULL && xml_node->name != NULL) {
		// check our children
		node_iter = xml_node->children;
		crm_devel("Nothing yet... checking children");	    
		while(node_iter != NULL) {

			local_child = find_entity_recursive(
				node_iter, node_name,
				elem_filter_name, elem_filter_value,
				id, all);

			node_iter = node_iter->next;

			if(local_child == NULL) {
				continue;
			}
			
			if(local_node == NULL) {
				local_node = local_child;
				if(all == FALSE) {
					break;
				}
				
			} else {
				xmlAddSibling(local_node, local_child);
			}
		}

		return local_node;
	}

	crm_devel("Couldnt find anything appropriate for %s elem with id=%s.",
		  node_name, id);	    
	return NULL;
}

xmlNodePtr
copy_xml_node_recursive(xmlNodePtr src_node)
{
#if XML_TRACE
	const char *local_name = NULL;
	xmlNodePtr local_node = NULL, node_iter = NULL, local_child = NULL;
	xmlAttrPtr prop_iter = NULL;

	
	
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
			local_child = copy_xml_node_recursive(node_iter);
			if(local_child != NULL) {
				xmlAddChild(local_node, local_child);
				crm_trace("Copied node [%s [%s]", local_name, local_child->name);
			} 				
			node_iter = node_iter->next;
		}

		crm_trace("Returning [%s]", local_node->name);
		return local_node;
	}

	crm_trace("Returning null");
	return NULL;
#else
	return xmlCopyNode(src_node, 1);
#endif
}


xmlNodePtr
string2xml(const char *input)
{
	char ch = 0;
	int lpc = 0, input_len = strlen(input);
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	xmlNodePtr xml_object = NULL;
	const char *the_xml;
	xmlDocPtr doc;

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

	
	xmlInitParser();
	the_xml = xmlBufferContent(xml_buffer);
	doc = xmlParseMemory(the_xml, strlen(the_xml));
	xmlCleanupParser();

	if (doc == NULL) {
		crm_err("Malformed XML [xml=%s]", the_xml);
		xmlBufferFree(xml_buffer);
		return NULL;
	}

	xmlBufferFree(xml_buffer);
	xml_object = xmlDocGetRootElement(doc);

	return xml_object;
}

xmlNodePtr
file2xml(FILE *input)
{
	char ch = 0;
	gboolean more = TRUE;
	gboolean inTag = FALSE;
	xmlNodePtr xml_object = NULL;
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	const char *the_xml;
	xmlDocPtr doc;

	if(input == NULL) {
		crm_err("File pointer was NULL");
		return NULL;
	}
	
	while (more) {
		ch = fgetc(input);
//		crm_debug("Got [%c]", ch);
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

	xmlInitParser();
	the_xml = xmlBufferContent(xml_buffer);
	doc = xmlParseMemory(the_xml, strlen(the_xml));
	xmlCleanupParser();
	
	if (doc == NULL) {
		crm_err("Malformed XML [xml=%s]", the_xml);
		xmlBufferFree(xml_buffer);
		return NULL;
	}
	xmlBufferFree(xml_buffer);
	xml_object = xmlDocGetRootElement(doc);

	xml_message_debug(xml_object, "Created fragment");

	return xml_object;
}

void
dump_array(int log_level, const char *message, const char **array, int depth)
{
	int j;
	
	if(message != NULL) {
		do_crm_log(log_level, __FUNCTION__,  "%s", message);
	}

	do_crm_log(log_level, __FUNCTION__,  "Contents of the array:");
	if(array == NULL || array[0] == NULL || depth == 0) {
		do_crm_log(log_level, __FUNCTION__,  "\t<empty>");
	}
	
	for (j=0; j < depth && array[j] != NULL; j++) {
		if (array[j] == NULL) break;
		do_crm_log(log_level, __FUNCTION__,  "\t--> (%s).", array[j]);
	}
}

int
write_xml_file(xmlNodePtr xml_node, const char *filename) 
{
	int res = 0;
	crm_debug("Writing XML out to %s", filename);
	
	if (xml_node == NULL) {
		return -1;
		
	} else if (xml_node->doc == NULL) {
		crm_trace("Creating doc pointer for %s", xml_node->name);
		xmlDocPtr foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, xml_node);
		xmlSetTreeDoc(xml_node, foo);
	}

	time_t now = time(NULL);
	char *now_str = asctime(localtime(&now));
	set_xml_property_copy(xml_node, "last_written",now_str);
	free(now_str);
	
	/* save it.
	 * set arg 3 to 0 to disable line breaks,1 to enable
	 * res == num bytes saved
	 */
	res = xmlSaveFormatFile(filename, xml_node->doc, 1);
	
	/* for some reason, reading back after saving with
	 * line-breaks doesnt go real well 
	 */
	crm_debug("Saved %d bytes to the Cib as XML", res);

	return res;
}

void
print_xml_formatted(xmlNodePtr an_xml_node) 
{
	int len = 0;
	xmlChar *buffer = NULL;
	xmlNodePtr xml_node = copy_xml_node_recursive(an_xml_node);
	
	if (xml_node == NULL) {
		return;
		
	} else if (xml_node->doc == NULL) {
		crm_trace("Creating doc pointer for %s", xml_node->name);
		xmlDocPtr foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, xml_node);
		xmlSetTreeDoc(xml_node, foo);
	}

	xmlDocDumpFormatMemory(xml_node->doc, &buffer, &len,1);
	
	printf("%s", buffer);
	
	if(buffer != NULL) {
		xmlFree(buffer);
	}

	free_xml(xml_node);
}
