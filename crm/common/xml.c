/* $Id: xml.c,v 1.10 2004/08/30 03:17:38 msoffen Exp $ */
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
find_xml_node(xmlNodePtr root, const char * search_path)
{
	if(search_path == NULL) {
		crm_warn("Will never find <NULL>");
		return NULL;
	}
	
	xml_child_iter(
		root, a_child, search_path,
		crm_trace("returning node (%s).", xmlGetNodePath(a_child));
		crm_trace("contents\t%s", dump_xml_node(a_child, FALSE));
		crm_trace("found in\t%s", dump_xml_node(root, FALSE));
		return a_child;
		);

	crm_warn("Could not find %s in %s.", search_path, xmlGetNodePath(root));
	return NULL;
}

xmlNodePtr
find_xml_node_nested(xmlNodePtr root, const char **search_path, int len)
{
	int	j;
	gboolean is_found = TRUE;
	xmlNodePtr match =  NULL;
	xmlNodePtr lastMatch = root;
	
	if(search_path == NULL || search_path[0] == NULL) {
		crm_warn("Will never find NULL");
		return NULL;
	}
	
	dump_array(LOG_TRACE, "Looking for.", search_path, len);

	for (j=0; j < len; ++j) {
		if (search_path[j] == NULL) {
/* a NULL also means stop searching */
			break;
		}

		match = find_xml_node(lastMatch, search_path[j]);
		if(match == NULL) {
			is_found = FALSE;
			break;
		} else {
			lastMatch = match;
		}
	}

	if (is_found) {
		crm_trace("returning node (%s).",
			   xmlGetNodePath(lastMatch));

		crm_trace("found\t%s", dump_xml_node(lastMatch, FALSE));
		crm_trace("in \t%s", dump_xml_node(root, FALSE));
		
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
		/* get it from the current node */
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
set_xml_attr(
	xmlNodePtr parent,
	const char *node_name, const char *attr_name, const char *attr_value,
	gboolean create)
{
	xmlNodePtr node = parent;
	xmlAttrPtr result = NULL;
	
	if(node_name != NULL) {
		crm_trace("Setting %s=%s at [%s [%s]]",
			  attr_name, attr_value,
			  xmlGetNodePath(parent), node_name);
		node = find_xml_node(parent, node_name);
		if(node == NULL && create) {
			node = create_xml_node(parent, node_name);
			if(parent == NULL) {
				parent = node;
			}
		}
	}

	if(node == NULL) {
		crm_warn("Can not set attribute on NULL node");
		return NULL;
	} 

	result = set_xml_property_copy(node, attr_name, attr_value);
	if(result == NULL) {
		crm_warn("Could not set %s=%s at %s (found in %s)",
			 attr_name, attr_value,
			 xmlGetNodePath(node), xmlGetNodePath(parent));
	}

	return parent;
}

xmlNodePtr
find_entity(xmlNodePtr parent,
	    const char *node_name,
	    const char *id,
	    gboolean siblings)
{
	while(parent != NULL) {
		xml_child_iter(
			parent, a_child, node_name,
			if(id == NULL || safe_str_eq(id, xmlGetProp(a_child, XML_ATTR_ID))) {
				crm_debug("returning node (%s).", xmlGetNodePath(a_child));
				return a_child;
			}
			);
		if(siblings) {
			parent = parent->next;
		} else {
			break;
		}
	}
	crm_warn("node <%s id=%s> not found in %s.", node_name, id, xmlGetNodePath(parent));
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
			xmlNodePtr top = msg;
/* 			while(top->parent != NULL) { */
/* 				top = top->parent; */
/* 			} */
			xmlDocPtr foo = xmlNewDoc("1.0");
			xmlDocSetRootElement(foo, top);
			xmlSetTreeDoc(top,foo);
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
	
	/*  HA wont send messages with newlines in them. */
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
		; /*  nothing to do */
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
/* 		crm_debug("Got [%c]", ch); */
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
	xmlDocPtr foo = NULL;
	char now_str[26];
	time_t now;

	crm_debug("Writing XML out to %s", filename);
	
	if (xml_node == NULL) {
		return -1;
		
	} else if (xml_node->doc == NULL) {
		crm_trace("Creating doc pointer for %s", xml_node->name);
		foo = xmlNewDoc("1.0");
		xmlDocSetRootElement(foo, xml_node);
		xmlSetTreeDoc(xml_node, foo);
	}

	now = time(NULL);
	ctime_r(&now, now_str);
	set_xml_property_copy(xml_node, "last_written",now_str);

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
	xmlDocPtr foo = NULL;

	xmlNodePtr xml_node = copy_xml_node_recursive(an_xml_node);
	
	if (xml_node == NULL) {
		return;
		
	} else if (xml_node->doc == NULL) {
		crm_trace("Creating doc pointer for %s", xml_node->name);
		foo = xmlNewDoc("1.0");
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
