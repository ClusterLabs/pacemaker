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

// all manipulations should be done in and on the XML Doc


#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm.h>
//#include <crmutils.h>
#include <xmlutils.h>
#include <xmltags.h>

/* int		xmlGetDocCompressMode	(xmlDocPtr doc); */
/* void		xmlSetDocCompressMode	(xmlDocPtr doc, */
/* 					 int mode); */
/* int		xmlGetCompressMode	(void); */
/* void		xmlSetCompressMode	(int mode); */

/* void		xmlDocDumpMemory	(xmlDocPtr cur, */
/* 					 xmlChar **mem, */
/* 					 int *size); */

/* int		xmlNodeDump		(xmlBufferPtr buf, */
/* 					 xmlDocPtr doc, */
/* 					 xmlNodePtr cur, */
/* 					 int level, */
/* 					 int format); */

xmlNodePtr
find_xmlnode_nested(xmlNodePtr root, const char **search_path, int len)
{
    // debug tools:
    // xmlChar *	xmlGetNodePath		(xmlNodePtr node);
    // long		xmlGetLineNo		(xmlNodePtr node);

    if(root == NULL)
    {
	CRM_DEBUG("Will never find anything in NULL :)");
	return NULL;
    }
    int	j;
    CRM_DEBUG("looking for...");
    for (j=0; j < len; ++j)
    {
	if(search_path[j] == NULL) break;
	CRM_DEBUG2(" --> (%s).", search_path[j]);
    }
    
    xmlNodePtr child = root->children, lastMatch = NULL;
    for (j=0; j < len; ++j)
    {
	gboolean is_found = FALSE;
	if(search_path[j] == NULL) break;
	
	while(child != NULL)
	{
	    const char * child_name = (const char*)child->name;
	    CRM_DEBUG3("comparing (%s) with (%s).", search_path[j], child->name);
	    if(strcmp(child_name, search_path[j]) == 0)
	    {
		lastMatch = child;
		child = lastMatch->children;
		CRM_DEBUG3("found node (%s) @line (%ld).", search_path[j], xmlGetLineNo(child));
		is_found = TRUE;
		break;
	    }
	    child = child->next;
	}
	if(is_found == FALSE)
	{
	    CRM_DEBUG2("No more siblings left... %s cannot be found.", search_path[j]);
	    break;
	}
    }

    if(j == len && lastMatch != NULL && strcmp(lastMatch->name, search_path[j-1]) == 0)
    {
	CRM_DEBUG2("returning node (%s).", xmlGetNodePath(lastMatch));
	return lastMatch;
    }

    cl_log(LOG_DEBUG,
	   "Could not find the full path to the node you specified."
	   "  Closest point was node (%s).", xmlGetNodePath(lastMatch));
    return NULL;
    
}

xmlNodePtr
find_xmlnode(xmlNodePtr root, const char * search_path)
{
    return find_xmlnode_nested(root, &search_path, 1);
}

xmlNodePtr
find_entity(xmlNodePtr parent, const char *node_name, const char *id, gboolean siblings)
{
    return find_entity_nested(parent, node_name, NULL, NULL, id, siblings);
}

xmlNodePtr
find_entity_nested(xmlNodePtr parent, const char *node_name, const char *elem_filter_name, const char *elem_filter_value, const char *id, gboolean siblings)
{
    // debug tools:
    // xmlChar *	xmlGetNodePath		(xmlNodePtr node);
    // long		xmlGetLineNo		(xmlNodePtr node);

    cl_log(LOG_DEBUG, "Looking for %s elem with id=%s.", node_name, id);

    xmlNodePtr child;

    while(parent != NULL)
    {
	CRM_DEBUG2("examining (%s).", xmlGetNodePath(parent));
	child = parent->children;
	
	while(child != NULL)
	{
	    
	    CRM_DEBUG2("looking for (%s) [name].", node_name);
	    if(node_name != NULL && strcmp(child->name, node_name) != 0)
	    {    
		CRM_DEBUG3("skipping entity (%s=%s) [node_name].", xmlGetNodePath(child), child->name);
		break;
	    }
	    else if(elem_filter_name != NULL && elem_filter_value != NULL)
	    {
		const char* child_value = (const char*)xmlGetProp(child, elem_filter_name);
		cl_log(LOG_DEBUG, "comparing (%s) with (%s) [attr_value].", child_value, elem_filter_value);
		if(strcmp(child_value, elem_filter_value))
		{
		    CRM_DEBUG2("skipping entity (%s) [attr_value].", xmlGetNodePath(child));
		    break;
		}
	    }
		
//	    cl_log(LOG_DEBUG, "looking for entity (%s) in %s.", id, xmlGetNodePath(child));
	    while(child != NULL)
	    {
		cl_log(LOG_DEBUG, "looking for entity (%s) in %s.", id, xmlGetNodePath(child));
		xmlChar *child_id = xmlGetProp(child, "id");
		if(child_id == NULL)
		{
		    cl_log(LOG_CRIT, "Entity (%s) has id=NULL... Cib not valid!", xmlGetNodePath(child));
		}
		else if(strcmp(id, child_id) == 0)
		{
		    CRM_DEBUG2("found entity (%s).", id);
		    return child;
		}   
		child = child->next;
	    }
	}

	if(siblings == TRUE)
	{
	    CRM_DEBUG("Nothing yet... checking siblings");	    
	    parent = parent->next;
	}
	else
	    parent = NULL;
    }
    CRM_DEBUG("Couldnt find anything appropriate");	    
    return NULL;
    
}


int
add_xmlnode_to_cib(xmlNodePtr cib, const char *node_path, xmlNodePtr xml_node)
{
    xmlNodePtr parent = find_xmlnode(cib, node_path);

    if(parent == NULL)
    {
	CRM_DEBUG2("could not find parent for new node (%s).", xml_node->name);
	return -1;
    }
    
    if(xmlAddChild(parent, xml_node) != NULL)
	return 0;

    return -2;
}

void
copy_in_properties(xmlNodePtr src, xmlNodePtr target)
{
#if 0
    xmlAttrPtr property = src->properties;
    char *node_id = xmlGetProp(src, "id");
    while(property != NULL)
    {
	cl_log(LOG_DEBUG, "Update: (%s) with property:value (%s:%s)", node_id, property->name, xmlGetProp(src, property->name));
	set_xml_property_copy(target, property->name, xmlGetProp(src, property->name));
	property = property->next;
    }
#else
    xmlCopyPropList(target, src->properties);
#endif
}


xmlNodePtr
xmlLinkedCopyNoSiblings(xmlNodePtr src, int recursive)
{
    /*
     * keep the properties linked so there is only one point of update
     *   but we dont want the sibling pointers
     */
    xmlNodePtr node_copy = xmlCopyNode(src, recursive);
    //node_copy->properties = src->properties;
    return node_copy;
}

char * 
dump_xml(xmlNodePtr msg)
{
    return dump_xml_node(msg, FALSE);
}

void
xml_message_debug(xmlNodePtr msg)
{
    char *msg_buffer = dump_xml_node(msg, FALSE);
    CRM_DEBUG2("Dumping xml message: %s", msg_buffer);
//    ha_free(msg_buffer);
}



char * 
dump_xml_node(xmlNodePtr msg, gboolean whole_doc)
{
    CRM_DEBUG("delete me - 2.");
    xmlChar *xml_message = NULL;
    if(msg == NULL) return NULL;

    int msg_size = -1;
    xmlInitParser();

    if(whole_doc)
    {
	if(msg->doc == NULL)
	{
	    cl_log(LOG_ERR, "XML doc was NULL");
	    return NULL;
	}
	xmlDocDumpMemory(msg->doc, &xml_message, &msg_size);
    }
    else
    {
	CRM_DEBUG2("mem used by xml: %d", xmlMemUsed());
    
	xmlMemoryDump ();
	
	xmlBufferPtr xml_buffer = xmlBufferCreate();
	CRM_DEBUG("About to dump XML into buffer");
	msg_size = xmlNodeDump(xml_buffer, msg->doc, msg, 0, 0);

	CRM_DEBUG2("Dumped XML into buffer: [%s]", xmlBufferContent(xml_buffer));
	
	xml_message = (xmlChar*)strdup((char*)xml_buffer->content); 
	if(!xml_message) {
		cl_log(LOG_ERR, "memory allocation failed in dump_xml_node()");
		return NULL;
	}
	
//	CRM_DEBUG2("Before free: [%s]", xml_message);
	xmlBufferFree(xml_buffer);
//	CRM_DEBUG2("After free: [%s]", xml_message);
    }
    CRM_DEBUG2("Dumped %d XML characters into buffer", msg_size);

    // HA wont send messages with newlines in them.
    int lpc = 0;
    for(; lpc < msg_size; lpc++)
	if(xml_message[lpc] == '\n')
	    xml_message[lpc] = ' ';
    
    return (char*)xml_message; 
}


void
free_xml(xmlNodePtr a_node)
{
    if(a_node == NULL)
	; // nothing to do
    else if(a_node->doc != NULL)
	;// not just yet: xmlFreeDoc(a_node->doc);
    else
	;// not just yet: xmlFreeNode(a_node);
}


int
add_node_copy(xmlNodePtr cib, const char *node_path, xmlNodePtr xml_node)
{
    xmlNodePtr node_copy = xmlCopyNode(xml_node, 1);
    return add_xmlnode_to_cib(cib, node_path, node_copy);
}

    

xmlAttrPtr
set_xml_property_copy(xmlNodePtr node, const xmlChar *name, const xmlChar *value)
{
    if(name == NULL) return NULL;
    else if(value == NULL) return xmlSetProp(node, strdup(name),NULL);
    return xmlSetProp(node, strdup(name), strdup(value));
}
