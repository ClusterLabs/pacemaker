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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/tree.h>
#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 

#include <crm.h>
#include <xmlutils.h>
#include <xmltags.h>

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

    CRM_DEBUG("looking for...");
    for (j=0; j < len; ++j) {
		if (search_path[j] == NULL) break;
		CRM_DEBUG2(" --> (%s).", search_path[j]);
    }
    
    xmlNodePtr child = root->children, lastMatch = NULL;
    for (j=0; j < len; ++j) {
		gboolean is_found = FALSE;
		if (search_path[j] == NULL) break;
	
		while(child != NULL) {
			const char * child_name = (const char*)child->name;
			CRM_DEBUG3("comparing (%s) with (%s).",
					   search_path[j],
					   child->name);
			if (strcmp(child_name, search_path[j]) == 0) {
				lastMatch = child;
				child = lastMatch->children;
				CRM_DEBUG3("found node (%s) @line (%ld).",
						   search_path[j],
						   xmlGetLineNo(child));
				is_found = TRUE;
				break;
			}
			child = child->next;
		}
		if (is_found == FALSE) {
			CRM_DEBUG2("No more siblings left... %s cannot be found.",
					   search_path[j]);
			break;
		}
    }

    if (j == len
	   && lastMatch != NULL
	   && strcmp(lastMatch->name, search_path[j-1]) == 0) {
		CRM_DEBUG2("returning node (%s).", xmlGetNodePath(lastMatch));
		FNRET(lastMatch);
    }

    cl_log(LOG_DEBUG,
		   "Could not find the full path to the node you specified."
		   "  Closest point was node (%s).", xmlGetNodePath(lastMatch));

    FNRET(NULL);
    
}

xmlNodePtr
find_xml_node(xmlNodePtr root, const char * search_path)
{
    return find_xml_node_nested(root, &search_path, 1);
}

xmlNodePtr
find_entity(xmlNodePtr parent,
			const char *node_name,
			const char *id,
			gboolean siblings)
{
    return find_entity_nested(parent, node_name, NULL, NULL, id, siblings);
}

xmlNodePtr
find_entity_nested(xmlNodePtr parent,
				   const char *node_name,
				   const char *elem_filter_name,
				   const char *elem_filter_value,
				   const char *id,
				   gboolean siblings)
{
    /* debug tools:
	 * xmlChar *	xmlGetNodePath		(xmlNodePtr node);
	 * long		xmlGetLineNo		(xmlNodePtr node);
	 */


    xmlNodePtr child;
	FNIN();
    cl_log(LOG_DEBUG, "Looking for %s elem with id=%s.", node_name, id);

    while(parent != NULL) {
		CRM_DEBUG2("examining (%s).", xmlGetNodePath(parent));
		child = parent->children;
	
		while(child != NULL) {
			CRM_DEBUG2("looking for (%s) [name].", node_name);
			if (node_name != NULL && strcmp(child->name, node_name) != 0) {    
				CRM_DEBUG3("skipping entity (%s=%s) [node_name].",
						   xmlGetNodePath(child), child->name);
				break;
			} else if (elem_filter_name != NULL && elem_filter_value != NULL) {
				const char* child_value = (const char*)
					xmlGetProp(child, elem_filter_name);
				
				cl_log(LOG_DEBUG, "comparing (%s) with (%s) [attr_value].",
					   child_value, elem_filter_value);
				if (strcmp(child_value, elem_filter_value)) {
					CRM_DEBUG2("skipping entity (%s) [attr_value].",
							   xmlGetNodePath(child));
					break;
				}
			}
		
//	    cl_log(LOG_DEBUG, "looking for entity (%s) in %s.", id, xmlGetNodePath(child));
			while(child != NULL) {
				cl_log(LOG_DEBUG, "looking for entity (%s) in %s.",
					   id, xmlGetNodePath(child));
				xmlChar *child_id = xmlGetProp(child, "id");
				if (child_id == NULL) {
					cl_log(LOG_CRIT,
						   "Entity (%s) has id=NULL... Cib not valid!",
						   xmlGetNodePath(child));
				} else if (strcmp(id, child_id) == 0) {
					CRM_DEBUG2("found entity (%s).", id);
					FNRET(child);
				}   
				child = child->next;
			}
		}

		if (siblings == TRUE) {
			CRM_DEBUG("Nothing yet... checking siblings");	    
			parent = parent->next;
		} else
			parent = NULL;
    }
    CRM_DEBUG("Couldnt find anything appropriate");	    
	FNRET(NULL);
}


int
add_xmlnode_to_cib(xmlNodePtr cib,
				   const char *node_path,
				   xmlNodePtr xml_node)
{
	int ret = -1;
    xmlNodePtr parent = NULL;
	FNIN();
	
	parent = find_xml_node(cib, node_path);

    if (parent == NULL) {
		CRM_DEBUG2("could not find parent for new node (%s).",
				   xml_node->name);
		ret = -2;
    } else if (xmlAddChild(parent, xml_node) != NULL) {
		ret = 0;
	}

	FNRET(ret);
}

void
copy_in_properties(xmlNodePtr src, xmlNodePtr target)
{
	FNIN();
    xmlCopyPropList(target, src->properties);
	FNOUT();
}

// remove this function ?
xmlNodePtr
xmlLinkedCopyNoSiblings(xmlNodePtr src, int recursive)
{
    xmlNodePtr node_copy = NULL;
	FNIN();
    /*
     * keep the properties linked so there is only one point of update
     *   but we dont want the sibling pointers
     */
	node_copy = xmlCopyNode(src, recursive);
    //node_copy->properties = src->properties;
    FNRET(node_copy);
}

char * 
dump_xml(xmlNodePtr msg)
{
	FNIN();
    FNRET(dump_xml_node(msg, FALSE));
}

void
xml_message_debug(xmlNodePtr msg)
{
	FNIN();
    char *msg_buffer = dump_xml_node(msg, FALSE);
    CRM_DEBUG2("Dumping xml message: %s", msg_buffer);
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
			cl_log(LOG_ERR, "XML doc was NULL");
			FNRET(NULL);
		}
		xmlDocDumpMemory(msg->doc, &xml_message, &msg_size);
    } else {
		CRM_DEBUG2("mem used by xml: %d", xmlMemUsed());
    
		xmlMemoryDump ();
	
		xmlBufferPtr xml_buffer = xmlBufferCreate();
		CRM_DEBUG("About to dump XML into buffer");
		msg_size = xmlNodeDump(xml_buffer, msg->doc, msg, 0, 0);

		//CRM_DEBUG2("Dumped XML into buffer: [%s]", xmlBufferContent(xml_buffer));
		CRM_DEBUG2("Dumped %d XML characters into buffer", msg_size);
	
		xml_message = (xmlChar*)ha_strdup(xmlBufferContent(xml_buffer)); 
		xmlBufferFree(xml_buffer);

		if (!xml_message) {
			cl_log(LOG_ERR, "memory allocation failed in dump_xml_node()");
		}
	}

    // HA wont send messages with newlines in them.
    for(; xml_message != NULL && lpc < msg_size; lpc++)
		if (xml_message[lpc] == '\n')
			xml_message[lpc] = ' ';
    
    FNRET((char*)xml_message); 
}

int
add_node_copy(xmlNodePtr cib, const char *node_path, xmlNodePtr xml_node)
{
	int ret = -1;
	xmlNodePtr node_copy = NULL;
	
	FNIN();
    node_copy = xmlCopyNode(xml_node, 1);
    ret = add_xmlnode_to_cib(cib, node_path, node_copy);
	FNRET(ret);
}

xmlAttrPtr
set_xml_property_copy(xmlNodePtr node,
					  const xmlChar *name,
					  const xmlChar *value)
{
	const char *local_name = NULL;
	const char *local_value = NULL;

	xmlAttrPtr ret_value = NULL;
	FNIN();

	CRM_DEBUG3("Attempting to set %s to %s", name, value);

	if (name == NULL)
		ret_value = NULL;
    else {
		if (value == NULL)
			local_value = "";
		else
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
	xmlNodePtr ret_value = NULL;
	FNIN();

	CRM_DEBUG2("Attempting create node set %s", name);

	if (name == NULL)
		ret_value = NULL;
    else {
		local_name = ha_strdup(name);

		if(parent == NULL)
			ret_value = xmlNewNode(NULL, local_name);
		else
			ret_value = xmlNewChild(parent, NULL, local_name, NULL);
	}
	
	FNRET(ret_value);
}

xmlNodePtr
create_xml_doc_node(xmlDocPtr parent, const char *name)
{
	const char *local_name = NULL;
	xmlNodePtr ret_value = NULL;
	FNIN();

	CRM_DEBUG2("Attempting create node set %s", name);

	if (parent == NULL || name == NULL)
		ret_value = NULL;
    else {
		local_name = ha_strdup(name);
		ret_value = xmlNewDocNode(parent, NULL, local_name, NULL);
	}
	
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
		xmlDocPtr foo = xmlNewDoc("1.0");
		xmlSetTreeDoc(a_node,foo);

		CRM_DEBUG2("new doc %s ", dump_xml(xmlDocGetRootElement(foo)));
		xmlFreeNode(a_node);
		xmlFreeDoc(foo);
	}
	
	FNOUT();
}
