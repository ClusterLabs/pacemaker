/* $Id: cibprimatives.c,v 1.16 2004/03/19 10:43:42 andrew Exp $ */
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

#include <crm/common/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>

#include <libxml/tree.h>

#include <cibprimatives.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/xmlutils.h>
#include <cibio.h>

#include <crm/dmalloc_wrapper.h>


/*
 * In case of confusion, this is the memory management policy for
 *  all functions in this file.
 *
 * All add/modify functions use copies of supplied data.
 * It is therefore appropriate that the callers free the supplied data
 *  at some point after the function has finished.
 *
 * All delete functions will handle the freeing of deleted data
 *  but not the function arguments.
 */


int cib_delete_node(xmlNodePtr node_to_delete);
void handle_object_children(xmlNodePtr new_parent,
			    xmlNodePtr children,
			    const char *filter);
void do_status_update(xmlNodePtr old, cibStatus *new);


//--- Resource

int
addResource(xmlNodePtr cib, cibResource *xml_node)
{
	int add_res = 0;
	const char * id = NULL;
	const char * type = NULL;
	xmlNodePtr new_parent = NULL;

	FNIN();
	
	id = xmlGetProp(xml_node, XML_ATTR_ID);
	type = xmlGetProp(xml_node, XML_CIB_ATTR_RESTYPE);
	
	if (id == NULL || strlen(id) < 1)
		add_res = CIB_ERROR_MISSING_ID;
	else if (findResource(cib, ID(xml_node)) != NULL)
		add_res = CIB_ERROR_EXISTS;
	else if (type == NULL || strlen(type) < 1)
		add_res = CIB_ERROR_MISSING_TYPE;
	else {
		new_parent = get_object_root(XML_CIB_TAG_RESOURCES, cib);

		if(new_parent == NULL) {
			// create it?
			add_res = CIB_ERROR_CORRUPT;
		} else {
			add_node_copy(new_parent, xml_node);
		}
	}

	FNRET(add_res);
}


xmlNodePtr
findResource(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	FNIN();
	
	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	ret = find_entity(root, XML_CIB_TAG_RESOURCE, id, FALSE);

	FNRET(ret);
}

int
updateResource(xmlNodePtr cib, cibResource *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr res = NULL;
	
	FNIN();

	CRM_DEBUG2("Updating " XML_CIB_TAG_RESOURCE " (%s)...",
		   ID(anXmlNode));
    
	res = findResource(cib, id);

	if (res == NULL) {
		CRM_DEBUG2("Update: " XML_CIB_TAG_RESOURCE
			   " (%s) did not exist, adding.",
			   id);
		
		addResource(cib, anXmlNode);
	} else {
		copy_in_properties(res, anXmlNode);	

		CRM_DEBUG2("Update: Copying in children for "
			   XML_CIB_TAG_RESOURCE " (%s).",
			   id);

		handle_object_children(res,
				       anXmlNode->children,
				       XML_CIB_ATTR_NODEREF);
	}
	FNRET(0);
    
}

int
delResource(xmlNodePtr cib, const char *id)
{
	int del_res = CIB_ERROR_OTHER;
	FNIN();

	if(id == NULL || strlen(id) == 0) {
		del_res = CIB_ERROR_MISSING_ID;
	} else {
		del_res = cib_delete_node(findResource(cib, id));
	}
	
	FNRET(del_res);
}


//--- Constraint

int
addConstraint(xmlNodePtr cib, cibConstraint *xml_node)
{
	int add_res = CIB_ERROR_NONE;
	const char * id = NULL;
	const char * type = NULL;
	xmlNodePtr new_parent = NULL;

	FNIN();
	
	id = xmlGetProp(xml_node, XML_ATTR_ID);
	type = xmlGetProp(xml_node, XML_CIB_ATTR_CONTYPE);
	
	if (id == NULL || strlen(id) < 1)
		add_res = CIB_ERROR_MISSING_ID;
	else if (findConstraint(cib, ID(xml_node)) != NULL)
		add_res = CIB_ERROR_EXISTS;
/* 	else if (type == NULL || strlen(type) < 1) */
/* 		add_res = CIB_ERROR_MISSING_TYPE; */
	else {
		new_parent = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);

		if(new_parent == NULL) {
			// create it?
			add_res = CIB_ERROR_CORRUPT;
		} else {
			add_node_copy(new_parent, xml_node);
		}
	}

	FNRET(add_res);
}

xmlNodePtr
findConstraint(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	FNIN();
	
	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	ret = find_entity(root, XML_CIB_TAG_CONSTRAINT, id, FALSE);

	FNRET(ret);
}


int
updateConstraint(xmlNodePtr cib, cibConstraint *anXmlNode)
{
	xmlNodePtr res = NULL;
	const char *id = ID(anXmlNode);

	FNIN();

	CRM_DEBUG2("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...",
		   id);
	res = findConstraint(cib, id);
	if (res == NULL) {
		CRM_DEBUG2("Update: " XML_CIB_TAG_CONSTRAINT
			   " (%s) did not exist, adding.",
			   id);
		addConstraint(cib, anXmlNode);
	} else {
		copy_in_properties(res, anXmlNode);	

		CRM_DEBUG2("Update: Copying in children for "
			   XML_CIB_TAG_CONSTRAINT " (%s).",
			   id);
		
		handle_object_children(res,
				       anXmlNode->children,
				       XML_CIB_TAG_NVPAIR);
	}
	FNRET(0);
}

int
delConstraint(xmlNodePtr cib, const char *id)
{
	int del_res = CIB_ERROR_OTHER;
	FNIN();

	if(id == NULL || strlen(id) == 0) {
		del_res = CIB_ERROR_MISSING_ID;
	} else {
		del_res = cib_delete_node(findConstraint(cib, id));
	}
	
	FNRET(del_res);
}

//--- HaNode

int
addHaNode(xmlNodePtr cib, cibHaNode *xml_node)
{
	int add_res = 0;
	const char * id = NULL;
	const char * type = NULL;
	xmlNodePtr new_parent = NULL;

	FNIN();
	
	id = xmlGetProp(xml_node, XML_ATTR_ID);
	type = xmlGetProp(xml_node, XML_CIB_ATTR_NODETYPE);
	
	if (id == NULL || strlen(id) < 1)
		add_res = CIB_ERROR_MISSING_ID;
	else if (findHaNode(cib, ID(xml_node)) != NULL)
		add_res = CIB_ERROR_EXISTS;
/* 	else if (type == NULL || strlen(type) < 1) */
/* 		add_res = CIB_ERROR_MISSING_TYPE; */
	else {
		new_parent = get_object_root(XML_CIB_TAG_NODES, cib);

		if(new_parent == NULL) {
			// create it?
			add_res = CIB_ERROR_CORRUPT;
		} else {
			add_node_copy(new_parent, xml_node);
		}
	}
	
	FNRET(add_res);
}

xmlNodePtr
findHaNode(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	FNIN();
	
	root = get_object_root(XML_CIB_TAG_NODES, cib);
	ret = find_entity(root, XML_CIB_TAG_NODE, id, FALSE);

	FNRET(ret);
}



int
updateHaNode(xmlNodePtr cib, cibHaNode *anXmlNode)
{
	xmlNodePtr res = NULL;
	FNIN();
	CRM_DEBUG2("Update: " XML_CIB_TAG_NODE " (%s).", ID(anXmlNode));

	res = findHaNode(cib, ID(anXmlNode));
	if (res == NULL) {
		cl_log(LOG_INFO,
		       "Update: " XML_CIB_TAG_NODE
		       " (%s) did not exist, adding.",
		       ID(anXmlNode));
		addHaNode(cib, anXmlNode);
	} else {
		copy_in_properties(res, anXmlNode);	
	}
	FNRET(0);
}

int
delHaNode(xmlNodePtr cib, const char *id)
{
	int del_res = CIB_ERROR_OTHER;
	FNIN();

	if(id == NULL || strlen(id) == 0) {
		del_res = CIB_ERROR_MISSING_ID;
	} else {
		del_res = cib_delete_node(findHaNode(cib, id));
	}
	
	FNRET(del_res);
}

int
cib_delete_node(xmlNodePtr node_to_delete)
{
	int del_res = CIB_ERROR_NOT_EXISTS;
	if (node_to_delete != NULL) {
		unlink_xml_node(node_to_delete);
		free_xml(node_to_delete);
		del_res = CIB_ERROR_NONE;
	}
	return del_res;
}


void
handle_object_children(xmlNodePtr new_parent,
		       xmlNodePtr children,
		       const char *filter)
{
	const char *id = NULL;
	const char *action = NULL;
	xmlNodePtr iter = children, dest = NULL;
	FNIN();
	
	while(iter != NULL) {
		if (filter != NULL && strcmp(filter, iter->name) != 0)
			continue;

		id = ID(iter);
		action = xmlGetProp(iter, XML_CIB_ATTR_ACTION);
		dest = find_entity(new_parent,
				   XML_CIB_ATTR_NODEREF,
				   id,
				   FALSE);
			
		cib_delete_node(dest);
		
		if (action == NULL || strcmp("add", action) == 0) {
			// remove the action property first
			xmlNodePtr node_copy =
				add_node_copy(new_parent, iter);
			if(node_copy != NULL) {
				xmlUnsetProp(node_copy, XML_CIB_ATTR_ACTION);
			}
		}

		iter = iter->next;
	}
	FNOUT();
}




//--- Status

int
addStatus(xmlNodePtr cib, cibStatus *xml_node)
{
	int add_res = 0;
	const char *id = NULL;
	const char *instance = NULL;
	xmlNodePtr new_parent = NULL;

	FNIN();
	
	id = xmlGetProp(xml_node, XML_ATTR_ID);
	instance = xmlGetProp(xml_node, XML_CIB_ATTR_INSTANCE);
	
	if (id == NULL || strlen(id) < 1)
		add_res = CIB_ERROR_MISSING_ID;
	else if (findStatus(cib, id, instance) != NULL)
		add_res = -2;
	else {
		new_parent = get_object_root(XML_CIB_TAG_STATUS, cib);

		if(new_parent == NULL) {
			// create it?
			add_res = -4;
		} else {
			add_node_copy(new_parent, xml_node);
		}
	}

	FNRET(add_res);
}

xmlNodePtr
findStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
	xmlNodePtr root = NULL, ret = NULL;
	FNIN();
	
	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	ret = find_entity(root, XML_CIB_TAG_STATE, id, FALSE);

	FNRET(ret);
}

int
updateStatus(xmlNodePtr cib, cibStatus *anXmlNode)
{
	xmlNodePtr res = NULL;
	const char *ts_existing = NULL;
	const char *ts_new = NULL;
	const char *src_existing = NULL;
	const char *src_new = NULL;
	
	FNIN();
	
	res = findStatus(cib, ID(anXmlNode), INSTANCE(anXmlNode));

	ts_existing  = TSTAMP(res);
	ts_new       = TSTAMP(anXmlNode);
	src_existing = xmlGetProp(res, XML_CIB_ATTR_SOURCE);
	src_new      = xmlGetProp(anXmlNode, XML_CIB_ATTR_SOURCE);

	if (res == NULL) {
		CRM_DEBUG4("Update: %s (%s:%s) did not exist, adding.",
			   XML_CIB_TAG_STATE,
			   ID(anXmlNode),
			   INSTANCE(anXmlNode));
		addStatus(cib, anXmlNode);

	// local information always takes priority
	} else if(src_new != NULL
		  && src_existing != NULL
		  && strcmp(src_new, src_existing) == 0) {
		do_status_update(res, anXmlNode);
		
	} else if(ts_new == NULL) {
		cl_log(LOG_ERR,
		       "Update did not have a timestamp!  Discarding");

	// only use new data	
	} else if(ts_existing == NULL || strcmp(ts_new, ts_existing) > 0) {
		do_status_update(res, anXmlNode);

	} else {
		cl_log(LOG_WARNING,
		       "Ignoring old \"update\" (%s vs. %s)",
		       ts_new, ts_existing);
	}
	
	FNRET(0);
}

void
do_status_update(xmlNodePtr old, cibStatus *new)
{
	xmlNodePtr the_children = old->children;
	unlink_xml_node(the_children);
	free_xml(the_children);
	old->children = NULL;
	
	the_children = copy_xml_node_recursive(new->children, 1);
	copy_in_properties(old, new);
	xmlAddChildList(old, the_children);
}

int
delStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
	int del_res = -1;
	FNIN();

	del_res = cib_delete_node(findStatus(cib, id, instanceNum));
	
	FNRET(del_res);
}
