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

//#define REPLACE

#include <cibprimatives.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/xmlutils.h>
//#include <crm/common/msgutils.h>
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

//--- Resource

int
addResource(xmlNodePtr cib, cibResource *xml_node)
{
    if (findResource(cib, ID(xml_node)) != NULL) FNRET(-1);
    FNRET(add_node_copy(cib, XML_CIB_TAG_RESOURCES, xml_node));
}


xmlNodePtr
findResource(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = find_xml_node(cib, XML_CIB_TAG_RESOURCES);
    FNRET(find_entity(root, XML_CIB_TAG_RESOURCE, id, FALSE));
}

xmlNodePtr
newResource(const char *id, const char *type,
			const char *name, const char *max_instances)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_RESOURCE " (%s).", id);

    xmlNodePtr xml_node = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);

    set_xml_property_copy(xml_node, XML_ATTR_ID,          id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_RESTYPE,     type);
    set_xml_property_copy(xml_node, XML_ATTR_DESC,        name);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_MAXINSTANCE, max_instances);
    set_xml_property_copy(xml_node, XML_ATTR_TSTAMP,      getNow());
    
    FNRET(xml_node);
}


int
updateResource(xmlNodePtr cib, cibResource *anXmlNode)
{
    CRM_DEBUG2("Updating " XML_CIB_TAG_RESOURCE " (%s)...", ID(anXmlNode));
    
    xmlNodePtr res = findResource(cib, ID(anXmlNode));

    if (res == NULL) {
		CRM_DEBUG2("Update: " XML_CIB_TAG_RESOURCE " (%s) did not exist, adding.",
				   ID(anXmlNode));
		addResource(cib, anXmlNode);
    } else {
		copy_in_properties(anXmlNode, res);	

		CRM_DEBUG2("Update: Copying in children for " XML_CIB_TAG_RESOURCE " (%s).",
				   ID(anXmlNode));
		xmlNodePtr iter = anXmlNode->children;
		while(iter != NULL) {
			if (strcmp(XML_CIB_ATTR_NODEREF, iter->name) == 0) {
				const char *action = xmlGetProp(iter, XML_CIB_ATTR_ACTION);
				const char *id = ID(iter);
				xmlNodePtr dest = find_entity(res, XML_CIB_ATTR_NODEREF, id, FALSE);
		
				if (dest != NULL) {
					unlink_xml_node(dest);
					xmlFreeNode(dest);
				}
		
				if (strcmp("add", action) == 0) {
					xmlNodePtr node_copy = xmlCopyNode(iter, 1);

					// remove the action property first
					xmlUnsetProp(node_copy, XML_CIB_ATTR_ACTION);
					
					xmlAddChild(res, node_copy);
				}
			}
		}
    }
    FNRET(0);
    
}

int
delResource(xmlNodePtr cib, const char *id)
{
    xmlNodePtr res = NULL;
	FNIN();
	
	res = findResource(cib, id);
    if (res != NULL) {
		unlink_xml_node(res);
		xmlFreeNodeList(res);
    }
    
    FNRET(0);
}


//--- Status

int
addStatus(xmlNodePtr cib, cibStatus *xml_node)
{
	FNIN();
    if (findStatus(cib, ID(xml_node), INSTANCE(xml_node)) != NULL) FNRET(-1);
    FNRET(add_node_copy(cib, XML_CIB_TAG_STATUS, xml_node));
}

xmlNodePtr
findStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
    xmlNodePtr root = find_xml_node(cib, XML_CIB_TAG_STATUS);
    FNRET(find_entity(root, XML_CIB_TAG_STATE, id, FALSE));
}

int
updateStatus(xmlNodePtr cib, cibStatus *anXmlNode)
{
    xmlNodePtr res = findStatus(cib, ID(anXmlNode), INSTANCE(anXmlNode));
    if (res == NULL) {
		CRM_DEBUG3("Update: " XML_CIB_TAG_STATE " (%s:%s) did not exist, adding.",
				   ID(anXmlNode),
				   INSTANCE(anXmlNode));
		addStatus(cib, anXmlNode);
    } else {
		copy_in_properties(anXmlNode, res);	
    }
    FNRET(0);
}

xmlNodePtr
newStatus(const char *res_id, const char *node_id, const char *instance)
{

    /* verify the node and resource exist
	 * get max_instances from resource or update later
	 */

    char *id = (char*)ha_malloc(128*(sizeof(char)));
    sprintf(id, "%s-%s", res_id, instance);

    CRM_DEBUG2("Creating " XML_CIB_TAG_STATUS " (%s).", id);
    
    
    xmlNodePtr xml_node = create_xml_node(NULL, XML_CIB_TAG_STATE);

    set_xml_property_copy(xml_node, XML_ATTR_ID,          id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_RESID,       res_id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_INSTANCE,    instance);

	set_xml_property_copy(xml_node, XML_CIB_ATTR_NODEID,      node_id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_SOURCE,      "none");
    set_xml_property_copy(xml_node, XML_ATTR_TSTAMP,      getNow());

	// a sensible default... parent can update later if required 
    set_xml_property_copy(xml_node, XML_CIB_ATTR_MAXINSTANCE, instance);

    set_xml_property_copy(xml_node, XML_CIB_ATTR_RESSTATUS,
						  CIB_VAL_RESSTATUS_DEFAULT);

//    xmlNodePtr xml_node = xmlStringLenGetNodeList(cib, c_object, 1);
    
    FNRET(xml_node);
}

int
delStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
    xmlNodePtr res = NULL;
	FNIN();
	
	res = findStatus(cib, id, instanceNum);
    if (res != NULL) {
		unlink_xml_node(res);
		xmlFreeNodeList(res);
    }
    
    FNRET(0);
}

//--- Constraint

int
addConstraint(xmlNodePtr cib, cibConstraint *xml_node)
{
	int ret = -1;
	FNIN();

	if (findConstraint(cib, ID(xml_node)) == NULL)
		ret = add_node_copy(cib, XML_CIB_TAG_CONSTRAINTS, xml_node);

	FNRET(ret);
}

xmlNodePtr
findConstraint(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = NULL, ret = NULL;
	FNIN();
	
	root = find_xml_node(cib, XML_CIB_TAG_CONSTRAINTS);
	ret = find_entity(root, XML_CIB_TAG_CONSTRAINT, id, FALSE);

	FNRET(ret);
}

xmlNodePtr
newConstraint(const char *id)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_CONSTRAINT " (%s)...", id);    
    xmlNodePtr xml_node = create_xml_node(NULL,  XML_CIB_TAG_CONSTRAINT);

    set_xml_property_copy(xml_node, XML_ATTR_ID,      id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_CONTYPE, CIB_VAL_CONTYPE_DEFAULT);

// these should be filled in by the parent as appropriate
/*     set_xml_property_copy(xml_node, "constraint_type", type); */
/*     set_xml_property_copy(xml_node, "r_id_1",          r_id_1); */
/*     if (c_object->r_id_2 != NULL)    set_xml_property_copy(xml_node, "r_id_2",     c_object->r_id_2); */
/*     if (c_object->var_name != NULL)  set_xml_property_copy(xml_node, "var_name",   c_object->var_name); */
/*     if (c_object->var_value != NULL) set_xml_property_copy(xml_node, "var_value",  c_object->var_value); */

    set_xml_property_copy(xml_node, XML_CIB_ATTR_CLEAR,   CIB_VAL_CLEARON_DEFAULT);
    set_xml_property_copy(xml_node, XML_ATTR_TSTAMP,  getNow());

    FNRET(xml_node);
}


int
updateConstraint(xmlNodePtr cib, cibConstraint *anXmlNode)
{
    CRM_DEBUG2("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...", ID(anXmlNode));
    xmlNodePtr res = findConstraint(cib, ID(anXmlNode));
    if (res == NULL) {
		CRM_DEBUG2("Update: " XML_CIB_TAG_CONSTRAINT " (%s) did not exist, adding.", ID(anXmlNode));
		addConstraint(cib, anXmlNode);
    }
    else
    {
#ifdef REPLACE
		// make a copy first
		xmlReplaceNode(res, anXmlNode);
#else
		copy_in_properties(anXmlNode, res);	


		CRM_DEBUG2("Update: Copying in children for " XML_CIB_TAG_CONSTRAINT " (%s).", ID(anXmlNode));
		xmlNodePtr iter = anXmlNode->children;
		while(iter != NULL)
		{
			if (strcmp(XML_CIB_TAG_NVPAIR, iter->name) == 0)
			{
				const char *action = xmlGetProp(iter, XML_CIB_ATTR_ACTION);
				const char *id = ID(iter);
				xmlNodePtr dest = find_entity(res, XML_CIB_TAG_NVPAIR, id, FALSE);
		
				if (dest != NULL)
				{
					unlink_xml_node(dest);
//		    xmlFreeNode(dest);
				}
		
				if (strcmp("add", action) == 0)
				{
					xmlNodePtr node_copy = xmlCopyNode(iter, 1);

					xmlUnsetProp(node_copy, XML_CIB_ATTR_ACTION); // remove the action property
					xmlAddChild(res, node_copy);
				}
			}
		}
#endif
    }
    FNRET(0);
}

int
delConstraint(xmlNodePtr cib, const char *id)
{
    xmlNodePtr res = findConstraint(cib, id);
    if (res != NULL) {
		unlink_xml_node(res);
//	xmlFreeNodeList(res);
    }
    FNRET(0);
}


//--- HaNode

int
addHaNode(xmlNodePtr cib, cibHaNode *xml_node)
{
    const char * id = xmlGetProp(xml_node, XML_ATTR_ID);
    if (id == NULL || strlen(id) < 1) FNRET(-1);

    if (findHaNode(cib, ID(xml_node)) != NULL) FNRET(-2);

    const char * type = xmlGetProp(xml_node, XML_CIB_ATTR_NODETYPE);
    if (type == NULL || strlen(type) < 1) {
		FNRET(-3);
    }
    
    FNRET(add_node_copy(cib, XML_CIB_TAG_NODES, xml_node));
}

xmlNodePtr
findHaNode(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = find_xml_node(cib, XML_CIB_TAG_NODES);
    FNRET(find_entity(root, XML_CIB_TAG_NODE, id, FALSE));
}


xmlNodePtr
newHaNode(const char *id, const char *type)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_NODE " (%s)...", id);
    xmlNodePtr xml_node = create_xml_node(NULL, XML_CIB_TAG_NODE);

    if (type == NULL || strlen(type) < 1) {
		cl_log(LOG_WARNING,
			   "You did not specify a value for %s for node (id=%s).  Using default: %s",
			   XML_CIB_ATTR_NODETYPE, id, CIB_VAL_NODETYPE_DEFAULT);
		type = CIB_VAL_NODETYPE_DEFAULT;
    }

    set_xml_property_copy(xml_node, XML_ATTR_ID,             id);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_NODETYPE,   type);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_HEALTH,     CIB_VAL_HEALTH_DEFAULT);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_NODESTATUS, CIB_VAL_NODESTATUS_DEFAULT);
    set_xml_property_copy(xml_node, XML_CIB_ATTR_SOURCE,     CIB_VAL_SOURCE_DEFAULT);
    set_xml_property_copy(xml_node, XML_ATTR_TSTAMP,         getNow());

    FNRET(xml_node);
}


int
updateHaNode(xmlNodePtr cib, cibHaNode *anXmlNode)
{
    CRM_DEBUG2("Update: " XML_CIB_TAG_NODE " (%s).", ID(anXmlNode));
    xmlNodePtr res = findHaNode(cib, ID(anXmlNode));
    if (res == NULL) {
		cl_log(LOG_INFO, "Update: " XML_CIB_TAG_NODE " (%s) did not exist, adding.", ID(anXmlNode));
		addHaNode(cib, anXmlNode);
    }
    else
    {
#ifdef REPLACE
		// make a copy first
		xmlReplaceNode(res, anXmlNode);
#else
		copy_in_properties(anXmlNode, res);	
#endif
    }
    FNRET(0);
}

int
delHaNode(xmlNodePtr cib, const char *id)
{
    xmlNodePtr res = findHaNode(cib, id);
    if (res != NULL) {
		unlink_xml_node(res);
//	xmlFreeNodeList(res);
    }
    FNRET(0);
}
