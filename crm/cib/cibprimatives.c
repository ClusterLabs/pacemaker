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

//--- Resource

int
addResource(xmlNodePtr cib, cibResource *xml_node)
{
    if(findResource(cib, ID(xml_node)) != NULL) FNRET(-1);
    // make these global constants
    FNRET(addNode(cib, XML_CIB_TAG_RESOURCES, xml_node));
}


xmlNodePtr
findResource(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = findNode(cib, XML_CIB_TAG_RESOURCES);
    FNRET(findEntity(root, XML_CIB_TAG_RESOURCE, id, FALSE));
}

xmlNodePtr
newResource(const char *id, const char *type, const char *name, const char *max_instances)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_RESOURCE " (%s).", id);

    xmlNodePtr xml_node = xmlNewNode(NULL, XML_CIB_TAG_RESOURCE); // replace with #define s

    xmlSetProp(xml_node, XML_ATTR_ID,          id);
    xmlSetProp(xml_node, XML_CIB_ATTR_RESTYPE,     type);
    xmlSetProp(xml_node, XML_ATTR_DESC,        name);
    xmlSetProp(xml_node, XML_CIB_ATTR_MAXINSTANCE, max_instances);
    xmlSetProp(xml_node, XML_ATTR_TSTAMP,      getNow());
    
    FNRET(xml_node);
}


int
updateResource(xmlNodePtr cib, cibResource *anXmlNode)
{
    CRM_DEBUG2("Updating " XML_CIB_TAG_RESOURCE " (%s)...", ID(anXmlNode));
    
    xmlNodePtr res = findResource(cib, ID(anXmlNode));

    if(res == NULL)
    {
	CRM_DEBUG2("Update: " XML_CIB_TAG_RESOURCE " (%s) did not exist, adding.", ID(anXmlNode));
	addResource(cib, anXmlNode);
    }
    else
    {
	//need to call?? xmlFreeNodeList();
#ifdef REPLACE
	xmlReplaceNode(res, anXmlNode);
	anXmlNode->children = res->children;
	res->children = NULL; // make sure res doesnt modify them
#else
	copyInProperties(anXmlNode, res);	

	CRM_DEBUG2("Update: Copying in children for " XML_CIB_TAG_RESOURCE " (%s).", ID(anXmlNode));
	xmlNodePtr iter = anXmlNode->children;
	while(iter != NULL)
	{
	    if(strcmp(XML_CIB_ATTR_NODEREF, iter->name) == 0)
	    {
		const char *action = xmlGetProp(iter, XML_CIB_ATTR_ACTION);
		const char *id = ID(iter);
		xmlNodePtr dest = findEntity(res, XML_CIB_ATTR_NODEREF, id, FALSE);
		
		if(dest != NULL) xmlUnlinkNode(dest);
		if(strcmp("add", action) == 0)
		{
		    xmlUnsetProp(iter, XML_CIB_ATTR_ACTION); // remove the action property
		    xmlAddChild(res, iter);
		}
	    }
	}
#endif
    }
    FNRET(0);
    
}

int
delResource(xmlNodePtr cib, const char *id)
{
    xmlNodePtr res = findResource(cib, id);
    if(res != NULL) xmlUnlinkNode(res);
    //need to call?? xmlFreeNodeList(res);
    FNRET(0);
}


//--- Status

int
addStatus(xmlNodePtr cib, cibStatus *xml_node)
{
    if(findStatus(cib, ID(xml_node), INSTANCE(xml_node)) != NULL) FNRET(-1);
    FNRET(addNode(cib, XML_CIB_TAG_STATUS, xml_node));
}

xmlNodePtr
findStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
    xmlNodePtr root = findNode(cib, XML_CIB_TAG_STATUS);
    FNRET(findEntity(root, XML_CIB_TAG_STATE, id, FALSE));
}

int
updateStatus(xmlNodePtr cib, cibStatus *anXmlNode)
{
    xmlNodePtr res = findStatus(cib, ID(anXmlNode), INSTANCE(anXmlNode));
    if(res == NULL)
    {
	CRM_DEBUG3("Update: " XML_CIB_TAG_STATE " (%s:%s) did not exist, adding.", ID(anXmlNode), INSTANCE(anXmlNode));
	addStatus(cib, anXmlNode);
    }
    else
    {
	//need to call?? xmlFreeNodeList();
#ifdef REPLACE
	xmlReplaceNode(res, anXmlNode);
#else
	copyInProperties(anXmlNode, res);	
#endif
    }
    FNRET(0);
}

xmlNodePtr
newStatus(const char *res_id, const char *node_id, const char *instance)
{

    // verify the node and resource exist?, get max_instances from resource or update later

    char *id = (char*)ha_malloc(128*(sizeof(char)));
    sprintf(id, "%s-%s", res_id, instance);

    CRM_DEBUG2("Creating " XML_CIB_TAG_STATUS " (%s).", id);
    
    
    xmlNodePtr xml_node = xmlNewNode(NULL, XML_CIB_TAG_STATE); // replace with #define s

    xmlSetProp(xml_node, XML_ATTR_ID,          id);
    xmlSetProp(xml_node, XML_CIB_ATTR_RESID,       res_id);
    xmlSetProp(xml_node, XML_CIB_ATTR_INSTANCE,    instance);
    xmlSetProp(xml_node, XML_CIB_ATTR_MAXINSTANCE, instance); // a sensible default... parent can update later if required 
    xmlSetProp(xml_node, XML_CIB_ATTR_NODEID,      node_id);
    xmlSetProp(xml_node, XML_CIB_ATTR_RESSTATUS,   CIB_VAL_RESSTATUS_DEFAULT);
    xmlSetProp(xml_node, XML_CIB_ATTR_SOURCE,      "none");
    xmlSetProp(xml_node, XML_ATTR_TSTAMP,      getNow());
//    xmlNodePtr xml_node = xmlStringLenGetNodeList(cib, c_object, 1);
    
    FNRET(xml_node);
}

int
delStatus(xmlNodePtr cib, const char *id, const char *instanceNum)
{
    xmlNodePtr res = findStatus(cib, id, instanceNum);
    if(res != NULL) xmlUnlinkNode(res);
    //need to call?? xmlFreeNodeList(res);
    FNRET(0);
}

//--- Constraint

int
addConstraint(xmlNodePtr cib, cibConstraint *xml_node)
{
    if(findConstraint(cib, ID(xml_node)) != NULL) FNRET(-1);
    FNRET(addNode(cib, XML_CIB_TAG_CONSTRAINTS, xml_node));
}

xmlNodePtr
findConstraint(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = findNode(cib, XML_CIB_TAG_CONSTRAINTS);
    FNRET(findEntity(root, XML_CIB_TAG_CONSTRAINT, id, FALSE));
}

xmlNodePtr
newConstraint(const char *id)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_CONSTRAINT " (%s)...", id);    
    xmlNodePtr xml_node = xmlNewNode(NULL,  XML_CIB_TAG_CONSTRAINT);

    xmlSetProp(xml_node, XML_ATTR_ID,      id);
    xmlSetProp(xml_node, XML_CIB_ATTR_CONTYPE, CIB_VAL_CONTYPE_DEFAULT);

// these should be filled in by the parent as appropriate
/*     xmlSetProp(xml_node, "constraint_type", type); */
/*     xmlSetProp(xml_node, "r_id_1",          r_id_1); */
/*     if(c_object->r_id_2 != NULL)    xmlSetProp(xml_node, "r_id_2",     c_object->r_id_2); */
/*     if(c_object->var_name != NULL)  xmlSetProp(xml_node, "var_name",   c_object->var_name); */
/*     if(c_object->var_value != NULL) xmlSetProp(xml_node, "var_value",  c_object->var_value); */

    xmlSetProp(xml_node, XML_CIB_ATTR_CLEAR,   CIB_VAL_CLEARON_DEFAULT);
    xmlSetProp(xml_node, XML_ATTR_TSTAMP,  getNow());

    FNRET(xml_node);
}


int
updateConstraint(xmlNodePtr cib, cibConstraint *anXmlNode)
{
    CRM_DEBUG2("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...", ID(anXmlNode));
    xmlNodePtr res = findConstraint(cib, ID(anXmlNode));
    if(res == NULL)
    {
	CRM_DEBUG2("Update: " XML_CIB_TAG_CONSTRAINT " (%s) did not exist, adding.", ID(anXmlNode));
	addConstraint(cib, anXmlNode);
    }
    else
    {
	//need to call?? xmlFreeNodeList();
#ifdef REPLACE
	xmlReplaceNode(res, anXmlNode);
#else
	copyInProperties(anXmlNode, res);	


	CRM_DEBUG2("Update: Copying in children for " XML_CIB_TAG_CONSTRAINT " (%s).", ID(anXmlNode));
	xmlNodePtr iter = anXmlNode->children;
	while(iter != NULL)
	{
	    if(strcmp(XML_CIB_TAG_NVPAIR, iter->name) == 0)
	    {
		const char *action = xmlGetProp(iter, XML_CIB_ATTR_ACTION);
		const char *id = ID(iter);
		xmlNodePtr dest = findEntity(res, XML_CIB_TAG_NVPAIR, id, FALSE);
		
		if(dest != NULL) xmlUnlinkNode(dest);
		if(strcmp("add", action) == 0)
		{
		    xmlUnsetProp(iter, XML_CIB_ATTR_ACTION); // remove the action property
		    xmlAddChild(res, iter);
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
    if(res != NULL) xmlUnlinkNode(res);
    //need to call?? xmlFreeNodeList(res);
    FNRET(0);
}


//--- HaNode

int
addHaNode(xmlNodePtr cib, cibHaNode *xml_node)
{
    const char * id = xmlGetProp(xml_node, XML_ATTR_ID);
    if(id == NULL || strlen(id) < 1) FNRET(-1);

    if(findHaNode(cib, ID(xml_node)) != NULL) FNRET(-2);

    const char * type = xmlGetProp(xml_node, XML_CIB_ATTR_NODETYPE);
    if(type == NULL || strlen(type) < 1)
    {
	type = CIB_VAL_NODETYPE_DEFAULT;
	cl_log(LOG_WARNING,
	       "You did not specify a value for %s for node (id=%s).  Using default: %s",
	       XML_CIB_ATTR_NODETYPE, id, CIB_VAL_NODETYPE_DEFAULT);
	xmlSetProp(xml_node, XML_CIB_ATTR_NODETYPE, CIB_VAL_NODETYPE_DEFAULT);
	       
    }
    //FNRET(-3); // or fill in a default
    
    FNRET(addNode(cib, XML_CIB_TAG_NODES, xml_node));
}

xmlNodePtr
findHaNode(xmlNodePtr cib, const char *id)
{
    xmlNodePtr root = findNode(cib, XML_CIB_TAG_NODES);
    FNRET(findEntity(root, XML_CIB_TAG_NODE, id, FALSE));
}


xmlNodePtr
newHaNode(const char *id, const char *type)
{
    CRM_DEBUG2("Creating " XML_CIB_TAG_NODE " (%s)...", id);
    xmlNodePtr xml_node = xmlNewNode(NULL, XML_CIB_TAG_NODE);

    xmlSetProp(xml_node, XML_ATTR_ID,         id);
    xmlSetProp(xml_node, XML_CIB_ATTR_NODETYPE,   type);
    xmlSetProp(xml_node, XML_CIB_ATTR_HEALTH,     CIB_VAL_HEALTH_DEFAULT);
    xmlSetProp(xml_node, XML_CIB_ATTR_NODESTATUS, CIB_VAL_NODESTATUS_DEFAULT);
    xmlSetProp(xml_node, XML_CIB_ATTR_SOURCE,     CIB_VAL_SOURCE_DEFAULT);
    xmlSetProp(xml_node, XML_ATTR_TSTAMP,     getNow());

    FNRET(xml_node);
}


int
updateHaNode(xmlNodePtr cib, cibHaNode *anXmlNode)
{
    CRM_DEBUG2("Update: " XML_CIB_TAG_NODE " (%s).", ID(anXmlNode));
    xmlNodePtr res = findHaNode(cib, ID(anXmlNode));
    if(res == NULL)
    {
	cl_log(LOG_INFO, "Update: " XML_CIB_TAG_NODE " (%s) did not exist, adding.", ID(anXmlNode));
	addHaNode(cib, anXmlNode);
    }
    else
    {
	//need to call?? xmlFreeNodeList();
#ifdef REPLACE
	xmlReplaceNode(res, anXmlNode);
#else
	copyInProperties(anXmlNode, res);	
#endif
    }
    FNRET(0);
}

int
delHaNode(xmlNodePtr cib, const char *id)
{
    xmlNodePtr res = findHaNode(cib, id);
    if(res != NULL) xmlUnlinkNode(res);
    //need to call?? xmlFreeNodeList(res);
    FNRET(0);
}
