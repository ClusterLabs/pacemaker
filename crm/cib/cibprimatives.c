/* $Id: cibprimatives.c,v 1.38 2004/08/18 10:21:53 andrew Exp $ */
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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <cibprimatives.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

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


void update_node_state(xmlNodePtr existing_node, xmlNodePtr update);



//--- Resource

int
addResource(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_verbose("Adding " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return add_cib_object(root, anXmlNode);
}


xmlNodePtr
findResource(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	ret = find_entity(root, XML_CIB_TAG_RESOURCE, id, FALSE);

	return ret;
}

int
updateResource(xmlNodePtr cib,  xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_verbose("Updating " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delResource(xmlNodePtr cib, xmlNodePtr delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNodePtr root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_verbose("Deleting " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return delete_cib_object(root, delete_spec);
}


//--- Constraint

int
addConstraint(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_verbose("Adding " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNodePtr
findConstraint(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	ret = find_entity(root, XML_CIB_TAG_CONSTRAINT, id, FALSE);

	return ret;
}


int
updateConstraint(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;
	
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_verbose("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delConstraint(xmlNodePtr cib, xmlNodePtr delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNodePtr root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 
	crm_verbose("Deleting " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

//--- HaNode

int
addHaNode(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_verbose("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNodePtr
findHaNode(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_NODES, cib);
	ret = find_entity(root, XML_CIB_TAG_NODE, id, FALSE);

	return ret;
}



int
updateHaNode(xmlNodePtr cib, cibHaNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_verbose("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delHaNode(xmlNodePtr cib, xmlNodePtr delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNodePtr root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_verbose("Deleting " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

//--- Status

int
addStatus(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_verbose("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNodePtr
findStatus(xmlNodePtr cib, const char *id)
{
	xmlNodePtr root = NULL, ret = NULL;

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	ret = find_entity(root, XML_CIB_TAG_STATE, id, FALSE);

	return ret;
}

int
updateStatus(xmlNodePtr cib, xmlNodePtr anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNodePtr root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_verbose("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delStatus(xmlNodePtr cib, xmlNodePtr delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNodePtr root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_verbose("Deleting " XML_CIB_TAG_STATE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return delete_cib_object(root, delete_spec);
}





int
delete_cib_object(xmlNodePtr parent, xmlNodePtr delete_spec)
{
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNodePtr equiv_node = NULL;
	xmlNodePtr children = NULL;
	int result = CIBRES_OK;
	
	if(delete_spec == NULL) {
		return CIBRES_FAILED_NOOBJECT;
	} else if(parent == NULL) {
		return CIBRES_FAILED_NOPARENT;
	}

	object_name = delete_spec->name;
	object_id = xmlGetProp(delete_spec, XML_ATTR_ID);
	children = delete_spec->children;
	
	if(object_id == NULL) {
		// placeholder object
		equiv_node = find_xml_node(parent, object_name);
		
	} else {
		equiv_node =
			find_entity(parent, object_name, object_id, FALSE);
		
	}

	if(equiv_node == NULL) {
		return CIBRES_FAILED_NOTEXISTS;

	} else if(children == NULL) {

		// only leaves are deleted
		unlink_xml_node(equiv_node);
		free_xml(equiv_node);

	} else {

		while(children != NULL) {
			int tmp_result =
				delete_cib_object(equiv_node, children);
			
			// only the first error is likely to be interesting
			if(tmp_result != CIBRES_OK
			   && result == CIBRES_OK) {
				result = tmp_result;
			}
			children = children->next;
		}
	}

	return result;
}

int
add_cib_object(xmlNodePtr parent, xmlNodePtr new_obj)
{
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNodePtr equiv_node = NULL;
	xmlNodePtr children = NULL;
	
	if(new_obj == NULL) {
		return CIBRES_FAILED_NOOBJECT;
	} else if(parent == NULL) {
		return CIBRES_FAILED_NOPARENT;
	}

	object_name = new_obj->name;
	object_id = xmlGetProp(new_obj, XML_ATTR_ID);
	children = new_obj->children;
	
	if(object_id == NULL) {
		// placeholder object
		equiv_node = find_xml_node(parent, object_name);
		
	} else {
		equiv_node =
			find_entity(parent, object_name, object_id, FALSE);
		
	}
	
	if(equiv_node != NULL) {
		return CIBRES_FAILED_EXISTS;

	} else if(add_node_copy(parent, new_obj) == NULL) {
		return CIBRES_FAILED_NODECOPY;
		
	}
	
	return CIBRES_OK;
}


int
update_cib_object(xmlNodePtr parent, xmlNodePtr new_obj, gboolean force)
{
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNodePtr equiv_node = NULL;
	xmlNodePtr children = NULL;
	int result = CIBRES_OK;
	
	if(new_obj == NULL) {
		return CIBRES_FAILED_NOOBJECT;

	} else if(parent == NULL) {
		return CIBRES_FAILED_NOPARENT;

	}

	object_name = new_obj->name;
	object_id = xmlGetProp(new_obj, XML_ATTR_ID);
	children = new_obj->children;
	
	if(object_id == NULL) {
		// placeholder object
		equiv_node = find_xml_node(parent, object_name);

	} else {
		equiv_node = find_entity(parent, object_name, object_id, FALSE);
	}
	
	if(equiv_node == NULL) {
		crm_debug("No node to update, creating %s instead", new_obj->name);
		if(parent == NULL) {
			crm_warn("Failed to add <%s id=%s> (NULL parent)",
				 object_name, object_id);
			return CIBRES_FAILED_NODECOPY;
			
		} else if(add_node_copy(parent, new_obj) == NULL) {
			crm_warn("Failed to add  <%s id=%s>", object_name, object_id);
			return CIBRES_FAILED_NODECOPY;
		}
		
	} else {
		crm_verbose("Found node <%s id=%s> to update", object_name, object_id);

		const char *replace = xmlGetProp(new_obj, "replace");
		
		if(force == FALSE) {
			const char *ts_existing  = NULL;
			const char *ts_new       = NULL;

			/* default to false?
			 *
			 * that would mean every node would have to
			 * carry a timestamp
			 */
			gboolean is_update = TRUE;
			
			ts_existing  = TSTAMP(equiv_node);
			ts_new       = TSTAMP(new_obj);
			
			if(ts_new != NULL && ts_existing != NULL) {
				is_update = (strcmp(ts_new, ts_existing) > 0);
			}
			
			if(is_update == FALSE) {
				crm_err(
				       "Ignoring old update to <%s id=\"%s\">"
				       "(%s vs. %s)",
				       object_name, object_id,
				       ts_new, ts_existing);
				return CIBRES_FAILED_STALE;
			}
		}

		if(replace != NULL) {
			xmlNodePtr remove = find_xml_node(equiv_node, replace);
			if(remove != NULL) {
				xmlUnlinkNode(remove);
				remove->doc = NULL;
				free_xml(remove);	
			}
			xmlUnsetProp(new_obj, "replace");
		}
		
		if(safe_str_eq(XML_CIB_TAG_STATE, object_name)){
			update_node_state(equiv_node, new_obj);
			
		} else {
			copy_in_properties(equiv_node, new_obj);
			
		}
		
		while(children != NULL) {
			int tmp_result =
				update_cib_object(equiv_node, children, force);

			// only the first error is likely to be interesting
			if(tmp_result != CIBRES_OK
			   && result == CIBRES_OK) {
				result = tmp_result;
			}
			children = children->next;
		}
		
	}
	
	return result;
}


void
update_node_state(xmlNodePtr target, xmlNodePtr update)
{
	const char *source	= NULL;
	xmlAttrPtr prop_iter    = NULL;
	gboolean any_updates    = FALSE;
	gboolean clear_stonith  = FALSE;
	gboolean clear_shutdown = FALSE;
	
	prop_iter = update->properties;
	while(prop_iter != NULL) {
		const char *local_prop_name = prop_iter->name;
		const char *local_prop_value =
			xmlGetProp(update, local_prop_name);

		if(local_prop_name == NULL) {
			// error
			
		} else if(strcmp(local_prop_name, XML_ATTR_ID) == 0) {
			
		} else if(strcmp(local_prop_name, XML_ATTR_TSTAMP) == 0) {

		} else if(strcmp(local_prop_name, XML_CIB_ATTR_CLEAR_SHUTDOWN) == 0) {
			clear_shutdown = TRUE;
			
		} else if(strcmp(local_prop_name, XML_CIB_ATTR_CLEAR_STONITH) == 0) {
			clear_stonith = TRUE;
			clear_shutdown = TRUE;			
			
		} else if(strcmp(local_prop_name, "source") == 0) {
			source = local_prop_value;
			
		} else {
			any_updates = TRUE;
			set_xml_property_copy(target,
					      local_prop_name,
					      local_prop_value);
		}
			  
		prop_iter = prop_iter->next;
	}
	
	if(clear_shutdown) {
		// unset XML_CIB_ATTR_SHUTDOWN 
		crm_verbose("Clearing %s", XML_CIB_ATTR_SHUTDOWN);
		xmlUnsetProp(target, XML_CIB_ATTR_SHUTDOWN);
		any_updates = TRUE;
	}

	if(clear_stonith) {
		// unset XML_CIB_ATTR_STONITH
		crm_verbose("Clearing %s", XML_CIB_ATTR_STONITH);
		xmlUnsetProp(target, XML_CIB_ATTR_STONITH);
		any_updates = TRUE;
	}	
	
	if(any_updates) {
		set_node_tstamp(target);
		set_xml_property_copy(target, "source", source);
	}
	
}
