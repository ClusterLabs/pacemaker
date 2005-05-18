/* $Id: primatives.c,v 1.16 2005/05/18 20:15:57 andrew Exp $ */
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
#include <notify.h>
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


void update_node_state(crm_data_t *existing_node, crm_data_t *update);

/* --- Resource */

int
addResource(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return add_cib_object(root, anXmlNode);
}


crm_data_t*
findResource(crm_data_t *cib, const char *id)
{
	crm_data_t *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	ret = find_entity(root, XML_CIB_TAG_RESOURCE, id, FALSE);

	return ret;
}

int
updateResource(crm_data_t *cib,  crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root = NULL;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delResource(crm_data_t *cib, crm_data_t *delete_spec)
{
	const char *id = ID(delete_spec);
	crm_data_t *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return delete_cib_object(root, delete_spec);
}


/* --- Constraint */

int
addConstraint(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return add_cib_object(root, anXmlNode);
}

crm_data_t*
findConstraint(crm_data_t *cib, const char *id)
{
	crm_data_t *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	ret = find_entity(root, XML_CIB_TAG_CONSTRAINT, id, FALSE);

	return ret;
}


int
updateConstraint(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;
	
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delConstraint(crm_data_t *cib, crm_data_t *delete_spec)
{
	const char *id = ID(delete_spec);
	crm_data_t *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 
	crm_debug_2("Deleting " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

/* --- HaNode */

int
addHaNode(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return add_cib_object(root, anXmlNode);
}

crm_data_t*
findHaNode(crm_data_t *cib, const char *id)
{
	crm_data_t *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_NODES, cib);
	ret = find_entity(root, XML_CIB_TAG_NODE, id, FALSE);

	return ret;
}



int
updateHaNode(crm_data_t *cib, cibHaNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delHaNode(crm_data_t *cib, crm_data_t *delete_spec)
{
	const char *id = ID(delete_spec);
	crm_data_t *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

/* --- Status */

int
addStatus(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return add_cib_object(root, anXmlNode);
}

crm_data_t*
findStatus(crm_data_t *cib, const char *id)
{
	crm_data_t *root = NULL, *ret = NULL;

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	ret = find_entity(root, XML_CIB_TAG_STATE, id, FALSE);

	return ret;
}

int
updateStatus(crm_data_t *cib, crm_data_t *anXmlNode)
{
	const char *id = ID(anXmlNode);
	crm_data_t *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return update_cib_object(root, anXmlNode, FALSE);
}

int
delStatus(crm_data_t *cib, crm_data_t *delete_spec)
{
	const char *id = ID(delete_spec);
	crm_data_t *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_STATE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return delete_cib_object(root, delete_spec);
}

int
delete_cib_object(crm_data_t *parent, crm_data_t *delete_spec)
{
	const char *object_name = NULL;
	const char *object_id = NULL;
	crm_data_t *equiv_node = NULL;
	int result = cib_ok;
	
	if(delete_spec != NULL) {
		object_name = crm_element_name(delete_spec);
	}
	object_id = crm_element_value(delete_spec, XML_ATTR_ID);

	if(delete_spec == NULL) {
		result = cib_NOOBJECT;

	} else if(parent == NULL) {
		result = cib_NOPARENT;

	} else if(object_id == NULL) {
		/*  placeholder object */
		equiv_node = find_xml_node(parent, object_name, FALSE);
		
	} else {
		equiv_node = find_entity(
			parent, object_name, object_id, FALSE);
	}
	cib_pre_notify(CRM_OP_CIB_DELETE, equiv_node, delete_spec);

	if(result != cib_ok) {
		; /* nothing */
		
	} else if(equiv_node == NULL) {
		result = cib_NOTEXISTS;

	} else if(xml_has_children(delete_spec)) {
		/*  only leaves are deleted */
		zap_xml_from_parent(parent, equiv_node);

	} else {

		xml_child_iter(
			delete_spec, child, NULL,

			int tmp_result = delete_cib_object(equiv_node, child);
			
			/*  only the first error is likely to be interesting */
			if(tmp_result != cib_ok && result == cib_ok) {
				result = tmp_result;
			}
			);
	}

	cib_post_notify(CRM_OP_CIB_DELETE, delete_spec, result, equiv_node);

	return result;
}

int
add_cib_object(crm_data_t *parent, crm_data_t *new_obj)
{
	enum cib_errors result = cib_ok;
	const char *object_name = NULL;
	const char *object_id = NULL;
	crm_data_t *equiv_node = NULL;
	
	if(new_obj != NULL) {
		object_name = crm_element_name(new_obj);
	}
	object_id = crm_element_value(new_obj, XML_ATTR_ID);

	if(new_obj == NULL) {
		result = cib_NOOBJECT;

	} else if(parent == NULL) {
		result = cib_NOPARENT;

	} else if(object_id == NULL) {
		/*  placeholder object */
		equiv_node = find_xml_node(parent, object_name, FALSE);
		
	} else {
		equiv_node = find_entity(
			parent, object_name, object_id, FALSE);
	}
	cib_pre_notify(CRM_OP_CIB_CREATE, equiv_node, new_obj);

	if(result != cib_ok) {
		; /* do nothing */
		
	} else if(equiv_node != NULL) {
		result = cib_EXISTS;

	} else if(add_node_copy(parent, new_obj) == NULL) {
		result = cib_NODECOPY;
		
	}
	
	cib_post_notify(CRM_OP_CIB_CREATE, new_obj, result, new_obj);

	return result;
}


int
update_cib_object(crm_data_t *parent, crm_data_t *new_obj, gboolean force)
{
	const char *replace = NULL;
	const char *object_name = NULL;
	char *object_id = NULL;
	crm_data_t *equiv_node = NULL;
	int result = cib_ok;
	
	if(new_obj != NULL) {
		object_name = crm_element_name(new_obj);
		if(crm_element_value(new_obj, XML_ATTR_ID) != NULL){
			object_id = crm_element_value_copy(new_obj,XML_ATTR_ID);
		}
	}

	if(new_obj == NULL) {
		result = cib_NOOBJECT;

	} else if(parent == NULL) {
		result = cib_NOPARENT;

	} else if(object_id == NULL) {
		/*  placeholder object */
		equiv_node = find_xml_node(parent, object_name, FALSE);

	} else {
		equiv_node = find_entity(parent, object_name, object_id, FALSE);
	}
	cib_pre_notify(CRM_OP_CIB_UPDATE, equiv_node, new_obj);

	if(result != cib_ok) {
		; /* nothing */
		
	} else if(equiv_node == NULL) {
		crm_debug("No node to update, creating %s instead",
			  crm_element_name(new_obj));
		if(parent == NULL) {
			crm_err("Failed to add <%s id=%s> (NULL parent)",
				 object_name, object_id);
			result = cib_NODECOPY;
			
		} else if(add_node_copy(parent, new_obj) == NULL) {
			crm_err("Failed to add  <%s id=%s>",
				 crm_str(object_name), crm_str(object_id));
			result = cib_NODECOPY;
		} else {
			crm_debug("Added  <%s id=%s>",
				  crm_str(object_name), crm_str(object_id));

			if(object_id == NULL) {
				/*  placeholder object */
				equiv_node = find_xml_node(
					parent, object_name, TRUE);
				
			} else {
				equiv_node = find_entity(
					parent, object_name, object_id, FALSE);
			}
		}
		
	} else {
		crm_debug_2("Found node <%s id=%s> to update",
			    crm_str(object_name), crm_str(object_id));

		replace = crm_element_value(new_obj, XML_CIB_ATTR_REPLACE);
		
		if(replace != NULL) {
			crm_data_t *remove = find_xml_node(
				equiv_node, replace, FALSE);
			if(remove != NULL) {
				crm_debug_3("Replacing node <%s> in <%s>",
					  replace, crm_element_name(equiv_node));
				zap_xml_from_parent(equiv_node, remove);
			}
			xml_remove_prop(new_obj, XML_CIB_ATTR_REPLACE);
			xml_remove_prop(equiv_node, XML_CIB_ATTR_REPLACE);
		}
		
		if(safe_str_eq(XML_CIB_TAG_STATE, object_name)){
			update_node_state(equiv_node, new_obj);
			
		} else {
			copy_in_properties(equiv_node, new_obj);
		}

		crm_debug_3("Processing children of <%s id=%s>",
			  crm_str(object_name), crm_str(object_id));
		
		xml_child_iter(
			new_obj, a_child, NULL, 
			int tmp_result = 0;
			crm_debug_3("Updating child <%s id=%s>",
				  crm_element_name(a_child),
				  crm_element_value(a_child, XML_ATTR_ID));
			
			tmp_result =
				update_cib_object(equiv_node, a_child, force);

			/*  only the first error is likely to be interesting */
			if(tmp_result != cib_ok) {
				crm_err("Error updating child <%s id=%s>",
					crm_element_name(a_child),
					crm_element_value(a_child, XML_ATTR_ID));
				
				if(result == cib_ok) {
					result = tmp_result;
				}
			}
			);
		
	}
	crm_debug_3("Finished with <%s id=%s>",
		  crm_str(object_name), crm_str(object_id));
	
	cib_post_notify(CRM_OP_CIB_UPDATE, new_obj, result, equiv_node);
	crm_free(object_id);
	return result;
}


void
update_node_state(crm_data_t *target, crm_data_t *update)
{
	const char *source	= NULL;
	gboolean any_updates    = FALSE;
	gboolean clear_stonith  = FALSE;
	gboolean clear_shutdown = FALSE;

	xml_prop_iter(
		update, local_prop_name, local_prop_value,
		
		if(local_prop_name == NULL) {
			/*  error */
			
		} else if(strcmp(local_prop_name, XML_ATTR_ID) == 0) {
			
		} else if(strcmp(local_prop_name, XML_ATTR_TSTAMP) == 0) {

		} else if(strcmp(local_prop_name, XML_CIB_ATTR_CLEAR_SHUTDOWN) == 0) {
			clear_shutdown = TRUE;
			
		} else if(strcmp(local_prop_name, XML_CIB_ATTR_CLEAR_STONITH) == 0) {
			clear_stonith = TRUE;
			clear_shutdown = TRUE;			
			
		} else if(strcmp(local_prop_name, XML_CIB_ATTR_SOURCE) == 0) {
			source = local_prop_value;
			
		} else {
			any_updates = TRUE;
			set_xml_property_copy(
				target, local_prop_name, local_prop_value);
		}
		);
	
	xml_remove_prop(target, XML_CIB_ATTR_CLEAR_SHUTDOWN);
	if(clear_shutdown) {
		/*  unset XML_CIB_ATTR_SHUTDOWN  */
		crm_debug_2("Clearing %s", XML_CIB_ATTR_SHUTDOWN);
		xml_remove_prop(target, XML_CIB_ATTR_SHUTDOWN);
		any_updates = TRUE;
	}

	xml_remove_prop(target, XML_CIB_ATTR_CLEAR_STONITH);
	if(clear_stonith) {
		/*  unset XML_CIB_ATTR_STONITH */
		crm_debug_2("Clearing %s", XML_CIB_ATTR_STONITH);
		xml_remove_prop(target, XML_CIB_ATTR_STONITH);
		any_updates = TRUE;
	}	
	
	if(any_updates) {
		set_node_tstamp(target);
		set_xml_property_copy(target, XML_CIB_ATTR_SOURCE, source);
	}
	
}
