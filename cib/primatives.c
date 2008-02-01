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

#include <crm_internal.h>

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


void update_node_state(xmlNode *existing_node, xmlNode *update);

/* --- Resource */

int
addResource(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return add_cib_object(root, anXmlNode);
}


xmlNode*
findResource(xmlNode *cib, const char *id)
{
	xmlNode *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	ret = find_entity(root, XML_CIB_TAG_RESOURCE, id);

	return ret;
}

int
updateResource(xmlNode *cib,  xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root = NULL;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return update_cib_object(root, anXmlNode);
}

int
delResource(xmlNode *cib, xmlNode *delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNode *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_RESOURCE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_RESOURCES, cib);
	return delete_cib_object(root, delete_spec);
}


/* --- Constraint */

int
addConstraint(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNode*
findConstraint(xmlNode *cib, const char *id)
{
	xmlNode *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	ret = find_entity(root, XML_CIB_TAG_CONSTRAINT, id);

	return ret;
}


int
updateConstraint(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;
	
	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return update_cib_object(root, anXmlNode);
}

int
delConstraint(xmlNode *cib, xmlNode *delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNode *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 
	crm_debug_2("Deleting " XML_CIB_TAG_CONSTRAINT " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

/* --- HaNode */

int
addHaNode(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNode*
findHaNode(xmlNode *cib, const char *id)
{
	xmlNode *root = NULL, *ret = NULL;
	
	
	root = get_object_root(XML_CIB_TAG_NODES, cib);
	ret = find_entity(root, XML_CIB_TAG_NODE, id);

	return ret;
}



int
updateHaNode(xmlNode *cib, cibHaNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_NODES, cib);
	return update_cib_object(root, anXmlNode);
}

int
delHaNode(xmlNode *cib, xmlNode *delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNode *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_CONSTRAINTS, cib);
	return delete_cib_object(root, delete_spec);
}

/* --- Status */

int
addStatus(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}

	crm_debug_2("Adding " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return add_cib_object(root, anXmlNode);
}

xmlNode*
findStatus(xmlNode *cib, const char *id)
{
	xmlNode *root = NULL, *ret = NULL;

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	ret = find_entity(root, XML_CIB_TAG_STATE, id);

	return ret;
}

int
updateStatus(xmlNode *cib, xmlNode *anXmlNode)
{
	const char *id = ID(anXmlNode);
	xmlNode *root;

	if (id == NULL || strlen(id) < 1) {
		return CIBRES_MISSING_ID;
	}
	
	crm_debug_2("Updating " XML_CIB_TAG_NODE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return update_cib_object(root, anXmlNode);
}

int
delStatus(xmlNode *cib, xmlNode *delete_spec)
{
	const char *id = ID(delete_spec);
	xmlNode *root;

	if(id == NULL || strlen(id) == 0) {
		return CIBRES_MISSING_ID;
	} 

	crm_debug_2("Deleting " XML_CIB_TAG_STATE " (%s)...", id);

	root = get_object_root(XML_CIB_TAG_STATUS, cib);
	return delete_cib_object(root, delete_spec);
}

int
delete_cib_object(xmlNode *parent, xmlNode *delete_spec)
{
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNode *equiv_node = NULL;
	int result = cib_ok;
	
	if(delete_spec != NULL) {
		object_name = crm_element_name(delete_spec);
	}
	object_id = crm_element_value(delete_spec, XML_ATTR_ID);

	crm_debug_3("Processing: <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	
	if(delete_spec == NULL) {
		result = cib_NOOBJECT;

	} else if(parent == NULL) {
		result = cib_NOPARENT;

	} else if(object_id == NULL) {
		/*  placeholder object */
		equiv_node = find_xml_node(parent, object_name, FALSE);
		
	} else {
		equiv_node = find_entity(parent, object_name, object_id);
	}

	if(result != cib_ok) {
		; /* nothing */
		
	} else if(equiv_node == NULL) {
		result = cib_ok;

	} else if(xml_has_children(delete_spec) == FALSE) {
		/*  only leaves are deleted */
		crm_debug("Removing leaf: <%s id=%s>",
			  crm_str(object_name), crm_str(object_id));
		zap_xml_from_parent(parent, equiv_node);

	} else {

		xml_child_iter(
			delete_spec, child, 

			int tmp_result = delete_cib_object(equiv_node, child);
			
			/*  only the first error is likely to be interesting */
			if(tmp_result != cib_ok && result == cib_ok) {
				result = tmp_result;
			}
			);
	}

	return result;
}

int
add_cib_object(xmlNode *parent, xmlNode *new_obj)
{
	enum cib_errors result = cib_ok;
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNode *equiv_node = NULL;
	
	if(new_obj != NULL) {
		object_name = crm_element_name(new_obj);
	}
	object_id = crm_element_value(new_obj, XML_ATTR_ID);

	crm_debug_3("Processing: <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	
	if(new_obj == NULL || object_name == NULL) {
		result = cib_NOOBJECT;

	} else if(parent == NULL) {
		result = cib_NOPARENT;

	} else if(object_id == NULL) {
		/*  placeholder object */
		equiv_node = find_xml_node(parent, object_name, FALSE);
		
	} else {
		equiv_node = find_entity(parent, object_name, object_id);
	}

	if(result != cib_ok) {
		; /* do nothing */
		
	} else if(equiv_node != NULL) {
		result = cib_EXISTS;

	} else {
		result = update_cib_object(parent, new_obj);
	}

	return result;
}


int
update_cib_object(xmlNode *parent, xmlNode *update)
{
	const char *replace = NULL;
	const char *object_name = NULL;
	const char *object_id = NULL;
	xmlNode *target = NULL;
	int result = cib_ok;

	CRM_DEV_ASSERT(update != NULL);
	if(crm_assert_failed) { return cib_NOOBJECT; }

	CRM_DEV_ASSERT(parent != NULL);
	if(crm_assert_failed) { return cib_NOPARENT; }

	object_name = crm_element_name(update);
	object_id = ID(update);

	CRM_DEV_ASSERT(object_name != NULL);
	if(crm_assert_failed) { return cib_NOOBJECT; }

	crm_debug_3("Processing: <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	
	if(object_id == NULL) {
		/*  placeholder object */
		target = find_xml_node(parent, object_name, FALSE);

	} else {
		target = find_entity(parent, object_name, object_id);
	}

	if(target == NULL) {
		target = create_xml_node(parent, object_name);
	} 

	crm_debug_2("Found node <%s id=%s> to update",
		    crm_str(object_name), crm_str(object_id));
	
	replace = crm_element_value(update, XML_CIB_ATTR_REPLACE);
	if(replace != NULL) {
	    xmlNode *remove = NULL;
	    int last = 0, lpc = 0, len = 0;

	    len = strlen(replace);
	    while(lpc <= len) {
		if(replace[lpc] == ',' || replace[lpc] == 0) {
		    char *replace_item = NULL;
		    if ( last == lpc ) {
			/* nothing to do */
			last = lpc+1;
			goto incr;
		    }

		    crm_malloc0(replace_item, lpc - last + 1);
		    strncpy(replace_item, replace+last, lpc-last);
		    
		    remove = find_xml_node(target, replace_item, FALSE);
		    if(remove != NULL) {
			crm_debug_3("Replacing node <%s> in <%s>",
				    replace_item, crm_element_name(target));
			zap_xml_from_parent(target, remove);
		    }
		    crm_free(replace_item);
		    last = lpc+1;
		}
	      incr:
		lpc++;
	    }
	    xml_remove_prop(update, XML_CIB_ATTR_REPLACE);
	    xml_remove_prop(target, XML_CIB_ATTR_REPLACE);
	}
	
	copy_in_properties(target, update);

	crm_debug_3("Processing children of <%s id=%s>",
		    crm_str(object_name), crm_str(object_id));
	
	xml_child_iter(
		update, a_child,  
		int tmp_result = 0;
		crm_debug_3("Updating child <%s id=%s>",
			    crm_element_name(a_child), ID(a_child));
		
		tmp_result = update_cib_object(target, a_child);
		
		/*  only the first error is likely to be interesting */
		if(tmp_result != cib_ok) {
			crm_err("Error updating child <%s id=%s>",
				crm_element_name(a_child), ID(a_child));
			
			if(result == cib_ok) {
				result = tmp_result;
			}
		}
		);
	
	crm_debug_3("Finished with <%s id=%s>",
		  crm_str(object_name), crm_str(object_id));

	return result;
}

