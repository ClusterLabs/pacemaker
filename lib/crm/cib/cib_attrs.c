/* $Id: cib_attrs.c,v 1.15 2006/04/04 13:09:27 andrew Exp $ */

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

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/cib.h>

#include <crm/dmalloc_wrapper.h>


enum cib_errors 
update_attr(cib_t *the_cib, int call_options,
	    const char *section, const char *node_uuid, const char *set_name,
	    const char *attr_id, const char *attr_name, const char *attr_value)
{
	const char *tag = NULL;
	
	enum cib_errors rc = cib_ok;
	crm_data_t *xml_top = NULL;
	crm_data_t *xml_obj = NULL;
	crm_data_t *fragment = NULL;

	if(attr_id == NULL) {
		attr_id = attr_name;
	}
	if(attr_name == NULL) {
		attr_name = attr_id;
	}

	CRM_ASSERT(attr_id != NULL);
	CRM_ASSERT(attr_name != NULL);
	
	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		tag = NULL;
		
	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		tag = XML_CIB_TAG_NODE;
		
	} else if(section != NULL && node_uuid != NULL) {
		xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_STATE);
		crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
		if(xml_top == NULL) {
			xml_top = xml_obj;
		}
		tag = XML_TAG_TRANSIENT_NODEATTRS;

	} else if(section != NULL) {
		tag = XML_TAG_TRANSIENT_NODEATTRS;

	} else {
		return cib_NOSECTION;
	}
	
	crm_debug_2("Creating %s/%s", section, tag);
	if(tag != NULL) {
		xml_obj = create_xml_node(xml_obj, tag);
		crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
		if(xml_top == NULL) {
			xml_top = xml_obj;
		}
	}

	if(set_name != NULL) {
		xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
		if(xml_top == NULL) {
			xml_top = xml_obj;
		}
		crm_xml_add(xml_obj, XML_ATTR_ID, set_name);
		xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
	}
	xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
	if(xml_top == NULL) {
		xml_top = xml_obj;
	}
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	crm_log_xml_debug_2(xml_top, "Update");
	fragment = create_cib_fragment(xml_top, section);
	crm_log_xml_debug_3(fragment, "Update Fragment");
	
	free_xml(xml_top);
	
	rc = the_cib->cmds->update(
		the_cib, section, fragment, NULL, call_options|cib_quorum_override);

	if(rc == cib_diff_resync) {
		/* this is an internal matter - the update succeeded */ 
		rc = cib_ok;
	}

	if(rc < cib_ok) {
		crm_err("Error setting %s=%s (section=%s, set=%s): %s",
			attr_name, attr_value, section, crm_str(set_name),
			cib_error2string(rc));
	}
	
	free_xml(fragment);
	return rc;
}

enum cib_errors 
read_attr(cib_t *the_cib,
	  const char *section, const char *node_uuid, const char *set_name,
	  const char *attr_id, const char *attr_name, char **attr_value)
{
	const char *tag = NULL;
	enum cib_errors rc = cib_ok;
	crm_data_t *xml_obj = NULL;
	crm_data_t *xml_next = NULL;
	crm_data_t *fragment = NULL;

	CRM_ASSERT(attr_value != NULL);
	*attr_value = NULL;

	crm_debug("Searching for attribute %s (section=%s, node=%s, set=%s)",
		  attr_name, section, crm_str(node_uuid), crm_str(set_name));

	rc = the_cib->cmds->query(
		the_cib, section, &fragment, cib_sync_call);

	if(rc != cib_ok) {
		crm_err("Query failed for attribute %s (section=%s, node=%s, set=%s): %s",
			attr_name, section, crm_str(set_name), crm_str(node_uuid),
			cib_error2string(rc));
		return rc;
	}

#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(fragment), section)) {
		xml_obj = fragment;
	} else {
		crm_data_t *a_node = NULL;
		a_node = find_xml_node(fragment, XML_TAG_CIB, TRUE);
		xml_obj = get_object_root(section, a_node);
	}
#else
	xml_obj = fragment;
	CRM_CHECK(safe_str_eq(crm_element_name(xml_obj), section),
		  return cib_output_data);
#endif
	CRM_ASSERT(xml_obj != NULL);
	crm_log_xml_debug_2(xml_obj, "Result section");


	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		tag = NULL;
		
	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		tag = XML_CIB_TAG_NODE;
		
	} else if(section != NULL && node_uuid != NULL) {
		xml_next = find_entity(xml_obj, XML_CIB_TAG_STATE, node_uuid);
		tag = XML_TAG_TRANSIENT_NODEATTRS;
		if(xml_next == NULL) {
			crm_debug("%s=%s not found in %s", XML_CIB_TAG_STATE, node_uuid,
				  crm_element_name(xml_obj));
			return cib_NOTEXISTS;
		}
		xml_obj = xml_next;

	} else if(section != NULL) {
		tag = XML_TAG_TRANSIENT_NODEATTRS;

	} else {
		return cib_NOSECTION;
	}
	
	
	if(tag != NULL) {
		xml_next = find_entity(xml_obj, tag, node_uuid);
		if(xml_next == NULL) {
			crm_debug("%s=%s not found in %s", tag, node_uuid,
				  crm_element_name(xml_obj));
			return cib_NOTEXISTS;
		}
		xml_obj = xml_next;
	}
	if(set_name != NULL) {
		xml_next = find_entity(xml_obj, XML_TAG_ATTR_SETS, set_name);
		if(xml_next == NULL) {
			crm_debug("%s=%s object not found in %s",
				  XML_TAG_ATTR_SETS, set_name,
				  crm_element_name(xml_obj));
			return cib_NOTEXISTS;
		}
		xml_obj = xml_next;

		xml_next = find_xml_node(xml_obj, XML_TAG_ATTRS, TRUE);
		if(xml_next == NULL) {
			crm_debug("%s object not found in %s",
				  XML_TAG_ATTRS, crm_element_name(xml_obj));
			return cib_NOTEXISTS;
		}
		xml_obj = xml_next;
	}

	xml_next = NULL;
	xml_child_iter_filter(
		xml_obj, a_child, XML_CIB_TAG_NVPAIR,
		const char *name = crm_element_value(
			a_child, XML_NVPAIR_ATTR_NAME);

		if(attr_id != NULL
		   && safe_str_neq(attr_id, ID(a_child))) {
			continue;
			
		} else if(attr_name != NULL
			  && safe_str_neq(attr_name, name)) {
			continue;
		}
		xml_next = a_child;
		break;
		);
	
	if(xml_next == NULL) {
		crm_debug("<%s id=%s name=%s/> not found in %s",
			  XML_CIB_TAG_NVPAIR, attr_id, attr_name,
			  crm_element_name(xml_obj));
		return cib_NOTEXISTS;
	}
	xml_obj = xml_next;
	
	if(crm_element_value(xml_obj, XML_NVPAIR_ATTR_VALUE) != NULL) {
		*attr_value = crm_element_value_copy(
			xml_obj, XML_NVPAIR_ATTR_VALUE);
	}
	
	free_xml(fragment);
	return cib_ok;
}


enum cib_errors 
delete_attr(cib_t *the_cib,
	    const char *section, const char *node_uuid, const char *set_name,
	    const char *attr_id, const char *attr_name, const char *attr_value)
{
	char *tmp = NULL;
	enum cib_errors rc = cib_ok;
	crm_data_t *xml_obj = NULL;

	rc = read_attr(the_cib, section, node_uuid, set_name,
		       attr_id, attr_name, &tmp);

	if(rc != cib_ok) {
		return rc;

	} else if(attr_value != NULL
		  && safe_str_neq(attr_value, tmp)) {
		crm_free(tmp);
		return cib_NOTEXISTS;
	}
	crm_free(tmp);

	xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	rc = the_cib->cmds->delete(
		the_cib, section, xml_obj, NULL,
		cib_sync_call|cib_quorum_override);

	free_xml(xml_obj);
	return rc;
}

enum cib_errors 
query_node_uuid(cib_t *the_cib, const char *uname, char **uuid)
{
	enum cib_errors rc = cib_ok;
	crm_data_t *xml_obj = NULL;
	crm_data_t *fragment = NULL;
	const char *child_name = NULL;

	CRM_ASSERT(uname != NULL);
	CRM_ASSERT(uuid != NULL);
	
	rc = the_cib->cmds->query(
		the_cib, XML_CIB_TAG_NODES, &fragment, cib_sync_call);
	if(rc != cib_ok) {
		return rc;
	}

#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(fragment), XML_CIB_TAG_NODES)) {
		xml_obj = fragment;
	} else {
		xml_obj = find_xml_node(fragment, XML_TAG_CIB, TRUE);
		xml_obj = get_object_root(XML_CIB_TAG_NODES, xml_obj);
	}
#else
	xml_obj = fragment;
	CRM_CHECK(safe_str_eq(crm_element_name(xml_obj), XML_CIB_TAG_NODES),
		  return cib_output_data);
#endif
	CRM_ASSERT(xml_obj != NULL);
	crm_log_xml_debug(xml_obj, "Result section");

	rc = cib_NOTEXISTS;
	*uuid = NULL;
	
	xml_child_iter_filter(
		xml_obj, a_child, XML_CIB_TAG_NODE,
		child_name = crm_element_value(a_child, XML_ATTR_UNAME);

		if(safe_str_eq(uname, child_name)) {
			child_name = ID(a_child);
			if(child_name != NULL) {
				*uuid = crm_strdup(child_name);
				rc = cib_ok;
			}
			break;
		}
		);
	free_xml(fragment);
	return rc;
}

enum cib_errors 
query_node_uname(cib_t *the_cib, const char *uuid, char **uname)
{
	enum cib_errors rc = cib_ok;
	crm_data_t *xml_obj = NULL;
	crm_data_t *fragment = NULL;
	const char *child_name = NULL;

	CRM_ASSERT(uname != NULL);
	CRM_ASSERT(uuid != NULL);
	
	rc = the_cib->cmds->query(
		the_cib, XML_CIB_TAG_NODES, &fragment, cib_sync_call);
	if(rc != cib_ok) {
		return rc;
	}

#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(fragment), XML_CIB_TAG_NODES)) {
		xml_obj = fragment;
	} else {
		xml_obj = find_xml_node(fragment, XML_TAG_CIB, TRUE);
		xml_obj = get_object_root(XML_CIB_TAG_NODES, xml_obj);
	}
#else
	xml_obj = fragment;
	CRM_CHECK(safe_str_eq(crm_element_name(xml_obj), XML_CIB_TAG_NODES),
		  return cib_output_data);
#endif
	CRM_ASSERT(xml_obj != NULL);
	crm_log_xml_debug_2(xml_obj, "Result section");

	rc = cib_NOTEXISTS;
	*uname = NULL;
	
	xml_child_iter_filter(
		xml_obj, a_child, XML_CIB_TAG_NODE,
		child_name = ID(a_child);

		if(safe_str_eq(uuid, child_name)) {
			child_name = crm_element_value(a_child, XML_ATTR_UNAME);
			if(child_name != NULL) {
				*uname = crm_strdup(child_name);
				rc = cib_ok;
			}
			break;
		}
		);
	free_xml(fragment);
	return rc;
}

#define standby_common 	char *attr_id  = NULL;				\
	int str_length = 3;						\
	char *set_name = NULL;						\
	const char *attr_name  = "standby";				\
	const char *type = XML_CIB_TAG_NODES;				\
									\
	CRM_CHECK(uuid != NULL, return cib_missing_data);		\
	str_length += strlen(attr_name);				\
	str_length += strlen(uuid);					\
	if(safe_str_eq(scope, "reboot")					\
	   || safe_str_eq(scope, XML_CIB_TAG_STATUS)) {			\
		const char *extra = "transient";			\
 		type = XML_CIB_TAG_STATUS;				\
		str_length += strlen(extra);				\
		crm_malloc0(attr_id, str_length);			\
		sprintf(attr_id, "%s-%s-%s", extra, attr_name, uuid);	\
									\
	} else {							\
		crm_malloc0(attr_id, str_length);			\
		sprintf(attr_id, "%s-%s", attr_name, uuid);		\
	}								\
	set_name = crm_strdup(attr_id);

enum cib_errors 
query_standby(cib_t *the_cib, const char *uuid, const char *scope,
	      char **standby_value)
{
	enum cib_errors rc = cib_ok;
	CRM_CHECK(standby_value != NULL, return cib_missing_data);

	if(scope != NULL) {
		standby_common;
		rc = read_attr(the_cib, type, uuid, set_name,
			       attr_id, attr_name, standby_value);
		crm_free(attr_id);
		crm_free(set_name);

	} else {
		rc = query_standby(
			the_cib, uuid, XML_CIB_TAG_NODES, standby_value);

		if(rc == cib_NOTEXISTS) {
			crm_debug("No standby value found with "
				  "lifetime=forever, checking lifetime=reboot");
			rc = query_standby(the_cib, uuid,
					   XML_CIB_TAG_STATUS, standby_value);
		}
	}
	
	return rc;
}

enum cib_errors 
set_standby(cib_t *the_cib, const char *uuid, const char *scope,
	    const char *standby_value)
{
	enum cib_errors rc = cib_ok;
	CRM_CHECK(standby_value != NULL, return cib_missing_data);
	if(scope != NULL) {
		standby_common;
		rc = update_attr(the_cib, cib_sync_call, type, uuid, set_name,
				 attr_id, attr_name, standby_value);
		crm_free(attr_id);
		crm_free(set_name);

	} else {
		rc = set_standby(the_cib, uuid, XML_CIB_TAG_NODES, standby_value);
	}

	return rc;
}

enum cib_errors 
delete_standby(cib_t *the_cib, const char *uuid, const char *scope,
	       const char *standby_value)
{
	enum cib_errors rc = cib_ok;
	if(scope != NULL) {
		standby_common;
		rc = delete_attr(the_cib, type, uuid, set_name,
				 attr_id, attr_name, standby_value);
		crm_free(attr_id);
		crm_free(set_name);

	} else {
		rc = delete_standby(
			the_cib, uuid, XML_CIB_TAG_STATUS, standby_value);

		rc = delete_standby(
			the_cib, uuid, XML_CIB_TAG_NODES, standby_value);
	}

	return rc;
}

