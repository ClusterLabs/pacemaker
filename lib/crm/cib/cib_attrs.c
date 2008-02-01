
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


#define attr_common_setup(section)					\
	gboolean is_crm_config = FALSE;					\
	gboolean is_node_transient = FALSE;				\
	char *local_set_name = NULL;					\
	if(attr_id == NULL && attr_name == NULL) {			\
		return cib_missing;					\
									\
	} else if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {	\
		node_uuid = NULL;					\
		is_crm_config = TRUE;					\
		tag = XML_CIB_TAG_CRMCONFIG;				\
		if(set_name == NULL) {					\
			set_name = CIB_OPTIONS_FIRST;			\
		}							\
									\
	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {		\
		tag = XML_CIB_TAG_NODE;					\
		if(node_uuid == NULL) {					\
			return cib_missing;				\
		}							\
		if(set_name == NULL) {					\
			local_set_name = crm_concat(section, node_uuid, '-'); \
			set_name = local_set_name;			\
		}							\
									\
	} else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {		\
		is_node_transient = TRUE;				\
		tag = XML_TAG_TRANSIENT_NODEATTRS;			\
		if(set_name == NULL) {					\
			local_set_name = crm_concat(section, node_uuid, '-'); \
			set_name = local_set_name;			\
		}							\
									\
	} else {							\
		return cib_bad_section;					\
	}								\
									\
	if(attr_id == NULL) {						\
		local_attr_id = crm_concat(set_name, attr_name, '-');	\
		attr_id = local_attr_id;				\
									\
	} else if(attr_name == NULL) {					\
		attr_name = attr_id;					\
	}								\

#define attr_msg(level, fmt, args...) do {	\
	if(to_console) {			\
	    printf(fmt"\n", ##args);		\
	} else {				\
	    do_crm_log(level, fmt , ##args);	\
	}					\
} while(0)

enum cib_errors
find_attr_details(xmlNode *xml_search, const char *node_uuid,
		  const char *set_name, const char *attr_id, const char *attr_name,
		  xmlNode **xml_obj, gboolean to_console)
{
	int matches = 0;
	xmlNode *nv_children = NULL;
	xmlNode *set_children = NULL;
	const char *set_type = XML_TAG_ATTR_SETS;
	const char *tag = crm_element_name(xml_search);

	CRM_CHECK(xml_obj != NULL, return cib_output_ptr);
	*xml_obj = NULL;
	
	CRM_CHECK(xml_search != NULL, return cib_NOTEXISTS);
	
	if(node_uuid != NULL || safe_str_eq(tag, XML_CIB_TAG_CRMCONFIG)) {
		set_type = XML_CIB_TAG_PROPSET;

		/* filter by node */
		matches = find_xml_children(
			&set_children, xml_search, 
			NULL, XML_ATTR_ID, node_uuid, FALSE);
		crm_log_xml_debug_2(set_children, "search by node:");
		if(matches == 0) {
			CRM_CHECK(set_children == NULL, crm_err("Memory leak"));
			attr_msg(LOG_INFO, "No node matching id=%s in %s",
				 node_uuid, TYPE(xml_search));
			return cib_NOTEXISTS;
		}
	}

	/* filter by set name */
	if(set_name != NULL) {
		xmlNode *tmp = NULL;
		matches = find_xml_children(
			&tmp, set_children?set_children:xml_search, 
			set_type, XML_ATTR_ID, set_name, FALSE);
		free_xml(set_children);
		set_children = tmp;
		crm_log_xml_debug_2(set_children, "search by set:");
		if(matches == 0) {
			attr_msg(LOG_INFO, "No set matching id=%s in %s", set_name, TYPE(xml_search));
			CRM_CHECK(set_children == NULL, crm_err("Memory leak"));
			return cib_NOTEXISTS;
		}
	}

	matches = 0;
	if(attr_id == NULL) {
		matches = find_xml_children(
			&nv_children, set_children?set_children:xml_search,
			XML_CIB_TAG_NVPAIR, XML_NVPAIR_ATTR_NAME, attr_name, FALSE);
		crm_log_xml_debug_2(nv_children, "search by name:");

	} else if(attr_id != NULL) {
		matches = find_xml_children(
			&nv_children, set_children?set_children:xml_search,
			XML_CIB_TAG_NVPAIR, XML_ATTR_ID, attr_id, FALSE);
		crm_log_xml_debug(nv_children, "search by id:");
	}
	
		
	if(matches == 1) {
		xmlNode *single_match = NULL;
		xml_child_iter(nv_children, child,
			       single_match = copy_xml(child);
			       break;
			);
		free_xml(nv_children);
		free_xml(set_children);
		*xml_obj = single_match;
		return cib_ok;

	} else if(matches == 0) {
	    free_xml(set_children);
	    return cib_NOTEXISTS;
	}

	attr_msg(LOG_WARNING, "Multiple attributes match name=%s in %s:",
		 attr_name, TYPE(xml_search));
	
	if(set_name != NULL) {
 	    xml_child_iter(
		nv_children, child,
		attr_msg(LOG_INFO, "  Value: %s \t(set=%s, id=%s)", 
			 crm_element_value(child, XML_NVPAIR_ATTR_VALUE), set_name, ID(child));
		);
	    
 	} else {
	    free_xml(set_children);
	    set_children = NULL;

	    find_xml_children(
		&set_children, xml_search, 
		set_type, NULL, NULL, FALSE);

	    xml_child_iter(
		set_children, set,
		const char *set_id = ID(set);

		free_xml(nv_children);
		nv_children = NULL;

		find_xml_children(
		    &nv_children, set,
		    XML_CIB_TAG_NVPAIR, XML_NVPAIR_ATTR_NAME, attr_name, FALSE);

		xml_child_iter(
		    nv_children, child,
		    attr_msg(LOG_INFO, "  Value: %s \t(set=%s, id=%s)",
			     crm_element_value(child, XML_NVPAIR_ATTR_VALUE),
			     set_id, ID(child));
		    );
		);
 	}
	
	free_xml(nv_children);
	free_xml(set_children);
	return cib_missing_data;
}


enum cib_errors 
update_attr(cib_t *the_cib, int call_options,
	    const char *section, const char *node_uuid, const char *set_name,
	    const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
	const char *tag = NULL;
	
	enum cib_errors rc = cib_ok;
	xmlNode *xml_top = NULL;
	xmlNode *xml_obj = NULL;
	xmlNode *xml_search = NULL;

	char *local_attr_id = NULL;
	
	CRM_CHECK(section != NULL, return cib_missing);
	CRM_CHECK(attr_name != NULL || attr_id != NULL, return cib_missing);

	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		node_uuid = NULL;

	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
		
	} else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
	}
	
	rc = the_cib->cmds->query(the_cib, section, &xml_search,
				  cib_sync_call|cib_scope_local);
	
	if(rc != cib_ok) {
		attr_msg(LOG_ERR, "Query failed for attribute %s (section=%s, node=%s, set=%s): %s",
			attr_name, section, crm_str(set_name), crm_str(node_uuid),
			cib_error2string(rc));
		return rc;
	}
		
	rc = find_attr_details(
	    xml_search, node_uuid, set_name, attr_id, attr_name, &xml_obj, to_console);
	free_xml(xml_search);

	if(rc == cib_missing_data) {
	    return rc;
	}
	
	if(xml_obj != NULL) {
		local_attr_id = crm_strdup(ID(xml_obj));
		attr_id = local_attr_id;
	}
	
	if(attr_id == NULL || xml_obj == NULL) {
		attr_common_setup(section);	
		
		CRM_CHECK(attr_id != NULL,
			  crm_free(local_attr_id);
			  free_xml(xml_obj);
			  return cib_missing);
		CRM_CHECK(set_name != NULL,
			  crm_free(local_attr_id);
			  free_xml(xml_obj);
			  return cib_missing);
		
		if(attr_value == NULL) {
			crm_free(local_attr_id);
			free_xml(xml_obj);
			return cib_missing_data;
		}
		
		if(is_node_transient) {
			xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_STATE);
			crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
			if(xml_top == NULL) {
				xml_top = xml_obj;
			}
		}
		
		crm_debug_2("Creating %s/%s", section, tag);
		if(tag != NULL) {
			xml_obj = create_xml_node(xml_obj, tag);
			crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
			if(xml_top == NULL) {
				xml_top = xml_obj;
			}
		}
		
		if(node_uuid == NULL) {
			xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_PROPSET);
		} else {
			xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
		}
		crm_xml_add(xml_obj, XML_ATTR_ID, set_name);
		
		if(xml_top == NULL) {
			xml_top = xml_obj;
		}
		
		xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
		crm_free(local_set_name);
	} else {
		free_xml(xml_obj);
		xml_obj = NULL;
	}

	xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
	if(xml_top == NULL) {
		xml_top = xml_obj;
	}

	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	crm_log_xml_debug_2(xml_top, "update_attr");
	
	rc = the_cib->cmds->modify(the_cib, section, xml_top, NULL,
				   call_options|cib_quorum_override);

	if(rc == cib_diff_resync) {
		/* this is an internal matter - the update succeeded */ 
		rc = cib_ok;
	}

	if(rc < cib_ok) {
		attr_msg(LOG_ERR, "Error setting %s=%s (section=%s, set=%s): %s",
			attr_name, attr_value, section, crm_str(set_name),
			cib_error2string(rc));
		crm_log_xml_info(xml_top, "Update");
	}
	
	crm_free(local_attr_id);
	free_xml(xml_top);
	
	return rc;
}

enum cib_errors 
read_attr(cib_t *the_cib,
	  const char *section, const char *node_uuid, const char *set_name,
	  const char *attr_id, const char *attr_name, char **attr_value, gboolean to_console)
{
	enum cib_errors rc = cib_ok;

	xmlNode *xml_obj = NULL;
	xmlNode *xml_next = NULL;
	xmlNode *fragment = NULL;

	CRM_CHECK(section != NULL, return cib_missing);
	CRM_CHECK(attr_name != NULL || attr_id != NULL, return cib_missing);

	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		node_uuid = NULL;

	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
		
	} else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
	}
	
	CRM_ASSERT(attr_value != NULL);
	*attr_value = NULL;

	crm_debug("Searching for attribute %s (section=%s, node=%s, set=%s)",
		  attr_name, section, crm_str(node_uuid), crm_str(set_name));

	rc = the_cib->cmds->query(
		the_cib, section, &fragment, cib_sync_call|cib_scope_local);

	if(rc != cib_ok) {
		attr_msg(LOG_ERR, "Query failed for attribute %s (section=%s, node=%s, set=%s): %s",
			attr_name, section, crm_str(set_name), crm_str(node_uuid),
			cib_error2string(rc));
		return rc;
	}

#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(fragment), section)) {
		xml_obj = fragment;
	} else {
		xmlNode *a_node = NULL;
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
	
	rc = find_attr_details(
	    xml_obj, node_uuid, set_name, attr_id, attr_name, &xml_next, to_console);
	free_xml(fragment);

	if(rc == cib_missing_data) {
	    return rc;
	}
	
	if(xml_next != NULL) {
		*attr_value = crm_element_value_copy(
			xml_next, XML_NVPAIR_ATTR_VALUE);
	}

	return xml_next == NULL?cib_NOTEXISTS:cib_ok;
}


enum cib_errors 
delete_attr(cib_t *the_cib, int options, 
	    const char *section, const char *node_uuid, const char *set_name,
	    const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
	enum cib_errors rc = cib_ok;
	xmlNode *xml_obj = NULL;
	xmlNode *xml_search = NULL;
	char *local_attr_id = NULL;

	CRM_CHECK(section != NULL, return cib_missing);
	CRM_CHECK(attr_name != NULL || attr_id != NULL, return cib_missing);

	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		node_uuid = NULL;

	} else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
		
	} else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
		CRM_CHECK(node_uuid != NULL, return cib_NOTEXISTS);
	}
	
	if(attr_id == NULL || attr_value != NULL) {
		rc = the_cib->cmds->query(the_cib, section, &xml_search,
					  cib_sync_call|cib_scope_local);

		if(rc != cib_ok) {
			attr_msg(LOG_ERR, "Query failed for section=%s of the CIB: %s",
				section, cib_error2string(rc));
			return rc;
		}
		
		rc = find_attr_details(
		    xml_search, node_uuid, set_name, attr_id, attr_name, &xml_obj, to_console);
		free_xml(xml_search);

		if(rc == cib_missing_data) {
		    return rc;
		}
		
		if(xml_obj != NULL) {
			if(attr_value != NULL) {
				const char *current = crm_element_value(xml_obj, XML_NVPAIR_ATTR_VALUE);
				if(safe_str_neq(attr_value, current)) {
					return cib_NOTEXISTS;
				}
			}
			local_attr_id = crm_strdup(ID(xml_obj));
			attr_id = local_attr_id;			
			xml_obj = NULL;
		}
	}

	if(attr_id == NULL) {
		return cib_NOTEXISTS;
	}
	
	xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);
	
	rc = the_cib->cmds->delete(
		the_cib, section, xml_obj, NULL,
		options|cib_quorum_override);

	crm_free(local_attr_id);
	free_xml(xml_obj);
	return rc;
}

enum cib_errors 
query_node_uuid(cib_t *the_cib, const char *uname, char **uuid)
{
	enum cib_errors rc = cib_ok;
	xmlNode *xml_obj = NULL;
	xmlNode *fragment = NULL;
	const char *child_name = NULL;

	CRM_ASSERT(uname != NULL);
	CRM_ASSERT(uuid != NULL);
	
	rc = the_cib->cmds->query(the_cib, XML_CIB_TAG_NODES, &fragment,
				  cib_sync_call|cib_scope_local);
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
	xmlNode *xml_obj = NULL;
	xmlNode *fragment = NULL;
	const char *child_name = NULL;

	CRM_ASSERT(uname != NULL);
	CRM_ASSERT(uuid != NULL);
	
	rc = the_cib->cmds->query(the_cib, XML_CIB_TAG_NODES, &fragment,
				  cib_sync_call|cib_scope_local);
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
									\
	CRM_CHECK(uuid != NULL, return cib_missing_data);		\
	str_length += strlen(attr_name);				\
	str_length += strlen(uuid);					\
	if(safe_str_eq(type, "reboot")					\
	   || safe_str_eq(type, XML_CIB_TAG_STATUS)) {			\
		const char *extra = "transient";			\
 		type = XML_CIB_TAG_STATUS;				\
		str_length += strlen(extra);				\
		crm_malloc0(attr_id, str_length);			\
		sprintf(attr_id, "%s-%s-%s", extra, attr_name, uuid);	\
									\
	} else {							\
		crm_malloc0(attr_id, str_length);			\
		sprintf(attr_id, "%s-%s", attr_name, uuid);		\
	}

enum cib_errors 
query_standby(cib_t *the_cib, const char *uuid,
	      char **scope, char **standby_value)
{
	enum cib_errors rc = cib_ok;
	CRM_CHECK(standby_value != NULL, return cib_missing_data);
	CRM_CHECK(scope != NULL, return cib_missing_data);
	
	if(*scope != NULL) {
		const char *type = *scope;
		standby_common;
		rc = read_attr(the_cib, type, uuid, set_name,
			       attr_id, attr_name, standby_value, TRUE);
		crm_free(attr_id);
		crm_free(set_name);

	} else {
		*scope = crm_strdup(XML_CIB_TAG_NODES);
		rc = query_standby(the_cib, uuid, scope, standby_value);

		if(rc == cib_NOTEXISTS) {
			crm_free(*scope);
			*scope = crm_strdup(XML_CIB_TAG_STATUS);
			crm_debug("No standby value found with "
				  "lifetime=forever, checking lifetime=reboot");
			rc = query_standby(the_cib, uuid, scope, standby_value);
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
		const char *type = scope;
		standby_common;
		rc = update_attr(the_cib, cib_sync_call, type, uuid, set_name,
				 attr_id, attr_name, standby_value, TRUE);
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
		const char *type = scope;
		standby_common;
		rc = delete_attr(the_cib, cib_sync_call, type, uuid, set_name,
				 attr_id, attr_name, standby_value, TRUE);
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

