/* $Id: messages.c,v 1.8 2004/12/10 20:07:07 andrew Exp $ */
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

#include <time.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>

#include <cibio.h>
#include <cibmessages.h>
#include <cibprimatives.h>
#include <notify.h>
#include <callbacks.h>

#include <crm/dmalloc_wrapper.h>

extern const char *cib_our_uname;

enum cib_errors updateList(
	xmlNodePtr local_cib, xmlNodePtr update_command, xmlNodePtr failed,
	int operation, const char *section);

xmlNodePtr createCibFragmentAnswer(const char *section, xmlNodePtr failed);

gboolean replace_section(
	const char *section, xmlNodePtr tmpCib, xmlNodePtr command);

gboolean check_generation(xmlNodePtr newCib, xmlNodePtr oldCib);

gboolean update_results(
	xmlNodePtr failed, xmlNodePtr target, int operation, int return_code);

enum cib_errors cib_update_counter(
	xmlNodePtr xml_obj, const char *field, gboolean reset);


enum cib_errors 
cib_process_default(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) *answer = NULL;

	if(op == NULL) {
		result = cib_operation;
		crm_err("No operation specified\n");
		
	} else if(strcmp(CRM_OP_NOOP, op) == 0) {
		;

	} else {
		result = cib_NOTSUPPORTED;
		crm_err("Action [%s] is not supported by the CIB", op);
	}
	return result;
}

enum cib_errors 
cib_process_quit(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);

	cib_pre_notify(op, get_the_CIB(), NULL);
	crm_warn("The CRMd has asked us to exit... complying");
	exit(0);
	return result;
}

enum cib_errors 
cib_process_readwrite(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);

	if(safe_str_eq(op, CRM_OP_CIB_ISMASTER)) {
		if(cib_is_master == TRUE) {
			result = cib_ok;
		} else {
			result = cib_not_master;
		}
		return result;
	}

	cib_pre_notify(op, get_the_CIB(), NULL);
	if(safe_str_eq(op, CRM_OP_CIB_MASTER)) {
		crm_info("We are now in R/W mode");
		cib_is_master = TRUE;
	} else {
		crm_info("We are now in R/O mode");
		cib_is_master = FALSE;
	}
	cib_post_notify(op, NULL, result, NULL);

	return result;
}

enum cib_errors 
cib_process_ping(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) *answer = NULL;

	*answer = createPingAnswerFragment(CRM_SYSTEM_CIB, "ok");
	return result;
}


enum cib_errors 
cib_process_query(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	xmlNodePtr cib      = NULL;
	xmlNodePtr obj_root = NULL;
	enum cib_errors result = cib_ok;

	if(answer != NULL) *answer = NULL;
	
	crm_debug("Processing \"%s\" event", op);
	crm_verbose("Handling a query for section=%s of the cib", section);

	*answer = create_xml_node(NULL, XML_TAG_FRAGMENT);
	set_xml_property_copy(*answer, XML_ATTR_SECTION, section);
	set_xml_property_copy(*answer, "generated_on", cib_our_uname);

	if (safe_str_eq("all", section)) {
		section = NULL;
	} 

	obj_root = get_object_root(section, get_the_CIB());
	
	if(obj_root == NULL) {
		result = cib_NOTEXISTS;

	} else if(obj_root == get_the_CIB()) {
		add_node_copy(*answer, obj_root);

	} else {
		cib = create_xml_node(*answer, XML_TAG_CIB);
		add_node_copy(cib, obj_root);
		copy_in_properties(cib, get_the_CIB());
	}
	
	return result;
}

enum cib_errors 
cib_process_erase(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	xmlNodePtr tmpCib = NULL;
	enum cib_errors result = cib_ok;

	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) *answer = NULL;

	tmpCib = createEmptyCib();
	copy_in_properties(tmpCib, get_the_CIB());
	
	cib_pre_notify(op, get_the_CIB(), tmpCib);
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, TRUE);
		
	if(activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
	}

	cib_post_notify(op, NULL, result, get_the_CIB());
	*answer = createCibFragmentAnswer(NULL, NULL);
	
	return result;
}

enum cib_errors 
cib_process_bump(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	xmlNodePtr tmpCib = NULL;
	enum cib_errors result = cib_ok;

	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) *answer = NULL;

	tmpCib = copy_xml_node_recursive(the_cib);

	cib_pre_notify(op, get_the_CIB(), NULL);

	crm_verbose("Handling a %s for section=%s of the cib",
		    CRM_OP_CIB_BUMP, section);

	cib_update_counter(tmpCib, XML_ATTR_GENERATION, FALSE);
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, TRUE);
		
	if(activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
	}

	cib_post_notify(op, NULL, result, get_the_CIB());
	*answer = createCibFragmentAnswer(NULL, NULL);
	
	return result;
}

enum cib_errors 
cib_update_counter(xmlNodePtr xml_obj, const char *field, gboolean reset)
{
	char *new_value = NULL;
	char *old_value = NULL;
	int  int_value  = -1;

	/* modify the timestamp */
	set_node_tstamp(xml_obj);
	if(reset == FALSE) {
		old_value = xmlGetProp(xml_obj, field);
	}
	if(old_value != NULL) {
		crm_malloc(new_value, 128*(sizeof(char)));
		int_value = atoi(old_value);
		sprintf(new_value, "%d", ++int_value);
	} else {
		new_value = crm_strdup("1");
	}

	crm_trace("%s %d(%s)->%s",
		  field, int_value, crm_str(old_value), crm_str(new_value));
	set_xml_property_copy(xml_obj, field, new_value);
	crm_free(new_value);

	return cib_ok;
}

enum cib_errors 
cib_process_replace(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	gboolean verbose       = FALSE;
	xmlNodePtr tmpCib      = NULL;
	xmlNodePtr cib_update  = NULL;
	xmlNodePtr the_update  = NULL;
	const char *section_name = section;
	enum cib_errors result = cib_ok;
	
	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) *answer = NULL;

	if (options & cib_verbose) {
		verbose = TRUE;
	}
	if(safe_str_eq("all", section)) {
		section = NULL;
	}
	
	cib_update = find_xml_node(input, XML_TAG_CIB);
	
	if (cib_update == NULL) {
		result = cib_NOOBJECT;
		
	} else if (section == NULL) {
		tmpCib = copy_xml_node_recursive(cib_update);
		the_update = cib_update;
		section_name = tmpCib->name;
		
	} else {
		tmpCib = copy_xml_node_recursive(get_the_CIB());
		replace_section(section, tmpCib, input);
		the_update = get_object_root(section, cib_update);
	}

	cib_pre_notify(op, get_object_root(section, get_the_CIB()), the_update);
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, FALSE);

	if (result == cib_ok && activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		crm_warn("Replacment of section=%s failed", section);
		result = cib_ACTIVATION;
	}

	if (verbose || result != cib_ok) {
		*answer = createCibFragmentAnswer(section, NULL);
	}
	
	cib_post_notify(op, the_update, result,
			get_object_root(section, get_the_CIB()));

	return result;
}

enum cib_errors 
cib_process_modify(
	const char *op, int options, const char *section, xmlNodePtr input,
	xmlNodePtr *answer)
{
	gboolean verbose = FALSE;
	enum cib_errors result = cib_ok;
	const char *section_name = section;

	xmlNodePtr failed = NULL;
	xmlNodePtr cib_update = NULL;
	xmlNodePtr the_update = NULL;
	
	int cib_update_op = CIB_OP_NONE;

	xmlNodePtr tmpCib  = NULL;

	char *xml_text  = NULL;

	crm_debug("Processing \"%s\" event", op);

	failed  = create_xml_node(NULL, XML_TAG_FAILED);

	if (strcmp(CRM_OP_CIB_CREATE, op) == 0) {
		cib_update_op = CIB_OP_ADD;
		
	} else if (strcmp(CRM_OP_CIB_UPDATE, op) == 0
		   || strcmp(CRM_OP_JOINACK, op) == 0
		   || strcmp(CRM_OP_SHUTDOWN_REQ, op) == 0) {
		cib_update_op = CIB_OP_MODIFY;
		
	} else if (strcmp(CRM_OP_CIB_DELETE, op) == 0) {
		cib_update_op = CIB_OP_DELETE;
		
	} else {
		crm_err("Incorrect request handler invoked for \"%s\" op",
			crm_str(op));
		return cib_operation;
	}

	result = cib_ok;
	if (options & cib_verbose) {
		verbose = TRUE;
	}
	if(safe_str_eq("all", section)) {
		section = NULL;
	}

	if(input == NULL) {
		crm_err("Cannot perform modification with no data");
		return cib_NOOBJECT;
	}
	
	tmpCib = copy_xml_node_recursive(get_the_CIB());
	cib_update = find_xml_node(input, XML_TAG_CIB);
	
	/* should we be doing this? */
	/* do logging */
			
	cib_pre_notify(op, get_object_root(section, get_the_CIB()), the_update);
	
	/* make changes to a temp copy then activate */
	if(section == NULL) {
		/* order is no longer important here */
		section_name = tmpCib->name;
		the_update = cib_update;

		result = updateList(tmpCib, input, failed, cib_update_op,
				    XML_CIB_TAG_NODES);

		if(result == cib_ok) {
			result = updateList(
				tmpCib, input, failed,
				cib_update_op, XML_CIB_TAG_RESOURCES);
		}
		if(result == cib_ok) {
			result = updateList(
				tmpCib, input, failed,
				cib_update_op, XML_CIB_TAG_CONSTRAINTS);
		}
		if(result == cib_ok) {
			result = updateList(tmpCib, input, failed,
					    cib_update_op, XML_CIB_TAG_STATUS);
		}

	} else {
		the_update = get_object_root(section, cib_update);
		result = updateList(tmpCib, input, failed,
				     cib_update_op, section);
	}

	crm_trace("Activating temporary CIB");
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, FALSE);

	if (result == cib_ok && activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
			
	} else if (result != cib_ok || failed->children != NULL) {
		if(result == cib_ok) {
			result = cib_unknown;
		}
		crm_xml_info(failed, "CIB Update failures");
		
		xml_text = dump_xml_formatted(failed);
		crm_free(xml_text);
	}

	if (verbose || failed->children != NULL || result != cib_ok) {
		*answer = createCibFragmentAnswer(section, failed);
	}

	cib_post_notify(op, the_update, result,
			get_object_root(section, get_the_CIB()));

	free_xml(failed);

	return result;
}


gboolean
replace_section(const char *section, xmlNodePtr tmpCib, xmlNodePtr fragment)
{
	xmlNodePtr parent = NULL,
		cib_updates = NULL,
		new_section = NULL,
		old_section = NULL;
	
	cib_updates = find_xml_node(fragment, XML_TAG_CIB);

	/* find the old and new versions of the section */
	new_section = get_object_root(section, cib_updates);
	old_section = get_object_root(section, tmpCib);
	
	if(old_section == NULL) {
		crm_err("The CIB is corrupt, cannot replace missing section %s",
		       section);
		return FALSE;

	} else if(new_section == NULL) {
		crm_err("The CIB is corrupt, cannot set section %s to nothing",
		       section);
		return FALSE;
	}

	parent = old_section->parent;
	
	/* unlink and free the old one */
	unlink_xml_node(old_section);
	free_xml(old_section);

	/* add the new copy */
	add_node_copy(parent, new_section);

	return TRUE;
}



enum cib_errors
updateList(xmlNodePtr local_cib, xmlNodePtr update_fragment, xmlNodePtr failed,
	   int operation, const char *section)
{
	int rc = cib_ok;
	xmlNodePtr this_section = get_object_root(section, local_cib);
	xmlNodePtr cib_updates  = NULL;
	xmlNodePtr xml_section  = NULL;

	cib_updates  = find_xml_node(update_fragment, XML_TAG_CIB);
	xml_section  = get_object_root(section, cib_updates);
	
	if (section == NULL || xml_section == NULL) {
		crm_err("Section %s not found in message."
			"  CIB update is corrupt, ignoring.",
			crm_str(section));
		return cib_NOSECTION;
	}

	if(CIB_OP_NONE > operation > CIB_OP_MAX) {
		crm_err("Invalid operation on section %s", crm_str(section));
		return cib_operation;
	}

	set_node_tstamp(this_section);

	xml_child_iter(
		xml_section, a_child, NULL,

		rc = cib_ok;
		if(operation == CIB_OP_DELETE) {
			rc = delete_cib_object(this_section, a_child);
			update_results(failed, a_child, operation, rc);

		} else if(operation == CIB_OP_MODIFY) {
			rc = update_cib_object(this_section, a_child, FALSE);
			update_results(failed, a_child, operation, rc);
				       
		} else {
			rc = add_cib_object(this_section, a_child);
			update_results(failed, a_child, operation, rc);
		} 
		);

	if(rc == cib_ok && failed->children != NULL) {
		rc = cib_unknown;
	}
	return rc;
}

xmlNodePtr
createCibFragmentAnswer(const char *section, xmlNodePtr failed)
{
	xmlNodePtr cib = NULL;
	xmlNodePtr fragment = NULL;
	
	fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);

	if (section == NULL
		   || strlen(section) == 0
		   || strcmp("all", section) == 0) {

		cib = get_the_CIB();
		if(cib != NULL) {
			add_node_copy(fragment, get_the_CIB());
		}
		
	} else {
		xmlNodePtr obj_root = get_object_root(section, get_the_CIB());

		if(obj_root != NULL) {
			cib      = create_xml_node(fragment, XML_TAG_CIB);

			add_node_copy(cib, obj_root);
			copy_in_properties(cib, get_the_CIB());
		} 
	}

	if (failed != NULL && failed->children != NULL) {
		add_node_copy(fragment, failed);
	}
		
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);
	set_xml_property_copy(fragment, "generated_on", cib_our_uname);
	return fragment;
}

gboolean
check_generation(xmlNodePtr newCib, xmlNodePtr oldCib)
{
	if(cib_compare_generation(newCib, oldCib) >= 0) {
		return TRUE;
	}

	crm_warn("Generation from update is older than the existing one");
	return FALSE;
}
 
gboolean
update_results(
	xmlNodePtr failed, xmlNodePtr target, int operation, int return_code)
{
	gboolean   was_error      = FALSE;
	const char *error_msg     = NULL;
	const char *operation_msg = NULL;
	xmlNodePtr xml_node       = NULL;
	
	operation_msg = cib_op2string(operation);
    
	if (return_code != cib_ok) {
		error_msg = cib_error2string(return_code);

		xml_node = create_xml_node(failed, XML_FAIL_TAG_CIB);

		was_error = TRUE;

		add_node_copy(xml_node, target);
		
		set_xml_property_copy(
			xml_node, XML_FAILCIB_ATTR_ID, ID(target));

		set_xml_property_copy(
			xml_node, XML_FAILCIB_ATTR_OBJTYPE, TYPE(target));

		set_xml_property_copy(
			xml_node, XML_FAILCIB_ATTR_OP, operation_msg);
	
		set_xml_property_copy(
			xml_node, XML_FAILCIB_ATTR_REASON, error_msg);

		crm_debug("Action %s failed: %s (cde=%d)",
			  operation_msg, error_msg, return_code);
	
	} else {
		crm_debug("CIB %s passed", operation_msg);
	}

	return was_error;
}

