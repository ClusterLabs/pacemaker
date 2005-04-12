/* $Id: messages.c,v 1.33 2005/04/12 09:23:26 andrew Exp $ */
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

#include <heartbeat.h>
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
enum cib_errors revision_check(crm_data_t *cib_update, crm_data_t *cib_copy, int flags);
int get_revision(crm_data_t *xml_obj, int cur_revision);

enum cib_errors updateList(
	crm_data_t *local_cib, crm_data_t *update_command, crm_data_t *failed,
	int operation, const char *section);

crm_data_t *createCibFragmentAnswer(const char *section, crm_data_t *failed);

enum cib_errors replace_section(
	const char *section, crm_data_t *tmpCib, crm_data_t *command);

gboolean check_generation(crm_data_t *newCib, crm_data_t *oldCib);

gboolean update_results(
	crm_data_t *failed, crm_data_t *target, int operation, int return_code);

enum cib_errors cib_update_counter(
	crm_data_t *xml_obj, const char *field, gboolean reset);

int set_connected_peers(crm_data_t *xml_obj);
void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data);


int
set_connected_peers(crm_data_t *xml_obj)
{
	int active = 0;
	char *peers_s = NULL;

	g_hash_table_foreach(peer_hash, GHFunc_count_peers, &active);
	peers_s = crm_itoa(active);
	set_xml_property_copy(xml_obj, XML_ATTR_NUMPEERS, peers_s);
	crm_free(peers_s);

	return active;
}

void GHFunc_count_peers(gpointer key, gpointer value, gpointer user_data)
{
	int *active = user_data;
	if(safe_str_eq(value, ONLINESTATUS)) {
		(*active)++;
		
	} else if(safe_str_eq(value, JOINSTATUS)) {
		(*active)++;
	}
}

enum cib_errors 
cib_process_default(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) { *answer = NULL; }	

	if(op == NULL) {
		result = cib_operation;
		crm_err("No operation specified");
		
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
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
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
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
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
		if(cib_is_master == FALSE) {
			crm_info("We are now in R/W mode");
			cib_is_master = TRUE;
		} else {
			crm_debug("We are still in R/W mode");
		}
		
	} else if(cib_is_master) {
		crm_info("We are now in R/O mode");
		cib_is_master = FALSE;
	}
	cib_post_notify(op, NULL, result, NULL);

	return result;
}

enum cib_errors 
cib_process_ping(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) {
		*answer = createPingAnswerFragment(CRM_SYSTEM_CIB, "ok");
	}
	return result;
}


enum cib_errors 
cib_process_query(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	crm_data_t *obj_root = NULL;
	enum cib_errors result = cib_ok;

	crm_debug("Processing \"%s\" event for section=%s",
		  op, crm_str(section));

	if(answer != NULL) { *answer = NULL; }	
	else { return cib_output_ptr; }
	
#if 1
	if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
		section = NULL;
	}
#else
	if (section == NULL) {
		section = XML_CIB_TAG_SECTION_ALL;
	}
#endif

	*answer = create_xml_node(NULL, XML_TAG_FRAGMENT);
/*  	set_xml_property_copy(*answer, XML_ATTR_SECTION, section); */

	obj_root = get_object_root(section, get_the_CIB());
	
	if(obj_root == NULL) {
		result = cib_NOTEXISTS;

	} else if(obj_root == get_the_CIB()) {
		set_xml_property_copy(obj_root, "origin", cib_our_uname);
		add_node_copy(*answer, obj_root);

	} else {
		crm_data_t *cib = createEmptyCib();
		crm_data_t *query_obj_root = get_object_root(section, cib);
		copy_in_properties(cib, get_the_CIB());
		set_xml_property_copy(cib, "origin", cib_our_uname);

		xml_child_iter(
			obj_root, an_obj, NULL,
			add_node_copy(query_obj_root, an_obj);
			);

		add_node_copy(*answer, cib);
		free_xml(cib);
	}

	if(result == cib_ok && *answer == NULL) {
		crm_err("Error creating query response");
		result = cib_output_data;
	}
	
	return result;
}

enum cib_errors 
cib_process_erase(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	crm_data_t *tmpCib = NULL;
	enum cib_errors result = cib_ok;

	crm_debug("Processing \"%s\" event", op);
	if(answer != NULL) { *answer = NULL; }	

	tmpCib = createEmptyCib();

	result = revision_check(get_the_CIB(), tmpCib, options);		
	copy_in_properties(tmpCib, get_the_CIB());
	
	cib_pre_notify(op, the_cib, tmpCib);
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, TRUE);

	if(result == cib_ok && activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
	}

	cib_post_notify(op, NULL, result, the_cib);
	if(answer != NULL) {
		*answer = createCibFragmentAnswer(NULL, NULL);
	}
	
	return result;
}

enum cib_errors 
cib_process_bump(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	crm_data_t *tmpCib = NULL;
	enum cib_errors result = cib_ok;

	crm_debug("Processing \"%s\" event for epoche=%s",
		  op, crm_str(crm_element_value(the_cib, XML_ATTR_GENERATION)));
	
	if(answer != NULL) { *answer = NULL; }	

	cib_pre_notify(op, get_the_CIB(), NULL);

	tmpCib = copy_xml_node_recursive(the_cib);
	cib_update_counter(tmpCib, XML_ATTR_GENERATION, FALSE);
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, FALSE);
	
	if(activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
	}

	cib_post_notify(op, NULL, result, get_the_CIB());
	if(answer != NULL) {
		*answer = createCibFragmentAnswer(NULL, NULL);
	}
	
	return result;
}

enum cib_errors 
cib_update_counter(crm_data_t *xml_obj, const char *field, gboolean reset)
{
	char *new_value = NULL;
	char *old_value = NULL;
	int  int_value  = -1;

	/* modify the timestamp */
	set_node_tstamp(xml_obj);
	if(reset == FALSE && crm_element_value(xml_obj, field) != NULL) {
		old_value = crm_element_value_copy(xml_obj, field);
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

	if(safe_str_eq(field, XML_ATTR_NUMUPDATES)) {
		set_connected_peers(xml_obj);
		if(cib_have_quorum) {
			set_xml_property_copy(
				xml_obj, XML_ATTR_HAVE_QUORUM, XML_BOOLEAN_TRUE);
		} else {
			set_xml_property_copy(
				xml_obj, XML_ATTR_HAVE_QUORUM, XML_BOOLEAN_FALSE);
		}
	}
	
	crm_free(old_value);
	return cib_ok;
}

enum cib_errors 
cib_process_replace(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	gboolean verbose       = FALSE;
	crm_data_t *tmpCib      = NULL;
	crm_data_t *cib_update  = NULL;
	crm_data_t *the_update  = NULL;
	char *section_name = NULL;
	enum cib_errors result = cib_ok;
	
	crm_debug("Processing \"%s\" event for section=%s", op, crm_str(section));
	if(answer != NULL) { *answer = NULL; }	

	if (options & cib_verbose) {
		verbose = TRUE;
	}
	if(safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
		section = NULL;
	}
	
	cib_update = find_xml_node(input, XML_TAG_CIB, TRUE);
	
	if (cib_update == NULL) {
		result = cib_NOOBJECT;
		
	} else if (section == NULL) {
		tmpCib = copy_xml_node_recursive(cib_update);
		the_update = cib_update;
		section_name = crm_strdup(crm_element_name(tmpCib));
		
	} else {
		tmpCib = copy_xml_node_recursive(get_the_CIB());
		section_name = crm_strdup(section);
		
		result = replace_section(section_name, tmpCib, input);
		the_update = get_object_root(section_name, cib_update);
	}

	cib_pre_notify(
		op, get_object_root(section_name, get_the_CIB()), the_update);

	if(result == cib_ok) {
		cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, FALSE);
		
		result = revision_check(the_update, tmpCib, options);		
		copy_in_properties(tmpCib, cib_update);
	}
	
	if (result == cib_ok && activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		crm_warn("Replacment of section=%s failed", section);
		result = cib_ACTIVATION;
	}

	if (verbose || result != cib_ok) {
		if(answer != NULL) {
			*answer = createCibFragmentAnswer(section_name, NULL);
		}
	}
	
	cib_post_notify(op, the_update, result,
			get_object_root(section_name, get_the_CIB()));

	crm_free(section_name);
	return result;
}


/* FILE *msg_cibup_strm = NULL; */

enum cib_errors 
cib_process_modify(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t **answer)
{
	gboolean verbose = FALSE;
	enum cib_errors result = cib_ok;
	char *section_name = NULL;

	crm_data_t *failed = NULL;
	crm_data_t *cib_update = NULL;
	crm_data_t *the_update = NULL;
	
	int cib_update_op = CIB_OP_NONE;

	crm_data_t *tmpCib  = NULL;

	crm_debug("Processing \"%s\" event for section=%s", op, crm_str(section));

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
	
	if(safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
		section = NULL;
	}

	if(input == NULL) {
		crm_err("Cannot perform modification with no data");
		return cib_NOOBJECT;
	}
	
	tmpCib = copy_xml_node_recursive(get_the_CIB());
	cib_update = find_xml_node(input, XML_TAG_CIB, TRUE);
	
	/* do logging */
	the_update = get_object_root(section, cib_update);

	crm_validate_data(the_update);
	crm_validate_data(tmpCib);

	cib_pre_notify(op, get_object_root(section, tmpCib), the_update);

	crm_validate_data(the_update);
	crm_validate_data(tmpCib);
	
	result = revision_check(cib_update, tmpCib, options);		
	copy_in_properties(tmpCib, cib_update);
	
	/* make changes to a temp copy then activate */
	if(section == NULL) {
		/* order is no longer important here */
		section_name = crm_strdup(crm_element_name(tmpCib));
	
		if(result == cib_ok) {

			result = updateList(
				tmpCib, input, failed, cib_update_op,
				XML_CIB_TAG_NODES);
		}
		
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
		section_name = crm_strdup(section);
		result = updateList(tmpCib, input, failed,
				     cib_update_op, section);
	}

	crm_trace("Activating temporary CIB");
	cib_update_counter(tmpCib, XML_ATTR_NUMUPDATES, FALSE);

	if (result == cib_ok && activateCibXml(tmpCib, CIB_FILENAME) < 0) {
		result = cib_ACTIVATION;
			
	} else if (result != cib_ok || xml_has_children(failed)) {
		if(result == cib_ok) {
			result = cib_unknown;
		}
		crm_xml_err(failed, "CIB Update failures");
	}

	if (verbose || xml_has_children(failed) || result != cib_ok) {
		*answer = createCibFragmentAnswer(section_name, failed);
	}

	cib_post_notify(op, the_update, result,
			get_object_root(section_name, get_the_CIB()));

	free_xml(failed);
	crm_free(section_name);
	
	return result;
}


enum cib_errors
replace_section(const char *section, crm_data_t *tmpCib, crm_data_t *fragment)
{
	crm_data_t *cib_updates = NULL;
	crm_data_t *new_section = NULL;
	crm_data_t *old_section = NULL;
	
	cib_updates = find_xml_node(fragment, XML_TAG_CIB, TRUE);

	/* find the old and new versions of the section */
	new_section = get_object_root(section, cib_updates);
	old_section = get_object_root(section, tmpCib);
	
	if(old_section == NULL) {
		crm_err("The CIB is corrupt, cannot replace missing section %s",
		       section);
		return cib_NOSECTION;

	} else if(new_section == NULL) {
		crm_err("The CIB is corrupt, cannot set section %s to nothing",
		       section);
		return cib_NOSECTION;
	}

	xml_child_iter(
		old_section, a_child, NULL,
		free_xml_from_parent(old_section, a_child);
		);

	copy_in_properties(old_section, new_section);

	xml_child_iter(
		new_section, a_child, NULL,
		add_node_copy(old_section, a_child);
		);

	return cib_ok;
}



enum cib_errors
updateList(crm_data_t *local_cib, crm_data_t *update_fragment, crm_data_t *failed,
	   int operation, const char *section)
{
	int rc = cib_ok;
	crm_data_t *this_section = get_object_root(section, local_cib);
	crm_data_t *cib_updates  = NULL;
	crm_data_t *xml_section  = NULL;

	cib_updates  = find_xml_node(update_fragment, XML_TAG_CIB, TRUE);
	xml_section  = get_object_root(section, cib_updates);
	
	if (section == NULL || xml_section == NULL) {
		crm_err("Section %s not found in message."
			"  CIB update is corrupt, ignoring.",
			crm_str(section));
		return cib_NOSECTION;
	}

	if((CIB_OP_NONE > operation) || (operation > CIB_OP_MAX)) {
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

	if(rc == cib_ok && xml_has_children(failed)) {
		rc = cib_unknown;
	}
	return rc;
}

crm_data_t*
createCibFragmentAnswer(const char *section, crm_data_t *failed)
{
	crm_data_t *cib = NULL;
	crm_data_t *fragment = NULL;
	
	fragment = create_xml_node(NULL, XML_TAG_FRAGMENT);

	if (section == NULL
		   || strlen(section) == 0
		   || strcmp(XML_CIB_TAG_SECTION_ALL, section) == 0) {

		cib = get_the_CIB();
		if(cib != NULL) {
			add_node_copy(fragment, get_the_CIB());
		}
		
	} else {
		crm_data_t *obj_root = get_object_root(section, get_the_CIB());

		if(obj_root != NULL) {
			cib = create_xml_node(fragment, XML_TAG_CIB);

			add_node_copy(cib, obj_root);
			copy_in_properties(cib, get_the_CIB());
		} 
	}

	if (failed != NULL && xml_has_children(failed)) {
		add_node_copy(fragment, failed);
	}
		
	set_xml_property_copy(fragment, XML_ATTR_SECTION, section);
	set_xml_property_copy(fragment, "generated_on", cib_our_uname);
	return fragment;
}

gboolean
check_generation(crm_data_t *newCib, crm_data_t *oldCib)
{
	if(cib_compare_generation(newCib, oldCib) >= 0) {
		return TRUE;
	}

	crm_warn("Generation from update is older than the existing one");
	return FALSE;
}
 
gboolean
update_results(
	crm_data_t *failed, crm_data_t *target, int operation, int return_code)
{
	gboolean   was_error      = FALSE;
	const char *error_msg     = NULL;
	const char *operation_msg = NULL;
	crm_data_t *xml_node       = NULL;
	
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

		crm_warn("Action %s failed: %s (cde=%d)",
			  operation_msg, error_msg, return_code);
	
	} else {
		crm_devel("CIB %s passed", operation_msg);
	}

	return was_error;
}

enum cib_errors
revision_check(crm_data_t *cib_update, crm_data_t *cib_copy, int flags)
{
	enum cib_errors rc = cib_ok;
	char *revision = crm_element_value_copy(
		cib_update, XML_ATTR_CIB_REVISION);
	const char *cur_revision = crm_element_value(
		cib_copy, XML_ATTR_CIB_REVISION);

	crm_validate_data(cib_update);
	crm_validate_data(cib_copy);
	
	if(revision == NULL) {
		return cib_ok;

	} else if(cur_revision == NULL
		  || strcmp(revision, cur_revision) > 0) {
		crm_info("Updating CIB revision to %s", revision);
		set_xml_property_copy(
			cib_copy, XML_ATTR_CIB_REVISION, revision);
	} else {
		/* make sure we end up with the right value in the end */
		set_xml_property_copy(
			cib_update, XML_ATTR_CIB_REVISION, cur_revision);
	}
	
	if(strcmp(revision, cib_feature_revision_s) > 0) {
		CRM_DEV_ASSERT(cib_is_master == FALSE);
		CRM_DEV_ASSERT((flags & cib_scope_local) == 0);

		if(cib_is_master) {
			crm_err("Update uses an unsupported tag/feature:"
				" %s vs %s",
				revision, cib_feature_revision_s);
			rc = cib_revision_unsupported;

		} else if(flags & cib_scope_local) {
			 /* an admin has forced a local change using a tag we
			  * dont understand... ERROR
			  */
			crm_err("Local update uses an unsupported tag/feature:"
				" %s vs %s",
				revision, cib_feature_revision_s);
			rc = cib_revision_unsupported;
		}
	}
	
	crm_free(revision);
	return rc;
}
