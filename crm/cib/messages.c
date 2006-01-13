/* $Id: messages.c,v 1.61 2006/01/13 10:31:14 andrew Exp $ */
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
#include <callbacks.h>
#include <notify.h>

#include <crm/dmalloc_wrapper.h>

#define MAX_DIFF_RETRY 5

extern const char *cib_our_uname;
extern gboolean syncd_once;
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

enum cib_errors sync_our_cib(HA_Message *request, gboolean all);

enum cib_errors 
cib_process_default(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);
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
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);

	crm_warn("The CRMd has asked us to exit... complying");
	exit(0);
	return result;
}


enum cib_errors 
cib_process_readwrite(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);

	if(safe_str_eq(op, CIB_OP_ISMASTER)) {
		if(cib_is_master == TRUE) {
			result = cib_ok;
		} else {
			result = cib_not_master;
		}
		return result;
	}

	if(safe_str_eq(op, CIB_OP_MASTER)) {
		if(cib_is_master == FALSE) {
			crm_info("We are now in R/W mode");
			cib_is_master = TRUE;
			syncd_once = TRUE;
			
		} else {
			crm_debug("We are still in R/W mode");
		}
		
	} else if(cib_is_master) {
		crm_info("We are now in R/O mode");
		cib_is_master = FALSE;
	}

	return result;
}

enum cib_errors 
cib_process_ping(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);
	if(answer != NULL) {
		*answer = createPingAnswerFragment(CRM_SYSTEM_CIB, "ok");
	}
	return result;
}


enum cib_errors 
cib_process_query(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	crm_data_t *obj_root = NULL;
	enum cib_errors result = cib_ok;

	crm_debug_2("Processing \"%s\" event for section=%s",
		  op, crm_str(section));

	if(answer != NULL) { *answer = NULL; }	
	else { return cib_output_ptr; }
	
	if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
		section = NULL;
	}

	*answer = create_xml_node(NULL, XML_TAG_FRAGMENT);
/*  	crm_xml_add(*answer, XML_ATTR_SECTION, section); */

	obj_root = get_object_root(section, existing_cib);
	
	if(obj_root == NULL) {
		result = cib_NOTEXISTS;

	} else if(obj_root == existing_cib) {
		crm_xml_add(obj_root, "origin", cib_our_uname);
		add_node_copy(*answer, obj_root);

	} else {
		crm_data_t *cib = createEmptyCib();
		crm_data_t *query_obj_root = get_object_root(section, cib);
		copy_in_properties(cib, existing_cib);
		crm_xml_add(cib, "origin", cib_our_uname);

		xml_child_iter(
			obj_root, an_obj, 
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
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;

	crm_debug_2("Processing \"%s\" event", op);
	if(answer != NULL) { *answer = NULL; }	

	*result_cib = createEmptyCib();

	result = revision_check(existing_cib, *result_cib, options);
	copy_in_properties(*result_cib, existing_cib);
	
	if(result == cib_ok && !(options & cib_inhibit_bcast)) {
		cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, TRUE);
	}
	
	if(answer != NULL) {
		*answer = createCibFragmentAnswer(NULL, NULL);
	}
	
	return result;
}

enum cib_errors 
cib_process_bump(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	enum cib_errors result = cib_ok;

	crm_debug_2("Processing \"%s\" event for epoch=%s",
		  op, crm_str(crm_element_value(the_cib, XML_ATTR_GENERATION)));
	
	if(answer != NULL) { *answer = NULL; }	

	*result_cib = copy_xml(the_cib);

	cib_update_counter(*result_cib, XML_ATTR_GENERATION, FALSE);
	cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, FALSE);
	
	if(answer != NULL) {
		*answer = createCibFragmentAnswer(NULL, NULL);
	}
	
	return result;
}

extern ll_cluster_t *hb_conn;
extern HA_Message *cib_msg_copy(const HA_Message *msg, gboolean with_data);

enum cib_errors 
cib_process_sync(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	return sync_our_cib(input, TRUE);
}

enum cib_errors 
cib_process_sync_one(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	return sync_our_cib(input, FALSE);
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
		crm_malloc0(new_value, 128*(sizeof(char)));
		int_value = atoi(old_value);
		sprintf(new_value, "%d", ++int_value);
	} else {
		new_value = crm_strdup("1");
	}

	crm_debug_4("%s %d(%s)->%s",
		  field, int_value, crm_str(old_value), crm_str(new_value));
	crm_xml_add(xml_obj, field, new_value);
	crm_free(new_value);

	crm_free(old_value);
	return cib_ok;
}

int sync_in_progress = 0;

enum cib_errors 
cib_process_diff(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	unsigned int log_level = LOG_DEBUG;
	const char *value = NULL;
	const char *reason = NULL;
	gboolean apply_diff = TRUE;
	gboolean do_resync = FALSE;
	enum cib_errors result = cib_ok;

	int this_updates = 0;
	int this_epoch  = 0;
	int this_admin_epoch = 0;

	int diff_add_updates = 0;
	int diff_add_epoch  = 0;
	int diff_add_admin_epoch = 0;

	int diff_del_updates = 0;
	int diff_del_epoch  = 0;
	int diff_del_admin_epoch = 0;

	crm_debug_2("Processing \"%s\" event", op);

	if(cib_is_master) {
		/* the master is never waiting for a resync */
		sync_in_progress = 0;
	}
	
	cib_diff_version_details(
		input,
		&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

	if(sync_in_progress > MAX_DIFF_RETRY) {
		/* request another full-sync,
		 * the last request may have been lost
		 */
		sync_in_progress = 0;
	} 
	if(sync_in_progress) {
		sync_in_progress++;
		crm_warn("Not applying diff %d.%d.%d -> %d.%d.%d (sync in progress)",
			diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
			diff_add_admin_epoch,diff_add_epoch,diff_add_updates);
		return cib_diff_resync;
	}
	
	value = crm_element_value(existing_cib, XML_ATTR_GENERATION);
	this_epoch = atoi(value?value:"0");
	
	value = crm_element_value(existing_cib, XML_ATTR_NUMUPDATES);
	this_updates = atoi(value?value:"0");
	
	value = crm_element_value(existing_cib, XML_ATTR_GENERATION_ADMIN);
	this_admin_epoch = atoi(value?value:"0");
	
	if(diff_del_admin_epoch == diff_add_admin_epoch
	   && diff_del_epoch == diff_add_epoch
	   && diff_del_updates == diff_add_updates) {
		apply_diff = FALSE;
		log_level = LOG_ERR;
		reason = "+ and - versions in the diff did not change";
		log_cib_diff(LOG_ERR, input, __FUNCTION__);
	}

	if(apply_diff && diff_del_admin_epoch > this_admin_epoch) {
		do_resync = TRUE;
		apply_diff = FALSE;
		log_level = LOG_INFO;
		reason = "current \""XML_ATTR_GENERATION_ADMIN"\" is less than required";
		
	} else if(apply_diff && diff_del_admin_epoch < this_admin_epoch) {
		apply_diff = FALSE;
		log_level = LOG_WARNING;
		reason = "current \""XML_ATTR_GENERATION_ADMIN"\" is greater than required";
	}

	if(apply_diff && diff_del_epoch > this_epoch) {
		do_resync = TRUE;
		apply_diff = FALSE;
		log_level = LOG_INFO;
		reason = "current \""XML_ATTR_GENERATION"\" is less than required";
		
	} else if(apply_diff && diff_del_epoch < this_epoch) {
		apply_diff = FALSE;
		log_level = LOG_WARNING;
		reason = "current \""XML_ATTR_GENERATION"\" is greater than required";
	}

	if(apply_diff && diff_del_updates > this_updates) {
		do_resync = TRUE;
		apply_diff = FALSE;
		log_level = LOG_INFO;
		reason = "current \""XML_ATTR_NUMUPDATES"\" is less than required";
		
	} else if(apply_diff && diff_del_updates < this_updates) {
		apply_diff = FALSE;
		log_level = LOG_WARNING;
		reason = "current \""XML_ATTR_NUMUPDATES"\" is greater than required";
	}

	if(apply_diff
	   && apply_cib_diff(existing_cib, input, result_cib) == FALSE) {
		log_level = LOG_WARNING;
		reason = "Failed application of an update diff";
		if(options & cib_force_diff && cib_is_master == FALSE) {
  			log_level = LOG_INFO;
			reason = "Failed application of a global update.  Requesting full refresh.";
			do_resync = TRUE;
		} else if(options & cib_force_diff) {
			reason = "Failed application of a global update.  Not requesting full refresh.";
		}
	}
	

	if(reason != NULL) {
		crm_log_maybe(
			log_level,
			"Diff %d.%d.%d -> %d.%d.%d not applied to %d.%d.%d: %s",
			diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
			diff_add_admin_epoch,diff_add_epoch,diff_add_updates,
			this_admin_epoch,this_epoch,this_updates, reason);
		
		result = cib_diff_failed;

	} else if(apply_diff) {
		crm_debug_2("Diff %d.%d.%d -> %d.%d.%d was applied",
			    diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
			    diff_add_admin_epoch,diff_add_epoch,diff_add_updates);
	}

	if(do_resync && cib_is_master == FALSE) {
		HA_Message *sync_me = ha_msg_new(3);
		free_xml(*result_cib);
		*result_cib = NULL;
		result = cib_diff_resync;
		crm_info("Requesting re-sync from peer: %s", reason);
		sync_in_progress++;
		
		ha_msg_add(sync_me, F_TYPE, "cib");
		ha_msg_add(sync_me, F_CIB_OPERATION, CIB_OP_SYNC_ONE);
		ha_msg_add(sync_me, F_CIB_DELEGATED, cib_our_uname);

		if(send_ha_message(hb_conn, sync_me, NULL, FALSE) == FALSE) {
			result = cib_not_connected;
		}
		ha_msg_del(sync_me);
		
	} else if(do_resync) {
		crm_err("Not resyncing in master mode");
	}
	
	
	return result;
}

enum cib_errors 
cib_process_replace(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	gboolean send_notify   = FALSE;
	gboolean verbose       = FALSE;
	enum cib_errors result = cib_ok;
	
	crm_debug_2("Processing \"%s\" event for section=%s", op, crm_str(section));
	if(answer != NULL) { *answer = NULL; }	

	if (options & cib_verbose) {
		verbose = TRUE;
	}
	if(safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
		section = NULL;
	}
	
	if (input == NULL) {
		result = cib_NOOBJECT;
		
	} else if(section == NULL) {
		int updates = 0;
		int epoch  = 0;
		int admin_epoch = 0;
		
		int replace_updates = 0;
		int replace_epoch  = 0;
		int replace_admin_epoch = 0;
		const char *reason = NULL;
		
		cib_version_details(
			existing_cib, &admin_epoch, &epoch, &updates);
		cib_version_details(input, &replace_admin_epoch,
				    &replace_epoch, &replace_updates);

		if(replace_admin_epoch < admin_epoch) {
			reason = XML_ATTR_GENERATION_ADMIN;

		} else if(replace_admin_epoch > admin_epoch) {
			/* no more checks */
		} else if(replace_epoch < epoch) {
			reason = XML_ATTR_GENERATION;

		} else if(replace_epoch > epoch) {
			/* no more checks */

		} else if(replace_updates < updates) {
			reason = XML_ATTR_NUMUPDATES;
		}

		if(reason != NULL) {
			crm_warn("Replacement %d.%d.%d not applied to %d.%d.%d:"
				 " current %s is greater than the replacement",
				 replace_admin_epoch, replace_epoch,
				 replace_updates, admin_epoch, epoch, updates,
				 reason);
			result = cib_old_data;
		}
		sync_in_progress = 0;
		*result_cib = copy_xml(input);
		send_notify = TRUE;
		
	} else {
		*result_cib = copy_xml(existing_cib);
		result = replace_section(section, *result_cib, input);

		if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
			send_notify = TRUE;
		}
	}

	if(send_notify) {
		crm_data_t *local_diff = NULL;
		local_diff = diff_cib_object(existing_cib, *result_cib, FALSE);
		cib_replace_notify(*result_cib, result, local_diff);
		free_xml(local_diff);
	}	

	if(result == cib_ok && section != NULL) {
		cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, FALSE);
	}
	
	if (answer != NULL && (verbose || result != cib_ok)) {
		*answer = createCibFragmentAnswer(section, NULL);
	}

	return result;
}

enum cib_errors 
cib_process_delete(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	crm_debug_2("Processing \"%s\" event", op);

	if(input == NULL) {
		crm_err("Cannot perform modification with no data");
		return cib_NOOBJECT;
	}
	
	*result_cib = copy_xml(existing_cib);
	
	crm_validate_data(input);
	crm_validate_data(*result_cib);

	if(delete_xml_child(NULL, *result_cib, input) == FALSE) {
		return cib_NOTEXISTS;		
	}
	
	cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, FALSE);
	return cib_ok;
}


enum cib_errors 
cib_process_modify(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	crm_debug_2("Processing \"%s\" event", op);

	if(input == NULL) {
		crm_err("Cannot perform modification with no data");
		return cib_NOOBJECT;
	}
	
	*result_cib = copy_xml(existing_cib);
	
	crm_validate_data(input);
	crm_validate_data(*result_cib);

	if(update_xml_child(*result_cib, input) == FALSE) {
		return cib_NOTEXISTS;		
	}
	
	cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, FALSE);
	return cib_ok;
}

enum cib_errors 
cib_process_change(
	const char *op, int options, const char *section, crm_data_t *input,
	crm_data_t *existing_cib, crm_data_t **result_cib, crm_data_t **answer)
{
	gboolean verbose = FALSE;
	crm_data_t *failed = NULL;
	enum cib_errors result = cib_ok;
	int cib_update_op = CIB_UPDATE_OP_NONE;

	crm_debug_2("Processing \"%s\" event for section=%s", op, crm_str(section));

	failed = create_xml_node(NULL, XML_TAG_FAILED);

	if (strcmp(CIB_OP_CREATE, op) == 0) {
		cib_update_op = CIB_UPDATE_OP_ADD;
		
	} else if (strcmp(CIB_OP_UPDATE, op) == 0) {
		cib_update_op = CIB_UPDATE_OP_MODIFY;
		
	} else if (strcmp(CIB_OP_DELETE_ALT, op) == 0) {
		cib_update_op = CIB_UPDATE_OP_DELETE;
		
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
	
	*result_cib = copy_xml(existing_cib);
	
	crm_validate_data(input);
	crm_validate_data(*result_cib);
	
	/* make changes to a temp copy then activate */
	if(section == NULL) {
		crm_data_t *sub_input = NULL;
		copy_in_properties(*result_cib, input);
		/* order is no longer important here */
		if(result == cib_ok) {
			sub_input = get_object_root(XML_CIB_TAG_NODES, input);
			result = updateList(
				*result_cib, sub_input, failed, cib_update_op,
				XML_CIB_TAG_NODES);
		}
		
		if(result == cib_ok) {
			sub_input = get_object_root(XML_CIB_TAG_NODES, input);
			result = updateList(
				*result_cib, sub_input, failed, cib_update_op,
				XML_CIB_TAG_RESOURCES);
		}
		if(result == cib_ok) {
			sub_input = get_object_root(XML_CIB_TAG_NODES, input);
			result = updateList(
				*result_cib, sub_input, failed, cib_update_op,
				XML_CIB_TAG_CONSTRAINTS);
		}
		if(result == cib_ok) {
			sub_input = get_object_root(XML_CIB_TAG_NODES, input);
			result = updateList(
				*result_cib, sub_input, failed, cib_update_op,
				XML_CIB_TAG_STATUS);
		}

	} else {
		result = updateList(
			*result_cib, input, failed, cib_update_op, section);
	}

	if(result == cib_ok && !(options & cib_inhibit_bcast)) {
		cib_update_counter(*result_cib, XML_ATTR_NUMUPDATES, FALSE);
	}
	
	if (result != cib_ok || xml_has_children(failed)) {
		if(result == cib_ok) {
			result = cib_unknown;
		}
		crm_log_xml_err(failed, "CIB Update failures");
	}

	if (verbose || xml_has_children(failed) || result != cib_ok) {
		*answer = createCibFragmentAnswer(section, failed);
	}

	free_xml(failed);

	return result;
}


enum cib_errors
replace_section(
	const char *section, crm_data_t *tmpCib, crm_data_t *new_section)
{
	crm_data_t *old_section = NULL;

	/* find the old and new versions of the section */
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
		old_section, a_child, 
		free_xml_from_parent(old_section, a_child);
		);

	copy_in_properties(old_section, new_section);

	xml_child_iter(
		new_section, a_child, 
		add_node_copy(old_section, a_child);
		);

	return cib_ok;
}



enum cib_errors
updateList(crm_data_t *local_cib, crm_data_t *xml_section, crm_data_t *failed,
	   int operation, const char *section)
{
	int rc = cib_ok;
	crm_data_t *this_section = get_object_root(section, local_cib);
	
	if (section == NULL || xml_section == NULL) {
		crm_err("Section %s not found in message."
			"  CIB update is corrupt, ignoring.",
			crm_str(section));
		return cib_NOSECTION;
	}

	if((CIB_UPDATE_OP_NONE > operation) || (operation > CIB_UPDATE_OP_MAX)){
		crm_err("Invalid operation on section %s", crm_str(section));
		return cib_operation;
	}

	set_node_tstamp(this_section);

	xml_child_iter(
		xml_section, a_child, 

		rc = cib_ok;
		if(operation == CIB_UPDATE_OP_DELETE) {
			rc = delete_cib_object(this_section, a_child);
			update_results(failed, a_child, operation, rc);

		} else if(operation == CIB_UPDATE_OP_MODIFY) {
			rc = update_cib_object(this_section, a_child);
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
		
	crm_xml_add(fragment, XML_ATTR_SECTION, section);
	crm_xml_add(fragment, "generated_on", cib_our_uname);
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
		
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_ID, ID(target));
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_OBJTYPE, TYPE(target));
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_OP, operation_msg);
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_REASON, error_msg);

		crm_warn("Action %s failed: %s (cde=%d)",
			  operation_msg, error_msg, return_code);
	
	} else {
		crm_debug_3("CIB %s passed", operation_msg);
	}

	return was_error;
}

enum cib_errors
revision_check(crm_data_t *cib_update, crm_data_t *cib_copy, int flags)
{
	int cmp = 0;
	enum cib_errors rc = cib_ok;
	char *new_revision = NULL;
	const char *cur_revision = crm_element_value(
		cib_copy, XML_ATTR_CIB_REVISION);

	crm_validate_data(cib_update);
	crm_validate_data(cib_copy);
	
	if(crm_element_value(cib_update, XML_ATTR_CIB_REVISION) == NULL) {
		return cib_ok;
	}

	new_revision = crm_element_value_copy(cib_update,XML_ATTR_CIB_REVISION);
	
	cmp = compare_version(new_revision, CIB_FEATURE_SET);
	if(cmp > 0) {
		CRM_DEV_ASSERT(cib_is_master == FALSE);
		CRM_DEV_ASSERT((flags & cib_scope_local) == 0);

		if(cib_is_master) {
			crm_err("Update uses an unsupported tag/feature:"
				" %s vs %s", new_revision,CIB_FEATURE_SET);
			rc = cib_revision_unsupported;

		} else if(flags & cib_scope_local) {
			 /* an admin has forced a local change using a tag we
			  * dont understand... ERROR
			  */
			crm_err("Local update uses an unsupported tag/feature:"
				" %s vs %s", new_revision,CIB_FEATURE_SET);
			rc = cib_revision_unsupported;
		}

	} else if(cur_revision == NULL) {
		crm_info("Updating CIB revision to %s", new_revision);
		crm_xml_add(cib_copy, XML_ATTR_CIB_REVISION, new_revision);

	} else {
		/* make sure we end up with the right value in the end */
		crm_xml_add(cib_update, XML_ATTR_CIB_REVISION, cur_revision);
	} 
	
	crm_free(new_revision);
	return rc;
}


enum cib_errors
sync_our_cib(HA_Message *request, gboolean all) 
{
	enum cib_errors result      = cib_ok;
	const char *host            = cl_get_string(request, F_ORIG);
	const char *op              = cl_get_string(request, F_CIB_OPERATION);

	crm_data_t *sync_data       = create_cib_fragment(the_cib,XML_TAG_CIB);
	HA_Message *replace_request = cib_msg_copy(request, FALSE);
	
	CRM_DEV_ASSERT(sync_data != NULL);
	CRM_DEV_ASSERT(replace_request != NULL);
	
	crm_info("Syncing CIB to %s", all?"all peers":host);
	if(all == FALSE && host == NULL) {
		crm_log_message(LOG_ERR, request);
	}
	
	/* remove the "all == FALSE" condition
	 *
	 * sync_from was failing, the local client wasnt being notified
	 *    because it didnt know it was a reply
	 * setting this does not prevent the other nodes from applying it
	 *    if all == TRUE
	 */
	if(host != NULL) {
		ha_msg_add(replace_request, F_CIB_ISREPLY, host);
	}
	ha_msg_mod(replace_request, F_CIB_OPERATION, CIB_OP_REPLACE);
	ha_msg_add(replace_request, "original_"F_CIB_OPERATION, op);
	ha_msg_add(replace_request, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
	add_message_xml(replace_request, F_CIB_CALLDATA, sync_data);
	
	if(send_ha_message(hb_conn, replace_request, all?NULL:host, FALSE) == FALSE) {
		result = cib_not_connected;
	}
	ha_msg_del(replace_request);
	free_xml(sync_data);
	return result;
}
