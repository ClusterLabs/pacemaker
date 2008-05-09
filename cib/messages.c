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

#include <heartbeat.h>
#include <clplumbing/cl_log.h>

#include <time.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <crm/common/cluster.h>

#include <cibio.h>
#include <cibmessages.h>
#include <cibprimatives.h>
#include <callbacks.h>

#define MAX_DIFF_RETRY 5

#ifdef CIBPIPE
gboolean cib_is_master = TRUE;
#else
gboolean cib_is_master = FALSE;
#endif

gboolean syncd_once = FALSE;
xmlNode *the_cib = NULL;
extern const char *cib_our_uname;
enum cib_errors revision_check(xmlNode *cib_update, xmlNode *cib_copy, int flags);
int get_revision(xmlNode *xml_obj, int cur_revision);

enum cib_errors updateList(
	xmlNode *local_cib, xmlNode *update_command, xmlNode *failed,
	int operation, const char *section);

gboolean check_generation(xmlNode *newCib, xmlNode *oldCib);

gboolean update_results(
	xmlNode *failed, xmlNode *target, int operation, int return_code);

enum cib_errors cib_update_counter(
	xmlNode *xml_obj, const char *field, gboolean reset);

enum cib_errors sync_our_cib(xmlNode *request, gboolean all);

extern xmlNode *cib_msg_copy(const xmlNode *msg, gboolean with_data);
extern gboolean cib_shutdown_flag;
extern void terminate_cib(const char *caller);

enum cib_errors 
cib_process_shutdown_req(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
#ifdef CIBPIPE
    return cib_invalid_argument;
#else
	enum cib_errors result = cib_ok;
	const char *host = crm_element_value(req, F_ORIG);
	
	*answer = NULL;

	if(crm_element_value(req, F_CIB_ISREPLY) == NULL) {
		crm_info("Shutdown REQ from %s", host);
		return cib_ok;

	} else if(cib_shutdown_flag) {
		crm_info("Shutdown ACK from %s", host);
		terminate_cib(__FUNCTION__);
		return cib_ok;

	} else {
		crm_err("Shutdown ACK from %s - not shutting down",host);
		result = cib_unknown;
	}
	
	return result;
#endif
}

enum cib_errors 
cib_process_default(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);
	*answer = NULL;

	if(op == NULL) {
		result = cib_operation;
		crm_err("No operation specified");
		
	} else if(strcasecmp(CRM_OP_NOOP, op) == 0) {
		;

	} else {
		result = cib_NOTSUPPORTED;
		crm_err("Action [%s] is not supported by the CIB", op);
	}
	return result;
}

enum cib_errors 
cib_process_quit(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);

	crm_warn("The CRMd has asked us to exit... complying");
	exit(0);
	return result;
}

enum cib_errors 
cib_process_readwrite(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
#ifdef CIBPIPE
    return cib_invalid_argument;
#else
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
			*result_cib = update_validation(*result_cib, TRUE, TRUE);
			
		} else {
			crm_debug("We are still in R/W mode");
		}
		
	} else if(cib_is_master) {
		crm_info("We are now in R/O mode");
		cib_is_master = FALSE;
	}

	return result;
#endif
}

enum cib_errors 
cib_process_ping(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
#ifdef CIBPIPE
    return cib_invalid_argument;
#else
	enum cib_errors result = cib_ok;
	crm_debug_2("Processing \"%s\" event", op);
	*answer = createPingAnswerFragment(CRM_SYSTEM_CIB, "ok");
	return result;
#endif
}


enum cib_errors 
cib_process_sync(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
#ifdef CIBPIPE
    return cib_invalid_argument;
#else
    return sync_our_cib(req, TRUE);
#endif
}

enum cib_errors 
cib_process_sync_one(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
#ifdef CIBPIPE
    return cib_invalid_argument;
#else
    return sync_our_cib(req, FALSE);
#endif
}

int sync_in_progress = 0;

enum cib_errors 
cib_server_process_diff(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
	int rc = cib_ok;

	if(cib_is_master) {
		/* the master is never waiting for a resync */
		sync_in_progress = 0;
	}
	
	if(sync_in_progress > MAX_DIFF_RETRY) {
		/* request another full-sync,
		 * the last request may have been lost
		 */
		sync_in_progress = 0;
	} 

	if(sync_in_progress) {
	    int diff_add_updates = 0;
	    int diff_add_epoch  = 0;
	    int diff_add_admin_epoch = 0;
	    
	    int diff_del_updates = 0;
	    int diff_del_epoch  = 0;
	    int diff_del_admin_epoch = 0;
	    
	    cib_diff_version_details(
		input,
		&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);
	    
	    sync_in_progress++;
	    crm_warn("Not applying diff %d.%d.%d -> %d.%d.%d (sync in progress)",
		     diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
		     diff_add_admin_epoch,diff_add_epoch,diff_add_updates);
	    return cib_diff_resync;
	}

    
	rc = cib_process_diff(op, options, section, req, input, existing_cib, result_cib, answer);
	
	if(rc == cib_diff_resync && cib_is_master == FALSE) {
		xmlNode *sync_me = create_xml_node(NULL, "sync-me");
		free_xml(*result_cib);
		*result_cib = NULL;
		crm_info("Requesting re-sync from peer");
		sync_in_progress++;
		
		crm_xml_add(sync_me, F_TYPE, "cib");
		crm_xml_add(sync_me, F_CIB_OPERATION, CIB_OP_SYNC_ONE);
		crm_xml_add(sync_me, F_CIB_DELEGATED, cib_our_uname);

		if(send_cluster_message(NULL, crm_msg_cib, sync_me, FALSE) == FALSE) {
			rc = cib_not_connected;
		}
		free_xml(sync_me);
		
	} else if(rc == cib_diff_resync) {
	    rc = cib_diff_failed;
	    if(options & cib_force_diff) {
		crm_warn("Not requesting full refresh in slave mode.");
	    }
	}
	
	return rc;
}

enum cib_errors 
cib_process_replace_svr(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
    const char *tag = crm_element_name(input);
    enum cib_errors rc = cib_process_replace(
	op, options, section, req, input, existing_cib, result_cib, answer);
    if(rc == cib_ok && safe_str_eq(tag, XML_TAG_CIB)) {
	sync_in_progress = 0;
    }
    return rc;
}

enum cib_errors 
cib_process_change(
	const char *op, int options, const char *section, xmlNode *req, xmlNode *input,
	xmlNode *existing_cib, xmlNode **result_cib, xmlNode **answer)
{
	gboolean verbose = FALSE;
	xmlNode *failed = NULL;
	enum cib_errors result = cib_ok;
	int cib_update_op = CIB_UPDATE_OP_NONE;

	crm_debug_2("Processing \"%s\" event for section=%s", op, crm_str(section));


	if (strcasecmp(CIB_OP_CREATE, op) == 0) {
		cib_update_op = CIB_UPDATE_OP_ADD;
		
	} else if (strcasecmp(CIB_OP_UPDATE, op) == 0) {
		cib_update_op = CIB_UPDATE_OP_MODIFY;
		
	} else if (strcasecmp(CIB_OP_DELETE_ALT, op) == 0) {
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

	} else if(safe_str_eq(XML_TAG_CIB, section)) {
		section = NULL;
	}

	if(input == NULL) {
		crm_err("Cannot perform modification with no data");
		return cib_NOOBJECT;
	}
	
	crm_validate_data(input);
	crm_validate_data(*result_cib);
	failed = create_xml_node(NULL, XML_TAG_FAILED);
	
	/* make changes to a temp copy then activate */
	if(section == NULL) {
		int lpc = 0;
		const char *type = NULL;
		xmlNode *sub_input = NULL;

		/* order is no longer important here */
		const char *type_list[] = {
			XML_CIB_TAG_NODES,
			XML_CIB_TAG_CONSTRAINTS,
			XML_CIB_TAG_RESOURCES,
			XML_CIB_TAG_STATUS,
			XML_CIB_TAG_CRMCONFIG
		};

		copy_in_properties(*result_cib, input);
	
		for(lpc = 0; lpc < DIMOF(type_list); lpc++) {
			type = type_list[lpc];
	
			if(result == cib_ok) {
				crm_debug_2("Processing section=%s", type);
				sub_input = get_object_root(type, input);
				if(sub_input) {
				    result = updateList(
					*result_cib, sub_input, failed,
					cib_update_op, type);
				}
			}
		}

	} else {
		result = updateList(
			*result_cib, input, failed, cib_update_op, section);
	}

	if (result != cib_ok || xml_has_children(failed)) {
		if(result == cib_ok) {
			result = cib_unknown;
		}
		crm_log_xml_err(failed, "CIB Update failures");
		*answer = failed;
	} else {
		free_xml(failed);
	}

	return result;
}

#define cib_update_xml_macro(parent, xml_update)			\
	if(operation == CIB_UPDATE_OP_DELETE) {				\
		rc = delete_cib_object(parent, xml_update);		\
		update_results(failed, xml_update, operation, rc);	\
									\
	} else if(operation == CIB_UPDATE_OP_MODIFY) {			\
		rc = update_cib_object(parent, xml_update);		\
		update_results(failed, xml_update, operation, rc);	\
									\
	} else {							\
		rc = add_cib_object(parent, xml_update);		\
		update_results(failed, xml_update, operation, rc);	\
	}								\

enum cib_errors
updateList(xmlNode *local_cib, xmlNode *xml_section, xmlNode *failed,
	   int operation, const char *section)
{
	int rc = cib_ok;
	xmlNode *this_section = get_object_root(section, local_cib);
	
	if (section == NULL || xml_section == NULL) {
		crm_err("Section %s not found in message."
			"  CIB update is corrupt, ignoring.",
			crm_str(section));
		return cib_NOSECTION;
	}

	if((CIB_UPDATE_OP_NONE > operation)
	   || (operation > CIB_UPDATE_OP_MAX)){
		crm_err("Invalid operation on section %s", crm_str(section));
		return cib_operation;
	}

	if(safe_str_eq(crm_element_name(xml_section), section)) {
		xml_child_iter(xml_section, a_child, 
			       rc = cib_ok;
			       cib_update_xml_macro(this_section, a_child);
			);

	} else {
		cib_update_xml_macro(this_section, xml_section);
	}
	
	if(rc == cib_ok && xml_has_children(failed)) {
		rc = cib_unknown;
	}
	return rc;
}

gboolean
check_generation(xmlNode *newCib, xmlNode *oldCib)
{
	if(cib_compare_generation(newCib, oldCib) >= 0) {
		return TRUE;
	}

	crm_warn("Generation from update is older than the existing one");
	return FALSE;
}

static const char *
cib_op2string(enum cib_update_op operation)
{
	const char *operation_msg = NULL;
	switch(operation) {
		case 0:
			operation_msg = "none";
			break;
		case 1:
			operation_msg = "add";
			break;
		case 2:
			operation_msg = "modify";
			break;
		case 3:
			operation_msg = "delete";
			break;
		case CIB_UPDATE_OP_MAX:
			operation_msg = "invalid operation";
			break;
			
	}

	if(operation_msg == NULL) {
		crm_err("Unknown CIB operation %d", operation);
		operation_msg = "<unknown operation>";
	}
	
	return operation_msg;
}


gboolean
update_results(
	xmlNode *failed, xmlNode *target, int operation, int return_code)
{
	gboolean   was_error      = FALSE;
	const char *error_msg     = NULL;
	const char *operation_msg = NULL;
	xmlNode *xml_node       = NULL;
	
    
	if (return_code != cib_ok) {
		operation_msg = cib_op2string(operation);
		error_msg = cib_error2string(return_code);

		xml_node = create_xml_node(failed, XML_FAIL_TAG_CIB);

		was_error = TRUE;

		add_node_copy(xml_node, target);
		
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_ID,      ID(target));
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_OBJTYPE, TYPE(target));
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_OP,      operation_msg);
		crm_xml_add(xml_node, XML_FAILCIB_ATTR_REASON,  error_msg);

		crm_warn("Action %s failed: %s (cde=%d)",
			  operation_msg, error_msg, return_code);
	}

	return was_error;
}

enum cib_errors
revision_check(xmlNode *cib_update, xmlNode *cib_copy, int flags)
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

#ifndef CIBPIPE
enum cib_errors
sync_our_cib(xmlNode *request, gboolean all) 
{
	enum cib_errors result      = cib_ok;
	const char *host            = crm_element_value(request, F_ORIG);
	const char *op              = crm_element_value(request, F_CIB_OPERATION);

	xmlNode *replace_request = cib_msg_copy(request, FALSE);
	
	CRM_CHECK(the_cib != NULL, ;);
	CRM_CHECK(replace_request != NULL, ;);
	
	crm_info("Syncing CIB to %s", all?"all peers":host);
	if(all == FALSE && host == NULL) {
	    crm_log_xml(LOG_ERR, "bad sync", request);
	}
	
	/* remove the "all == FALSE" condition
	 *
	 * sync_from was failing, the local client wasnt being notified
	 *    because it didnt know it was a reply
	 * setting this does not prevent the other nodes from applying it
	 *    if all == TRUE
	 */
	if(host != NULL) {
		crm_xml_add(replace_request, F_CIB_ISREPLY, host);
	}
	crm_xml_add(replace_request, F_CIB_OPERATION, CIB_OP_REPLACE);
	crm_xml_add(replace_request, "original_"F_CIB_OPERATION, op);
	crm_xml_add(replace_request, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
	add_message_xml(replace_request, F_CIB_CALLDATA, the_cib);
	
	if(send_cluster_message(all?NULL:host, crm_msg_cib, replace_request, FALSE) == FALSE) {
		result = cib_not_connected;
	}
	free_xml(replace_request);
	return result;
}
#endif
