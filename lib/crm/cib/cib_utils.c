/*
 * Copyright (c) 2004 International Business Machines
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <heartbeat.h>
#include <clplumbing/ipc.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <lib/crm/cib/cib_private.h>

struct config_root_s 
{
	const char *name;
	const char *parent;
	const char *path;
};

 /*
  * "//crm_config" will also work in place of "/cib/configuration/crm_config"
  * The / prefix means find starting from the root, whereas the // prefix means
  * find anywhere and risks multiple matches
  */
struct config_root_s known_paths[] = {
    { NULL,			NULL,                 "/cib" },
    { XML_TAG_CIB,		NULL,                 "/cib" },
    { XML_CIB_TAG_STATUS,       "/cib",               "/cib/status" },
    { XML_CIB_TAG_CONFIGURATION,"/cib",               "/cib/configuration" },
    { XML_CIB_TAG_CRMCONFIG,    "/cib/configuration", "/cib/configuration/crm_config" },
    { XML_CIB_TAG_NODES,        "/cib/configuration", "/cib/configuration/nodes" },
    { XML_CIB_TAG_RESOURCES,    "/cib/configuration", "/cib/configuration/resources" },
    { XML_CIB_TAG_CONSTRAINTS,  "/cib/configuration", "/cib/configuration/constraints" },
    { XML_CIB_TAG_OPCONFIG,	"/cib/configuration", "/cib/configuration/op_defaults" },
    { XML_CIB_TAG_RSCCONFIG,	"/cib/configuration", "/cib/configuration/rsc_defaults" },
    { XML_CIB_TAG_SECTION_ALL,  NULL,                 "/cib" },
};

const char *
cib_error2string(enum cib_errors return_code)
{
	const char *error_msg = NULL;
	switch(return_code) {
		case cib_bad_permissions:
			error_msg = "bad permissions for the on-disk configuration. shutdown heartbeat and repair.";
			break;
		case cib_bad_digest:
			error_msg = "the on-disk configuration was manually altered. shutdown heartbeat and repair.";
			break;
		case cib_bad_config:
			error_msg = "the on-disk configuration is not valid";
			break;
		case cib_msg_field_add:
			error_msg = "failed adding field to cib message";
			break;			
		case cib_id_check:
			error_msg = "missing id or id-collision detected";
			break;			
		case cib_operation:
			error_msg = "invalid operation";
			break;
		case cib_create_msg:
			error_msg = "couldnt create cib message";
			break;
		case cib_client_gone:
			error_msg = "client left before we could send reply";
			break;
		case cib_not_connected:
			error_msg = "not connected";
			break;
		case cib_not_authorized:
			error_msg = "not authorized";
			break;
		case cib_send_failed:
			error_msg = "send failed";
			break;
		case cib_reply_failed:
			error_msg = "reply failed";
			break;
		case cib_return_code:
			error_msg = "no return code";
			break;
		case cib_output_ptr:
			error_msg = "nowhere to store output";
			break;
		case cib_output_data:
			error_msg = "corrupt output data";
			break;
		case cib_connection:
			error_msg = "connection failed";
			break;
		case cib_callback_register:
			error_msg = "couldnt register callback channel";
			break;
		case cib_authentication:
			error_msg = "";
			break;
		case cib_registration_msg:
			error_msg = "invalid registration msg";
			break;
		case cib_callback_token:
			error_msg = "callback token not found";
			break;
		case cib_missing:
			error_msg = "cib object missing";
			break;
		case cib_variant:
			error_msg = "unknown/corrupt cib variant";
			break;
		case CIBRES_MISSING_ID:
			error_msg = "The id field is missing";
			break;
		case CIBRES_MISSING_TYPE:
			error_msg = "The type field is missing";
			break;
		case CIBRES_MISSING_FIELD:
			error_msg = "A required field is missing";
			break;
		case CIBRES_OBJTYPE_MISMATCH:
			error_msg = "CIBRES_OBJTYPE_MISMATCH";
			break;
		case cib_EXISTS:
			error_msg = "The object already exists";
			break;
		case cib_NOTEXISTS:
			error_msg = "The object/attribute does not exist";
			break;
		case CIBRES_CORRUPT:
			error_msg = "The CIB is corrupt";
			break;
		case cib_NOOBJECT:
			error_msg = "The update was empty";
			break;
		case cib_NOPARENT:
			error_msg = "The parent object does not exist";
			break;
		case cib_NODECOPY:
			error_msg = "Failed while copying update";
			break;
		case CIBRES_OTHER:
			error_msg = "CIBRES_OTHER";
			break;
		case cib_ok:
			error_msg = "ok";
			break;
		case cib_unknown:
			error_msg = "Unknown error";
			break;
		case cib_STALE:
			error_msg = "Discarded old update";
			break;
		case cib_ACTIVATION:
			error_msg = "Activation Failed";
			break;
		case cib_NOSECTION:
			error_msg = "Required section was missing";
			break;
		case cib_NOTSUPPORTED:
			error_msg = "The action/feature is not supported";
			break;
		case cib_not_master:
			error_msg = "Local service is not the master instance";
			break;
		case cib_client_corrupt:
			error_msg = "Service client not valid";
			break;
		case cib_remote_timeout:
			error_msg = "Remote node did not respond";
			break;
		case cib_master_timeout:
			error_msg = "No master service is currently active";
			break;
		case cib_revision_unsupported:
			error_msg = "The required CIB revision number is not supported";
			break;
		case cib_revision_unknown:
			error_msg = "The CIB revision number could not be determined";
			break;
		case cib_missing_data:
			error_msg = "Required data for this CIB API call not found";
			break;
		case cib_no_quorum:
			error_msg = "Write requires quorum";
			break;
		case cib_diff_failed:
			error_msg = "Application of an update diff failed";
			break;
		case cib_diff_resync:
			error_msg = "Application of an update diff failed, requesting a full refresh";
			break;
		case cib_bad_section:
			error_msg = "Invalid CIB section specified";
			break;
		case cib_old_data:
			error_msg = "Update was older than existing configuration";
			break;
		case cib_dtd_validation:
			error_msg = "Update does not conform to the configured schema/DTD";
			break;
		case cib_invalid_argument:
			error_msg = "Invalid argument";
			break;
		case cib_transform_failed:
			error_msg = "Schema transform failed";
			break;
	}
			
	if(error_msg == NULL) {
		crm_err("Unknown CIB Error Code: %d", return_code);
		error_msg = "<unknown error>";
	}
	
	return error_msg;
}

int
cib_section2enum(const char *a_section) 
{
	if(a_section == NULL || strcasecmp(a_section, "all") == 0) {
		return cib_section_all;

	} else if(strcasecmp(a_section, XML_CIB_TAG_NODES) == 0) {
		return cib_section_nodes;

	} else if(strcasecmp(a_section, XML_CIB_TAG_STATUS) == 0) {
		return cib_section_status;

	} else if(strcasecmp(a_section, XML_CIB_TAG_CONSTRAINTS) == 0) {
		return cib_section_constraints;
		
	} else if(strcasecmp(a_section, XML_CIB_TAG_RESOURCES) == 0) {
		return cib_section_resources;

	} else if(strcasecmp(a_section, XML_CIB_TAG_CRMCONFIG) == 0) {
		return cib_section_crmconfig;

	}
	crm_err("Unknown CIB section: %s", a_section);
	return cib_section_none;
}


int
cib_compare_generation(xmlNode *left, xmlNode *right)
{
	int lpc = 0;
	const char *attributes[] = {
		XML_ATTR_GENERATION_ADMIN,
		XML_ATTR_GENERATION,
		XML_ATTR_NUMUPDATES,
	};

	crm_log_xml_debug_3(left, "left");
	crm_log_xml_debug_3(right, "right");
	
	for(lpc = 0; lpc < DIMOF(attributes); lpc++) {
		int int_elem_l = -1;
		int int_elem_r = -1;
		const char *elem_r = NULL;
		const char *elem_l = crm_element_value(left, attributes[lpc]);

		if(right != NULL) {
			elem_r = crm_element_value(right, attributes[lpc]);
		}
	
		if(elem_l != NULL) { int_elem_l = crm_parse_int(elem_l, NULL); }
		if(elem_r != NULL) { int_elem_r = crm_parse_int(elem_r, NULL); }

		if(int_elem_l < int_elem_r) {
			crm_debug_2("%s (%s < %s)", attributes[lpc],
				    crm_str(elem_l), crm_str(elem_r));
			return -1;
			
		} else if(int_elem_l > int_elem_r) {
			crm_debug_2("%s (%s > %s)", attributes[lpc],
				    crm_str(elem_l), crm_str(elem_r));
			return 1;
		}
	}
	
	return 0;
}

xmlNode*
get_cib_copy(cib_t *cib)
{
	xmlNode *xml_cib;
	int options = cib_scope_local|cib_sync_call;
	if(cib->cmds->query(cib, NULL, &xml_cib, options) != cib_ok) {
		crm_err("Couldnt retrieve the CIB");
		return NULL;
	} else if(xml_cib == NULL) {
		crm_err("The CIB result was empty");
		return NULL;
	}

	if(safe_str_eq(crm_element_name(xml_cib), XML_TAG_CIB)) {
		return xml_cib;
	}
	free_xml(xml_cib);
	return NULL;
}

xmlNode*
cib_get_generation(cib_t *cib)
{
	xmlNode *the_cib = get_cib_copy(cib);
	xmlNode *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	if(the_cib != NULL) {
		copy_in_properties(generation, the_cib);
		free_xml(the_cib);
	}
	
	return generation;
}


void
log_cib_diff(int log_level, xmlNode *diff, const char *function)
{
	int add_updates = 0;
	int add_epoch  = 0;
	int add_admin_epoch = 0;

	int del_updates = 0;
	int del_epoch  = 0;
	int del_admin_epoch = 0;

	if(diff == NULL) {
		return;
	}
	
	cib_diff_version_details(
		diff, &add_admin_epoch, &add_epoch, &add_updates, 
		&del_admin_epoch, &del_epoch, &del_updates);

	if(add_updates != del_updates) {
		do_crm_log(log_level, "%s: Diff: --- %d.%d.%d", function,
			   del_admin_epoch, del_epoch, del_updates);
		do_crm_log(log_level, "%s: Diff: +++ %d.%d.%d", function,
			   add_admin_epoch, add_epoch, add_updates);
	} else if(diff != NULL) {
		do_crm_log(log_level,
			   "%s: Local-only Change: %d.%d.%d", function,
			   add_admin_epoch, add_epoch, add_updates);
	}
	
	log_xml_diff(log_level, diff, function);
}

gboolean
cib_version_details(
	xmlNode *cib, int *admin_epoch, int *epoch, int *updates)
{
	if(cib == NULL) {
	    *admin_epoch = -1;
	    *epoch  = -1;
	    *updates = -1;
	    return FALSE;
		
	} else {
	    crm_element_value_int(cib, XML_ATTR_GENERATION, epoch);
	    crm_element_value_int(cib, XML_ATTR_NUMUPDATES, updates);
	    crm_element_value_int(cib, XML_ATTR_GENERATION_ADMIN, admin_epoch);
	}
	return TRUE;	
}

gboolean
cib_diff_version_details(
	xmlNode *diff, int *admin_epoch, int *epoch, int *updates, 
	int *_admin_epoch, int *_epoch, int *_updates)
{
	xmlNode *tmp = NULL;

	tmp = find_xml_node(diff, "diff-added", FALSE);
	cib_version_details(tmp, admin_epoch, epoch, updates);

	tmp = find_xml_node(diff, "diff-removed", FALSE);
	cib_version_details(tmp, _admin_epoch, _epoch, _updates);
	return TRUE;
}

/*
 * The caller should never free the return value
 */

const char *get_object_path(const char *object_type)
{
    int lpc = 0;
    int max = DIMOF(known_paths);
    for(; lpc < max; lpc++) {
	if((object_type == NULL && known_paths[lpc].name == NULL)
	   || safe_str_eq(object_type, known_paths[lpc].name)) {
	    return known_paths[lpc].path;
	}
    }
    return NULL;
}

const char *get_object_parent(const char *object_type)
{
    int lpc = 0;
    int max = DIMOF(known_paths);
    for(; lpc < max; lpc++) {
	if(safe_str_eq(object_type, known_paths[lpc].name)) {
	    return known_paths[lpc].parent;
	}
    }
    return NULL;
}

xmlNode*
get_object_root(const char *object_type, xmlNode *the_root)
{
    xmlNode *result = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    const char *xpath = get_object_path(object_type);

    if(xpath == NULL) {
	return the_root; /* or return NULL? */
    }
    
    xpathObj = xpath_search(the_root, xpath);
    if(xpathObj == NULL || xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr < 1) {
	crm_debug_2("Object %s not found", crm_str(object_type));
	
    } else if(xpathObj->nodesetval->nodeNr > 1) {
	crm_err("Too many matches for %s", crm_str(object_type));

    } else {
	result = xpathObj->nodesetval->nodeTab[0];
	CRM_CHECK(result->type == XML_ELEMENT_NODE, result = NULL);
    }
    
    if(xpathObj) {
	xmlXPathFreeObject(xpathObj);
    }
    return result;
}

xmlNode*
create_cib_fragment_adv(
	xmlNode *update, const char *update_section, const char *source)
{
	xmlNode *cib = NULL;
	gboolean whole_cib = FALSE;
	xmlNode *object_root  = NULL;
	char *local_section = NULL;

/* 	crm_debug("Creating a blank fragment: %s", update_section); */
	
	if(update == NULL && update_section == NULL) {
		crm_debug_3("Creating a blank fragment");
		update = createEmptyCib();
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
		return update;

	} else if(update == NULL) {
		crm_err("No update to create a fragment for");
		return NULL;
		
	}

	CRM_CHECK(update_section != NULL, return NULL);
	if(safe_str_eq(crm_element_name(update), XML_TAG_CIB)) {
		whole_cib = TRUE;
	}
	
	if(whole_cib == FALSE) {
		cib = createEmptyCib();
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
		object_root = get_object_root(update_section, cib);
		add_node_copy(object_root, update);

	} else {
		cib = copy_xml(update);
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
	}

	crm_free(local_section);
	crm_debug_3("Verifying created fragment");
	return cib;
}

/*
 * It is the callers responsibility to free both the new CIB (output)
 *     and the new CIB (input)
 */
xmlNode*
createEmptyCib(void)
{
	xmlNode *cib_root = NULL, *config = NULL, *status = NULL;
	
	cib_root = create_xml_node(NULL, XML_TAG_CIB);

	config = create_xml_node(cib_root, XML_CIB_TAG_CONFIGURATION);
	status = create_xml_node(cib_root, XML_CIB_TAG_STATUS);

/* 	crm_xml_add(cib_root, "version", "1"); */
	create_xml_node(config, XML_CIB_TAG_CRMCONFIG);
	create_xml_node(config, XML_CIB_TAG_NODES);
	create_xml_node(config, XML_CIB_TAG_RESOURCES);
	create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);
	
	return cib_root;
}


enum cib_errors
cib_perform_op(const char *op, int call_options, cib_op_t *fn, gboolean is_query,
	       const char *section, xmlNode *req, xmlNode *input,
	       gboolean manage_counters, gboolean *config_changed,
	       xmlNode *current_cib, xmlNode **result_cib, xmlNode **diff, xmlNode **output)
{
    int rc = cib_ok;
    xmlNode *scratch = NULL;
    
    CRM_CHECK(output != NULL && result_cib != NULL && config_changed != NULL,
	      return cib_output_data);
    
    *output = NULL;
    *result_cib = NULL;
    *config_changed = FALSE;

    if(fn == NULL) {
	return cib_operation;
    }
    
    if(rc != cib_ok) {
	return rc;
    }
    
    if(is_query) {
	rc = (*fn)(op, call_options, section, req, input, current_cib, result_cib, output);
	return rc;
    }
    
    scratch = copy_xml(current_cib);
    rc = (*fn)(op, call_options, section, req, input, current_cib, &scratch, output);    
/*
    crm_log_xml_debug(current_cib, "old");
    crm_log_xml_debug(scratch, "new");
    crm_log_xml_debug(*output, "output");
*/  
    CRM_CHECK(current_cib != scratch, return cib_unknown);
    
    if(rc == cib_ok) {

	CRM_CHECK(scratch != NULL, return cib_unknown);
	
	if(rc == cib_ok && current_cib && scratch) {
	    int old = 0;
	    int new = 0;
	    crm_element_value_int(scratch, XML_ATTR_GENERATION_ADMIN, &new);
	    crm_element_value_int(current_cib, XML_ATTR_GENERATION_ADMIN, &old);
	    
	    if(old > new) {
		crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
			XML_ATTR_GENERATION_ADMIN, old, new, call_options);
		crm_log_xml_warn(req, "Bad Op");
		crm_log_xml_warn(input, "Bad Data");
		rc = cib_old_data;

	    } else if(old == new) {
		crm_element_value_int(scratch, XML_ATTR_GENERATION, &new);
		crm_element_value_int(current_cib, XML_ATTR_GENERATION, &old);
		if(old > new) {
		    crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
			    XML_ATTR_GENERATION, old, new, call_options);
		    crm_log_xml_warn(req, "Bad Op");
		    crm_log_xml_warn(input, "Bad Data");
		    rc = cib_old_data;
		}
	    }
	}
	
	if(rc == cib_ok) {
	    gboolean dtd_ok;
	    const char *current_dtd;
	    
	    fix_plus_plus_recursive(scratch);
	    /* crm_log_xml_debug(scratch, "newer"); */
	    if(manage_counters) {
		*config_changed = cib_config_changed(current_cib, scratch, diff);

	    /* crm_log_xml_debug(scratch, "newest"); */
		if(*config_changed) {
		    cib_update_counter(scratch, XML_ATTR_NUMUPDATES, TRUE);
		    cib_update_counter(scratch, XML_ATTR_GENERATION, FALSE);

		} else {
		    cib_update_counter(scratch, XML_ATTR_NUMUPDATES, FALSE);
		}

		if(diff != NULL && *diff != NULL) {
		    /* Now fix the diff... */

		    xmlNode *cib = NULL;
		    xmlNode *diff_child = NULL;
		    const char *tag = NULL;
		    const char *value = NULL;

		    tag = "diff-removed";
		    diff_child = find_xml_node(*diff, tag, FALSE);
		    if(diff_child == NULL) {
			diff_child = create_xml_node(*diff, tag);
		    }

		    tag = XML_TAG_CIB;
		    cib = find_xml_node(diff_child, tag, FALSE);
		    if(cib == NULL) {
			cib = create_xml_node(diff_child, tag);
		    }
		    
		    tag = XML_ATTR_GENERATION;
		    value = crm_element_value(current_cib, tag);
		    crm_xml_add(diff_child, tag, value);

		    if(*config_changed) {
			crm_xml_add(cib, tag, value);
		    }
		    
		    tag = XML_ATTR_NUMUPDATES;
		    value = crm_element_value(current_cib, tag);
		    crm_xml_add(cib, tag, value);
		    crm_xml_add(diff_child, tag, value);
		    
		    tag = "diff-added";
		    diff_child = find_xml_node(*diff, tag, FALSE);
		    if(diff_child == NULL) {
			diff_child = create_xml_node(*diff, tag);
		    }
		    
		    tag = XML_TAG_CIB;
		    cib = find_xml_node(diff_child, tag, FALSE);
		    if(cib == NULL) {
			cib = create_xml_node(diff_child, tag);
		    }
		    
		    tag = XML_ATTR_GENERATION;
		    value = crm_element_value(scratch, tag);
		    crm_xml_add(diff_child, tag, value);
		    if(*config_changed) {
			crm_xml_add(cib, tag, value);
		    }

		    tag = XML_ATTR_NUMUPDATES;
		    value = crm_element_value(scratch, tag);
		    crm_xml_add(cib, tag, value);		    
		    crm_xml_add(diff_child, tag, value);
		}
	    }

	    current_dtd = crm_element_value(scratch, XML_ATTR_VALIDATION);
	    dtd_ok = validate_xml(scratch, NULL, TRUE);
	    
	    if(dtd_ok == FALSE) {
		crm_err("Updated CIB does not validate against %s schema/dtd", crm_str(current_dtd));
		rc = cib_dtd_validation;
	    }	    
	}
    }

    *result_cib = scratch;
    return rc;
}

int get_channel_token(IPC_Channel *ch, char **token) 
{
    int rc = cib_ok;
    xmlNode *reg_msg = NULL;
    const char *msg_type = NULL;
    const char *tmp_ticket = NULL;
    
    CRM_CHECK(ch != NULL, return cib_missing);
    CRM_CHECK(token != NULL, return cib_output_ptr);
    
    crm_debug_4("Waiting for msg on command channel");
    
    reg_msg = xmlfromIPC(ch, 0);
    
    if(ch->ops->get_chan_status(ch) != IPC_CONNECT) {
	crm_err("No reply message - disconnected");
	free_xml(reg_msg);
	return cib_not_connected;
	
    } else if(reg_msg == NULL) {
	crm_err("No reply message - empty");
	return cib_reply_failed;
    }
    
    msg_type = crm_element_value(reg_msg, F_CIB_OPERATION);
    tmp_ticket = crm_element_value(reg_msg, F_CIB_CLIENTID);
    
    if(safe_str_neq(msg_type, CRM_OP_REGISTER) ) {
	crm_err("Invalid registration message: %s", msg_type);
	rc = cib_registration_msg;
	
    } else if(tmp_ticket == NULL) {
	rc = cib_callback_token;

    } else {
	*token = crm_strdup(tmp_ticket);
    }

    free_xml(reg_msg);
    return cib_ok;
}


xmlNode *
cib_create_op(
    int call_id, const char *token, const char *op, const char *host, const char *section,
    xmlNode *data, int call_options) 
{
	int  rc = HA_OK;
	xmlNode *op_msg = create_xml_node(NULL, "cib_command");
	CRM_CHECK(op_msg != NULL, return NULL);
	CRM_CHECK(token != NULL, return NULL);

	crm_xml_add(op_msg, F_XML_TAGNAME, "cib_command");
	
	crm_xml_add(op_msg, F_TYPE, T_CIB);
	crm_xml_add(op_msg, F_CIB_CALLBACK_TOKEN, token);
	crm_xml_add(op_msg, F_CIB_OPERATION, op);
	crm_xml_add(op_msg, F_CIB_HOST, host);
	crm_xml_add(op_msg, F_CIB_SECTION, section);
	crm_xml_add_int(op_msg, F_CIB_CALLID, call_id);
	crm_debug_4("Sending call options: %.8lx, %d",
		    (long)call_options, call_options);
	crm_xml_add_int(op_msg, F_CIB_CALLOPTS, call_options);

	if(data != NULL) {
		add_message_xml(op_msg, F_CIB_CALLDATA, data);
	}
	
	if (rc != HA_OK) {
		crm_err("Failed to create CIB operation message");
		crm_log_xml(LOG_ERR, "op", op_msg);
		free_xml(op_msg);
		return NULL;
	}

	if(call_options & cib_inhibit_bcast) {
		CRM_CHECK((call_options & cib_scope_local), return NULL);
	}
	return op_msg;
}

void
cib_native_callback(cib_t *cib, xmlNode *msg, int call_id, int rc)
{
	xmlNode *output = NULL;
	cib_callback_client_t *blob = NULL;
	cib_callback_client_t local_blob;

	local_blob.id = NULL;
	local_blob.callback = NULL;
	local_blob.user_data = NULL;
	local_blob.only_success = FALSE;

	if(msg != NULL) {
	    crm_element_value_int(msg, F_CIB_RC, &rc);
	    crm_element_value_int(msg, F_CIB_CALLID, &call_id);
	    output = get_message_xml(msg, F_CIB_CALLDATA);
	}

	blob = g_hash_table_lookup(
		cib_op_callback_table, GINT_TO_POINTER(call_id));
	
	if(blob != NULL) {
		local_blob = *blob;
		blob = NULL;
		
		remove_cib_op_callback(call_id, FALSE);

	} else {
		crm_debug_2("No callback found for call %d", call_id);
		local_blob.callback = NULL;
	}

	if(cib == NULL) {
	    crm_debug("No cib object supplied");
	}
	
	if(rc == cib_diff_resync) {
	    /* This is an internal value that clients do not and should not care about */
	    rc = cib_ok;
	}

	if(local_blob.callback != NULL
	   && (rc == cib_ok || local_blob.only_success == FALSE)) {
	    crm_debug_2("Invoking callback %s for call %d", crm_str(local_blob.id), call_id);
	    local_blob.callback(msg, call_id, rc, output, local_blob.user_data);
		
	} else if(cib && cib->op_callback == NULL && rc != cib_ok) {
	    crm_warn("CIB command failed: %s", cib_error2string(rc));
	    crm_log_xml(LOG_DEBUG, "Failed CIB Update", msg);
	}
	
	if(cib && cib->op_callback != NULL) {
		crm_debug_2("Invoking global callback for call %d", call_id);
		cib->op_callback(msg, call_id, rc, output);
	}
	crm_debug_4("OP callback activated.");
}


void
cib_native_notify(gpointer data, gpointer user_data)
{
	xmlNode *msg = user_data;
	cib_notify_client_t *entry = data;
	const char *event = NULL;

	if(msg == NULL) {
		crm_warn("Skipping callback - NULL message");
		return;
	}

	event = crm_element_value(msg, F_SUBTYPE);
	
	if(entry == NULL) {
		crm_warn("Skipping callback - NULL callback client");
		return;

	} else if(entry->callback == NULL) {
		crm_warn("Skipping callback - NULL callback");
		return;

	} else if(safe_str_neq(entry->event, event)) {
		crm_debug_4("Skipping callback - event mismatch %p/%s vs. %s",
			  entry, entry->event, event);
		return;
	}
	
	crm_debug_4("Invoking callback for %p/%s event...", entry, event);
	entry->callback(event, msg);
	crm_debug_4("Callback invoked...");
}

