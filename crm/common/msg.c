/* $Id: msg.c,v 1.3 2004/06/03 07:52:16 andrew Exp $ */
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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>

#include <clplumbing/cl_log.h>

#include <time.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>

#include <crm/dmalloc_wrapper.h>

xmlNodePtr
create_common_message(xmlNodePtr original_request,
		      xmlNodePtr xml_response_data);


xmlNodePtr
createPingAnswerFragment(const char *from, const char *status)
{
	xmlNodePtr ping = NULL;
	
	
	ping = create_xml_node(NULL, XML_CRM_TAG_PING);
	
	set_xml_property_copy(ping, XML_PING_ATTR_STATUS, status);
	set_xml_property_copy(ping, XML_PING_ATTR_SYSFROM, from);

	return ping;
}

xmlNodePtr
createPingRequest(const char *crm_msg_reference, const char *to)
{
	xmlNodePtr root_xml_node = NULL;
	int sub_type_len;
	int msg_type_len;
	char *sub_type_target;
	char *msg_type_target;

	
	
	// 2 = "_" + '\0'
	sub_type_len = strlen(to) + strlen(XML_ATTR_REQUEST) + 2; 
	sub_type_target =
		(char*)crm_malloc(sizeof(char)*(sub_type_len));

	sprintf(sub_type_target, "%s_%s", to, XML_ATTR_REQUEST);
	root_xml_node   = create_xml_node(NULL, sub_type_target);
	set_xml_property_copy(root_xml_node,
			      XML_ATTR_REFERENCE,
			      crm_msg_reference);
    
	msg_type_len = strlen(to) + 10 + 1; // + "_operation" + '\0'
	msg_type_target =
		(char*)crm_malloc(sizeof(char)*(msg_type_len));
	sprintf(msg_type_target, "%s_operation", to);
	set_xml_property_copy(root_xml_node, msg_type_target, CRM_OP_PING);
	crm_free(msg_type_target);

	return root_xml_node;
}



xmlNodePtr
validate_crm_message(xmlNodePtr root_xml_node,
		     const char *sys,
		     const char *uuid,
		     const char *msg_type)
{
	const char *from = NULL;
	const char *to = NULL;
	const char *type = NULL;
	const char *crm_msg_reference = NULL;
	xmlNodePtr action = NULL;
	const char *true_sys;
	
	
	if (root_xml_node == NULL) {
		return NULL;
	}

	from = xmlGetProp(root_xml_node, XML_ATTR_SYSFROM);
	to   = xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
	type = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
	
	crm_msg_reference = xmlGetProp(root_xml_node,
				       XML_ATTR_REFERENCE);
/*
	crm_debug("Recieved XML message with (version=%s)",
	       xmlGetProp(root_xml_node, XML_ATTR_VERSION));
	crm_debug("Recieved XML message with (from=%s)", from);
	crm_debug("Recieved XML message with (to=%s)"  , to);
	crm_debug("Recieved XML message with (type=%s)", type);
	crm_debug("Recieved XML message with (ref=%s)" ,
	       crm_msg_reference);
*/
	action = root_xml_node;
	true_sys = sys;

	if (uuid != NULL) true_sys = generate_hash_key(sys, uuid);

	if (to == NULL) {
		crm_info("No sub-system defined.");
		action = NULL;
	} else if (true_sys != NULL && strcmp(to, true_sys) != 0) {
		crm_debug("The message is not for this sub-system (%s != %s).",
			  to, true_sys);
		action = NULL;
	}
    
	if (type == NULL) {
		crm_info("No message type defined.");
		return NULL;
	} else if (msg_type != NULL && strcmp(msg_type, type) != 0) {
		crm_info("Expecting a (%s) message but receieved a (%s).",
		       msg_type, type);
		action = NULL;
	}

	if (crm_msg_reference == NULL) {
		crm_info("No message crm_msg_reference defined.");
		action = NULL;
	}
/*
 	if(action != NULL) 
		crm_debug(
		       "XML is valid and node with message type (%s) found.",
		       type);
	crm_debug("Returning node (%s)", xmlGetNodePath(action));
*/
	
	return action;
}


void
send_hello_message(IPC_Channel *ipc_client,
		   const char *uuid,
		   const char *client_name,
		   const char *major_version,
		   const char *minor_version)
{
	xmlNodePtr hello_node = NULL;
	
	
	if (uuid == NULL || strlen(uuid) == 0
	    || client_name == NULL || strlen(client_name) == 0
	    || major_version == NULL || strlen(major_version) == 0
	    || minor_version == NULL || strlen(minor_version) == 0) {
		crm_err("Missing fields, Hello message will not be valid.");
		return;
	}

	hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(hello_node, "major_version", major_version);
	set_xml_property_copy(hello_node, "minor_version", minor_version);
	set_xml_property_copy(hello_node, "client_name",   client_name);
	set_xml_property_copy(hello_node, "client_uuid",   uuid);
	set_xml_property_copy(hello_node, XML_ATTR_OP,     CRM_OP_HELLO);


	send_ipc_request(ipc_client,
			 hello_node, NULL, 
			 NULL, NULL,
			 client_name, uuid,
			 NULL);

	free_xml(hello_node);
}


gboolean
process_hello_message(xmlNodePtr hello,
		      char **uuid,
		      char **client_name,
		      char **major_version,
		      char **minor_version)
{
	xmlNodePtr opts = NULL;
	const char *op = NULL;
	const char *local_uuid;
	const char *local_client_name;
	const char *local_major_version;
	const char *local_minor_version;

	
	*uuid = NULL;
	*client_name = NULL;
	*major_version = NULL;
	*minor_version = NULL;

	opts = find_xml_node(hello, XML_TAG_OPTIONS);
	
	op = xmlGetProp(opts, XML_ATTR_OP);
	local_uuid = xmlGetProp(opts, "client_uuid");
	local_client_name = xmlGetProp(opts, "client_name");
	local_major_version = xmlGetProp(opts, "major_version");
	local_minor_version = xmlGetProp(opts, "minor_version");

	if (op == NULL || strcmp(CRM_OP_HELLO, op) != 0) {
		return FALSE;

	} else if (local_uuid == NULL || strlen(local_uuid) == 0) {
		crm_err("Hello message was not valid (field %s not found)",
		       "uuid");
		return FALSE;

	} else if (local_client_name==NULL || strlen(local_client_name)==0){
		crm_err("Hello message was not valid (field %s not found)",
			"client name");
		return FALSE;

	} else if(local_major_version == NULL
		  || strlen(local_major_version) == 0){
		crm_err("Hello message was not valid (field %s not found)",
			"major version");
		return FALSE;

	} else if (local_minor_version == NULL
		   || strlen(local_minor_version) == 0){
		crm_err("Hello message was not valid (field %s not found)",
			"minor version");
		return FALSE;
	}
    
	*uuid          = crm_strdup(local_uuid);
	*client_name   = crm_strdup(local_client_name);
	*major_version = crm_strdup(local_major_version);
	*minor_version = crm_strdup(local_minor_version);

	return TRUE;
}

xmlNodePtr
create_request(xmlNodePtr msg_options, xmlNodePtr msg_data,
	       const char *host_to, const char *sys_to,
	       const char *sys_from, const char *uuid_from,
	       const char *crm_msg_reference)
{
	const char *true_from = sys_from;
	xmlNodePtr request;

	

	if (uuid_from != NULL)
		true_from = generate_hash_key(sys_from, uuid_from);
	// else make sure we are internal
	else {
		if (strcmp(CRM_SYSTEM_LRMD, sys_from) != 0
		    && strcmp(CRM_SYSTEM_PENGINE, sys_from) != 0
		    && strcmp(CRM_SYSTEM_TENGINE, sys_from) != 0
		    && strcmp(CRM_SYSTEM_DC, sys_from) != 0
		    && strcmp(CRM_SYSTEM_CRMD, sys_from) != 0) {
			crm_err("only internal systems can leave"
				" uuid_from blank");
			return FALSE;
		}
	}

	if (crm_msg_reference == NULL) {
		crm_msg_reference =
			generateReference(
				xmlGetProp(msg_options,XML_ATTR_OP),sys_from);
	}
	
	// host_from will get set for us if necessary by CRMd when routed
	request = create_xml_node(NULL, XML_MSG_TAG);

	set_node_tstamp(request);

	set_xml_property_copy(request, XML_ATTR_VERSION, CRM_VERSION);
	set_xml_property_copy(request, XML_ATTR_MSGTYPE, XML_ATTR_REQUEST);
	set_xml_property_copy(request, XML_ATTR_SYSTO,   sys_to);
	set_xml_property_copy(request, XML_ATTR_SYSFROM, true_from);
	set_xml_property_copy(request, XML_ATTR_REFERENCE, crm_msg_reference);
	if(host_to != NULL && strlen(host_to) > 0)
		set_xml_property_copy(request, XML_ATTR_HOSTTO,  host_to);

	if (msg_options != NULL) {
		add_node_copy(request, msg_options);
	}

	if (msg_data != NULL) {
		add_node_copy(request, msg_data);
	}

	return request;
}

/*
 * This method adds a copy of xml_response_data
 */
xmlNodePtr
create_reply(xmlNodePtr original_request,
	     xmlNodePtr xml_response_data)
{
	const char *host_from = NULL;
	const char *sys_from  = NULL;
	const char *sys_to    = NULL;
	xmlNodePtr reply;
	
	
	host_from = xmlGetProp(original_request, XML_ATTR_HOSTFROM);
	sys_from  = xmlGetProp(original_request, XML_ATTR_SYSFROM);
	sys_to  = xmlGetProp(original_request, XML_ATTR_SYSTO);

	reply = create_common_message(original_request, xml_response_data);
	
	set_xml_property_copy(reply, XML_ATTR_MSGTYPE, XML_ATTR_RESPONSE);
	
	/* since this is a reply, we reverse the from and to */

	// HOSTTO will be ignored if it is to the DC anyway.
	if(host_from != NULL && strlen(host_from) > 0)
		set_xml_property_copy(reply, XML_ATTR_HOSTTO,   host_from);

	set_xml_property_copy(reply, XML_ATTR_SYSTO,    sys_from);
	set_xml_property_copy(reply, XML_ATTR_SYSFROM,  sys_to);

	return reply;
}

xmlNodePtr
create_common_message(xmlNodePtr original_request,
		      xmlNodePtr xml_response_data)
{
	const char *crm_msg_reference = NULL;
	const char *type      = NULL;
	const char *operation = NULL;
	xmlNodePtr options = NULL;
	xmlNodePtr new_message;
	
	
	crm_msg_reference = xmlGetProp(original_request,
				       XML_ATTR_REFERENCE);
	type      = xmlGetProp(original_request, XML_ATTR_MSGTYPE);
	operation = xmlGetProp(original_request, XML_ATTR_OP);
	
	if (type == NULL) {
		crm_err("Cannot create new_message,"
			" no message type in original message");
		return NULL;
#if 0
	} else if (strcmp(XML_ATTR_REQUEST, type) != 0) {
		crm_err("Cannot create new_message,"
			" original message was not a request");
		return NULL;
#endif
	}
	new_message = create_xml_node(NULL, XML_MSG_TAG);

	set_node_tstamp(new_message);

	set_xml_property_copy(new_message, XML_ATTR_VERSION, CRM_VERSION);
	set_xml_property_copy(new_message, XML_ATTR_OP, operation);

	set_xml_property_copy(new_message,
			      XML_ATTR_REFERENCE,
			      crm_msg_reference);
    
	if (xml_response_data != NULL) {
		add_node_copy(new_message, xml_response_data);
	}
    
	options = find_xml_node(original_request, XML_TAG_OPTIONS);
	if (options != NULL) {
		add_node_copy(new_message, options);
	}

	return new_message;
}
