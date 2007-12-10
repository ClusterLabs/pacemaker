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
#include <string.h>

#include <stdlib.h>

#include <clplumbing/cl_log.h>
#include <ha_msg.h>

#include <time.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/ipc.h>


HA_Message *create_common_message(
	HA_Message *original_request, crm_data_t *xml_response_data);


crm_data_t*
createPingAnswerFragment(const char *from, const char *status)
{
	crm_data_t *ping = NULL;
	
	
	ping = create_xml_node(NULL, XML_CRM_TAG_PING);
	
	crm_xml_add(ping, XML_PING_ATTR_STATUS, status);
	crm_xml_add(ping, XML_PING_ATTR_SYSFROM, from);

	return ping;
}

HA_Message *
validate_crm_message(
	HA_Message *msg, const char *sys, const char *uuid, const char *msg_type)
{
	const char *from = NULL;
	const char *to = NULL;
	const char *type = NULL;
	const char *crm_msg_reference = NULL;
	HA_Message *action = NULL;
	const char *true_sys;
	char *local_sys = NULL;
	
	
	if (msg == NULL) {
		return NULL;
	}

	from = cl_get_string(msg, F_CRM_SYS_FROM);
	to   = cl_get_string(msg, F_CRM_SYS_TO);
	type = cl_get_string(msg, F_CRM_MSG_TYPE);
	
	crm_msg_reference = cl_get_string(msg, XML_ATTR_REFERENCE);
	action = msg;
	true_sys = sys;

	if (uuid != NULL) {
		local_sys = generate_hash_key(sys, uuid);
		true_sys = local_sys;
	}

	if (to == NULL) {
		crm_info("No sub-system defined.");
		action = NULL;
	} else if (true_sys != NULL && strcasecmp(to, true_sys) != 0) {
		crm_debug_3("The message is not for this sub-system (%s != %s).",
			  to, true_sys);
		action = NULL;
	}

	crm_free(local_sys);
	
	if (type == NULL) {
		crm_info("No message type defined.");
		return NULL;
		
	} else if (msg_type != NULL && strcasecmp(msg_type, type) != 0) {
		crm_info("Expecting a (%s) message but received a (%s).",
		       msg_type, type);
		action = NULL;
	}

	if (crm_msg_reference == NULL) {
		crm_info("No message crm_msg_reference defined.");
		action = NULL;
	}
/*
 	if(action != NULL) 
		crm_debug_3(
		       "XML is valid and node with message type (%s) found.",
		       type);
	crm_debug_3("Returning node (%s)", crm_element_name(action));
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
	crm_data_t *hello_node = NULL;
	HA_Message *hello = NULL;
	if (uuid == NULL || strlen(uuid) == 0
	    || client_name == NULL || strlen(client_name) == 0
	    || major_version == NULL || strlen(major_version) == 0
	    || minor_version == NULL || strlen(minor_version) == 0) {
		crm_err("Missing fields, Hello message will not be valid.");
		return;
	}

	hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
	crm_xml_add(hello_node, "major_version", major_version);
	crm_xml_add(hello_node, "minor_version", minor_version);
	crm_xml_add(hello_node, "client_name",   client_name);
	crm_xml_add(hello_node, "client_uuid",   uuid);

	crm_debug_4("creating hello message");
	hello = create_request(
		CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);

	send_ipc_message(ipc_client, hello);
	crm_debug_4("hello message sent");
	
	free_xml(hello_node);
	crm_msg_del(hello);
}


gboolean
process_hello_message(crm_data_t *hello,
		      char **uuid,
		      char **client_name,
		      char **major_version,
		      char **minor_version)
{
	const char *local_uuid;
	const char *local_client_name;
	const char *local_major_version;
	const char *local_minor_version;

	*uuid = NULL;
	*client_name = NULL;
	*major_version = NULL;
	*minor_version = NULL;

	if(hello == NULL) {
		return FALSE;
	}
	
	local_uuid = crm_element_value(hello, "client_uuid");
	local_client_name = crm_element_value(hello, "client_name");
	local_major_version = crm_element_value(hello, "major_version");
	local_minor_version = crm_element_value(hello, "minor_version");

	if (local_uuid == NULL || strlen(local_uuid) == 0) {
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

	crm_debug_3("Hello message ok");
	return TRUE;
}

HA_Message *
create_request_adv(const char *task, crm_data_t *msg_data,
		   const char *host_to,  const char *sys_to,
		   const char *sys_from, const char *uuid_from,
		   const char *origin)
{
	char *true_from = NULL;
	HA_Message *request = NULL;
	char *reference = generateReference(task, sys_from);

	if (uuid_from != NULL) {
		true_from = generate_hash_key(sys_from, uuid_from);
	} else if(sys_from != NULL) {
		true_from = crm_strdup(sys_from);
	} else {
		crm_err("No sys from specified");
	}
	
	/* host_from will get set for us if necessary by CRMd when routed */
	request = ha_msg_new(11);

	ha_msg_add(request, F_CRM_ORIGIN,	origin);
	ha_msg_add(request, F_TYPE,		T_CRM);
	ha_msg_add(request, F_CRM_VERSION,	CRM_FEATURE_SET);
	ha_msg_add(request, F_CRM_MSG_TYPE,     XML_ATTR_REQUEST);
	ha_msg_add(request, XML_ATTR_REFERENCE, reference);
	ha_msg_add(request, F_CRM_TASK,		task);
	ha_msg_add(request, F_CRM_SYS_TO,       sys_to);
	ha_msg_add(request, F_CRM_SYS_FROM,     true_from);

	/* HOSTTO will be ignored if it is to the DC anyway. */
	if(host_to != NULL && strlen(host_to) > 0) {
		ha_msg_add(request, F_CRM_HOST_TO,  host_to);
	}

	if (msg_data != NULL) {
		add_message_xml(request, F_CRM_DATA, msg_data);
	}
	crm_free(reference);
	crm_free(true_from);
	
	return request;
}

/*
 * This method adds a copy of xml_response_data
 */
HA_Message *
create_reply_adv(HA_Message *original_request,
		 crm_data_t *xml_response_data, const char *origin)
{
	HA_Message *reply = NULL;

	const char *host_from= cl_get_string(original_request, F_CRM_HOST_FROM);
	const char *sys_from = cl_get_string(original_request, F_CRM_SYS_FROM);
	const char *sys_to   = cl_get_string(original_request, F_CRM_SYS_TO);
	const char *type     = cl_get_string(original_request, F_CRM_MSG_TYPE);
	const char *operation= cl_get_string(original_request, F_CRM_TASK);
	const char *crm_msg_reference = cl_get_string(
		original_request, XML_ATTR_REFERENCE);
	
	if (type == NULL) {
		crm_err("Cannot create new_message,"
			" no message type in original message");
		CRM_ASSERT(type != NULL);
		return NULL;
#if 0
	} else if (strcasecmp(XML_ATTR_REQUEST, type) != 0) {
		crm_err("Cannot create new_message,"
			" original message was not a request");
		return NULL;
#endif
	}
	reply = ha_msg_new(10);

	ha_msg_add(reply, F_CRM_ORIGIN,		origin);
	ha_msg_add(reply, F_TYPE,		T_CRM);
	ha_msg_add(reply, F_CRM_VERSION,	CRM_FEATURE_SET);
	ha_msg_add(reply, F_CRM_MSG_TYPE,	XML_ATTR_RESPONSE);
	ha_msg_add(reply, XML_ATTR_REFERENCE,	crm_msg_reference);
	ha_msg_add(reply, F_CRM_TASK,		operation);

	/* since this is a reply, we reverse the from and to */
	ha_msg_add(reply, F_CRM_SYS_TO,		sys_from);
	ha_msg_add(reply, F_CRM_SYS_FROM,	sys_to);
	
	/* HOSTTO will be ignored if it is to the DC anyway. */
	if(host_from != NULL && strlen(host_from) > 0) {
		ha_msg_add(reply, F_CRM_HOST_TO, host_from);
	}

	if (xml_response_data != NULL) {
		add_message_xml(reply, F_CRM_DATA, xml_response_data);
	}

	return reply;
}


/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_ipc_reply(IPC_Channel *ipc_channel,
	       HA_Message *request, crm_data_t *xml_response_data)
{
	gboolean was_sent = FALSE;
	HA_Message *reply = NULL;

	reply = create_reply(request, xml_response_data);

	if (reply != NULL) {
		was_sent = send_ipc_message(ipc_channel, reply);
		crm_msg_del(reply);
	}
	return was_sent;
}

ha_msg_input_t *
new_ha_msg_input(const HA_Message *orig) 
{
	ha_msg_input_t *input_copy = NULL;
	crm_malloc0(input_copy, sizeof(ha_msg_input_t));

	input_copy->msg = ha_msg_copy(orig);
	input_copy->xml = get_message_xml(input_copy->msg, F_CRM_DATA);
	return input_copy;
}

ha_msg_input_t *
new_ipc_msg_input(IPC_Message *orig) 
{
	ha_msg_input_t *input_copy = NULL;
	
	crm_malloc0(input_copy, sizeof(ha_msg_input_t));
	input_copy->msg = ipcmsg2hamsg(orig);
	input_copy->xml = get_message_xml(input_copy->msg, F_CRM_DATA);
	return input_copy;
}

void
delete_ha_msg_input(ha_msg_input_t *orig) 
{
	if(orig == NULL) {
		return;
	}
 	crm_msg_del(orig->msg);
	free_xml(orig->xml);
	crm_free(orig);
}
