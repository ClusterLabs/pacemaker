/* $Id: callbacks.c,v 1.1 2004/12/15 07:37:50 andrew Exp $ */
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

#include <sys/stat.h>

#include <hb_api.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>

#include <tengine.h>

void te_update_confirm(const char *event, struct ha_msg *msg);

void
te_update_confirm(const char *event, struct ha_msg *msg)
{
	int rc = -1;
	gboolean done = FALSE;
	const char *op = cl_get_string(msg, F_CIB_OPERATION);
	const char *type = cl_get_string(msg, F_CIB_OBJTYPE);
	const char *update_s = cl_get_string(msg, F_CIB_UPDATE);
	xmlNodePtr update = string2xml(update_s);

	ha_msg_value_int(msg, F_CIB_RC, &rc);
	crm_trace("Processing %s...", event);

	if (MSG_LOG && msg_te_strm == NULL) {
		struct stat buf;
		if(stat(DEVEL_DIR, &buf) != 0) {
			cl_perror("Stat of %s failed... exiting", DEVEL_DIR);
			exit(100);
		}

		msg_te_strm = fopen(DEVEL_DIR"/te.log", "w");
	}
	
	if(op == NULL) {
		crm_err(
			"Illegal CIB update, the operation must be specified");
		send_abort("Illegal update", update);
		done = TRUE;
		
	} else if(strcmp(op, CRM_OP_CIB_CREATE) == 0
		  || strcmp(op, CRM_OP_CIB_DELETE) == 0
		  || strcmp(op, CRM_OP_CIB_REPLACE) == 0
		  || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0
		  || strcmp(op, CRM_OP_CIB_ERASE) == 0) {
		
		/* these are always unexpected, trigger the PE */
		send_abort("Non-update change", update);
		done = TRUE;
		
	} else if(strcmp(op, CRM_OP_CIB_UPDATE) != 0) {
		crm_verbose("Ignoring %s op confirmation", op);
		done = TRUE;
	}

	if(done) {
		free_xml(update);
		return;
	}
	
	if(safe_str_eq(type, XML_CIB_TAG_CRMCONFIG)) {
		/* ignore - for the moment */
		crm_debug("Ignoring changes to the %s section", type);
		
	} else if(safe_str_eq(type, XML_CIB_TAG_STATUS)) {
		/* this _may_ not be un-expected */
		extract_event(update);

	} else if(safe_str_eq(type, XML_CIB_TAG_NODES)
		|| safe_str_eq(type, XML_CIB_TAG_RESOURCES)
		|| safe_str_eq(type, XML_CIB_TAG_CONSTRAINTS)) {
		/* these are never expected	 */
		crm_debug("Aborting on changes to the %s section", type);
		send_abort("Non-status update", update);

	} else {
		crm_warn("Ignoring update confirmation for %s object", type);
	}

	free_xml(update);
}


gboolean
process_te_message(xmlNodePtr msg, IPC_Channel *sender)
{
	xmlNodePtr graph = NULL;
	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);
	const char *ref    = xmlGetProp(msg, XML_ATTR_REFERENCE);
	const char *op     = get_xml_attr(
		msg, XML_TAG_OPTIONS, XML_ATTR_OP, FALSE);

	crm_debug("Recieved %s (%s) message", op, ref);

	if (MSG_LOG && msg_te_strm == NULL) {
		struct stat buf;
		if(stat(DEVEL_DIR, &buf) != 0) {
			cl_perror("Stat of %s failed... exiting", DEVEL_DIR);
			exit(100);
		}
		msg_te_strm = fopen(DEVEL_DIR"/te.log", "w");
	}

#ifdef MSG_LOG
	{
		char *xml = dump_xml_formatted(msg);
		fprintf(msg_te_strm, "[Input %s]\t%s\n",
			op, xml);
		fflush(msg_te_strm);
		crm_free(xml);
	}
#endif
	
	if(safe_str_eq(xmlGetProp(msg, XML_ATTR_MSGTYPE), XML_ATTR_RESPONSE)
	   && safe_str_neq(op, CRM_OP_EVENTCC)) {
#ifdef MSG_LOG
	fprintf(msg_te_strm, "[Result ]\tDiscarded\n");
	fflush(msg_te_strm);
#endif
		crm_info("Message was a response not a request.  Discarding");
		return TRUE;
	}

	crm_debug("Processing %s (%s) message", op, ref);
	
	if(op == NULL){
		/* error */
	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */

	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_verbose("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(strcmp(op, CRM_OP_TRANSITION) == 0) {

		crm_trace("Initializing graph...");
		initialize_graph();

		graph = find_xml_node(msg, "transition_graph");
		crm_trace("Unpacking graph...");
		unpack_graph(graph);
		crm_trace("Initiating transition...");

		in_transition = TRUE;

		if(initiate_transition() == FALSE) {
			/* nothing to be done.. means we're done. */
			crm_info("No actions to be taken..."
			       " transition compelte.");
		}
		crm_trace("Processing complete...");
		
	} else if(strcmp(op, CRM_OP_TEABORT) == 0) {
		initialize_graph();

	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_err("Received quit message, terminating");
		exit(0);
		
	} else if(in_transition == FALSE) {
		crm_info("Received event_cc while not in a transition..."
			 "  Poking the Policy Engine");
		send_abort("Initiate a transition", NULL);
	}

	crm_debug("finished processing message");
	print_state(FALSE);
	
	return TRUE;
}
