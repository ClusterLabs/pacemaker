/* $Id: pengine.c,v 1.41 2004/08/27 15:21:59 andrew Exp $ */
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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>
FILE *pemsg_strm = NULL;

xmlNodePtr do_calculations(xmlNodePtr cib_object);

gboolean
process_pe_message(xmlNodePtr msg, IPC_Channel *sender)
{
	char *msg_buffer = NULL;
	const char *sys_to = NULL;
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,
				       XML_ATTR_OP, TRUE);

	const char *ref = xmlGetProp(msg, XML_ATTR_REFERENCE);

	if(safe_str_eq(xmlGetProp(msg, XML_ATTR_MSGTYPE), XML_ATTR_REQUEST)) {
		crm_info(
		       "Message was a response not a request."
		       "  Discarding");
	}

	crm_verbose("Processing %s op (ref=%s)...", op, ref);

	if(pemsg_strm == NULL) {
		pemsg_strm = fopen(DEVEL_DIR"/pe.log", "w");
	}

	msg_buffer = dump_xml_node(msg, FALSE);
	fprintf(pemsg_strm, "%s: %s\n", "[in ]", msg_buffer);
	fflush(pemsg_strm);
	crm_free(msg_buffer);
	
	sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);

	if(op == NULL){
		// error

	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		// ignore
		
	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
		crm_verbose("Bad sys-to %s", sys_to);
		return FALSE;
		
	} else if(strcmp(op, CRM_OP_PECALC) == 0) {
		xmlNodePtr input_cib = find_xml_node(msg, XML_TAG_CIB);
		xmlNodePtr output = do_calculations(input_cib);
		msg_buffer = dump_xml_node(output, FALSE);
		fprintf(pemsg_strm, "%s: %s\n", "[out ]", msg_buffer);
		fflush(pemsg_strm);
		crm_free(msg_buffer);
		if (send_ipc_reply(sender, msg, output) ==FALSE) {

			crm_warn("Answer could not be sent");
		}
		free_xml(output);

	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_err("Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

xmlNodePtr
do_calculations(xmlNodePtr cib_object)
{
	int lpc, lpc2;
	
	GListPtr resources = NULL;
	GListPtr nodes = NULL;
	GListPtr node_constraints = NULL;
	GListPtr actions = NULL;
	GListPtr action_constraints = NULL;
	GListPtr stonith_list = NULL;
	GListPtr shutdown_list = NULL;

	GListPtr colors = NULL;
	GListPtr action_sets = NULL;

	xmlNodePtr graph = NULL;

//	pe_debug_on();
	
	crm_verbose("=#=#=#=#= Stage 0 =#=#=#=#=");
		  
	stage0(cib_object,
	       &resources,
	       &nodes,  &node_constraints,
	       &actions,  &action_constraints,
	       &stonith_list, &shutdown_list);

	crm_verbose("=#=#=#=#= Stage 1 =#=#=#=#=");
	stage1(node_constraints, nodes, resources);

	crm_verbose("=#=#=#=#= Stage 2 =#=#=#=#=");
	stage2(resources, nodes, &colors);

	crm_verbose("========= Nodes =========");
	crm_debug_action(
		slist_iter(node, node_t, nodes, lpc,
			   print_node(NULL, node, TRUE)
			)
		);
		
	crm_verbose("========= Resources =========");
	crm_debug_action(
		slist_iter(resource, resource_t, resources, lpc,
			   print_resource(NULL, resource, TRUE)
			)
		);  
  
	crm_verbose("=#=#=#=#= Stage 3 =#=#=#=#=");
	stage3(colors);

	crm_verbose("=#=#=#=#= Stage 4 =#=#=#=#=");
	stage4(colors);
	crm_verbose("========= Colors =========");
	crm_debug_action(
		slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE)
			)
		);

	crm_verbose("=#=#=#=#= Stage 5 =#=#=#=#=");
	stage5(resources);

	crm_verbose("=#=#=#=#= Stage 6 =#=#=#=#=");
	stage6(&actions, &action_constraints, nodes, resources);

	crm_verbose("========= Action List =========");
	crm_debug_action(
		slist_iter(action, action_t, actions, lpc,
			   print_action(NULL, action, TRUE)
			)
		);
	
	crm_verbose("=#=#=#=#= Stage 7 =#=#=#=#=");
	stage7(resources, actions, action_constraints, &action_sets);
	
	crm_verbose("=#=#=#=#= Summary =#=#=#=#=");
	summary(resources);

	crm_verbose("========= Action Sets =========");

	crm_verbose("\t========= Set %d (Un-runnable) =========", -1);
	crm_debug_action(
		slist_iter(action, action_t, actions, lpc,
			   if(action->optional == FALSE
			      && action->runnable == FALSE) {
				   print_action("\t", action, TRUE);
			   }
			)
		);

	crm_debug_action(
		slist_iter(action_set, GList, action_sets, lpc,
			   crm_verbose("\t========= Set %d =========", lpc);
			   slist_iter(action, action_t, action_set, lpc2,
				      print_action("\t", action, TRUE);
				   )
			)
		);

	
	crm_verbose("========= Stonith List =========");
	crm_debug_action(
		slist_iter(node, node_t, stonith_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);
  
	crm_verbose("========= Shutdown List =========");
	crm_debug_action(
		slist_iter(node, node_t, shutdown_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);

	crm_verbose("=#=#=#=#= Stage 8 =#=#=#=#=");
	stage8(action_sets, &graph);

	crm_verbose("=#=#=#=#= Cleanup =#=#=#=#=");

	crm_verbose("deleting node cons");
	while(node_constraints) {
		pe_free_rsc_to_node((rsc_to_node_t*)node_constraints->data);
		node_constraints = node_constraints->next;
	}
	g_list_free(node_constraints);

	crm_verbose("deleting order cons");
	pe_free_shallow(action_constraints);

	crm_verbose("deleting action sets");

	slist_iter(action_set, GList, action_sets, lpc,
		   pe_free_shallow_adv(action_set, FALSE);
		);
	pe_free_shallow_adv(action_sets, FALSE);
	
	crm_verbose("deleting actions");
	pe_free_actions(actions);

	crm_verbose("deleting resources");
	pe_free_resources(resources); 
	
	crm_verbose("deleting colors");
	pe_free_colors(colors);

	crm_verbose("deleting nodes");
	pe_free_nodes(nodes);
	
	g_list_free(shutdown_list);
	g_list_free(stonith_list);

	return graph;
}
