/* $Id: tengine.c,v 1.18 2004/06/07 21:28:39 msoffen Exp $ */
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
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <tengine.h>

GListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;

typedef struct action_list_s 
{
		gboolean force;
		int index;
		int index_max;
		GListPtr actions;
} action_list_t;

void print_state(void);
gboolean initialize_graph(void);
gboolean unpack_graph(xmlNodePtr xml_graph);
gboolean extract_event(xmlNodePtr msg);
gboolean initiate_transition(void);
gboolean initiate_action(action_list_t *list);
gboolean process_graph_event(const char *event_node,
			     const char *event_rsc, 
			     const char *event_action, 
			     const char *event_status, 
			     const char *event_rc);

void send_success(void);
void send_abort(xmlNodePtr msg);

gboolean
initialize_graph(void)
{
	while(g_list_length(graph) > 0) {
		action_list_t *action_list = g_list_nth_data(graph, 0);
		while(g_list_length(action_list->actions) > 0) {
			xmlNodePtr action =
				g_list_nth_data(action_list->actions, 0);
			action_list->actions =
				g_list_remove(action_list->actions, action);
			free_xml(action);
		}
		graph = g_list_remove(graph, action_list);
		crm_free(action_list);
	}

	graph = NULL;
	
	return TRUE;
}


gboolean
unpack_graph(xmlNodePtr xml_graph)
{
/*
<transition_graph>
	<actions id="0">
		<rsc_op id="5" runnable=XML_BOOLEAN_FALSE optional=XML_BOOLEAN_TRUE task="stop">
			<resource id="rsc3" priority="3.0"/>
		</rsc_op>
*/
	xmlNodePtr xml_action_list = xml_graph?xml_graph->children:NULL;
	if(xml_action_list == NULL) {
		// nothing to do
		return FALSE;
	}
	
	while(xml_action_list != NULL) {
		xmlNodePtr xml_obj = xml_action_list;
		xmlNodePtr xml_action = xml_obj->children;
		action_list_t *action_list = (action_list_t*)
			crm_malloc(sizeof(action_list_t));

		xml_action_list = xml_action_list->next;

		action_list->force = FALSE;
		action_list->index = -1;
		action_list->index_max = 0;
		action_list->actions = NULL;
		
		while(xml_action != NULL) {
			xmlNodePtr action =
				copy_xml_node_recursive(xml_action);

			action_list->actions =
				g_list_append(action_list->actions, action);
			
			action_list->index_max++;
			xml_action = xml_action->next;
		}
		
		graph = g_list_append(graph, action_list);
	}
	

	return TRUE;
}

gboolean
extract_event(xmlNodePtr msg)
{
	gboolean abort      = FALSE;
	xmlNodePtr iter     = NULL;
	const char *section = NULL;

	const char *event_action = NULL;
	const char *event_node   = NULL;
	const char *event_rsc    = NULL;
	const char *event_status = NULL;
	const char *event_rc     = NULL;
	
/*
[cib fragment]
...
<status>
   <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/

	iter = find_xml_node(msg, XML_TAG_FRAGMENT);
	section = xmlGetProp(iter, XML_ATTR_SECTION);

	if(safe_str_neq(section, XML_CIB_TAG_STATUS)) {
		// these too are never expected
		return FALSE;
	}
	
	iter = find_xml_node(iter, XML_TAG_CIB);
	iter = get_object_root(XML_CIB_TAG_STATUS, iter);
	iter = iter->children;
	
	while(abort == FALSE && iter != NULL) {
		xmlNodePtr node_state = iter;
		xmlNodePtr child = iter->children;
		const char *state = xmlGetProp(
			node_state, XML_CIB_ATTR_JOINSTATE);
		iter = iter->next;

		if(xmlGetProp(node_state, XML_CIB_ATTR_SHUTDOWN) != NULL
		   || xmlGetProp(node_state, XML_CIB_ATTR_STONITH) != NULL) {
			abort = TRUE;
			
		} else if(state != NULL && child == NULL) {
			/* node state update,
			 * possibly from a shutdown we requested
			 */
			event_status = state;
			event_node   = xmlGetProp(node_state, XML_ATTR_ID);
			
			if(safe_str_eq(event_status, CRMD_JOINSTATE_DOWN)) {
				event_action = XML_CIB_ATTR_SHUTDOWN;
			} else {
				// never expected... yet.  STONITH?
				event_action = "startup";
			}
			
			abort = !process_graph_event(event_node,
						     event_rsc,
						     event_action,
						     event_status,
						     event_rc);

		} else if(state == NULL && child != NULL) {
			child = find_xml_node(node_state, XML_CIB_TAG_LRM);
			child = find_xml_node(child, XML_LRM_TAG_RESOURCES);

			if(child != NULL) {
				child = child->children;
			} else {
				abort = TRUE;
			}
			
			while(abort == FALSE && child != NULL) {
				event_action = xmlGetProp(
					child, XML_LRM_ATTR_LASTOP);
				event_node   = xmlGetProp(
					child, XML_LRM_ATTR_TARGET);
				event_rsc    = xmlGetProp(
					child, XML_ATTR_ID);
				event_status = xmlGetProp(
					child, XML_LRM_ATTR_OPSTATE);
				event_rc     = xmlGetProp(
					child, XML_LRM_ATTR_OPCODE);
				
				abort = !process_graph_event(event_node,
							     event_rsc,
							     event_action,
							     event_status,
							     event_rc);

				child = child->next;
			}	
		} else if(state != NULL && child != NULL) {
			/* this is a complex event and could not be completely
			 * due to any request we made
			 */
			abort = TRUE;
			
		} else {
			/* ignore */
		}
	}
	
	return !abort;
}

gboolean
process_graph_event(const char *event_node,
		    const char *event_rsc, 
		    const char *event_action, 
		    const char *event_status, 
		    const char *event_rc)
{
	int lpc;
	xmlNodePtr action        = NULL; // <rsc_op> or <crm_event>
	xmlNodePtr next_action   = NULL;
	action_list_t *matched_action_list = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	const char *this_rsc    = NULL;

// Find the action corresponding to this event
	slist_iter(
		action_list, action_list_t, graph, lpc,
		action = g_list_nth_data(action_list->actions,
					  action_list->index);

		if(action == NULL) {
			continue;
		}
/*
		<rsc_op id= runnable= optional= task= on_node= >
			<resource id="rsc3" priority="3.0"/>
		</rsc_op>
*/

		this_action = xmlGetProp(
			action, XML_LRM_ATTR_TASK);
		this_node   = xmlGetProp(
			action, XML_LRM_ATTR_TARGET);
		this_rsc    = xmlGetProp(
			action->children, XML_ATTR_ID);

		if(safe_str_neq(this_node, event_node)) {
			continue;

		} else if(safe_str_neq(this_action, event_action)) {
			continue;
			
		} else if(safe_str_eq(action->name, "rsc_op")
			  && safe_str_eq(this_rsc, event_rsc)) {
			matched_action_list = action_list;

		} else if(safe_str_eq(action->name, "crm_event")) {
			matched_action_list = action_list;
		}
		);			

	if(matched_action_list == NULL) {
		// unexpected event, trigger a pe-recompute
		// possibly do this only for certain types of actions
		crm_err("Unexpected event... matched action list was NULL");
		return FALSE;
	}
	
	// how do we distinguish action failure?
	if(safe_str_neq(event_rc, "0")){
		if(safe_str_neq((const char*)xmlGetProp(action, "allow_fail"),
				XML_BOOLEAN_TRUE)) {
			crm_err("Action %s to %s on %s resulted in failure..."
			       " aborting transition.",
			       event_action, event_rsc, event_node);
			return FALSE;
		}
	}
	
	while(matched_action_list->index <= matched_action_list->index_max) {
		gboolean passed = FALSE;
		next_action = g_list_nth_data(matched_action_list->actions,
					       matched_action_list->index);
		
		passed = initiate_action(matched_action_list);

		if(passed == FALSE) {
			crm_err("Initiation of next event failed");
			return FALSE;
			
		} else if(matched_action_list->index >
			  matched_action_list->index_max) {
			/* last action in that list, check if there are
			 *  anymore actions at all
			 */
			slist_iter(
				action_list, action_list_t, graph, lpc,
				if(action_list->index <=
				   action_list->index_max){
					return TRUE;
				}
				);
		} else {
			return TRUE;
			
		}

	}
	crm_info("Transition complete...");

	send_success();
	
	return TRUE;
}

gboolean
initiate_transition(void)
{
	int lpc;
	gboolean anything = FALSE;

	
	
	slist_iter(
		action_list, action_list_t, graph, lpc,
		if(initiate_action(action_list)
		   && action_list->index <= action_list->index_max) {
			anything = TRUE;
		}
		);

	return anything;
}

gboolean
initiate_action(action_list_t *list) 
{
	gboolean is_optional  = TRUE;
	xmlNodePtr xml_action = NULL;
	const char *on_node   = NULL;
	const char *id        = NULL;
	const char *runnable  = NULL;
	const char *optional  = NULL;
	const char *task      = NULL;
	const char *discard   = NULL;
#ifndef TESTING
	xmlNodePtr options = NULL;
	xmlNodePtr data = NULL;
	xmlNodePtr rsc_op = NULL;
#endif
	
	while(TRUE) {
		
		list->index++;
		xml_action = g_list_nth_data(list->actions, list->index);
		
		if(xml_action == NULL) {
			crm_info("No tasks left on this list");
			list->index = list->index_max + 1;
			
			return TRUE;
		}
		
		discard  = xmlGetProp(xml_action, XML_LRM_ATTR_DISCARD);
		on_node  = xmlGetProp(xml_action, XML_LRM_ATTR_TARGET);
		id       = xmlGetProp(xml_action, XML_ATTR_ID);
		runnable = xmlGetProp(xml_action, XML_LRM_ATTR_RUNNABLE);
		optional = xmlGetProp(xml_action, XML_LRM_ATTR_OPTIONAL);
		task     = xmlGetProp(xml_action, XML_LRM_ATTR_TASK);
		
		if(safe_str_eq(discard, XML_BOOLEAN_TRUE)) {
			crm_info("Skipping discarded rsc-op (%s): %s %s on %s",
				 id, task,
				 xmlGetProp(xml_action->children, XML_ATTR_ID),
				 on_node);
			continue;
		}

		if(safe_str_neq(optional, XML_BOOLEAN_TRUE)) {
			is_optional = FALSE;
		}
		
		list->force = list->force || !is_optional;

		crm_verbose("Processing action %s (id=%s) on %s",
		       task, id, on_node);
		
		if(list->force && is_optional) {
			crm_info("Forcing execution of otherwise optional task "
				 "due to a dependancy on a previous action");
		}
		
		if(list->force == FALSE && is_optional) {
			if(safe_str_eq(xml_action->name, "rsc_op")){
				crm_info("Skipping optional rsc-op (%s):"
					 " %s %s on %s",
					 id, task,
					 xmlGetProp(xml_action->children,
						    XML_ATTR_ID),
				       on_node);
			} else {
				crm_info("Skipping optional command"
					 " %s (id=%s) on %s",
					 task, id, on_node);
			}
			
		} else if(safe_str_eq(runnable, XML_BOOLEAN_FALSE)) {
			crm_err("Terminated transition on un-runnable command:"
				" %s (id=%s) on %s",
				task, id, on_node);
			return FALSE;
			
		} else if(id == NULL || strlen(id) == 0
			  || on_node == NULL || strlen(on_node) == 0
			  || task == NULL || strlen(task) == 0) {
			// error
			crm_err("Failed on corrupted command: %s (id=%s) on %s",
				task, id, on_node);
			
			return FALSE;
			
		} else if(safe_str_eq(xml_action->name, "pseduo_event")){
			if(safe_str_eq(task, "stonith")){
				crm_info("Executing %s (%s) of node %s",
					 task, id, on_node);
/*
  translate this into a stonith op by deisgnated node
  may need the CIB to determine who is running the stonith resource
    for this node
  more liekly, have the pengine find and supply that info 
*/
			} else {
				crm_err("Failed on unsupported %s: "
					"%s (id=%s) on %s",
					xml_action->name, task, id, on_node);
				
				return FALSE;
			}
			
			
		} else if(safe_str_eq(xml_action->name, "crm_event")){
			/*
			  <crm_msg op=XML_LRM_ATTR_TASK to=XML_RES_ATTR_TARGET>
			*/
			crm_info("Executing crm-event (%s): %s on %s",
				 id, task, on_node);
#ifndef TESTING
			options = create_xml_node(
				NULL, XML_TAG_OPTIONS);
			set_xml_property_copy(options, XML_ATTR_OP, task);
			
			send_ipc_request(crm_ch, options, NULL,
					 on_node, CRM_SYSTEM_CRMD, CRM_SYSTEM_TENGINE,
					 NULL, NULL);
			
			free_xml(options);
			return TRUE;
#endif			
		} else if(safe_str_eq(xml_action->name, "rsc_op")){
			crm_info("Executing rsc-op (%s): %s %s on %s",
				 id, task,
				 xmlGetProp(xml_action->children, XML_ATTR_ID),
				 on_node);
#ifndef TESTING
			/*
			  <msg_data>
			  <rsc_op id="operation number" on_node="" task="">
			  <resource>...</resource>
			*/
			options = create_xml_node(
				NULL, XML_TAG_OPTIONS);
			data = create_xml_node(NULL, "msg_data");
			rsc_op = create_xml_node(data, "rsc_op");
			
			set_xml_property_copy(options, XML_ATTR_OP, "rsc_op");
			
			set_xml_property_copy(rsc_op, XML_ATTR_ID, id);
			set_xml_property_copy(
				rsc_op, XML_LRM_ATTR_TASK, task);
			set_xml_property_copy(
				rsc_op, XML_LRM_ATTR_TARGET, on_node);
			
			add_node_copy(rsc_op, xml_action->children);
			
			send_ipc_request(crm_ch, options, data,
					 on_node, "lrmd", CRM_SYSTEM_TENGINE,
					 NULL, NULL);
			
			free_xml(options);
			free_xml(data);
			return TRUE;
#endif			
			
		} else {
			// error
			crm_err("Failed on unsupported command type: "
				"%s, %s (id=%s) on %s",
				xml_action->name, task, id, on_node);

			return FALSE;
		}
	}
	
	return FALSE;
}

FILE *msg_te_strm = NULL;

gboolean
process_te_message(xmlNodePtr msg, IPC_Channel *sender)
{
	xmlNodePtr graph = NULL;
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,
				       XML_ATTR_OP, FALSE);

	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);
	const char *ref    = xmlGetProp(msg, XML_ATTR_REFERENCE);

	crm_debug("Processing %s (%s) message", op, ref);

#ifdef MSG_LOG
	if(msg_te_strm == NULL) {
		msg_te_strm = fopen("/tmp/te.log", "w");
	}
	fprintf(msg_te_strm, "[Input %s]\t%s\n",
		op, dump_xml_node(msg, FALSE));
	fflush(msg_te_strm);
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

	
	if(op == NULL){
		// error
	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		// ignore

	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_verbose("Bad sys-to %s", sys_to);
		return FALSE;
		
	} else if(strcmp(op, CRM_OP_TRANSITION) == 0) {

		crm_trace("Initializing graph...");
		initialize_graph();

		graph = find_xml_node(msg, "transition_graph");
		crm_trace("Unpacking graph...");
		unpack_graph(graph);
		crm_trace("Initiating transition...");
		if(initiate_transition() == FALSE) {
			// nothing to be done.. means we're done.
			crm_info("No actions to be taken..."
			       " transition compelte.");
			send_success();		
		}
		crm_trace("Processing complete...");
		
		
	} else if(strcmp(op, CRM_OP_EVENTCC) == 0) {
		const char *true_op = get_xml_attr (msg, XML_TAG_OPTIONS,
						    XML_ATTR_TRUEOP, TRUE);
		if(true_op == NULL) {
			crm_err(
			       "Illegal update,"
			       " the original operation must be specified");
			send_abort(msg);
			
		} else if(strcmp(true_op, CRM_OP_CREATE) == 0
		   || strcmp(true_op, CRM_OP_DELETE) == 0
		   || strcmp(true_op, CRM_OP_REPLACE) == 0
		   || strcmp(true_op, CRM_OP_WELCOME) == 0
		   || strcmp(true_op, CRM_OP_SHUTDOWN_REQ) == 0
		   || strcmp(true_op, CRM_OP_ERASE) == 0) {

			// these are always unexpected, trigger the PE
			send_abort(msg);
			
		} else if(strcmp(true_op, CRM_OP_UPDATE) == 0) {
			// this may not be un-expected
			if(extract_event(msg) == FALSE){
				send_abort(msg);
			}
			
		} else {
			crm_err(
			       "Did not expect copy of action %s", op);
		}
		
	} else if(strcmp(op, CRM_OP_ABORT) == 0) {
		initialize_graph();

	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_err("Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

void
send_abort(xmlNodePtr msg)
{	
	xmlNodePtr options = create_xml_node(NULL, XML_TAG_OPTIONS);

	print_state();
	
	crm_trace("Sending \"abort\" message");
	
#ifdef MSG_LOG
	fprintf(msg_te_strm, "[Result ]\tTransition aborted\n");
	fflush(msg_te_strm);
#endif
	
	set_xml_property_copy(options, XML_ATTR_OP, CRM_OP_TEABORT);
	
	send_ipc_request(crm_ch, options, NULL,
			 NULL, CRM_SYSTEM_DC, CRM_SYSTEM_TENGINE,
			 NULL, NULL);
	
	free_xml(options);
}

void
send_success(void)
{	
	xmlNodePtr options = create_xml_node(NULL, XML_TAG_OPTIONS);

	print_state();

	crm_trace("Sending \"complete\" message");

#ifdef MSG_LOG
	fprintf(msg_te_strm, "[Result ]\tTransition complete\n");
	fflush(msg_te_strm);
#endif
	
	set_xml_property_copy(options, XML_ATTR_OP, CRM_OP_TECOMPLETE);
	
	send_ipc_request(crm_ch, options, NULL,
			 NULL, CRM_SYSTEM_DC, CRM_SYSTEM_TENGINE,
			 NULL, NULL);
	
	free_xml(options);
}

void
print_state(void)
{
	int lpc = 0;
	crm_debug("#!!#!!# Start Transitioner state");
	if(graph == NULL) {
		crm_debug("\tEmpty transition graph");
	} else {
		slist_iter(
			action_list, action_list_t, graph, lpc,

			crm_debug("\tAction set %d: %d of %d actions invoked",
				  lpc, action_list->index,
				  action_list->index_max);
			);
	}
	
	crm_debug("#!!#!!# End Transitioner state");
}
