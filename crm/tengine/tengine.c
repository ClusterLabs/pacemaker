/* $Id: tengine.c,v 1.27 2004/08/27 15:21:59 andrew Exp $ */
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
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <tengine.h>
#include <heartbeat.h>
#include <clplumbing/Gmain_timeout.h>
#include <lrm/lrm_api.h>

GListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;
uint default_op_timeout = 60*1000; // 60 seconds

typedef enum {
	TE_LIST_ACTIVE,
	TE_LIST_COMPLETE,
	TE_LIST_FAILED
} te_list_status_e;

typedef struct action_list_s 
{
		int id;
		int index;
		int index_max;

		gboolean force;
		guint timer_id;
		te_list_status_e status;

		GListPtr actions;
		
} action_list_t;

gboolean timer_callback(gpointer data);
void print_state(void);
gboolean initialize_graph(void);
gboolean unpack_graph(xmlNodePtr xml_graph);
gboolean extract_event(xmlNodePtr msg);
gboolean initiate_transition(void);
gboolean initiate_action(action_list_t *list);
gboolean process_graph_event(
	const char *event_node,   const char *event_rsc, const char *rsc_state,
	const char *event_action, const char *event_rc, const char *op_status);

gboolean do_update_cib(xmlNodePtr xml_action, int status);

void send_success(void);
void send_abort(xmlNodePtr msg);

gboolean
initialize_graph(void)
{
	while(g_list_length(graph) > 0) {
		action_list_t *action_list = g_list_nth_data(graph, 0);
		while(g_list_length(action_list->actions) > 0) {
			xmlNodePtr action = g_list_nth_data(
				action_list->actions, 0);

			action_list->actions = g_list_remove(
				action_list->actions, action);

			free_xml(action);
		}
		if(action_list->timer_id > 0) {
			crm_debug("Removing timer for list: %d",
				  action_list->id);

			g_source_remove(action_list->timer_id);
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
		int listnum = 0;
		xmlNodePtr xml_obj         = xml_action_list;
		xmlNodePtr xml_action      = xml_obj->children;
		action_list_t *action_list = (action_list_t*)
			crm_malloc(sizeof(action_list_t));

		xml_action_list = xml_action_list->next;

		action_list->id        = ++listnum;
		action_list->force     = FALSE;
		action_list->index     = -1;
		action_list->index_max = 0;
		action_list->timer_id  = -1;
		action_list->status    = TE_LIST_ACTIVE;
		action_list->actions   = NULL;

		crm_debug("Created action list %d", action_list->id);
		
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
	xmlNodePtr cib      = NULL;
	const char *section = NULL;

	const char *event_action = NULL;
	const char *event_node   = NULL;
	const char *event_rsc    = NULL;
	const char *event_rc     = NULL;
	const char *rsc_state    = NULL;
	const char *op_status    = NULL;

	char *code = NULL;

/*
[cib fragment]
...
<status>
   <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/

	crm_trace("Extracting event");
	
	iter = find_xml_node(msg, XML_TAG_FRAGMENT);
	section = xmlGetProp(iter, XML_ATTR_SECTION);

	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		// ignore - for the moment
		crm_debug("Ignoring changes to the %s section", XML_CIB_TAG_CRMCONFIG);
		return TRUE;
		
	} else if(safe_str_neq(section, XML_CIB_TAG_STATUS)) {
		// these too are never expected	
		crm_debug("Ignoring changes outside the %s section", XML_CIB_TAG_STATUS);
		return FALSE;
	}
	
	cib = find_xml_node(iter, XML_TAG_CIB);
	iter = get_object_root(XML_CIB_TAG_STATUS, cib);
	if(iter != NULL) {
		iter = iter->children;
	} else {
		crm_warn("%s missing? %s",
			 XML_CIB_TAG_STATUS, dump_xml_node(cib, TRUE));
		crm_warn("fragment: %s", dump_xml_node(cib, FALSE));
	}
	
	
	while(abort == FALSE && iter != NULL) {
		xmlNodePtr node_state = iter;
		xmlNodePtr child = iter->children;
		const char *state = xmlGetProp(
			node_state, XML_CIB_ATTR_CRMDSTATE);
		iter = iter->next;

		if(xmlGetProp(node_state, XML_CIB_ATTR_SHUTDOWN) != NULL) {
			crm_trace("Aborting on %s attribute", XML_CIB_ATTR_SHUTDOWN);
			abort = TRUE;
			
		} else if(xmlGetProp(node_state, XML_CIB_ATTR_STONITH) != NULL) {
			/* node marked for STONITH
			 *   possibly by us when a shutdown timmed out
			 */
			crm_trace("Checking for STONITH");
			code = crm_itoa(LRM_OP_TIMEOUT);
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);

			abort = !process_graph_event(
				event_node, NULL, CRMD_RSCSTATE_GENERIC_OK,
				XML_CIB_ATTR_SHUTDOWN, code, "0");

			crm_free(code);
			
		} else if(state != NULL && child == NULL) {
			/* simple node state update...
			 *   possibly from a shutdown we requested
			 */
			crm_trace("Processing simple state update");
			code = crm_itoa(LRM_OP_DONE);
			if(safe_str_neq(state, OFFLINESTATUS)) {
				// always recompute
				abort = TRUE;
				continue;
			}
			
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);

			abort = !process_graph_event(
				event_node, NULL, CRMD_RSCSTATE_GENERIC_OK,
				XML_CIB_ATTR_SHUTDOWN, code, "0");
			
			crm_free(code);

		} else if(state == NULL && child != NULL) {
			/* LRM resource update...
			 */
			crm_trace("Processing LRM resource update");
			child = find_xml_node(node_state, XML_CIB_TAG_LRM);
			child = find_xml_node(child, XML_LRM_TAG_RESOURCES);

			if(child != NULL) {
				child = child->children;
			} else {
				abort = TRUE;
			}
			
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);
			while(abort == FALSE && child != NULL) {
				event_action = xmlGetProp(
					child, XML_LRM_ATTR_LASTOP);
				event_rsc    = xmlGetProp(
					child, XML_ATTR_ID);
				event_rc     = xmlGetProp(
					child, XML_LRM_ATTR_RCCODE);
				rsc_state    = xmlGetProp(
					child, XML_LRM_ATTR_RSCSTATE);
				op_status    = xmlGetProp(
					child, XML_LRM_ATTR_OPCODE);

				abort = !process_graph_event(
					event_node, event_rsc, rsc_state,
					event_action, event_rc, op_status);

				child = child->next;
			}	
		} else if(state != NULL && child != NULL) {
			/* this is a complex event and could not be completely
			 * due to any request we made
			 */
			crm_trace("Aborting on complex update");
			abort = TRUE;
			
		} else {
			/* ignore */
			crm_err("Ignoring message");
		}
	}
	
	return !abort;
}

gboolean
process_graph_event(
	const char *event_node,   const char *event_rsc, const char *rsc_state,
	const char *event_action, const char *event_rc, const char *op_status)
{
	int lpc;
	xmlNodePtr action        = NULL; // <rsc_op> or <crm_event>
	xmlNodePtr next_action   = NULL;
	action_list_t *matched_action_list = NULL;

// Find the action corresponding to this event
	crm_trace("looking for: task=%s node=%s rsc_id=%s rc=%s",
		  event_action, event_node, event_rsc, event_rc);
	
	slist_iter(
		action_list, action_list_t, graph, lpc,

		if(action_list->status != TE_LIST_ACTIVE) {
			crm_trace("skipping %s list[%d]",
				  action_list->status==TE_LIST_COMPLETE?"complete":"failed",
				  lpc);
			continue;
		}
		
		action = g_list_nth_data(action_list->actions,
					  action_list->index);

		if(action == NULL) {
			crm_warn("No action for list[%d][%d]",
				 lpc, action_list->index);
			
			continue;
		}
/*
		<rsc_op id= runnable= optional= task= on_node= >
			<resource id="rsc3" priority="3.0"/>
		</rsc_op>
*/
		const char *this_action = xmlGetProp(
			action, XML_LRM_ATTR_TASK);
		const char *this_node   = xmlGetProp(
			action, XML_LRM_ATTR_TARGET);
		const char *this_rsc    = xmlGetProp(
			action, XML_LRM_ATTR_RSCID);

		crm_trace("matching against: <%s task=%s node=%s rsc_id=%s/>",
			  action->name, this_action, this_node, this_rsc);
		
		if(safe_str_neq(this_node, event_node)) {
			crm_trace("node mismatch");
			continue;

		} else if(safe_str_neq(this_action, event_action)) {	
			crm_trace("action mismatch");
			continue;
			
		} else if(safe_str_eq(action->name, "rsc_op")) {
			crm_trace("rsc_op");
			if(safe_str_eq(this_rsc, event_rsc)) {
				matched_action_list = action_list;
			} else {
				crm_trace("bad rsc (%s) != (%s)",
					  this_rsc, event_rsc);
			}
			
		} else if(safe_str_eq(action->name, "crm_event")) {
			crm_trace("crm_event");
			matched_action_list = action_list;

		} else {
			crm_trace("no match");
		}
		
		);			

	if(matched_action_list == NULL) {
		// unexpected event, trigger a pe-recompute
		// possibly do this only for certain types of actions
		crm_err("Unexpected event... matched action list was NULL"
			" for: task=%s node=%s rsc_id=%s, rc=%s, state=%s",
			event_action, event_node, event_rsc, event_rc, rsc_state);
		
		return FALSE;
	} else {
		crm_trace("Matched event to item %d in list %d",
			  matched_action_list->index,
			  matched_action_list->id);
	}

	xmlNodePtr xml_action = g_list_nth_data(matched_action_list->actions,
						 matched_action_list->index);
	const char *allow_fail  = xmlGetProp(xml_action, "allow_fail");

	/* check for action failure */
	op_status_t rsc_code_i = -1;

	if(event_rc != NULL) {
		rsc_code_i = atoi(op_status);
	}
	
	if(rsc_code_i == -1) {
		// just information that the action was sent
		crm_trace("Ignoring TE initiated updates");
		return TRUE;
	}
	
	switch(rsc_code_i) {
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			if(safe_str_neq(allow_fail, XML_BOOLEAN_TRUE)) {
				crm_err("Action %s to %s on %s resulted in"
					" failure... aborting transition.",
					event_action, event_rsc, event_node);
				return FALSE;
			}
			break;
		case LRM_OP_CANCELLED:
			// do nothing??
			crm_warn("Dont know what to do for cancelled ops yet");
			break;
		default:
			crm_err("Unsupported action result: %s", event_rc);
			return FALSE;
			break;
	}
	
	crm_trace("Action was successful, looking for next action");

	while(matched_action_list->status == TE_LIST_ACTIVE) {
		gboolean passed = FALSE;

		if(matched_action_list->timer_id > 0) {
			crm_debug("Removing timer for list: %s",
				  xml_action->name);
			g_source_remove(matched_action_list->timer_id);
		}
		
		matched_action_list->timer_id = -1;
		next_action = g_list_nth_data(matched_action_list->actions,
					      matched_action_list->index);
		
		passed = initiate_action(matched_action_list);

		if(passed == FALSE) {
			crm_err("Initiation of next event failed");
			return FALSE;
			
		} else if(matched_action_list->status == TE_LIST_COMPLETE) {
			/* last action in that list, check if there are
			 *  anymore actions at all
			 */
			crm_debug("Our list is complete... anyone else?");
			slist_iter(
				action_list, action_list_t, graph, lpc,
				if(action_list->status != TE_LIST_COMPLETE){
					crm_debug("Another list is not yet complete");
					return TRUE;
				}
				);
		} else {
			crm_debug("Exiting with status: %d", matched_action_list->status);
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

	crm_info("Initating transition");
	
	slist_iter(
		action_list, action_list_t, graph, lpc,

		if(initiate_action(action_list)
		   && action_list->status != TE_LIST_COMPLETE) {
			anything = TRUE;
		}

		);

	crm_info("Transition %s", anything?"started":"complete");
	if(anything == FALSE)
		send_success();		

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
	const char *timeout   = NULL;
	
	crm_info("Initiating action on list %d", list->id);
	while(TRUE) {
		
		list->index++;
		xml_action = g_list_nth_data(list->actions, list->index);
		
		if(xml_action == NULL) {
			crm_info("No tasks left on list %d", list->id);
			list->status = TE_LIST_COMPLETE;
			
			return TRUE;
		}
		
		discard  = xmlGetProp(xml_action, XML_LRM_ATTR_DISCARD);
		on_node  = xmlGetProp(xml_action, XML_LRM_ATTR_TARGET);
		id       = xmlGetProp(xml_action, XML_ATTR_ID);
		runnable = xmlGetProp(xml_action, XML_LRM_ATTR_RUNNABLE);
		optional = xmlGetProp(xml_action, XML_LRM_ATTR_OPTIONAL);
		task     = xmlGetProp(xml_action, XML_LRM_ATTR_TASK);
		timeout  = xmlGetProp(xml_action, "timeout");

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
			crm_info("Forcing execution of otherwise optional task"
				 " due to a dependancy on a previous action");
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
			list->status = TE_LIST_FAILED;
			return FALSE;
			
		} else if(id == NULL || strlen(id) == 0
			  || on_node == NULL || strlen(on_node) == 0
			  || task == NULL || strlen(task) == 0) {
			// error
			crm_err("Failed on corrupted command: %s (id=%s) on %s",
				task, id, on_node);
			
			list->status = TE_LIST_FAILED;
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
				
				list->status = TE_LIST_FAILED;
				return FALSE;
			}
			
			
		} else if(safe_str_eq(xml_action->name, "crm_event")){
			/*
			  <crm_msg op=XML_LRM_ATTR_TASK to=XML_RES_ATTR_TARGET>
			*/
			crm_info("Executing crm-event (%s): %s on %s",
				 id, task, on_node);
#ifndef TESTING
			xmlNodePtr options = create_xml_node(
				NULL, XML_TAG_OPTIONS);
			set_xml_property_copy(options, XML_ATTR_OP, task);

			send_ipc_request(
				crm_ch, options, NULL, on_node,
				CRM_SYSTEM_CRMD,CRM_SYSTEM_TENGINE,NULL,NULL);

			list->timer_id = Gmain_timeout_add(
				default_op_timeout,timer_callback,(void*)list);
			
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
			unsigned   op_timeout = 0;
			xmlNodePtr data    = create_xml_node(NULL, "msg_data");
			xmlNodePtr rsc_op  = create_xml_node(data, "rsc_op");
			xmlNodePtr options = create_xml_node(
				NULL, XML_TAG_OPTIONS);

			if(timeout != NULL) {
				op_timeout = (unsigned)atoi(timeout);
				crm_debug("Decoded timeout %d from %s",
					  op_timeout, timeout);
			}
		
			set_xml_property_copy(options, XML_ATTR_OP, "rsc_op");
			
			set_xml_property_copy(rsc_op, XML_ATTR_ID, id);
			set_xml_property_copy(
				rsc_op, XML_LRM_ATTR_TASK, task);
			
			set_xml_property_copy(
				rsc_op, XML_LRM_ATTR_TARGET, on_node);
			
			add_node_copy(rsc_op, xml_action->children);

			// let everyone know this was invoked
			do_update_cib(xml_action, -1);

			send_ipc_request(crm_ch, options, data,
					 on_node, "lrmd", CRM_SYSTEM_TENGINE,
					 NULL, NULL);

			if(op_timeout > 0) {
				crm_debug("Setting timer for list %d",list->id);
				list->timer_id = Gmain_timeout_add(
					op_timeout,timer_callback,(void*)list);
			}
			
			free_xml(options);
			free_xml(data);
			return TRUE;
#endif			
			
		} else {
			crm_err("Failed on unsupported command type: "
				"%s, %s (id=%s) on %s",
				xml_action->name, task, id, on_node);

			list->status = TE_LIST_FAILED;
			return FALSE;
		}
	}
	
	return FALSE;
}

FILE *msg_te_strm = NULL;

gboolean
process_te_message(xmlNodePtr msg, IPC_Channel *sender)
{
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,
				       XML_ATTR_OP, FALSE);

	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);
	const char *ref    = xmlGetProp(msg, XML_ATTR_REFERENCE);

	crm_debug("Processing %s (%s) message", op, ref);

#ifdef MSG_LOG
	if(msg_te_strm == NULL) {
		msg_te_strm = fopen(DEVEL_DIR"/te.log", "w");
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

		xmlNodePtr graph = find_xml_node(msg, "transition_graph");
		crm_trace("Unpacking graph...");
		unpack_graph(graph);
		crm_trace("Initiating transition...");
		if(initiate_transition() == FALSE) {
			// nothing to be done.. means we're done.
			crm_info("No actions to be taken..."
			       " transition compelte.");
		}
		crm_trace("Processing complete...");
		
		
	} else if(strcmp(op, CRM_OP_EVENTCC) == 0) {
		const char *true_op = get_xml_attr (msg, XML_TAG_OPTIONS,
						    XML_ATTR_TRUEOP, TRUE);
		crm_trace("Processing %s...", CRM_OP_EVENTCC);
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

	crm_debug("finished processing message");
	print_state();
	
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
	if(msg_te_strm != NULL) {
		fprintf(msg_te_strm, "[Result ]\tTransition complete\n");
		fflush(msg_te_strm);
	}
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

			const char *state = NULL;
			switch(action_list->status) {
				case TE_LIST_COMPLETE:
					state = "complete";
					break;
				case TE_LIST_ACTIVE:
					state = "active";
					break;
				case TE_LIST_FAILED:
					state = "failed";
					break;
			}
			
			crm_debug("\tAction set %d: %s (%d of %d invoked)",
				  lpc, state, action_list->index,
				  action_list->index_max);
			);
	}
	
	crm_debug("#!!#!!# End Transitioner state");
}

gboolean
timer_callback(gpointer data)
{
	action_list_t *list = (action_list_t*)data;
	xmlNodePtr xml_action = g_list_nth_data(list->actions, list->index);

	list->timer_id = -1;

	return do_update_cib(xml_action, LRM_OP_TIMEOUT);	
}

gboolean
do_update_cib(xmlNodePtr xml_action, int status)
{
	const char *task   = xmlGetProp(xml_action, XML_LRM_ATTR_TASK);
	const char *rsc_id = xmlGetProp(xml_action, XML_LRM_ATTR_RSCID);
	const char *target = xmlGetProp(xml_action, XML_LRM_ATTR_TARGET);
	const char *target_uuid =
		xmlGetProp(xml_action, XML_LRM_ATTR_TARGET_UUID);

	if(status == LRM_OP_TIMEOUT) {
		if(xmlGetProp(xml_action, XML_LRM_ATTR_RSCID) != NULL) {
			crm_warn("%s: %s %s on %s timed out",
				 xml_action->name, task, rsc_id, target);
		} else {
			crm_warn("%s: %s on %s timed out",
				 xml_action->name, task, target);
		}
	}
	
	print_state();

/*
  update the CIB

<node_state id="hadev">
      <lrm>
        <lrm_resources>
          <lrm_resource id="rsc2" last_op="start" op_code="0" target="hadev"/>
*/

	char *code;
	char since_epoch[64];
	xmlNodePtr fragment = NULL;
	xmlNodePtr options  = create_xml_node(NULL, XML_TAG_OPTIONS);
	xmlNodePtr state    = create_xml_node(NULL, XML_CIB_TAG_STATE);
	xmlNodePtr rsc      = NULL;

	set_xml_property_copy(options, XML_ATTR_OP,    CRM_OP_UPDATE);
	set_xml_property_copy(state,   XML_ATTR_UUID,  target_uuid);
	set_xml_property_copy(state,   XML_ATTR_UNAME, target);
	
	if(status != -1 && (safe_str_eq(task, "shutdown_crm"))) {
		sprintf(since_epoch, "%ld", (unsigned long)time(NULL));
		set_xml_property_copy(rsc, "stonith", since_epoch);
		
	} else {
		code = crm_itoa(status);
		
		rsc = create_xml_node(state, "lrm");
		rsc = create_xml_node(rsc,   "lrm_resources");
		rsc = create_xml_node(rsc,   "lrm_resource");
		
		set_xml_property_copy(rsc, XML_ATTR_ID,         rsc_id);
		set_xml_property_copy(rsc, XML_LRM_ATTR_TARGET, target);
		set_xml_property_copy(
			rsc, XML_LRM_ATTR_TARGET_UUID, target_uuid);

		if(safe_str_eq(CRMD_RSCSTATE_START, task)) {
			set_xml_property_copy(
				rsc, XML_LRM_ATTR_RSCSTATE, CRMD_RSCSTATE_START_PENDING);

		} else if(safe_str_eq(CRMD_RSCSTATE_STOP, task)) {
			set_xml_property_copy(
				rsc, XML_LRM_ATTR_RSCSTATE, CRMD_RSCSTATE_STOP_PENDING);

		} else {
			crm_warn("Using status \"pending\" for op \"%s\""
				 "... this is still in the experimental stage.",
				 task);
			set_xml_property_copy(
				rsc, XML_LRM_ATTR_RSCSTATE, CRMD_RSCSTATE_GENERIC_PENDING);
		}
		
		set_xml_property_copy(rsc, XML_LRM_ATTR_OPCODE, code);
		set_xml_property_copy(rsc, XML_LRM_ATTR_RCCODE, code);
		set_xml_property_copy(rsc, XML_LRM_ATTR_LASTOP, task);

		crm_free(code);
	}

	fragment = create_cib_fragment(state, NULL);
	
#ifdef MSG_LOG
	fprintf(msg_te_strm,
		"[Result ]\tUpdate CIB with \"%s\" (%s): %s %s on %s\n",
		status<0?"new action":"timeout",
		xml_action->name, task, rsc_id, target);
	fprintf(msg_te_strm, "[Sent ]\t%s\n",
		dump_xml_node(fragment, FALSE));
	fflush(msg_te_strm);
#endif
	
	send_ipc_request(crm_ch, options, fragment,
			 NULL, CRM_SYSTEM_DCIB, CRM_SYSTEM_TENGINE,
			 NULL, NULL);
	
	free_xml(fragment);
	free_xml(options);
	free_xml(state);
	
	return TRUE;
}
		
