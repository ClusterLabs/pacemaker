#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>
#include <crm/cib.h>
#include <tengine.h>

GSListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;

typedef struct action_list_s 
{
		int index;
		int index_max;
		GSListPtr actions;
} action_list_t;

gboolean initialize_graph(void);
gboolean unpack_graph(xmlNodePtr xml_graph);
gboolean extract_event(xmlNodePtr msg);
gboolean initiate_transition(void);
gboolean initiate_action(xmlNodePtr xml_action);
gboolean process_graph_event(const char *event_node,
			     const char *event_rsc, 
			     const char *event_action, 
			     const char *event_status, 
			     const char *event_rc);

void send_success(void);
void send_abort(void);
gboolean process_fake_event(xmlNodePtr msg);


gboolean
initialize_graph(void)
{
	while(g_slist_length(graph) > 0) {
		action_list_t *action_list = g_slist_nth_data(graph, 0);
		while(g_slist_length(action_list->actions) > 0) {
			GSListPtr action = g_slist_nth(action_list->actions, 0);
			g_slist_remove(action_list->actions, action);
			cl_free(action->data);
		}
		g_slist_remove(graph, action_list);
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
		<rsc_op id="5" runnable="false" optional="true" task="stop">
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
			cl_malloc(sizeof(action_list_t));

		xml_action_list = xml_action_list->next;

		action_list->index = 0;
		action_list->index_max = 0;
		
		while(xml_action != NULL) {
			xmlNodePtr action = copy_xml_node_recursive(xml_action);

			action_list->actions =
				g_slist_append(action_list->actions, action);

			action_list->index_max++;
		}
		
		graph = g_slist_append(graph, action_list);
	}
	

	return TRUE;
}

gboolean
process_fake_event(xmlNodePtr msg)
{
	xmlNodePtr data = find_xml_node(msg, "lrm_resource");
	return process_graph_event(xmlGetProp(data, "op_node"),
				   xmlGetProp(data, "id"),
				   xmlGetProp(data, "last_op"),
				   xmlGetProp(data, "op_status"),
				   xmlGetProp(data, "op_code"));
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
<status>
   <node_state id="node1" state="active" exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/

	xml_message_debug(msg, "TE Event");
	
	iter = find_xml_node(msg, XML_TAG_FRAGMENT);
	section = xmlGetProp(iter, "section");

	if(safe_str_neq(section, XML_CIB_TAG_STATUS)) {
		// these too are never expected
		send_abort();
		return FALSE;
		
	}
	
	iter = find_xml_node(msg, XML_TAG_CIB);
	iter = get_object_root(XML_CIB_TAG_STATUS, iter);
	iter = iter->children;

	while(abort == FALSE && iter != NULL) {
		xmlNodePtr node_state = iter;
		xmlNodePtr child = iter->children;
		const char *state = xmlGetProp(node_state, "state");
		iter = iter->next;

		if(state != NULL && child == NULL) {
			/* node state update,
			 * possibly from a shutdown we requested
			 */
			event_status = state;
			event_node   = xmlGetProp(node_state, XML_ATTR_ID);
			if(safe_str_eq(event_status, "down")) {
				event_action = "shutdown";
			}
			
			abort = !process_graph_event(event_node,
						     event_rsc,
						     event_action,
						     event_status,
						     event_rc);

		} else if(state != NULL && child != NULL) {
			/* this is a complex eventand could not be completely
			 * due to any request we made
			 */
			send_abort();
			abort = TRUE;
		
		} else {
			child = find_xml_node(node_state, "lrm");
			child = find_xml_node(child, "lrm_resources");
			child = child->children;
			
			while(abort == FALSE && child != NULL) {
				event_action = xmlGetProp(child, "last_op");
				event_node   = xmlGetProp(child, "op_node");
				event_rsc    = xmlGetProp(child, "id");
				event_status = xmlGetProp(child, "op_status");
				event_rc     = xmlGetProp(child, "op_code");
				
				abort = !process_graph_event(event_node,
							     event_rsc,
							     event_action,
							     event_status,
							     event_rc);

				child = child->next;
			}	
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

// Find the action corresponding to this event
	slist_iter(
		action_list, action_list_t, graph, lpc,
		action = g_slist_nth_data(action_list->actions,
					  action_list->index);
/*
		<rsc_op id= runnable= optional= task= on_node= >
			<resource id="rsc3" priority="3.0"/>
		</rsc_op>
*/
		const char *this_action = xmlGetProp(action, "task");
		const char *this_node   = xmlGetProp(action, "on_node");
		const char *this_rsc    = xmlGetProp(action->children, "id");

		if(safe_str_neq(this_node, event_node)) {
			continue;

		} else if(safe_str_neq(this_action, event_action)) {
			continue;
			
		} else if(safe_str_eq(action->name, "rsc_op")
			  && safe_str_eq(this_rsc, event_rsc)) {
			action_list->index++;
			next_action = g_slist_nth_data(action_list->actions,
						       action_list->index);

		} else if(safe_str_eq(action->name, "crm_event")) {
			action_list->index++;
			next_action = g_slist_nth_data(action_list->actions,
						       action_list->index);
			
		}
		);

	// for the moment all actions succeed
	
	if(action == NULL) {
		// unexpected event, trigger a pe-recompute
		// possibly do this only for certain types of actions

		send_abort();
		
	} else if(next_action == NULL) {
		/* last action in that list, check if there are
		 *  anymore actions at all
		 */
		gboolean more_to_do = FALSE;
		slist_iter(
			action_list, action_list_t, graph, lpc,
			if(action_list->index <= action_list->index_max){
				more_to_do = TRUE;
				break;
			}
			);
		if(more_to_do == FALSE) {
			// indicate to the CRMd that we're done
			xmlNodePtr options = create_xml_node(NULL, "options");
			set_xml_property_copy(options, XML_ATTR_OP, "te_complete");

			send_ipc_request(crm_ch, options, NULL,
					 NULL, "dc", "tengine",
					 NULL, NULL);
			
			free_xml(options);

			return TRUE;
		} // else wait for the next event

	} else {
		return initiate_action(next_action);
	}
	
	return FALSE;
}

gboolean
initiate_transition(void)
{
	int lpc;
	gboolean anything = FALSE;
	xmlNodePtr action = NULL;

	FNIN();
	
	slist_iter(
		action_list, action_list_t, graph, lpc,
		action = g_slist_nth_data(action_list->actions,
					  action_list->index);

		if(action != NULL) {
			anything = TRUE;
			initiate_action(action);		
		}
		
		action_list->index++;
		);

	FNRET(anything);
}

gboolean
initiate_action(xmlNodePtr xml_action) 
{
	// initiate the next action

	const char *on_node  = xmlGetProp(xml_action, "on_node");
	const char *id       = xmlGetProp(xml_action, "id");
//		const char *runnable = xmlGetProp(xml_action, "runnable");
//		const char *optional = xmlGetProp(xml_action, "optional");
	const char *task     = xmlGetProp(xml_action, "task");

	FNIN();


	cl_log(LOG_INFO, "Invoking action %s (id=%s) on %s", task, id, on_node);

	
	if(id == NULL || strlen(id) == 0
	   || on_node == NULL || strlen(on_node) == 0
	   || task == NULL || strlen(task) == 0) {
		// error
		cl_log(LOG_ERR,
		       "Command: \"%s (id=%s) on %s\" was corrupted.",
		       task, id, on_node);

		FNRET(FALSE);
			
//	} else if(safe_str_eq(xml_action->name, "pseduo_event")){
			
	} else if(safe_str_eq(xml_action->name, "crm_event")){
		/*
		  <crm_msg op="task" to="on_node">
		*/
		xmlNodePtr options = create_xml_node(NULL, "options");
		set_xml_property_copy(options, XML_ATTR_OP, task);

		send_ipc_request(crm_ch, options, NULL,
				 on_node, "crmd", "tengine",
				 NULL, NULL);
			
		free_xml(options);
			
	} else if(safe_str_eq(xml_action->name, "rsc_op")){
		/*
		  <msg_data>
			  <rsc_op id="operation number" on_node="" task="">
				  <resource>...</resource>
		*/
		xmlNodePtr options = create_xml_node(NULL, "options");
		xmlNodePtr data = create_xml_node(NULL, "msg_data");
		xmlNodePtr rsc_op = create_xml_node(data, "rsc_op");

		set_xml_property_copy(options, XML_ATTR_OP, "rsc_op");

		set_xml_property_copy(rsc_op, "id", id);
		set_xml_property_copy(rsc_op, "task", task);
		set_xml_property_copy(rsc_op, "on_node", on_node);

		add_node_copy(rsc_op, xml_action->children);

		send_ipc_request(crm_ch, options, data,
				 on_node, "lrmd", "tengine",
				 NULL, NULL);
			
		free_xml(options);
		free_xml(data);
			
	} else {
		// error
		cl_log(LOG_ERR, "Action %s is not (yet?) supported",
		       xml_action->name);

		FNRET(FALSE);
	}

	FNRET(TRUE);

}

gboolean
process_te_message(xmlNodePtr msg, IPC_Channel *sender)
{
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,
				       XML_ATTR_OP, TRUE);

	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);

	cl_log(LOG_DEBUG, "Processing %s message", op);
	
	if(op == NULL){
		// error
	} else if(sys_to == NULL || strcmp(sys_to, "tengine") != 0) {
		CRM_DEBUG("Bad sys-to %s", sys_to);
		return FALSE;
		
	} else if(strcmp(op, "transition") == 0) {
		initialize_graph();

		xmlNodePtr graph = find_xml_node(msg, "transition_graph");
		unpack_graph(graph);
		if(initiate_transition() == FALSE) {
			// nothing to be done.. means we're done.
			cl_log(LOG_INFO, "No actions to be taken..."
			       " transition compelte.");
			send_success();		
		}
		
		
	} else if(strcmp(op, "event") == 0) {
		const char *true_op = get_xml_attr (msg, XML_TAG_OPTIONS,
						    "true_op", TRUE);
		if(true_op == NULL) {
#ifdef USE_FAKE_LRM
			process_fake_event(msg);
#else
			// error
#endif
		} else if(strcmp(op, CRM_OPERATION_CREATE) == 0
		   || strcmp(op, CRM_OPERATION_DELETE) == 0
		   || strcmp(op, CRM_OPERATION_REPLACE) == 0
		   || strcmp(op, CRM_OPERATION_WELCOME) == 0
		   || strcmp(op, CRM_OPERATION_SHUTDOWN_REQ) == 0
		   || strcmp(op, CRM_OPERATION_ERASE) == 0) {

			// these are always unexpected, trigger the PE
			send_abort();
			
		} else if(strcmp(op, CRM_OPERATION_UPDATE) == 0) {
			// this may not be un-expected
			extract_event(msg);
			
		} else {
			cl_log(LOG_ERR,
			       "Did not expect copy of action %s", op);
		}
		
	} else if(strcmp(op, "abort") == 0) {
		initialize_graph();

	} else if(strcmp(op, "quit") == 0) {
		cl_log(LOG_WARNING, "Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

void
send_abort(void)
{	
	xmlNodePtr options = create_xml_node(NULL, "options");

	CRM_DEBUG("Sending \"abort\" message");

	set_xml_property_copy(options, XML_ATTR_OP, "te_abort");
	
	send_ipc_request(crm_ch, options, NULL,
			 NULL, "dc", "tengine",
			 NULL, NULL);
	
	free_xml(options);
}

void
send_success(void)
{	
	xmlNodePtr options = create_xml_node(NULL, "options");

	CRM_DEBUG("Sending \"complete\" message");
	
	set_xml_property_copy(options, XML_ATTR_OP, "te_complete");
	
	send_ipc_request(crm_ch, options, NULL,
			 NULL, "dc", "tengine",
			 NULL, NULL);
	
	free_xml(options);
}
