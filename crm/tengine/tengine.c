#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>
#include <tengine.h>

GSListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;

typedef struct action_list_s 
{
		int index;
		int index_max;
		GSListPtr actions;
} action_list_t;

gboolean initiate_action(xmlNodePtr xml_action);
gboolean process_graph_event(const char *event_node,
			     const char *event_rsc, 
			     const char *event_action, 
			     const char *event_status, 
			     const char *event_rc);

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

	xmlNodePtr xml_action_list = xml_graph->children;
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
process_event(xmlNodePtr msg)
{
	const char *event_action = NULL;
	const char *event_node   = NULL;
	const char *event_rsc    = NULL;
	const char *event_status = NULL;
	const char *event_rc     = NULL;
	
	xmlNodePtr data = find_xml_node(msg, "lrm_resource");
	
	if(data != NULL) {
		event_action = xmlGetProp(data, "last_op");
		event_node   = xmlGetProp(data, "op_node");
		event_rsc    = xmlGetProp(data, "id");
		event_status = xmlGetProp(data, "op_status");
		event_rc     = xmlGetProp(data, "op_code");

		return process_graph_event(event_node, event_rsc, event_action,
					   event_status, event_rc);
	}

	data = find_xml_node(msg, "crm_events");
	
	if(data != NULL) {
		event_node   = xmlGetProp(data->children, XML_ATTR_ID);
		event_status = xmlGetProp(data->children, "state");
		event_rc     = xmlGetProp(data->children, "op_code");
		if(safe_str_eq(event_status, "down")) {
			event_action = "shutdown";
		}
		
		
		return process_graph_event(event_node, event_rsc, event_action,
					   event_status, event_rc);
	}

	// error: not (yet?) supported
	
	return FALSE;
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

		xmlNodePtr options = create_xml_node(NULL, "options");
		set_xml_property_copy(options, "op", "pe_restart");
		
		send_ipc_request(crm_ch, options, NULL,
				 NULL, "dc", "tengine",
				 NULL, NULL);
		
		free_xml(options);
		
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
			set_xml_property_copy(options, "op", "te_complete");

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
	xmlNodePtr action = NULL;

	FNIN();
	
	slist_iter(
		action_list, action_list_t, graph, lpc,
		action = g_slist_nth_data(action_list->actions,
					  action_list->index);

		initiate_action(action);		

		action_list->index++;
		);

	FNRET(TRUE);
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
		set_xml_property_copy(options, "op", task);

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

		set_xml_property_copy(options, "op", "rsc_op");

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

void
process_te_message(xmlNodePtr msg)
{
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,XML_ATTR_OP, TRUE);

	if(op == NULL){
		// error
	} else if(strcmp(op, "transition")) {
		initialize_graph();
		unpack_graph(msg);
		initiate_transition();
		
	} else if(strcmp(op, "event")) {
		process_event(msg);
		
	} else if(strcmp(op, "abort")) {
		initialize_graph();

	} else if(strcmp(op, "quit")) {
		cl_log(LOG_WARNING, "Received quit message, terminating");
		exit(0);
	}
	
/*
  answer = process_te_message(root_xml_node);
  if (send_xmlipc_message(sender, answer)==FALSE)
	 cl_log(LOG_WARNING, "Cib answer could not be sent");
*/
//	return NULL;
}
