#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/cib.h>
#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>

xmlNodePtr process_pe_message(xmlNodePtr msg);
xmlNodePtr do_calculations(xmlNodePtr msg);

gboolean
pe_input_dispatch(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	xmlDocPtr doc = NULL;
	IPC_Message *msg = NULL;
	gboolean all_is_well = TRUE;
	xmlNodePtr answer = NULL, root_xml_node = NULL;
	const char *sys_to;
	const char *type;

	
	FNIN();

	while(sender->ops->is_message_pending(sender)) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (sender->ops->recv(sender, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!all_is_well);
		}
		if (msg == NULL) {
			cl_log(LOG_ERR, "No message this time");
			continue;
		}

		lpc++;

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
//		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "Message %d [text=%s]", lpc, buffer);
		doc = xmlParseMemory(cl_strdup(buffer), strlen(buffer));

		if(doc == NULL) {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}

		root_xml_node = xmlDocGetRootElement(doc);

		sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			cl_log(LOG_ERR, "Root node was NULL!!");

		} else if(sys_to == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else if(strcmp(type, XML_ATTR_REQUEST) != 0) {
			cl_log(LOG_INFO,
			       "Message was a response not a request."
			       "  Discarding");
		} else if (strcmp(sys_to, CRM_SYSTEM_PENGINE) == 0) {
			answer = process_pe_message(root_xml_node);
			if (send_xmlipc_message(sender, answer)==FALSE)
				cl_log(LOG_WARNING,
				       "Cib answer could not be sent");
		} else {
			cl_log(LOG_WARNING,
			       "Received a message destined for %s by mistake",
			       sys_to);
		}
		
		if(answer != NULL)
			free_xml(answer);
		
		msg->msg_done(msg);
		msg = NULL;
	}

	// clean up after a break
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	CRM_DEBUG("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); // shutdown properly later
		
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
}

xmlNodePtr
process_pe_message(xmlNodePtr msg)
{
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,XML_ATTR_OP, TRUE);

	if(op == NULL){
		// error
	} else if(strcmp(op, "pecalc")) {
		xmlNodePtr fragment = find_xml_node(msg, XML_TAG_FRAGMENT);
		xmlNodePtr input_cib = find_xml_node(fragment, XML_TAG_CIB);
		return do_calculations(input_cib);
	} else if(strcmp(op, "quit")) {
		cl_log(LOG_WARNING, "Received quit message, terminating");
		exit(0);
	}
	
	return NULL;
}

xmlNodePtr
do_calculations(xmlNodePtr cib_object)
{
	int lpc, lpc2;
	
	GSListPtr resources = NULL;
	GSListPtr nodes = NULL;
	GSListPtr node_constraints = NULL;
	GSListPtr actions = NULL;
	GSListPtr action_constraints = NULL;
	GSListPtr stonith_list = NULL;
	GSListPtr shutdown_list = NULL;

	GSListPtr colors = NULL;
	GSListPtr action_sets = NULL;

	xmlNodePtr graph = NULL;

	pdebug("=#=#=#=#= Stage 0 =#=#=#=#=");
		  
	stage0(cib_object,
	       &resources,
	       &nodes,  &node_constraints,
	       &actions,  &action_constraints,
	       &stonith_list, &shutdown_list);

	pdebug("=#=#=#=#= Stage 1 =#=#=#=#=");
	stage1(node_constraints, nodes, resources);

	pdebug("=#=#=#=#= Stage 2 =#=#=#=#=");
	stage2(resources, nodes, &colors);

	pdebug("========= Nodes =========");
	pdebug_action(
		slist_iter(node, node_t, nodes, lpc,
			   print_node(NULL, node, TRUE)
			)
		);
		
	pdebug("========= Resources =========");
	pdebug_action(
		slist_iter(resource, resource_t, resources, lpc,
			   print_resource(NULL, resource, TRUE)
			)
		);  
  
	pdebug("=#=#=#=#= Stage 3 =#=#=#=#=");
	stage3(colors);

	pdebug("=#=#=#=#= Stage 4 =#=#=#=#=");
	stage4(colors);
	pdebug("========= Colors =========");
	pdebug_action(
		slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE)
			)
		);

	pdebug("=#=#=#=#= Stage 5 =#=#=#=#=");
	stage5(resources);

	pdebug("=#=#=#=#= Stage 6 =#=#=#=#=");
	stage6(&actions, &action_constraints,
	       stonith_list, shutdown_list);

	pdebug("========= Action List =========");
	pdebug_action(
		slist_iter(action, action_t, actions, lpc,
			   print_action(NULL, action, TRUE)
			)
		);
	
	pdebug("=#=#=#=#= Stage 7 =#=#=#=#=");
	stage7(resources, actions, action_constraints, &action_sets);
	
	pdebug("=#=#=#=#= Summary =#=#=#=#=");
	summary(resources);

	pdebug("========= Action Sets =========");

	pdebug("\t========= Set %d (Un-runnable) =========", -1);
	pdebug_action(
		slist_iter(action, action_t, actions, lpc,
			   if(action->optional == FALSE
			      && action->runnable == FALSE) {
				   print_action("\t", action, TRUE);
			   }
			)
		);

	pdebug_action(
		slist_iter(action_set, GSList, action_sets, lpc,
			   pdebug("\t========= Set %d =========", lpc);
			   slist_iter(action, action_t, action_set, lpc2,
				      print_action("\t", action, TRUE);
				   )
			)
		);

	
	pdebug("========= Stonith List =========");
	pdebug_action(
		slist_iter(node, node_t, stonith_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);
  
	pdebug("========= Shutdown List =========");
	pdebug_action(
		slist_iter(node, node_t, shutdown_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);

	pdebug("=#=#=#=#= Stage 8 =#=#=#=#=");
	stage8(action_sets, &graph);

	return graph;
}
