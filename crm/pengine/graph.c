/* $Id: graph.c,v 1.39 2005/05/06 09:20:26 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>

gboolean update_action(action_t *action);

gboolean
update_action_states(GListPtr actions)
{
	crm_debug("Updating %d actions",  g_list_length(actions));
	slist_iter(
		action, action_t, actions, lpc,

		update_action(action);
		);

	return TRUE;
}


gboolean
update_action(action_t *action)
{
	gboolean change = FALSE;

	crm_verbose("Processing action %d", action->id);
	if(action->optional && action->runnable) {
		return FALSE;
	}
	
	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,

		if(action->pseudo == FALSE
		   && action->runnable == FALSE
		   && action->optional == FALSE) {
			if(other->action->runnable == FALSE) {
				crm_debug("Action %d already un-runnable",
					  other->action->id);
				continue;
			} else {
				change = TRUE;
				other->action->runnable =FALSE;
				crm_debug("Marking action %d un-runnable"
					  " because of %d",
					  other->action->id, action->id);
			}	

		} else if(other->action->optional
			  && action->optional == FALSE) {
			change = TRUE;
			other->action->optional = FALSE;
			crm_debug("Marking action %d manditory because of %d",
				  other->action->id, action->id);
		}
		

		if(action->optional == FALSE && other->action->optional) {

	switch(action->rsc->restart_type) {
		case pe_restart_ignore:
			break;
		case pe_restart_restart:
			change = TRUE;
			other->action->optional = FALSE;
			crm_debug("(Restart) Marking action %d manditory because of %d",
				  other->action->id, action->id);
	}
		}
		
		if(change) {
			update_action(other->action);
		}
		
		);

	return change;
}


gboolean
shutdown_constraints(
	node_t *node, action_t *shutdown_op, GListPtr *ordering_constraints)
{
	/* add the stop to the before lists so it counts as a pre-req
	 * for the shutdown
	 */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		order_new(rsc, stop_rsc, NULL,
			  NULL, shutdown_crm, shutdown_op,
			  pecs_must, ordering_constraints);

		);	

	return TRUE;	
}

gboolean
stonith_constraints(node_t *node,
		    action_t *stonith_op, action_t *shutdown_op,
		    GListPtr *ordering_constraints)
{
	GListPtr stop_actions = NULL;

	if(shutdown_op != NULL) {
		/* stop everything we can via shutdown_constraints() and then
		 *   shoot the node... the shutdown has been superceeded
		 */
		shutdown_op->pseudo = TRUE;
		shutdown_op->runnable = TRUE;

		/* shutdown before stonith */
		/* Give any resources a chance to shutdown normally */
		crm_devel("Adding shutdown (%d) as an input to stonith (%d)",
			  shutdown_op->id, stonith_op->id);
		
		order_new(NULL, shutdown_crm, shutdown_op,
			  NULL, stonith_node, stonith_op,
			  pecs_must, ordering_constraints);
		
	}
	
	/* add the stonith OP to the before lists so it counts as a pre-req */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		if(stonith_op != NULL) {
			stop_actions = find_actions(rsc->actions,stop_rsc,node);
			slist_iter(
				action, action_t, stop_actions, lpc2,
				if(node->details->online == FALSE
				   || rsc->unclean) {
					/* the stop would never complete and is
					 * now implied by the stonith operation
					 */
					action->pseudo = TRUE;
					action->runnable = TRUE;
					order_new(NULL,stonith_node,stonith_op,
						  rsc, stop_rsc, NULL,
						  pecs_must, ordering_constraints);
				} else {
					/* stop healthy resources before the
					 * stonith op
					 */
					order_new(rsc, stop_rsc, NULL,
						  NULL,stonith_node,stonith_op,
						  pecs_must, ordering_constraints);
				}
				);

			crm_devel("Adding stonith (%d) as an input to stop",
				  stonith_op->id);
			
		} else if((rsc->unclean || node->details->unclean)
			  && rsc->stopfail_type == pesf_block) {
			/* depend on the stop action which will fail */
			crm_err("SHARED RESOURCE %s WILL REMAIN BLOCKED"
				 " ON NODE %s UNTIL %s",
				rsc->id, node->details->uname,
				stonith_enabled?"QUORUM RETURNS":"CLEANED UP MANUALLY");
			continue;
			
		} else if((rsc->unclean || node->details->unclean)
			  && rsc->stopfail_type == pesf_ignore) {
			/* nothing to do here */
			crm_err("SHARED RESOURCE %s IS NOT PROTECTED",
				 rsc->id);
			continue;
		}
		);
	
	return TRUE;
}

crm_data_t *
action2xml(action_t *action, gboolean as_input)
{
	crm_data_t * action_xml = NULL;
	crm_data_t * args_xml = NULL;
	
	if(action == NULL) {
		return NULL;
	}

	crm_devel("Dumping action %d as XML", action->id);
	switch(action->task) {
		case stonith_node:
		case shutdown_crm:
			action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			set_xml_property_copy(action_xml, XML_LRM_ATTR_TASK,
					      task2text(action->task));

			break;
		default:
			if(action->pseudo) {
				action_xml = create_xml_node(NULL,XML_GRAPH_TAG_PSEUDO_EVENT);
			} else {
				action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
			}

			if(!as_input && action->rsc != NULL) {
				crm_data_t *rsc_xml = create_xml_node(
					action_xml, crm_element_name(action->rsc->xml));
				copy_in_properties(rsc_xml, action->rsc->xml);
			}
			
			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			if(safe_val3(NULL, action, rsc, id) != NULL) {
				set_xml_property_copy(
					action_xml, XML_LRM_ATTR_RSCID,
					safe_val3(NULL, action, rsc, id));
			}
			
			set_xml_property_copy(action_xml, XML_LRM_ATTR_TASK,
					      task2text(action->task));
			
			break;
	}

	if(action->task != stonith_node
	   && (action->pseudo == FALSE || action->node != NULL)) {
		const char *default_value = NULL;
		if(as_input) {
			default_value = "__none__";
		}

		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET,
			safe_val4(default_value, action, node, details,uname));

		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET_UUID,
			safe_val4(default_value, action, node, details, id));

		CRM_DEV_ASSERT(NULL != crm_element_value(
				       action_xml, XML_LRM_ATTR_TARGET));
		
		CRM_DEV_ASSERT(NULL != crm_element_value(
				       action_xml, XML_LRM_ATTR_TARGET_UUID));

	}

	set_xml_property_copy(
		action_xml, "allow_fail",
		action->failure_is_fatal?XML_BOOLEAN_FALSE:XML_BOOLEAN_TRUE);
	
	if(as_input) {
		return action_xml;
	}

	crm_xml_debug(action_xml, "dumped action");
	
	args_xml = create_xml_node(action_xml, XML_TAG_ATTRS);
	g_hash_table_foreach(action->extra, hash2nvpair, args_xml);

	if(action->rsc != NULL) {
		g_hash_table_foreach(
			action->rsc->parameters, hash2nvpair, args_xml);
	}
	
	crm_xml_verbose(args_xml, "copied in extra attributes");
	
	return action_xml;
}

void
graph_element_from_action(action_t *action, crm_data_t * *graph)
{
	char *syn_id = NULL;
	crm_data_t * syn = NULL;
	crm_data_t * set = NULL;
	crm_data_t * in  = NULL;
	crm_data_t * input = NULL;
	crm_data_t * xml_action = NULL;
	if(action == NULL) {
		crm_err("Cannot dump NULL action");
		return;

	} else if(action->optional) {
		crm_trace("action %d was optional", action->id);
		return;

	} else if(action->pseudo == FALSE && action->runnable == FALSE) {
		crm_trace("action %d was not runnable", action->id);
		return;

	} else if(action->dumped) {
		crm_trace("action %d was already dumped", action->id);
		return;

	} else if(action->pseudo
		  || action->task == stonith_node
		  || action->task == shutdown_crm) {
		/* skip the next check */
		
	} else {
		if(action->node == NULL) {
			crm_err("action %d was not allocated", action->id);
			log_action(LOG_DEBUG, "Unallocated action", action, FALSE);
			return;
			
		} else if(action->node->details->online == FALSE) {
			crm_err("action %d was scheduled for offline node", action->id);
			log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
			return;
		}
	}
	
	action->dumped = TRUE;
	
	syn = create_xml_node(*graph, "synapse");
	set = create_xml_node(syn, "action_set");
	in  = create_xml_node(syn, "inputs");

	syn_id = crm_itoa(num_synapse++);
	set_xml_property_copy(syn, XML_ATTR_ID, syn_id);
	crm_free(syn_id);
	
	xml_action = action2xml(action, FALSE);
	add_node_copy(set, xml_action);
	
	slist_iter(wrapper,action_wrapper_t,action->actions_before,lpc,
			
		   if(wrapper->action->optional == TRUE) {
			   crm_debug("Input %d optional", wrapper->action->id);
			   continue;
		   }
		   
		   input = create_xml_node(in, "trigger");
		   
		   xml_action = action2xml(wrapper->action, TRUE);
		   add_node_copy(input, xml_action);
		   
		);
	free_xml(xml_action);
}
