/* $Id: graph.c,v 1.29 2005/03/31 07:57:32 andrew Exp $ */
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

	if(action->optional && action->runnable) {
		return FALSE;
	}
	
	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,

		if(action->runnable == FALSE && action->optional == FALSE) {
			if(other->action->runnable == FALSE) {
				continue;
			} else if (other->strength == pecs_must) {
				change = TRUE;
				other->action->runnable =FALSE;
				crm_devel_action(
					print_action("Marking unrunnable",
						     other->action, FALSE);
					print_action("Reason",
						     action, FALSE);
					);
			}	
		}

		if(action->optional == FALSE && other->action->optional) {

	switch(action->rsc->restart_type) {
		case pe_restart_ignore:
			break;
		case pe_restart_recover:
				crm_err("Recover after dependancy "
					"restart not supported... "
					"forcing a restart");
				/* keep going */
		case pe_restart_restart:
			change = TRUE;
			other->action->optional = FALSE;
			crm_devel_action(
				print_action("Marking manditory",
					     other->action, FALSE));
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
		/* shutdown before stonith */
		/* add the shutdown OP to the before lists so it counts as a pre-req */
		crm_devel("Adding shutdown (%d) as an input to stonith (%d)",
			  shutdown_op->id, stonith_op->id);
		
		order_new(NULL, shutdown_crm, shutdown_op,
			  NULL, stonith_node, stonith_op,
			  pecs_must, ordering_constraints);
	}
	
	/* add the stonith OP to the before lists so it counts as a pre-req */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		/* make use of timeouts in the TE for cases such
		 *   as this.
		 * ie. the node may be cactus and unable to receive the
		 *  stop let alone reply with failed.
		 */

		stop_actions = find_actions(rsc->actions, stop_rsc, node);
		slist_iter(
			action, action_t, stop_actions, lpc2,
			action->discard = TRUE;
			);

		if(rsc->stopfail_type == pesf_block) {
			/* depend on the stop action which will fail */
			crm_warn("SHARED RESOURCE %s WILL REMAIN BLOCKED"
				 " UNTIL CLEANED UP MANUALLY ON NODE %s",
				 rsc->id, node->details->uname);
			continue;
			
		} else if(rsc->stopfail_type == pesf_ignore) {
			/* nothing to do here */
			crm_warn("SHARED RESOURCE %s IS NOT PROTECTED",
				 rsc->id);
			continue;
		}
		
		/* case pesf_stonith: */
		/* remedial action:
		 *   shutdown (so all other resources are
		 *   stopped gracefully) and then STONITH node
		 */
		if(stonith_enabled == FALSE) {
			/* depend on an action that will never complete */
			crm_err("STONITH is not enabled in this"
				" cluster but is required for "
				"resource %s after a failed stop",
				rsc->id);
		}
		crm_devel("Adding stonith (%d) as an input to start",
			  stonith_op->id);
		
		/* stonith before start */
		order_new(NULL, stonith_node, stonith_op,
			  rsc, start_rsc, NULL,
			  pecs_must, ordering_constraints);

/* 		a pointless optimization?  probably */
/* 		if(shutdown_op != NULL) { */
/* 			/\* the next rule is implied *\/ */
/* 			continue; */
/* 		} */

		/* stop before stonith */
		order_new(rsc, stop_rsc, NULL,
			  NULL, stonith_node, stonith_op,
			  pecs_must, ordering_constraints);
		);
	
	return TRUE;
}

crm_data_t *
action2xml(action_t *action, gboolean as_input)
{
	crm_data_t * action_xml = NULL;
	
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
		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET,
			safe_val4("__no_node__", action, node, details,uname));

		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET_UUID,
			safe_val4("__no_uuid__", action, node, details, id));
	}

	set_xml_property_copy(
		action_xml, "allow_fail",
		action->failure_is_fatal?XML_BOOLEAN_FALSE:XML_BOOLEAN_TRUE);

	set_xml_property_copy(
		action_xml, XML_ATTR_TIMEOUT, action->timeout);
	
	if(as_input) {
		return action_xml;
	}
	
	if(action->rsc != NULL) {
		g_hash_table_foreach(
			action->rsc->parameters, hash2nvpair, action->args);
	}
	
	crm_xml_debug(action->args, "copied in extra attributes");
	add_node_copy(action_xml, action->args);
	
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
	} else if(action->runnable == FALSE) {
		crm_trace("action %d was not runnable", action->id);
		return;
	} else if(action->dumped) {
		crm_trace("action %d was already dumped", action->id);
		return;

	} else if(action->discard) {
		crm_trace("action %d was discarded", action->id);
		return;
	}
	action->dumped = TRUE;
	
	syn    = create_xml_node(*graph, "synapse");
	set    = create_xml_node(syn, "action_set");
	in     = create_xml_node(syn, "inputs");

	syn_id = crm_itoa(num_synapse++);
	set_xml_property_copy(syn, XML_ATTR_ID, syn_id);
	crm_free(syn_id);
	
	xml_action = action2xml(action, FALSE);
	add_node_copy(set, xml_action);
	
	slist_iter(wrapper,action_wrapper_t,action->actions_before,lpc,
			
		   if(wrapper->action->optional == TRUE) {
			   continue;

		   } else if(wrapper->action->discard == TRUE) {
			   continue;
		   }
		   
		   switch(wrapper->strength) {
			   case pecs_must_not:
			   case pecs_ignore:
				   /* ignore both */
				   break;
			   case pecs_startstop:
				   if(wrapper->action->runnable == FALSE){
					   break;
				   }
				   /* keep going */
			   case pecs_must:
				   input = create_xml_node(in, "trigger");
				   
				   xml_action = action2xml(
					   wrapper->action, TRUE);
				   add_node_copy(input, xml_action);
				   break;
		   }
		   
		);
	free_xml(xml_action);
}
