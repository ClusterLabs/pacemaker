/* $Id: graph.c,v 1.4 2004/06/09 14:34:48 andrew Exp $ */
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
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>




GListPtr
create_action_set(action_t *action)
{
	int lpc;
	GListPtr tmp = NULL;
	GListPtr result = NULL;
	gboolean preceeding_complete = FALSE;

	if(action->processed) {
		return NULL;
	}

	crm_debug_action(print_action("Create action set for", action, FALSE));
	
	// process actions_before
	if(action->seen_count == 0) {
		crm_verbose("Processing \"before\" for action %d", action->id);
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,

			tmp = create_action_set(other->action);
			result = g_list_concat(result, tmp);
			preceeding_complete = TRUE;
			);
		
	} else {
		crm_verbose("Already seen action %d", action->id);
		crm_verbose("Processing \"before\" for action %d", action->id);
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			
			if(other->action->seen_count > action->seen_count
			   && other->strength == must) {
				tmp = create_action_set(other->action);
				result = g_list_concat(result, tmp);
			}	
			);
	}
	
	// add ourselves
	if(action->runnable) {
		if(action->processed == FALSE) {
			crm_verbose("Adding self %d", action->id);
			result = g_list_append(result, action);
		} else {
			crm_verbose("Already added self %d", action->id);
		}
		
	} else {
		crm_verbose("Skipping ourselves, we're not runnable");
	}
	action->processed = TRUE;
	
	if(preceeding_complete == FALSE) {
		
		/* add any "before" actions that arent already processed */
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			
			tmp = create_action_set(other->action);
			result = g_list_concat(result, tmp);
			);
	}

	action->seen_count = action->seen_count + 1;
	
	/* process actions_after
	 *
	 * do this regardless of whether we are runnable.  Any direct or
	 *  indirect hard/XML_STRENGTH_VAL_MUST dependancies on us will have
	 *  been picked up earlier on in stage 7
	 */
	crm_verbose("Processing \"after\" for action %d", action->id);
	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,
		
		tmp = create_action_set(other->action);
		result = g_list_concat(result, tmp);
		);
	
	return result;
}


gboolean
update_runnable(GListPtr actions)
{

	int lpc = 0, lpc2 = 0;
	gboolean change = TRUE;

	while(change) {
		change = FALSE;
		slist_iter(
			action, action_t, actions, lpc,

			if(action->runnable) {
				continue;
			} else if(action->optional) {
				continue;
			}
			
			slist_iter(
				other, action_wrapper_t, action->actions_after, lpc2,
				if(other->action->runnable == FALSE) {
					continue;
				}
				
				change = TRUE;
				crm_debug_action(
					print_action("Marking unrunnable",
						     other->action, FALSE));
				other->action->runnable = FALSE;
				);
			);
	}
	return TRUE;
}


gboolean
shutdown_constraints(
	node_t *node, action_t *shutdown_op, GListPtr *action_constraints)
{
	int lpc = 0;
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,
		
		order_constraint_t *order = (order_constraint_t*)
		crm_malloc(sizeof(order_constraint_t));
		
		/* stop resources before shutdown */
		order->id        = order_id++;
		order->lh_action = rsc->stop;
		order->rh_action = shutdown_op;
		order->strength  = must;

		*action_constraints = g_list_append(*action_constraints,order);
		
		crm_debug_action(
			print_action("LH (Shutdown)",order->lh_action, FALSE));
		crm_debug_action(
			print_action("RH (Shutdown)",order->rh_action, FALSE));
		);	

	return TRUE;	
}

gboolean
stonith_constraints(node_t *node,
		    action_t *stonith_op, action_t *shutdown_op,
		    GListPtr *action_constraints)
{
	int lpc = 0;
	order_constraint_t *order = NULL;

	if(shutdown_op != NULL) {
		order = (order_constraint_t*)
			crm_malloc(sizeof(order_constraint_t));

		/* shutdown before stonith if both are requested */
		order->lh_action = shutdown_op;
		order->rh_action = stonith_op;
		order->id        = order_id++;
		order->strength  = must;
		
		*action_constraints = g_list_append(
			*action_constraints, order);
	}
	
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,
#if 0
		/*
		 * Mark the stop as irrelevant
		 *
		 * Possibly one day failed actions wont terminate
		 *   the transition, but not yet
		 */
		rsc->stop->discard = TRUE;
#else			
		/* need to add timeouts in the TE for actions such as this.
		 * ie. the node may be cactus and unable to receive the
		 *  stop let alone reply with failed.
		 */
		rsc->stop->failure_is_fatal = FALSE;
#endif

#if 0
		obsoleted by shutdown before stonith
		
		/* try stopping the resource before stonithing the node
		 *
		 * if the stop succeeds, the transitioner can then
		 * decided if  stonith is needed
		 */
		order = (order_constraint_t*)
		crm_malloc(sizeof(order_constraint_t));

		order->lh_action = rsc->stop;
		order->rh_action = stonith_op;
		order->id        = order_id++;
		order->strength  = must;
		
		*action_constraints = g_list_append(*action_constraints,order);
#endif
		/* stonith before start */
		order = (order_constraint_t*)
		crm_malloc(sizeof(order_constraint_t));
		
		order->id        = order_id++;
		order->lh_action = stonith_op;
		order->rh_action = rsc->start;
		order->strength  = must;
		
		*action_constraints = g_list_append(*action_constraints,order);

		);
	
	return TRUE;
}

xmlNodePtr
action2xml(action_t *action)
{
	xmlNodePtr action_xml = NULL;
	
	if(action == NULL) {
		return NULL;
	}
	
	switch(action->task) {
		case stonith_op:
			action_xml = create_xml_node(NULL, "pseduo_event");

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			break;
		case shutdown_crm:
			action_xml = create_xml_node(NULL, "crm_event");

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			break;
		default:
			action_xml = create_xml_node(NULL, "rsc_op");
			add_node_copy(action_xml, action->rsc->xml);

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			set_xml_property_copy(
				action_xml, "rsc_id",
				safe_val3(NULL, action, rsc, id));
			
			break;
	}

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_TARGET,
		safe_val4(NULL, action, node, details, id));

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_TASK, task2text(action->task));

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_RUNNABLE,
		action->runnable?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_OPTIONAL,
		action->optional?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_DISCARD,
		action->discard?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(
		action_xml, "allow_fail",
		action->failure_is_fatal?XML_BOOLEAN_FALSE:XML_BOOLEAN_TRUE);

	return action_xml;
}
