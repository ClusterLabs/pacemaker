/* $Id: graph.c,v 1.15 2004/09/17 15:53:12 andrew Exp $ */
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

gboolean update_action(action_t *action);

gboolean
update_action_states(GListPtr actions)
{
	int lpc = 0;
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
	int lpc = 0;

	if(action->optional && action->runnable) {
		return FALSE;
	}
	
	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,

		if(action->runnable == FALSE) {
			if(other->action->runnable == FALSE) {
				continue;
			} else if (other->strength == pecs_must) {
				change = TRUE;
				other->action->runnable =FALSE;
				crm_debug_action(
					print_action("Marking unrunnable",
						     other->action, FALSE));
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
			crm_debug_action(
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
	node_t *node, action_t *shutdown_op, GListPtr *action_constraints)
{
	int lpc = 0;
	action_wrapper_t *wrapper = NULL;

	/* add the shutdown OP to the before lists so it counts as a pre-req */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		crm_malloc(wrapper, sizeof(action_wrapper_t));
		if(wrapper != NULL) {
			wrapper->action = rsc->start;
			wrapper->strength = pecs_must;
			shutdown_op->actions_before = g_list_append(
				shutdown_op->actions_before, wrapper);
		}
/* 		order_new(rsc->stop, shutdown_op, pecs_must, action_constraints); */
		);	

	return TRUE;	
}

gboolean
stonith_constraints(node_t *node,
		    action_t *stonith_op, action_t *shutdown_op,
		    GListPtr *action_constraints)
{
	int lpc = 0;
	action_wrapper_t *wrapper = NULL;

	if(shutdown_op != NULL) {
		/* shutdown before stonith */
		/* add the shutdown OP to the before lists so it counts as a pre-req */
		crm_debug("Adding shutdown (%d) as an input to stonith (%d)",
			  shutdown_op->id, stonith_op->id);
		
		crm_malloc(wrapper, sizeof(action_wrapper_t));
		if(wrapper != NULL) {
			wrapper->action = shutdown_op;
			wrapper->strength = pecs_must;
			stonith_op->actions_before = g_list_append(
				stonith_op->actions_before, wrapper);
		}
	}
	
	/* add the stonith OP to the before lists so it counts as a pre-req */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		/* make use of timeouts in the TE for cases such
		 *   as this.
		 * ie. the node may be cactus and unable to receive the
		 *  stop let alone reply with failed.
		 */
		rsc->stop->failure_is_fatal = FALSE;
		
		crm_debug("Adding stonith (%d) as an input to start (%d)",
			  stonith_op->id, rsc->start->id);

		/* stonith before start */
		crm_malloc(wrapper, sizeof(action_wrapper_t));
		if(wrapper != NULL) {
			wrapper->action = stonith_op;
			wrapper->strength = pecs_must;
			rsc->start->actions_before = g_list_append(
				rsc->start->actions_before, wrapper);
		}

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
		case shutdown_crm:
			action_xml = create_xml_node(NULL, "crm_event");

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			break;
		default:
			action_xml = create_xml_node(NULL, "rsc_op");
			add_node_copy(action_xml,
				      safe_val3(NULL, action, rsc, xml));

			set_xml_property_copy(
				action_xml, XML_ATTR_ID, crm_itoa(action->id));

			set_xml_property_copy(
				action_xml, XML_LRM_ATTR_RSCID,
				safe_val3("__no_rsc__", action, rsc, id));
			
			break;
	}

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_TARGET,
		safe_val4("__no_node__", action, node, details, uname));

	set_xml_property_copy(
		action_xml, XML_LRM_ATTR_TARGET_UUID,
		safe_val4("__no_node_uuid__", action, node, details, id));

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

	add_node_copy(action_xml, action->args);


/* 	slist_iter( */
/* 		wrapper, action_wrapper_t, action->actions_before, lpc, */

/* 		xmlNodePtr prereq = create_xml_node(action_xml, "trigger"); */
/* 		set_xml_property_copy(prereq, "action_id", wrapper->action->id); */
/* 		); */

	
	return action_xml;
}
