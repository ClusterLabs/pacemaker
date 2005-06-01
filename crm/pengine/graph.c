/* $Id: graph.c,v 1.47 2005/06/01 22:30:21 andrew Exp $ */
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
	crm_debug_2("Updating %d actions", g_list_length(actions));
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

	crm_debug_3("Processing action %d", action->id);
	slist_iter(
		other, action_wrapper_t, action->actions_before, lpc,
		crm_debug_3("\tChecking action %d: %s/%s",
			    other->action->id, ordering_type2text(other->type),
			    other->action->optional?"optional":"required");
		if(action->optional == FALSE
		   && other->type == pe_ordering_manditory
		   && other->action->optional) {
			change = TRUE;
			other->action->optional = FALSE;
			crm_debug_2("Marking action %d manditory because of %d",
				    other->action->id, action->id);
			update_action(other->action);
		} 
		);

	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,

		if(action->pseudo == FALSE
		   && action->runnable == FALSE
		   && action->optional == FALSE) {
			if(other->action->runnable == FALSE) {
				crm_debug_2("Action %d already un-runnable",
					  other->action->id);
				continue;
			} else {
				change = TRUE;
				other->action->runnable =FALSE;
				crm_debug_2("Marking action %d un-runnable"
					  " because of %d",
					  other->action->id, action->id);
				update_action(other->action);
			}
		}
		

		if(action->optional == FALSE && other->action->optional) {
			crm_debug_3("\t(restart)Checking action %d",
				    other->action->id);

	switch(action->rsc->restart_type) {
		case pe_restart_ignore:
			break;
		case pe_restart_restart:
			change = TRUE;
			other->action->optional = FALSE;
			crm_debug_2("(Restart) Marking action %d manditory because of %d",
				  other->action->id, action->id);
			update_action(other->action);
	}
		}
		
		);

	return change;
}


gboolean
shutdown_constraints(
	node_t *node, action_t *shutdown_op, pe_working_set_t *data_set)
{
	/* add the stop to the before lists so it counts as a pre-req
	 * for the shutdown
	 */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		custom_action_order(
			rsc, stop_key(rsc), NULL,
			NULL, crm_strdup(CRM_OP_SHUTDOWN), shutdown_op,
			pe_ordering_manditory, data_set);

		);	

	return TRUE;	
}

gboolean
stonith_constraints(node_t *node,
		    action_t *stonith_op, action_t *shutdown_op,
		    pe_working_set_t *data_set)
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
		crm_debug_4("Adding shutdown (%d) as an input to stonith (%d)",
			  shutdown_op->id, stonith_op->id);
		
		custom_action_order(
			NULL, crm_strdup(CRM_OP_SHUTDOWN), shutdown_op,
			NULL, crm_strdup(CRM_OP_FENCE), stonith_op,
			pe_ordering_manditory, data_set);
		
	}
	
	/* add the stonith OP to the before lists so it counts as a pre-req */
	slist_iter(
		rsc, resource_t, node->details->running_rsc, lpc,

		if(stonith_op != NULL) {
			char *key = stop_key(rsc);
			stop_actions = find_actions(rsc->actions, key, node);
			crm_free(key);
			
			slist_iter(
				action, action_t, stop_actions, lpc2,
				if(node->details->online == FALSE
				   || rsc->unclean) {
					/* the stop would never complete and is
					 * now implied by the stonith operation
					 */
					action->pseudo = TRUE;
					action->runnable = TRUE;
					custom_action_order(
						NULL, crm_strdup(CRM_OP_FENCE),stonith_op,
						rsc, stop_key(rsc), NULL,
						pe_ordering_manditory, data_set);
				} else {
					/* stop healthy resources before the
					 * stonith op
					 */
					custom_action_order(
						rsc, stop_key(rsc), NULL,
						NULL,crm_strdup(CRM_OP_FENCE),stonith_op,
						pe_ordering_manditory, data_set);
				}
				);

			crm_debug_4("Adding stonith (%d) as an input to stop",
				  stonith_op->id);
			
		} else if((rsc->unclean || node->details->unclean)
			  && rsc->stopfail_type == pesf_block) {
			/* depend on the stop action which will fail */
			pe_err("SHARED RESOURCE %s WILL REMAIN BLOCKED"
				 " ON NODE %s UNTIL %s",
				rsc->id, node->details->uname,
				data_set->stonith_enabled?"QUORUM RETURNS":"CLEANED UP MANUALLY");
			continue;
			
		} else if((rsc->unclean || node->details->unclean)
			  && rsc->stopfail_type == pesf_ignore) {
			/* nothing to do here */
			pe_err("SHARED RESOURCE %s IS NOT PROTECTED",
				 rsc->id);
			continue;
		}
		);
	
	return TRUE;
}

crm_data_t *
action2xml(action_t *action, gboolean as_input)
{
	gboolean needs_node_info = TRUE;
	crm_data_t * action_xml = NULL;
	crm_data_t * args_xml = NULL;
	char *action_id_s = NULL;
	
	if(action == NULL) {
		return NULL;
	}

	crm_debug_4("Dumping action %d as XML", action->id);
	if(safe_str_eq(action->task, CRM_OP_FENCE)) {
		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);
		needs_node_info = FALSE;
		
	} else if(safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

	} else if(action->pseudo) {
		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_PSEUDO_EVENT);
		needs_node_info = FALSE;

	} else {
		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
	}

	action_id_s = crm_itoa(action->id);
	set_xml_property_copy(action_xml, XML_ATTR_ID, action_id_s);
	crm_free(action_id_s);
	
	if(action->rsc != NULL) {
		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_RSCID, action->rsc->id);
	}
	set_xml_property_copy(action_xml, XML_LRM_ATTR_TASK, action->task);

	if(needs_node_info && action->node != NULL) {
		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET,
			action->node->details->uname);

		set_xml_property_copy(
			action_xml, XML_LRM_ATTR_TARGET_UUID,
			action->node->details->id);
		
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

	if(action->rsc != NULL && action->pseudo == FALSE) {
		crm_data_t *rsc_xml = create_xml_node(
			action_xml, crm_element_name(action->rsc->xml));

		copy_in_properties(rsc_xml, action->rsc->xml);

		args_xml = create_xml_node(action_xml, XML_TAG_ATTRS);
		g_hash_table_foreach(action->extra, hash2nvpair, args_xml);
		
		g_hash_table_foreach(
			action->rsc->parameters, hash2nvpair, args_xml);

	} else {
		args_xml = create_xml_node(action_xml, XML_TAG_ATTRS);
		g_hash_table_foreach(action->extra, hash2nvpair, args_xml);
	}
	
	
	crm_log_xml_debug_2(action_xml, "dumped action");
	
	return action_xml;
}

void
graph_element_from_action(action_t *action, pe_working_set_t *data_set)
{
	char *syn_id = NULL;
	crm_data_t * syn = NULL;
	crm_data_t * set = NULL;
	crm_data_t * in  = NULL;
	crm_data_t * input = NULL;
	crm_data_t * xml_action = NULL;
	if(action == NULL) {
		pe_err("Cannot dump NULL action");
		return;

	} else if(action->optional) {
		crm_debug_5("action %d was optional", action->id);
		return;

	} else if(action->pseudo == FALSE && action->runnable == FALSE) {
		crm_debug_5("action %d was not runnable", action->id);
		return;

	} else if(action->dumped) {
		crm_debug_5("action %d was already dumped", action->id);
		return;

	} else if(action->pseudo
		  || safe_str_eq(action->task,  CRM_OP_FENCE)
		  || safe_str_eq(action->task,  CRM_OP_SHUTDOWN)) {
		/* skip the next check */
		
	} else {
		if(action->node == NULL) {
			pe_err("action %d was not allocated", action->id);
			log_action(LOG_DEBUG, "Unallocated action", action, FALSE);
			return;
			
		} else if(action->node->details->online == FALSE) {
			pe_err("action %d was scheduled for offline node", action->id);
			log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
			return;
		}
	}
	
	action->dumped = TRUE;
	
	syn = create_xml_node(data_set->graph, "synapse");
	set = create_xml_node(syn, "action_set");
	in  = create_xml_node(syn, "inputs");

	syn_id = crm_itoa(data_set->num_synapse);
	set_xml_property_copy(syn, XML_ATTR_ID, syn_id);
	crm_free(syn_id);
	data_set->num_synapse++;
	
	xml_action = action2xml(action, FALSE);
	add_node_copy(set, xml_action);
	free_xml(xml_action);
	
	slist_iter(wrapper,action_wrapper_t,action->actions_before,lpc,
			
		   if(wrapper->action->optional == TRUE) {
			   crm_debug_2("Input %d optional", wrapper->action->id);
			   continue;
		   }
		   
		   input = create_xml_node(in, "trigger");
		   
		   xml_action = action2xml(wrapper->action, TRUE);
		   add_node_copy(input, xml_action);
		   free_xml(xml_action);
		   
		);
}
