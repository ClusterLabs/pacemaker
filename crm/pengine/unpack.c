/* $Id: unpack.c,v 1.4 2004/06/09 14:34:48 andrew Exp $ */
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
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <lrm/lrm_api.h>

#include <glib.h>
#include <libxml/tree.h>

#include <heartbeat.h> // for ONLINESTATUS

#include <pengine.h>
#include <pe_utils.h>

int max_valid_nodes = 0;
int order_id = 1;
int action_id = 1;

GListPtr match_attrs(xmlNodePtr attr_exp, GListPtr node_list);

gboolean unpack_rsc_to_attr(xmlNodePtr xml_obj,
			    GListPtr rsc_list,
			    GListPtr node_list,
			    GListPtr *node_constraints);

gboolean unpack_rsc_to_node(xmlNodePtr xml_obj,
			    GListPtr rsc_list,
			    GListPtr node_list,
			    GListPtr *node_constraints);

gboolean unpack_rsc_to_rsc(
	xmlNodePtr xml_obj, GListPtr rsc_list, GListPtr *action_constraints);

gboolean unpack_lrm_rsc_state(node_t *node,
			      xmlNodePtr lrm_state,
			      GListPtr rsc_list,
			      GListPtr *node_constraints);

gboolean add_node_attrs(xmlNodePtr attrs, node_t *node);

gboolean unpack_healthy_resource(GListPtr *node_constraints,
	xmlNodePtr rsc_entry, resource_t *rsc_lh, node_t *node);

gboolean unpack_failed_resource(GListPtr *node_constraints,
	xmlNodePtr rsc_entry, resource_t *rsc_lh, node_t *node);

gboolean determine_online_status(xmlNodePtr node_state, node_t *this_node);

gboolean unpack_lrm_agents(node_t *node, xmlNodePtr agent_list);

gboolean is_node_unclean(xmlNodePtr node_state);

gboolean create_rsc_to_rsc(const char *id, enum con_strength strength,
			   resource_t *rsc_lh, resource_t *rsc_rh);

gboolean create_ordering(const char *id, enum con_strength strength,
			 resource_t *rsc_lh, resource_t *rsc_rh,
			 GListPtr *action_constraints);


gboolean
unpack_nodes(xmlNodePtr xml_nodes, GListPtr *nodes)
{
	crm_verbose("Begining unpack...");
	while(xml_nodes != NULL) {
		xmlNodePtr xml_obj = xml_nodes;
		xmlNodePtr attrs   = xml_obj->children;
		const char *id     = xmlGetProp(xml_obj, XML_ATTR_ID);
		const char *type   = xmlGetProp(xml_obj, XML_ATTR_TYPE);

		crm_verbose("Processing node %s", id);

		if(attrs != NULL) {
			attrs = attrs->children;
		}
		
		xml_nodes = xml_nodes->next;
	
		if(id == NULL) {
			crm_err("Must specify id tag in <node>");
			continue;
		}
		if(type == NULL) {
			crm_err("Must specify type tag in <node>");
			continue;
		}
		node_t *new_node  = crm_malloc(sizeof(node_t));
		new_node->weight  = 1.0;
		new_node->fixed   = FALSE;
		new_node->details = (struct node_shared_s*)
			crm_malloc(sizeof(struct node_shared_s));
//		new_node->details->id		= crm_strdup(id);
		new_node->details->id		= id;
		new_node->details->type		= node_ping;
		new_node->details->online	= FALSE;
		new_node->details->unclean	= FALSE;
		new_node->details->shutdown	= FALSE;
		new_node->details->running_rsc	= NULL;
		new_node->details->agents	= NULL;
		new_node->details->attrs	= g_hash_table_new(
			g_str_hash, g_str_equal);

		if(safe_str_eq(type, "member")) {
			new_node->details->type = node_member;
		}

		add_node_attrs(attrs, new_node);
		*nodes = g_list_append(*nodes, new_node);    

		crm_verbose("Done with node %s", xmlGetProp(xml_obj, "uname"));

		crm_debug_action(print_node("Added", new_node, FALSE));
	}
  
	*nodes = g_list_sort(*nodes, sort_node_weight);

	return TRUE;
}

gboolean 
unpack_resources(xmlNodePtr xml_resources,
		 GListPtr *resources,
		 GListPtr *actions,
		 GListPtr *action_cons,
		 GListPtr all_nodes)
{
	crm_verbose("Begining unpack...");
	while(xml_resources != NULL) {
		action_t *action_stop  = NULL;
		action_t *action_start = NULL;
		xmlNodePtr xml_obj     = xml_resources;
		const char *id         = xmlGetProp(xml_obj, XML_ATTR_ID);
		const char *priority   = xmlGetProp(
			xml_obj, XML_CIB_ATTR_PRIORITY);
		// todo: check for null
		float priority_f       = atof(priority);

		xml_resources = xml_resources->next;

		crm_verbose("Processing resource...");
		
		if(id == NULL) {
			crm_err("Must specify id tag in <resource>");
			continue;
		}
		resource_t *new_rsc = crm_malloc(sizeof(resource_t));
		new_rsc->id		= id;
		new_rsc->class		= xmlGetProp(xml_obj, "class");
		new_rsc->type		= xmlGetProp(xml_obj, "type");
		new_rsc->xml		= xml_obj;
		new_rsc->priority	= priority_f; 
		new_rsc->candidate_colors = NULL;
		new_rsc->color		= NULL; 
		new_rsc->runnable	= TRUE; 
		new_rsc->provisional	= TRUE; 
		new_rsc->allowed_nodes	= node_list_dup(all_nodes);    
		new_rsc->rsc_cons	= NULL; 
		new_rsc->node_cons	= NULL; 
		new_rsc->cur_node	= NULL;
		
		action_stop = action_new(action_id++, new_rsc, stop_rsc);

		action_start = action_new(action_id++, new_rsc, start_rsc);

		new_rsc->stop = action_stop;
		*actions = g_list_append(*actions, action_stop);

		new_rsc->start = action_start;
		*actions = g_list_append(*actions, action_start);

		order_constraint_t *order = (order_constraint_t*)
			crm_malloc(sizeof(order_constraint_t));
		order->id	 = order_id++;
		order->lh_action = action_stop;
		order->rh_action = action_start;
		order->strength  = startstop;

		*action_cons     = g_list_append(*action_cons, order);
		*resources       = g_list_append(*resources, new_rsc);
	
		crm_debug_action(print_resource("Added", new_rsc, FALSE));
	}
	*resources = g_list_sort(*resources, sort_rsc_priority);

	return TRUE;
}



gboolean 
unpack_constraints(xmlNodePtr xml_constraints,
		   GListPtr nodes, GListPtr resources,
		   GListPtr *node_constraints,
		   GListPtr *action_constraints)
{
	crm_verbose("Begining unpack...");
	while(xml_constraints != NULL) {
		const char *id = xmlGetProp(xml_constraints, XML_ATTR_ID);
		xmlNodePtr xml_obj = xml_constraints;
		xml_constraints = xml_constraints->next;
		if(id == NULL) {
			crm_err("Constraint must have an id");
			continue;
		}

		crm_verbose("Processing constraint %s %s", xml_obj->name,id);
		if(safe_str_eq("rsc_to_rsc", xml_obj->name)) {
			unpack_rsc_to_rsc(xml_obj, resources,
					  action_constraints);

		} else if(safe_str_eq("rsc_to_node", xml_obj->name)) {
			unpack_rsc_to_node(xml_obj, resources, nodes,
					   node_constraints);
			
		} else if(safe_str_eq("rsc_to_attr", xml_obj->name)) {
			unpack_rsc_to_attr(xml_obj, resources, nodes,
					   node_constraints);
			
		} else {
			crm_err("Unsupported constraint type: %s",
			       xml_obj->name);
		}
	}

	return TRUE;
}


gboolean
unpack_rsc_to_node(xmlNodePtr xml_obj, GListPtr rsc_list, GListPtr node_list,
		   GListPtr *node_constraints)	
{
	xmlNodePtr node_ref    = xml_obj->children;
	rsc_to_node_t *new_con = NULL;
	const char *id_lh      = xmlGetProp(xml_obj, "from");
	const char *id         = xmlGetProp(xml_obj, XML_ATTR_ID);
	const char *mod        = xmlGetProp(xml_obj, "modifier");
	const char *weight     = xmlGetProp(xml_obj, "weight");
	float weight_f         = atof(weight);
	resource_t *rsc_lh     = pe_find_resource(rsc_list, id_lh);

	if(rsc_lh == NULL) {
		crm_err("No resource (con=%s, rsc=%s)", id, id_lh);
	}

	new_con = (rsc_to_node_t*)crm_malloc(sizeof(rsc_to_node_t));
	new_con->id           = id;
	new_con->rsc_lh       = rsc_lh;
	new_con->weight       = weight_f;
	new_con->node_list_rh = NULL;
	
	if(safe_str_eq(mod, "set")){
		new_con->modifier = set;
		
	} else if(safe_str_eq(mod, "inc")){
		new_con->modifier = inc;
		
	} else if(safe_str_eq(mod, "dec")){
		new_con->modifier = dec;
		
	} else {
		// error
	}
/*
  <rsc_to_node>
  <node_ref id= type= name=/>
  <node_ref id= type= name=/>
  <node_ref id= type= name=/>
*/		
//			

	while(node_ref != NULL) {
		const char *xml_name = node_ref->name;

		const char *id_rh = xmlGetProp(node_ref, XML_NVPAIR_ATTR_NAME);
		node_t *node_rh   = pe_find_node(node_list, id_rh);

		node_ref = node_ref->next;
		
		if(node_rh == NULL) {
			crm_err("node %s (from %s) not found",id_rh, xml_name);
			continue;
		}
		
		new_con->node_list_rh =
			g_list_append(new_con->node_list_rh, node_rh);

		
		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
	}
	*node_constraints = g_list_append(*node_constraints, new_con);

	return TRUE;
}


gboolean
unpack_rsc_to_attr(xmlNodePtr xml_obj, GListPtr rsc_list, GListPtr node_list,
		   GListPtr *node_constraints)
{
/*
<rsc_to_attr id="cons4" from="rsc2" weight="20.0" modifier="inc">
<attr_expression id="attr_exp_1"/>
  <node_match id="node_match_1" type="has_attr" target="cpu"/>
  <node_match id="node_match_2" type="attr_value" target="kernel" value="2.6"/>
</attr_expression>
<attr_expression id="attr_exp_2"/>
  <node_match id="node_match_3" type="has_attr" target="hdd"/>
  <node_match id="node_match_4" type="attr_value" target="kernel" value="2.4"/>
</attr_expression>

   Translation:
       give any node a +ve weight of 20.0 to run rsc2 if:
          attr "cpu" is set _and_ "kernel"="2.6", _or_
	  attr "hdd" is set _and_ "kernel"="2.4"

   Further translation:
       2 constraints that give any node a +ve weight of 20.0 to run rsc2
       cons1: attr "cpu" is set and "kernel"="2.6"
       cons2: attr "hdd" is set and "kernel"="2.4"
       
*/
	
	xmlNodePtr attr_exp = xml_obj->children;
	const char *id_lh   = xmlGetProp(xml_obj, "from");
	const char *mod     = xmlGetProp(xml_obj, "modifier");
	const char *weight  = xmlGetProp(xml_obj, "weight");
	const char *id      = xmlGetProp(attr_exp, XML_ATTR_ID);
	float weight_f      = atof(weight);
	enum con_modifier a_modifier = modifier_none;
	
	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
	if(rsc_lh == NULL) {
		crm_err("No resource (con=%s, rsc=%s)",
		       id, id_lh);
		return FALSE;
	}
			
	if(safe_str_eq(mod, "set")){
		a_modifier = set;
	} else if(safe_str_eq(mod, "inc")){
		a_modifier = inc;
	} else if(safe_str_eq(mod, "dec")){
		a_modifier = dec;
	} else {
		// error
	}		

	if(attr_exp == NULL) {
		crm_err("no attrs for constraint %s", id);
	}
	
	while(attr_exp != NULL) {
		rsc_to_node_t *new_con = crm_malloc(sizeof(rsc_to_node_t));
		new_con->id            = xmlGetProp(attr_exp, XML_ATTR_ID);
		new_con->rsc_lh        = rsc_lh;
		new_con->weight        = weight_f;
		new_con->modifier      = a_modifier;
		new_con->node_list_rh  = match_attrs(attr_exp, node_list);
		
		if(new_con->node_list_rh == NULL) {
			crm_warn("No matching nodes for constraint  %s (%s)",
				 xmlGetProp(attr_exp, XML_NVPAIR_ATTR_NAME),
				 attr_exp->name);
		}
		crm_debug_action(print_rsc_to_node("Added", new_con, FALSE));
		*node_constraints = g_list_append(*node_constraints, new_con);

		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
		attr_exp = attr_exp->next;
	}
	return TRUE;
}


// remove nodes that are down, stopping
// create +ve rsc_to_node constraints between resources and the nodes they are running on
// anything else?
gboolean
unpack_status(xmlNodePtr status,
	      GListPtr nodes, GListPtr rsc_list, GListPtr *node_constraints)
{
	const char *id        = NULL;

	xmlNodePtr node_state = NULL;
	xmlNodePtr lrm_rsc    = NULL;
	xmlNodePtr lrm_agents = NULL;
	xmlNodePtr attrs      = NULL;
	node_t    *this_node  = NULL;
	
	crm_verbose("Begining unpack");
	while(status != NULL) {
		node_state = status;
		status     = status->next;
		id         = xmlGetProp(node_state, XML_ATTR_ID);
		attrs      = find_xml_node(node_state, "attributes");
		lrm_rsc    = find_xml_node(node_state, XML_CIB_TAG_LRM);
		lrm_agents = find_xml_node(lrm_rsc,    "lrm_agents");
		lrm_rsc    = find_xml_node(lrm_rsc,    XML_LRM_TAG_RESOURCES);
		lrm_rsc    = find_xml_node(lrm_rsc,    "lrm_resource");

		crm_verbose("Processing node %s", id);
		this_node = pe_find_node(nodes, id);

		if(id == NULL) {
			// error
			continue;

		} else if(this_node == NULL) {
			crm_err("Node %s in status section no longer exists",
				id);
			continue;
		}
		
		crm_verbose("Adding runtime node attrs");
		add_node_attrs(attrs, this_node);

		crm_verbose("determining node state");
		determine_online_status(node_state, this_node);

		crm_verbose("Processing lrm resource entries");
		unpack_lrm_rsc_state(
			this_node, lrm_rsc, rsc_list, node_constraints);

		crm_verbose("Processing lrm agents");
		unpack_lrm_agents(this_node, lrm_agents);

	}

	return TRUE;
	
}

gboolean
determine_online_status(xmlNodePtr node_state, node_t *this_node)
{
	const char *id	       = xmlGetProp(node_state,XML_ATTR_ID);
	const char *state      = xmlGetProp(node_state,XML_NODE_ATTR_STATE);
	const char *exp_state  = xmlGetProp(node_state,XML_CIB_ATTR_EXPSTATE);
	const char *join_state = xmlGetProp(node_state,XML_CIB_ATTR_JOINSTATE);
	const char *crm_state  = xmlGetProp(node_state,XML_CIB_ATTR_CRMDSTATE);
	const char *ccm_state  = xmlGetProp(node_state,XML_CIB_ATTR_INCCM);
	const char *shutdown   = xmlGetProp(node_state,XML_CIB_ATTR_SHUTDOWN);
	const char *unclean    = xmlGetProp(node_state,XML_CIB_ATTR_STONITH);
	
	if(safe_str_eq(join_state, CRMD_JOINSTATE_MEMBER)
	   && safe_str_eq(ccm_state, XML_BOOLEAN_YES)
	   && safe_str_eq(crm_state, ONLINESTATUS)
	   && shutdown == NULL) {
		this_node->details->online = TRUE;

	} else {
		crm_verbose("remove");
		// remove node from contention
		this_node->weight = -1;
		this_node->fixed = TRUE;

		crm_verbose("state %s, expected %s, shutdown %s",
			    state, exp_state, shutdown);

		if(unclean != NULL) {
			this_node->details->unclean = TRUE;
				
		} else if(shutdown != NULL) {
			this_node->details->shutdown = TRUE;

		} else if(is_node_unclean(node_state)) {
			/* report and or take remedial action */
			this_node->details->unclean = TRUE;
		}

		if(this_node->details->unclean) {
			crm_verbose("Node %s is due for STONITH", id);
		}

		if(this_node->details->shutdown) {
			crm_verbose("Node %s is due for shutdown", id);
		}
	}
	return TRUE;
}

gboolean
is_node_unclean(xmlNodePtr node_state)
{
	const char *state      = xmlGetProp(node_state,XML_NODE_ATTR_STATE);
	const char *exp_state  = xmlGetProp(node_state,XML_CIB_ATTR_EXPSTATE);
	const char *join_state = xmlGetProp(node_state,XML_CIB_ATTR_JOINSTATE);
	const char *crm_state  = xmlGetProp(node_state,XML_CIB_ATTR_CRMDSTATE);
	const char *ccm_state  = xmlGetProp(node_state,XML_CIB_ATTR_INCCM);

	if(safe_str_eq(exp_state, CRMD_STATE_INACTIVE)) {
		return FALSE;

	/* do an actual calculation once STONITH is available */

	// } else if(...) {
	}

	// for now...
	if(0) {
		state = NULL;
		join_state = NULL;
		crm_state = NULL;
		ccm_state = NULL;
	}
	
	return FALSE;
}

gboolean
unpack_lrm_agents(node_t *node, xmlNodePtr agent_list)
{
	/* if the agent is not listed, remove the node from
	 * the resource's list of allowed_nodes
	 */
	lrm_agent_t *agent = NULL;
	xmlNodePtr xml_agent = agent_list->children;
	while(xml_agent != NULL){
		agent = (lrm_agent_t*)crm_malloc(sizeof(lrm_agent_t));
		agent->class = xmlGetProp(xml_agent, "class");
		agent->type  = xmlGetProp(xml_agent, "type");

		node->details->agents = g_list_append(
			node->details->agents, agent);
		
		xml_agent = xml_agent->next;
	}
	
	return TRUE;
}


gboolean
unpack_lrm_rsc_state(node_t *node, xmlNodePtr lrm_rsc,
		     GListPtr rsc_list, GListPtr *node_constraints)
{
	xmlNodePtr rsc_entry  = NULL;
	const char *rsc_id    = NULL;
	const char *node_id   = NULL;
	const char *rsc_state = NULL;
	const char *rsc_code  = NULL;
	resource_t *rsc_lh    = NULL;
	
	while(lrm_rsc != NULL) {
		rsc_entry = lrm_rsc;
		lrm_rsc   = lrm_rsc->next;
		
		rsc_id    = xmlGetProp(rsc_entry, XML_ATTR_ID);
		node_id   = xmlGetProp(rsc_entry, XML_LRM_ATTR_TARGET);
		rsc_state = xmlGetProp(rsc_entry, XML_LRM_ATTR_OPSTATE);
		rsc_code  = xmlGetProp(rsc_entry, "op_code");
		
		rsc_lh    = pe_find_resource(rsc_list, rsc_id);

		crm_verbose("[%s] Processing %s on %s (%s)",
			    rsc_entry->name, rsc_id, node_id, rsc_state);

		if(rsc_lh == NULL) {
			crm_err("Could not find a match for resource"
				" %s in %s's status section",
				rsc_id, node_id);
			continue;
		}
		
		op_status_t  rsc_code_i = atoi(rsc_code);
		switch(rsc_code_i) {
			case LRM_OP_DONE:
				unpack_healthy_resource(node_constraints,
							rsc_entry,rsc_lh,node);
				break;
			case LRM_OP_ERROR:
			case LRM_OP_TIMEOUT:
			case LRM_OP_NOTSUPPORTED:
				unpack_failed_resource(node_constraints,
						       rsc_entry,rsc_lh,node);
				break;
			case LRM_OP_CANCELLED:
				// do nothing??
				crm_warn("Dont know what to do for cancelled ops yet");
				break;
		}
	}
	return TRUE;
}

gboolean
unpack_failed_resource(GListPtr *node_constraints,
		       xmlNodePtr rsc_entry, resource_t *rsc_lh, node_t *node)
{
	const char *last_op  = xmlGetProp(rsc_entry, "last_op");

	crm_debug("Unpacking failed action %s on %s", last_op, rsc_lh->id);
	
	if(safe_str_eq(last_op, "start")) {
		/* not running */
		/* do not run the resource here again */
		rsc_to_node_t *new_cons = crm_malloc(sizeof(rsc_to_node_t));
		new_cons->id		= "dont_run_generate"; // genereate
		new_cons->weight	= -1.0;
		new_cons->modifier	= set;
		new_cons->rsc_lh	= rsc_lh;
		new_cons->node_list_rh	= g_list_append(NULL, node);
		
		*node_constraints = g_list_append(*node_constraints, new_cons);

	} else if(safe_str_eq(last_op, "stop")) {
		/* must assume still running */
		rsc_lh->cur_node = node;
		node->details->running_rsc = g_list_append(
			node->details->running_rsc, rsc_lh);

		/* remedial action:
		 *   shutdown (so all other resources are stopped gracefully)
		 *   and then STONITH node
		 */
		if(node->details->online) {
			node->details->shutdown = TRUE;
		}
		node->details->unclean  = TRUE;
		
//	} else if(safe_str_eq(last_op, "???")) {

	} else {
		/* unknown action... */
		/* remedial action: ???
		 *   shutdown (so all other resources are stopped gracefully)
		 *   and then STONITH node
		 */
	}

	return TRUE;
}

gboolean
unpack_healthy_resource(GListPtr *node_constraints,
			xmlNodePtr rsc_entry, resource_t *rsc_lh, node_t *node)
{
	const char *last_op  = xmlGetProp(rsc_entry, "last_op");

	rsc_to_node_t *new_cons = crm_malloc(sizeof(rsc_to_node_t));

	crm_debug("Unpacking healthy action %s on %s", last_op, rsc_lh->id);

	new_cons->id		= "healthy_generate"; // genereate one
	new_cons->weight	= 1.0;
	new_cons->modifier	= inc;
	new_cons->rsc_lh	= rsc_lh;
	new_cons->node_list_rh	= g_list_append(NULL, node);
	
	*node_constraints = g_list_append(*node_constraints, new_cons);
	
	if(safe_str_neq(last_op, "stop")) {

		if(rsc_lh->cur_node != NULL) {
			crm_err("Resource %s running on multiple nodes %s, %s",
				rsc_lh->id,
				rsc_lh->cur_node->details->id,
				node->details->id);
			// TODO: some recovery action!!
			// like force a stop on the second node?
			
		} else {
			/* we prefer to stay running here */
			new_cons->weight = 100.0;
			
			/* create the link between this node and the rsc */
			crm_verbose("Setting cur_node = %s for rsc = %s",
				    node->details->id, rsc_lh->id);
			
			rsc_lh->cur_node = node;
			node->details->running_rsc = g_list_append(
				node->details->running_rsc, rsc_lh);
		}
		
	} else {
		/* we prefer to start where we once ran successfully */
		new_cons->weight = 20.0;
	}

	crm_debug_action(print_rsc_to_node("Added", new_cons, FALSE));
	
	return TRUE;
}

gboolean
create_rsc_to_rsc(const char *id, enum con_strength strength,
		  resource_t *rsc_lh, resource_t *rsc_rh)
{
	if(rsc_lh == NULL || rsc_rh == NULL){
		// error
		return FALSE;
	}

	rsc_to_rsc_t *new_con      = crm_malloc(sizeof(rsc_to_rsc_t));
	rsc_to_rsc_t *inverted_con = NULL;

	new_con->id       = id;
	new_con->rsc_lh   = rsc_lh;
	new_con->rsc_rh   = rsc_rh;
	new_con->strength = strength;
	
	inverted_con = invert_constraint(new_con);

	rsc_lh->rsc_cons = g_list_insert_sorted(
		rsc_lh->rsc_cons, new_con, sort_cons_strength);
	rsc_rh->rsc_cons = g_list_insert_sorted(
		rsc_rh->rsc_cons, inverted_con, sort_cons_strength);

	return TRUE;
}

gboolean
create_ordering(const char *id, enum con_strength strength,
		resource_t *rsc_lh, resource_t *rsc_rh,
		GListPtr *action_constraints)
{
	if(rsc_lh == NULL || rsc_rh == NULL){
		// error
		return FALSE;
	}
	
	action_t *lh_stop  = rsc_lh->stop;
	action_t *lh_start = rsc_lh->start;
	action_t *rh_stop  = rsc_rh->stop;
	action_t *rh_start = rsc_rh->start;
	
	order_constraint_t *order = (order_constraint_t*)
		crm_malloc(sizeof(order_constraint_t));
	
	order->id        = order_id++;
	order->lh_action = lh_stop;
	order->rh_action = rh_stop;
	order->strength  = strength;
	
	*action_constraints = g_list_append(*action_constraints, order);
	
	order = (order_constraint_t*)
		crm_malloc(sizeof(order_constraint_t));
	
	order->id        = order_id++;
	order->lh_action = rh_start;
	order->rh_action = lh_start;
	order->strength  = strength;
	
	*action_constraints = g_list_append(*action_constraints, order);

	return TRUE;
}

gboolean
unpack_rsc_to_rsc(xmlNodePtr xml_obj,
		  GListPtr rsc_list,
		  GListPtr *action_constraints)
{
	enum con_strength strength_e = ignore;

	const char *id_lh    = xmlGetProp(xml_obj, "from");
	const char *id       = xmlGetProp(xml_obj, XML_ATTR_ID);
	const char *id_rh    = xmlGetProp(xml_obj, "to");
	const char *strength = xmlGetProp(xml_obj, "strength");
	const char *type     = xmlGetProp(xml_obj, XML_ATTR_TYPE);

	resource_t *rsc_lh   = pe_find_resource(rsc_list, id_lh);
	resource_t *rsc_rh   = pe_find_resource(rsc_list, id_rh);
 
	if(rsc_lh == NULL) {
		crm_err("No resource (con=%s, rsc=%s)", id, id_lh);
		return FALSE;
	}
	
	if(safe_str_eq(strength, XML_STRENGTH_VAL_MUST)) {
		strength_e = must;
		
	} else if(safe_str_eq(strength, XML_STRENGTH_VAL_SHOULD)) {
		strength_e = should;
		
	} else if(safe_str_eq(strength, XML_STRENGTH_VAL_SHOULDNOT)) {
		strength_e = should_not;
		
	} else if(safe_str_eq(strength, XML_STRENGTH_VAL_MUSTNOT)) {
		strength_e = must_not;

	} else {
		crm_err("Unknown value for %s: %s", "strength", strength);
		return FALSE;
	}

	if(safe_str_eq(type, "ordering")) {
		// make an action_cons instead
		return create_ordering(
			id, strength_e, rsc_lh, rsc_rh, action_constraints);
	}

	return create_rsc_to_rsc(id, strength_e, rsc_lh, rsc_rh);
}

GListPtr
match_attrs(xmlNodePtr attr_exp, GListPtr node_list)
{
	int lpc = 0;
	GListPtr result = NULL;
	slist_iter(
		node, node_t, node_list, lpc,
		xmlNodePtr node_match = attr_exp->children;
		gboolean accept = TRUE;
		
		while(accept && node_match != NULL) {
			const char *type = xmlGetProp(
				node_match, XML_ATTR_TYPE);
			const char *value= xmlGetProp(
				node_match, XML_NVPAIR_ATTR_VALUE);
			const char *name = xmlGetProp(node_match, "target");

			node_match = node_match->next;
			
			if(name == NULL || type == NULL) {
				crm_err("Attribute %s (%s) was invalid",
					  name, type);
				continue;
			}
			
			const char *h_val = (const char*)
				g_hash_table_lookup(node->details->attrs,name);
			
			if(h_val != NULL && safe_str_eq(type, "has_attr")){
				accept = TRUE;
				
			} else if(h_val==NULL && safe_str_eq(type,"not_attr")){
				accept = TRUE;
				
			} else if(h_val != NULL
				  && safe_str_eq(type, "attr_value")
				  && safe_str_eq(h_val, value)) {
				accept = TRUE;
				
			} else {
				accept = FALSE;
			}
		}
		
		if(accept) {
			result = g_list_append(result, node);
		}		   
		);
	
	return result;
}

gboolean
add_node_attrs(xmlNodePtr attrs, node_t *node)
{
	const char *name  = NULL;
	const char *value = NULL;
	
	while(attrs != NULL){
		name  = xmlGetProp(attrs, XML_NVPAIR_ATTR_NAME);
		value = xmlGetProp(attrs, XML_NVPAIR_ATTR_VALUE);
			
		if(name != NULL
		   && value != NULL
		   && safe_val(NULL, node, details) != NULL) {
			crm_verbose("Adding %s => %s", name, value);

			/* this is frustrating... no way to pass in const
			 *  keys or values yet docs say:
			 *   Note: If keys and/or values are dynamically
			 *   allocated, you should free them first.
			 */
			g_hash_table_insert(node->details->attrs,
					    crm_strdup(name),
					    crm_strdup(value));
		}
		attrs = attrs->next;
	}	
	return TRUE;
}
