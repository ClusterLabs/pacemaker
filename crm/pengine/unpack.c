/* $Id: unpack.c,v 1.89 2005/05/17 14:33:39 andrew Exp $ */
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

#include <heartbeat.h> /* for ONLINESTATUS */

#include <pengine.h>
#include <pe_utils.h>
#include <pe_rules.h>

gint sort_op_by_callid(gconstpointer a, gconstpointer b);

gboolean unpack_rsc_to_attr(crm_data_t * xml_obj,
			    GListPtr rsc_list,
			    GListPtr node_list,
			    GListPtr *placement_constraints);

gboolean unpack_rsc_to_node(crm_data_t * xml_obj,
			    GListPtr rsc_list,
			    GListPtr node_list,
			    GListPtr *placement_constraints);

gboolean unpack_rsc_order(
	crm_data_t * xml_obj, GListPtr rsc_list, GListPtr *ordering_constraints);

gboolean unpack_rsc_colocation(
	crm_data_t * xml_obj, GListPtr rsc_list, GListPtr *ordering_constraints);

gboolean unpack_rsc_location(
	crm_data_t * xml_obj, GListPtr rsc_list, GListPtr node_list,
	GListPtr *ordering_constraints);

gboolean unpack_lrm_rsc_state(
	node_t *node, crm_data_t * lrm_state,
	GListPtr rsc_list, GListPtr nodes,
	GListPtr *actions, GListPtr *placement_constraints);

gboolean add_node_attrs(crm_data_t * attrs, node_t *node);

gboolean unpack_rsc_op(resource_t *rsc, node_t *node, crm_data_t *xml_op,
		       gboolean *running, gboolean *failed, int *max_call_id,
		       GListPtr *placement_constraints);

gboolean determine_online_status(crm_data_t * node_state, node_t *this_node);

gboolean unpack_lrm_agents(node_t *node, crm_data_t * agent_list);

gboolean rsc_colocation_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh);

gboolean create_ordering(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh, GListPtr *ordering_constraints);

rsc_to_node_t *rsc2node_new(
	const char *id, resource_t *rsc,
	double weight, gboolean can_run, node_t *node,
	GListPtr *placement_constraints);

const char *param_value(crm_data_t * parent, const char *name);

gboolean
unpack_config(crm_data_t * config)
{
	const char *value = NULL;
	
	value = param_value(config, "transition_timeout");
	if(value != NULL) {
		long tmp = crm_get_msec(value);
		if(tmp > 0) {
			transition_timeout = value;
		} else {
			crm_err("Invalid value for %s: %s",
				"transition_timeout", value);
		}
	}
	crm_devel("%s set to: %s",
		 "transition_timeout", transition_timeout);

	value = param_value(config, "stonith_enabled");
	if(value != NULL) {
		crm_str_to_boolean(value, &stonith_enabled);
	}
	crm_info("STONITH of failed nodes is %s",
		 stonith_enabled?"enabled":"disabled");
	
	value = param_value(config, "symmetric_cluster");
	if(value != NULL) {
		crm_str_to_boolean(value, &symmetric_cluster);
	}
	if(symmetric_cluster) {
		crm_info("Cluster is symmetric"
			 " - resources can run anywhere by default");
	}

	value = param_value(config, "no_quorum_policy");
	if(safe_str_eq(value, "ignore")) {
		no_quorum_policy = no_quorum_ignore;
		
	} else if(safe_str_eq(value, "freeze")) {
		no_quorum_policy = no_quorum_freeze;

	} else {
		no_quorum_policy = no_quorum_stop;
	}
	
	switch (no_quorum_policy) {
		case no_quorum_freeze:
			crm_info("On loss of CCM Quorum: Freeze resources");
			break;
		case no_quorum_stop:
			crm_info("On loss of CCM Quorum: Stop ALL resources");
			break;
		case no_quorum_ignore:
			crm_warn("On loss of CCM Quorum: Ignore");
			break;
	}
	
	return TRUE;
}

const char *
param_value(crm_data_t * parent, const char *name) 
{
	crm_data_t * a_default = NULL;

	if(parent != NULL) {
		a_default = find_entity(
			parent, XML_CIB_TAG_NVPAIR, name, FALSE);
	}
	
	if(a_default == NULL) {
		crm_warn("Option %s not set", name);
		return NULL;
	}
	
	return crm_element_value(a_default, XML_NVPAIR_ATTR_VALUE);
}

gboolean
unpack_nodes(crm_data_t * xml_nodes, GListPtr *nodes)
{
	node_t *new_node   = NULL;
	crm_data_t * attrs = NULL;
	const char *id     = NULL;
	const char *uname  = NULL;
	const char *type   = NULL;

	crm_verbose("Begining unpack...");
	xml_child_iter(
		xml_nodes, xml_obj, XML_CIB_TAG_NODE,

		new_node = NULL;

		id     = crm_element_value(xml_obj, XML_ATTR_ID);
		uname  = crm_element_value(xml_obj, XML_ATTR_UNAME);
		type   = crm_element_value(xml_obj, XML_ATTR_TYPE);
		crm_verbose("Processing node %s/%s", uname, id);

		attrs = find_xml_node(xml_obj, "attributes", FALSE);
		
		if(id == NULL) {
			pe_err("Must specify id tag in <node>");
			continue;
		}
		if(type == NULL) {
			pe_err("Must specify type tag in <node>");
			continue;
		}
		crm_malloc0(new_node, sizeof(node_t));
		if(new_node == NULL) {
			return FALSE;
		}
		
		new_node->weight = 0;
		new_node->fixed  = FALSE;
		crm_malloc0(new_node->details,
			   sizeof(struct node_shared_s));

		if(new_node->details == NULL) {
			crm_free(new_node);
			return FALSE;
		}

		crm_verbose("Creaing node for entry %s/%s", uname, id);
		new_node->details->id		= id;
		new_node->details->uname	= uname;
		new_node->details->type		= node_ping;
		new_node->details->online	= FALSE;
		new_node->details->shutdown	= FALSE;
		new_node->details->running_rsc	= NULL;
		new_node->details->agents	= NULL;
		new_node->details->attrs        = g_hash_table_new(
			g_str_hash, g_str_equal);

		if(have_quorum == FALSE && no_quorum_policy == no_quorum_stop) {
			/* start shutting resources down */
			new_node->weight = -INFINITY;
		}
		
		
		if(stonith_enabled) {
			/* all nodes are unclean until we've seen their
			 * status entry
			 */
			new_node->details->unclean = TRUE;
		} else {
			/* blind faith... */
			new_node->details->unclean = FALSE; 
		}
		
		
		if(safe_str_eq(type, "member")) {
			new_node->details->type = node_member;
		}

		add_node_attrs(xml_obj, new_node);

		if(crm_is_true(g_hash_table_lookup(
				       new_node->details->attrs, "standby"))) {
			crm_info("Node %s is in standby-mode",
				 new_node->details->uname);
			new_node->weight = -INFINITY;
		}
		
		*nodes = g_list_append(*nodes, new_node);    
		crm_verbose("Done with node %s",
			    crm_element_value(xml_obj, XML_ATTR_UNAME));

		crm_devel_action(print_node("Added", new_node, FALSE));
		);
  
	*nodes = g_list_sort(*nodes, sort_node_weight);

	return TRUE;
}

gboolean 
unpack_resources(crm_data_t * xml_resources,
		 GListPtr *resources,
		 GListPtr *actions,
		 GListPtr *ordering_constraints,
		 GListPtr *placement_constraints,
		 GListPtr all_nodes)
{
	crm_verbose("Begining unpack...");
	xml_child_iter(
		xml_resources, xml_obj, NULL,

		resource_t *new_rsc = NULL;
		if(common_unpack(xml_obj, &new_rsc)) {
			*resources = g_list_append(*resources, new_rsc);
			crm_devel_action(
				print_resource("Added", new_rsc, FALSE));

			if(symmetric_cluster) {
				rsc_to_node_t *new_con = rsc2node_new(
					"symmetric_default", new_rsc, 0,
					TRUE, NULL, placement_constraints);
				new_con->node_list_rh = node_list_dup(
					all_nodes, FALSE);
			}

		} else {
			pe_err("Failed unpacking resource %s",
				crm_element_value(xml_obj, XML_ATTR_ID));
		}
		);
	
	*resources = g_list_sort(*resources, sort_rsc_priority);

	return TRUE;
}

gboolean 
unpack_constraints(crm_data_t * xml_constraints,
		   GListPtr nodes, GListPtr resources,
		   GListPtr *placement_constraints,
		   GListPtr *ordering_constraints)
{
	crm_verbose("Begining unpack...");
	xml_child_iter(
		xml_constraints, xml_obj, NULL,

		const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
		if(id == NULL) {
			pe_err("Constraint <%s...> must have an id",
				crm_element_name(xml_obj));
			continue;
		}

		crm_verbose("Processing constraint %s %s",
			    crm_element_name(xml_obj),id);

		if(safe_str_eq(XML_CONS_TAG_RSC_ORDER,
			       crm_element_name(xml_obj))) {
			unpack_rsc_order(
				xml_obj, resources, ordering_constraints);

		} else if(safe_str_eq(XML_CONS_TAG_RSC_DEPEND,
				      crm_element_name(xml_obj))) {
			unpack_rsc_colocation(
				xml_obj, resources, ordering_constraints);

		} else if(safe_str_eq(XML_CONS_TAG_RSC_LOCATION,
				      crm_element_name(xml_obj))) {
			unpack_rsc_location(
				xml_obj, resources,nodes,placement_constraints);

		} else {
			pe_err("Unsupported constraint type: %s",
				crm_element_name(xml_obj));
		}
		);

	return TRUE;
}

rsc_to_node_t *
rsc2node_new(const char *id, resource_t *rsc,
	     double weight, gboolean can, node_t *node,
	     GListPtr *placement_constraints)
{
	rsc_to_node_t *new_con = NULL;

	if(rsc == NULL || id == NULL) {
		pe_err("Invalid constraint %s for rsc=%p", crm_str(id), rsc);
		return NULL;
	}

	crm_malloc0(new_con, sizeof(rsc_to_node_t));
	if(new_con != NULL) {
		new_con->id           = id;
		new_con->rsc_lh       = rsc;
		new_con->node_list_rh = NULL;
		new_con->weight = weight;
		
		if(node != NULL) {
			new_con->node_list_rh = g_list_append(NULL, node);
		}
		
		*placement_constraints = g_list_append(
			*placement_constraints, new_con);
	}
	
	return new_con;
}




/* remove nodes that are down, stopping */
/* create +ve rsc_to_node constraints between resources and the nodes they are running on */
/* anything else? */
gboolean
unpack_status(crm_data_t * status,
	      GListPtr nodes, GListPtr rsc_list,
	      GListPtr *actions, GListPtr *placement_constraints)
{
	const char *uname     = NULL;

	crm_data_t * lrm_rsc    = NULL;
	crm_data_t * lrm_agents = NULL;
	crm_data_t * attrs      = NULL;
	node_t    *this_node  = NULL;
	
	crm_verbose("Begining unpack");
	xml_child_iter(
		status, node_state, XML_CIB_TAG_STATE,

/*		id         = crm_element_value(node_state, XML_ATTR_ID); */
		uname = crm_element_value(node_state,    XML_ATTR_UNAME);
		attrs = find_xml_node(node_state, XML_LRM_TAG_ATTRIBUTES,FALSE);

		lrm_rsc    = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		lrm_agents = find_xml_node(lrm_rsc, XML_LRM_TAG_AGENTS, FALSE);

		lrm_rsc = find_xml_node(lrm_rsc, XML_LRM_TAG_RESOURCES, FALSE);

		crm_verbose("Processing node %s", uname);
		this_node = pe_find_node(nodes, uname);

		if(uname == NULL) {
			/* error */
			continue;

		} else if(this_node == NULL) {
			pe_warn("Node %s in status section no longer exists",
				uname);
			continue;
		}

		/* Mark the node as provisionally clean
		 * - at least we have seen it in the current cluster's lifetime
		 */
		this_node->details->unclean = FALSE;
		
		crm_verbose("Adding runtime node attrs");
		add_node_attrs(node_state, this_node);

		crm_verbose("determining node state");
		determine_online_status(node_state, this_node);

		if(this_node->details->online || stonith_enabled) {
			/* offline nodes run no resources...
			 * unless stonith is enabled in which case we need to
			 *   make sure rsc start events happen after the stonith
			 */
			crm_verbose("Processing lrm resource entries");
			unpack_lrm_rsc_state(
				this_node, lrm_rsc, rsc_list, nodes,
				actions, placement_constraints);
		}
		
		);

	return TRUE;
	
}

gboolean
determine_online_status(crm_data_t * node_state, node_t *this_node)
{
	gboolean online = FALSE;
	const char *uname      = crm_element_value(node_state,XML_ATTR_UNAME);
	const char *exp_state  =
		crm_element_value(node_state, XML_CIB_ATTR_EXPSTATE);
	const char *join_state =
		crm_element_value(node_state, XML_CIB_ATTR_JOINSTATE);
	const char *crm_state  =
		crm_element_value(node_state, XML_CIB_ATTR_CRMDSTATE);
	const char *ccm_state  =
		crm_element_value(node_state, XML_CIB_ATTR_INCCM);
	const char *ha_state   =
		crm_element_value(node_state, XML_CIB_ATTR_HASTATE);
	const char *shutdown   =
		crm_element_value(node_state, XML_CIB_ATTR_SHUTDOWN);

	if(this_node == NULL) {
		return online;
	}

	if(shutdown != NULL) {
		this_node->details->shutdown = TRUE;
	}
	if(safe_str_eq(join_state, CRMD_JOINSTATE_MEMBER)) {
		this_node->details->expected_up = TRUE;
	}

	if(stonith_enabled == FALSE) {
		if(!crm_is_true(ccm_state) || safe_str_eq(ha_state,DEADSTATUS)){
			crm_debug("Node is down: ha_state=%s, ccm_state=%s",
				  crm_str(ha_state), crm_str(ccm_state));
			
		} else if(!crm_is_true(ccm_state)
			  || safe_str_eq(ha_state, DEADSTATUS)) {
			
		} else if(safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)
			  && safe_str_eq(crm_state, ONLINESTATUS)) {
			online = TRUE;
			
		} else if(this_node->details->expected_up == FALSE) {
			crm_debug("CRMd is down: ha_state=%s, ccm_state=%s",
				  crm_str(ha_state), crm_str(ccm_state));
			crm_debug("\tcrm_state=%s, join_state=%s, expected=%s",
				  crm_str(crm_state), crm_str(join_state),
				  crm_str(exp_state));
			
		} else {
			/* mark it unclean */
			this_node->details->unclean = TRUE;
			
			pe_err("Node %s is partially & un-expectedly down",
				uname);
			crm_debug("\tcrm_state=%s, join_state=%s, expected=%s",
				  crm_str(crm_state), crm_str(join_state),
				  crm_str(exp_state));
		}
	} else {
		if(crm_is_true(ccm_state)
		   && (ha_state == NULL || safe_str_eq(ha_state, ACTIVESTATUS))
		   && safe_str_eq(crm_state, ONLINESTATUS)
		   && safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)) {
			online = TRUE;

		} else if(this_node->details->expected_up == FALSE) {
			crm_debug("CRMd on %s is down: ha_state=%s, ccm_state=%s",
				  uname, crm_str(ha_state), crm_str(ccm_state));
			crm_debug("\tcrm_state=%s, join_state=%s, expected=%s",
				  crm_str(crm_state), crm_str(join_state),
				  crm_str(exp_state));
			
		} else {
			/* mark it unclean */
			this_node->details->unclean = TRUE;
			
			pe_err("Node %s is un-expectedly down", uname);
			crm_debug("\tha_state=%s, ccm_state=%s",
				  crm_str(ha_state), crm_str(ccm_state));
			crm_debug("\tcrm_state=%s, join_state=%s, expected=%s",
				  crm_str(crm_state), crm_str(join_state),
				  crm_str(exp_state));
		}
	}
	
	if(online) {
		crm_debug("Node %s is online", uname);
		this_node->details->online = TRUE;

	} else {
		/* remove node from contention */
		crm_debug("Node %s is down", uname);
		this_node->weight = -INFINITY;
		this_node->fixed = TRUE;
	}

	if(this_node->details->unclean) {
		pe_warn("Node %s is unclean", uname);
	}

	if(this_node->details->shutdown) {
		/* dont run resources here */
		this_node->weight = -INFINITY;
		this_node->fixed = TRUE;
		crm_debug("Node %s is due for shutdown", uname);
	}
	
	return online;
}


gboolean
unpack_lrm_agents(node_t *node, crm_data_t * agent_list)
{
	/* if the agent is not listed, remove the node from
	 * the resource's list of allowed_nodes
	 */
	lrm_agent_t *agent   = NULL;
	const char *version  = NULL;

	if(agent_list == NULL) {
		return FALSE;
	}

	xml_child_iter(
		agent_list, xml_agent, XML_LRM_TAG_AGENT,

		crm_malloc0(agent, sizeof(lrm_agent_t));
		if(agent == NULL) {
			continue;
		}
		
		agent->class   = crm_element_value(xml_agent, XML_AGENT_ATTR_CLASS);
		agent->type    = crm_element_value(xml_agent, XML_ATTR_TYPE);
		version        = crm_element_value(xml_agent, XML_ATTR_VERSION);
		agent->version = version?version:"0.0";

		crm_trace("Adding agent %s/%s %s to node %s",
			  agent->class,
			  agent->type,
			  agent->version,
			  node->details->uname);
			  
		node->details->agents = g_list_append(
			node->details->agents, agent);
		);
	
	return TRUE;
}


gboolean
unpack_lrm_rsc_state(node_t *node, crm_data_t * lrm_rsc_list,
		     GListPtr rsc_list, GListPtr nodes,
		     GListPtr *actions, GListPtr *placement_constraints)
{
	const char *rsc_id    = NULL;
	const char *node_id   = node->details->uname;
	const char *rsc_state = NULL;

	int max_call_id = -1;
	gboolean failed  = FALSE;
	gboolean running = FALSE;

	resource_t *rsc   = NULL;
	GListPtr op_list = NULL;
	GListPtr sorted_op_list = NULL;
	
	CRM_DEV_ASSERT(node != NULL);
	if(crm_assert_failed) {
		return FALSE;
	}
	
	xml_child_iter(
		lrm_rsc_list, rsc_entry, XML_LRM_TAG_RESOURCE,
		
		rsc_id    = crm_element_value(rsc_entry, XML_ATTR_ID);
		rsc_state = crm_element_value(rsc_entry, XML_LRM_ATTR_RSCSTATE);
		
		rsc    = pe_find_resource(rsc_list, rsc_id);

		crm_verbose("[%s] Processing %s on %s (%s)",
			    crm_element_name(rsc_entry),
			    rsc_id, node_id, rsc_state);

		if(rsc == NULL) {
			pe_err("Could not find a match for resource"
				" %s in %s's status section",
				rsc_id, node_id);
			crm_xml_debug(rsc_entry, "Invalid status entry");
			continue;
		}

		failed  = FALSE;
		running = FALSE;
		max_call_id = -1;

		op_list = NULL;
		sorted_op_list = NULL;
		
		xml_child_iter(
			rsc_entry, rsc_op, XML_LRM_TAG_RSC_OP,
			op_list = g_list_append(op_list, rsc_op);
			);

		if(op_list == NULL) {
			continue;
		}
		
		sorted_op_list = g_list_sort(op_list, sort_op_by_callid);

		slist_iter(
			rsc_op, crm_data_t, sorted_op_list, lpc,
			unpack_rsc_op(rsc, node, rsc_op,
				      &running, &failed, &max_call_id,
				      placement_constraints);
			);

		/* no need to free the contents */
		g_list_free(sorted_op_list);

		if(running) {
			native_add_running(rsc, node);
			if(failed) {
				action_t *stop = stop_action(rsc, node);
				stop->optional = FALSE;
				rsc->recover = TRUE;
			}
		}
		);
	
	return TRUE;
}

gint
sort_op_by_callid(gconstpointer a, gconstpointer b)
{
 	const char *a_task_id = cl_get_string(a, XML_LRM_ATTR_CALLID);
 	const char *b_task_id = cl_get_string(b, XML_LRM_ATTR_CALLID);
	/* if task id is NULL, then its a pending op
	 * put pending ops last
	 */

	int a_id = -1;
	int b_id = -1;
	
	if(a_task_id == NULL && b_task_id == NULL) { return 0; }

	/* the reverse from normal so that NULLs appear last */
	if(a_task_id == NULL) { return -1; }
	if(b_task_id == NULL) { return 1; }

	a_id = atoi(a_task_id);
	b_id = atoi(b_task_id);

	if(a_id < b_id) {
		return -1;
	} else if(a_id > b_id) {
		return 1;
	}
	return 0;
}

gboolean
unpack_rsc_op(resource_t *rsc, node_t *node, crm_data_t *xml_op,
	      gboolean *running, gboolean *failed, int *max_call_id,
	      GListPtr *placement_constraints) 
{
	const char *task        = NULL;
 	const char *task_id     = NULL;
	const char *task_status = NULL;

	int task_status_i = -2;
	int task_id_i = -1;

	CRM_DEV_ASSERT(rsc    != NULL); if(crm_assert_failed) { return FALSE; }
	CRM_DEV_ASSERT(node   != NULL); if(crm_assert_failed) { return FALSE; }
	CRM_DEV_ASSERT(xml_op != NULL); if(crm_assert_failed) { return FALSE; }
	
	task        = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
 	task_id     = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
	task_status = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);


	CRM_DEV_ASSERT(task != NULL);
        if(crm_assert_failed) { return FALSE; }

	CRM_DEV_ASSERT(task_status != NULL);
	if(crm_assert_failed) { return FALSE; }

	task_status_i = atoi(task_status);

	CRM_DEV_ASSERT(task_status_i <= LRM_OP_ERROR);
	if(crm_assert_failed) {return FALSE;}

	CRM_DEV_ASSERT(task_status_i >= LRM_OP_PENDING);
	if(crm_assert_failed) {return FALSE;}

	if(task_status_i != LRM_OP_PENDING) {

		task_id_i = crm_atoi(task_id, "-1");

		CRM_DEV_ASSERT(task_id != NULL);
		if(crm_assert_failed) { return FALSE; }

		CRM_DEV_ASSERT(task_id_i >= 0);
		if(crm_assert_failed) { return FALSE; }

		if(task_id_i == *max_call_id) {
			crm_debug("Already processed this call");
			return TRUE;
		}

		CRM_DEV_ASSERT(task_id_i > *max_call_id);
		if(crm_assert_failed) { return FALSE; }
	}

	if(*max_call_id < task_id_i) {
		*max_call_id = task_id_i;
	}
	
	if(node->details->unclean) {
		crm_debug("Node %s (where %s is running) is unclean."
			  " Further action depends on the value of %s",
			  node->details->uname, rsc->id, XML_RSC_ATTR_STOPFAIL);
	}

	switch(task_status_i) {
		case LRM_OP_PENDING:
			/*
			 * TODO: this may need some more thought
			 * Some cases:
			 * - PE reinvoked with pending action that will succeed
			 * - PE reinvoked with pending action that will fail
			 * - After DC election
			 * - After startup
			 *
			 * pending start - required start
			 * pending stop  - required stop
			 * pending <any> on unavailable node - stonith
			 *
			 * For now this should do
			 */

			if(safe_str_eq(task, CRMD_ACTION_STOP)) {
				/* re-issue the stop and return */
				stop_action(rsc, node);
				*running = TRUE;
				rsc->recover = TRUE;
				
			} else if(safe_str_eq(task, CRMD_ACTION_START)) {
				rsc->start_pending = TRUE;
				rsc->schedule_recurring = TRUE;
				*running = TRUE;
		
				/* make sure it is re-issued but,
				 * only if we have quorum
				 */
				if(have_quorum == TRUE
				   || no_quorum_policy == no_quorum_ignore){
					/* do not specify the node, we may want
					 * to start it elsewhere
					 */
					start_action(rsc, NULL);
				}
				
			} else if(*running == TRUE) {
				crm_devel("Re-issuing pending recurring task:"
					  " %s for %s on %s",
					  task, rsc->id, node->details->id);
				rsc->schedule_recurring = TRUE;
			}
			break;
		
		case LRM_OP_DONE:
			crm_verbose("%s/%s completed on %s",
				    rsc->id, task, node->details->uname);

			if(safe_str_eq(task, CRMD_ACTION_STOP)) {
				*failed  = FALSE;
				*running = FALSE;				
				rsc->schedule_recurring = FALSE;

			} else if(safe_str_eq(task, CRMD_ACTION_START)) {
				crm_verbose("%s active on %s",
					    rsc->id, node->details->uname);
				*running = TRUE;
				rsc->schedule_recurring = FALSE;

			} else if(*running) {
				/* assume its a recurring action */
				action_t *mon = NULL;
				const char *id = crm_element_value(
					xml_op, XML_ATTR_ID);

				CRM_DEV_ASSERT(id != NULL);
				if(crm_assert_failed) { break; }

				mon = custom_action(
					rsc, crm_strdup(id), task, node);

				if(mon != NULL) {
					mon->optional = TRUE;
				}
			}
			
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			if(task_status_i == LRM_OP_NOTSUPPORTED
			   || safe_str_eq(task, CRMD_ACTION_STOP)
			   || safe_str_eq(task, CRMD_ACTION_START) ) {
				pe_warn("Handling failed %s for %s on %s",
					 task, rsc->id, node->details->uname);
				rsc2node_new("dont_run__failed_stopstart",
					     rsc, -INFINITY, FALSE, node,
					     placement_constraints);
			}

			crm_debug("Processing last op (%s) for %s on %s",
				  task, rsc->id, node->details->uname);

			if(safe_str_neq(task, CRMD_ACTION_STOP)) {
				*failed = TRUE;				
				*running = TRUE;				

			} else if(rsc->stopfail_type == pesf_stonith) {
				/* treat it as if it is still running
				 * but also mark the node as unclean
				 */
				rsc->unclean = TRUE;
				node->details->unclean = TRUE;
				*running = TRUE;				

			} else if(rsc->stopfail_type == pesf_block) {
				/* let this depend on the stop action
				 * which will fail but make sure the
				 * transition continues...
				 */
				*running = TRUE;				
				rsc->unclean = TRUE;

			} else { /* pretend the stop completed */
				*running = FALSE;
				rsc->schedule_recurring = FALSE;
			}
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			pe_err("Dont know what to do for cancelled ops yet");
			break;
	}
	return TRUE;
}

gboolean
rsc_colocation_new(const char *id, enum con_strength strength,
		   resource_t *rsc_lh, resource_t *rsc_rh)
{
	rsc_colocation_t *new_con      = NULL;
 	rsc_colocation_t *inverted_con = NULL; 

	if(rsc_lh == NULL || rsc_rh == NULL){
		/* error */
		return FALSE;
	}

	crm_malloc0(new_con, sizeof(rsc_colocation_t));
	if(new_con == NULL) {
		return FALSE;
	}

	new_con->id       = id;
	new_con->rsc_lh   = rsc_lh;
	new_con->rsc_rh   = rsc_rh;
	new_con->strength = strength;
	
	inverted_con = invert_constraint(new_con);
	
	crm_devel("Adding constraint %s (%p) to %s",
		  new_con->id, new_con, rsc_lh->id);
	
	rsc_lh->rsc_cons = g_list_insert_sorted(
		rsc_lh->rsc_cons, new_con, sort_cons_strength);
	
	crm_devel("Adding constraint %s (%p) to %s",
		  inverted_con->id, inverted_con, rsc_rh->id);
	
	rsc_rh->rsc_cons = g_list_insert_sorted(
		rsc_rh->rsc_cons, inverted_con, sort_cons_strength);
	
	return TRUE;
}

gboolean
custom_action_order(
	resource_t *lh_rsc, char *lh_action_task, action_t *lh_action,
	resource_t *rh_rsc, char *rh_action_task, action_t *rh_action,
	enum con_strength strength, GListPtr *ordering_constraints)
{
	order_constraint_t *order = NULL;

	if((lh_action == NULL && lh_rsc == NULL)
	   || (rh_action == NULL && rh_rsc == NULL)
	   || ordering_constraints == NULL){
		pe_err("Invalid inputs lh_rsc=%p, lh_a=%p,"
			" rh_rsc=%p, rh_a=%p,  l=%p",
			lh_rsc, lh_action, rh_rsc, rh_action,
			ordering_constraints);
		return FALSE;
	}

	crm_malloc0(order, sizeof(order_constraint_t));

	if(order == NULL) {
		return FALSE;
	}
	
	order->id             = order_id++;
	order->strength       = strength;
	order->lh_rsc         = lh_rsc;
	order->rh_rsc         = rh_rsc;
	order->lh_action      = lh_action;
	order->rh_action      = rh_action;
	order->lh_action_task = lh_action_task;
	order->rh_action_task = rh_action_task;
	
	*ordering_constraints = g_list_append(
		*ordering_constraints, order);
	
	if(lh_rsc != NULL && rh_rsc != NULL) {
		crm_devel("Created ordering constraint %d (%s):"
			 " %s/%s before %s/%s",
			 order->id, strength2text(order->strength),
			 lh_rsc->id, lh_action_task,
			 rh_rsc->id, rh_action_task);
		
	} else if(lh_rsc != NULL) {
		crm_devel("Created ordering constraint %d (%s):"
			 " %s/%s before action %d (%s)",
			 order->id, strength2text(order->strength),
			 lh_rsc->id, lh_action_task,
			 rh_action->id, rh_action_task);
		
	} else if(rh_rsc != NULL) {
		crm_devel("Created ordering constraint %d (%s):"
			 " action %d (%s) before %s/%s",
			 order->id, strength2text(order->strength),
			 lh_action->id, lh_action_task,
			 rh_rsc->id, rh_action_task);
		
	} else {
		crm_devel("Created ordering constraint %d (%s):"
			 " action %d (%s) before action %d (%s)",
			 order->id, strength2text(order->strength),
			 lh_action->id, lh_action_task,
			 rh_action->id, rh_action_task);
	}
	
	return TRUE;
}

gboolean
unpack_rsc_colocation(crm_data_t * xml_obj,
		  GListPtr rsc_list,
		  GListPtr *ordering_constraints)
{
	enum con_strength strength_e = pecs_ignore;

	const char *id    = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *id_rh = crm_element_value(xml_obj, XML_CONS_ATTR_TO);
	const char *id_lh = crm_element_value(xml_obj, XML_CONS_ATTR_FROM);
	const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);

	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
	resource_t *rsc_rh = pe_find_resource(rsc_list, id_rh);
 
	if(rsc_lh == NULL) {
		pe_err("No resource (con=%s, rsc=%s)", id, id_lh);
		return FALSE;
	} else if(rsc_rh == NULL) {
		pe_err("No resource (con=%s, rsc=%s)", id, id_rh);
		return FALSE;
	}

	/* the docs indicate that only +/- INFINITY are allowed,
	 *   but no-one ever reads the docs so all positive values will
	 *   count as "must" and negative values as "must not"
	 */
	if(score == NULL || score[0] != '-') {
		strength_e = pecs_must;
	} else {
		strength_e = pecs_must_not;
	}
	return rsc_colocation_new(id, strength_e, rsc_lh, rsc_rh);
}

gboolean
unpack_rsc_order(
	crm_data_t * xml_obj, GListPtr rsc_list, GListPtr *ordering_constraints)
{
	gboolean type_is_after    = TRUE;
	gboolean action_is_start  = TRUE;
	gboolean symmetrical_bool = TRUE;
	
	const char *id     = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *type   = crm_element_value(xml_obj, XML_ATTR_TYPE);
	const char *id_rh  = crm_element_value(xml_obj, XML_CONS_ATTR_TO);
	const char *id_lh  = crm_element_value(xml_obj, XML_CONS_ATTR_FROM);
	const char *action = crm_element_value(xml_obj, XML_CONS_ATTR_ACTION);

	const char *symmetrical = crm_element_value(
		xml_obj, XML_CONS_ATTR_SYMMETRICAL);

	resource_t *rsc_lh   = pe_find_resource(rsc_list, id_lh);
	resource_t *rsc_rh   = pe_find_resource(rsc_list, id_rh);

	if(xml_obj == NULL) {
		pe_err("No constraint object to process.");
		return FALSE;

	} else if(id == NULL) {
		pe_err("%s constraint must have an id",
			crm_element_name(xml_obj));
		return FALSE;
		
	} else if(rsc_lh == NULL || rsc_rh == NULL) {
		pe_err("Constraint %s needs two sides lh: %p rh: %p"
			" (NULL indicates missing side)",
			id, rsc_lh, rsc_rh);
		return FALSE;
	
	}

	crm_str_to_boolean(symmetrical, &symmetrical_bool);
	if(safe_str_eq(type, "before")) {
		type_is_after = FALSE;
	}
	if(safe_str_eq(action, task2text(stop_rsc))) {
		action_is_start = FALSE;
	}

#if 1
	if((type_is_after && action_is_start)
	   || (type_is_after == FALSE && action_is_start == FALSE)){
		if(symmetrical_bool || action_is_start == FALSE) {
			order_stop_stop(rsc_lh, rsc_rh);
		}
		
		if(symmetrical_bool || action_is_start) {
			order_start_start(rsc_rh, rsc_lh);
		}

	} else {
		if(symmetrical_bool || action_is_start == FALSE) {
			order_stop_stop(rsc_rh, rsc_lh);
		}
		if(symmetrical_bool || action_is_start) {
			order_start_start(rsc_lh, rsc_rh);
		}
	}
	
#else	
	if(type_is_after) {
		order_stop_stop(rsc_lh, rsc_rh);
		order_start_start(rsc_rh, rsc_lh);
	} else {
		order_stop_stop(rsc_rh, rsc_lh);
		order_start_start(rsc_lh, rsc_rh);
	}
#endif
	return TRUE;
}

gboolean
add_node_attrs(crm_data_t *xml_obj, node_t *node)
{
 	g_hash_table_insert(node->details->attrs,
			    crm_strdup("#"XML_ATTR_UNAME),
			    crm_strdup(node->details->uname));
 	g_hash_table_insert(node->details->attrs,
			    crm_strdup("#"XML_ATTR_ID),
			    crm_strdup(node->details->id));
	if(safe_str_eq(node->details->id, dc_uuid)) {
		node->details->is_dc = TRUE;
		g_hash_table_insert(node->details->attrs,
				    crm_strdup("#"XML_ATTR_DC),
				    crm_strdup(XML_BOOLEAN_TRUE));
	} else {
		g_hash_table_insert(node->details->attrs,
				    crm_strdup("#"XML_ATTR_DC),
				    crm_strdup(XML_BOOLEAN_FALSE));
	}
	
	unpack_instance_attributes(xml_obj, node->details->attrs);

	return TRUE;
}



gboolean
unpack_rsc_location(
	crm_data_t * xml_obj,
	GListPtr rsc_list, GListPtr node_list, GListPtr *placement_constraints)
{
	gboolean were_rules = FALSE;
	const char *id_lh   = crm_element_value(xml_obj, "rsc");
	const char *id      = crm_element_value(xml_obj, XML_ATTR_ID);
	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);

	if(rsc_lh == NULL) {
		pe_warn("No resource (con=%s, rsc=%s)", id, id_lh);
		return FALSE;
	}
			
	xml_child_iter(
		xml_obj, rule, XML_TAG_RULE,

		gboolean first_expr = TRUE;
		gboolean can_run    = FALSE;
		gboolean do_and     = TRUE;
		gboolean rule_has_expressions;

		const char *rule_id = crm_element_value(rule, XML_ATTR_ID);
		const char *score   = crm_element_value(rule, XML_RULE_ATTR_SCORE);
		const char *boolean = crm_element_value(rule, XML_RULE_ATTR_BOOLEAN_OP);
		GListPtr match_L    = NULL;
		GListPtr old_list   = NULL;

		float score_f       = 0.0;
		rsc_to_node_t *new_con = NULL;

		were_rules = TRUE;

		if(score == NULL) {
			score_f = 0.0;
			
		} else if(safe_str_eq(score, MINUS_INFINITY_S)) {
			score_f = -INFINITY;

		} else if(safe_str_eq(score, INFINITY_S)) {
			score_f = INFINITY;

		} else {
			score_f = atof(score);
		}
		
		if(safe_str_eq(boolean, "or")) {
			do_and = FALSE;
		}

		if(score_f >= 0.0) {
			can_run = TRUE;
		}

		new_con = rsc2node_new(rule_id, rsc_lh, score_f,
				       can_run, NULL, placement_constraints);

		if(new_con == NULL) {
			continue;
		}
		
		crm_trace("processing rule: %s",
			  crm_element_value(rule, XML_ATTR_ID));

		rule_has_expressions = FALSE;
		xml_child_iter(
			rule, expr, XML_TAG_EXPRESSION,

			const char *attr  = crm_element_value(
				expr, XML_EXPR_ATTR_ATTRIBUTE);
			const char *op    = crm_element_value(
				expr, XML_EXPR_ATTR_OPERATION);
			const char *value = crm_element_value(
				expr, XML_EXPR_ATTR_VALUE);
			const char *type  = crm_element_value(
				expr, XML_EXPR_ATTR_TYPE);
			
			rule_has_expressions = TRUE;
			crm_trace("processing expression: %s",
				  crm_element_value(expr, XML_ATTR_ID));

			match_L = apply_node_expression(
				attr, op, value, type, node_list);
			
			if(first_expr) {
				new_con->node_list_rh =	node_list_dup(
					match_L, FALSE);
				first_expr = FALSE;
				continue;
			}

			old_list = new_con->node_list_rh;

			if(do_and) {
				crm_trace("do_and");
				
				new_con->node_list_rh = node_list_and(
					old_list, match_L, FALSE);
			} else {
				crm_trace("do_or");
				
				new_con->node_list_rh = node_list_or(
					old_list, match_L, FALSE);
			}
			pe_free_shallow_adv(match_L,  FALSE);
			pe_free_shallow_adv(old_list, TRUE);
			);

		if(rule_has_expressions == FALSE && symmetric_cluster == FALSE) {
			/* feels like a hack */
			crm_devel("Rule %s had no expressions,"
				  " adding all nodes", crm_element_value(rule, XML_ATTR_ID));

			new_con->node_list_rh = node_list_dup(node_list,FALSE);
		}
		
		if(new_con->node_list_rh == NULL) {
			crm_debug("No matching nodes for constraint/rule %s/%s",
				 id, crm_element_value(rule, XML_ATTR_ID));
		}
		
		crm_devel_action(print_rsc_to_node("Added", new_con, FALSE));
		);

	if(were_rules == FALSE) {
		crm_debug("no rules for constraint %s", id);
	}
	
	return TRUE;
}
