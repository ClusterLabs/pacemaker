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

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <tengine.h>
#include <heartbeat.h>
#include <clplumbing/Gmain_timeout.h>
#include <lrm/lrm_api.h>
#include <clplumbing/lsb_exitcodes.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crm/common/cluster.h>

char *te_uuid = NULL;

void send_rsc_command(crm_action_t *action);

static void
te_start_action_timer(crm_graph_t *graph, crm_action_t *action) 
{
	crm_malloc0(action->timer, sizeof(crm_action_timer_t));
	action->timer->timeout   = action->timeout;
	action->timer->reason    = timeout_action;
	action->timer->action    = action;
	action->timer->source_id = Gmain_timeout_add(
		action->timer->timeout + graph->network_delay,
		action_timer_callback, (void*)action->timer);

	CRM_ASSERT(action->timer->source_id != 0);
}


static gboolean
te_pseudo_action(crm_graph_t *graph, crm_action_t *pseudo) 
{
	crm_info("Pseudo action %d fired and confirmed", pseudo->id);
	pseudo->confirmed = TRUE;
	update_graph(graph, pseudo);
	trigger_graph();
	return TRUE;
}

void
send_stonith_update(stonith_ops_t * op)
{
	enum cib_errors rc = cib_ok;
	const char *target = op->node_name;
	const char *uuid   = op->node_uuid;
	
	/* zero out the node-status & remove all LRM status info */
	xmlNode *node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	
	CRM_CHECK(op->node_name != NULL, return);
	CRM_CHECK(op->node_uuid != NULL, return);
	
	crm_xml_add(node_state, XML_ATTR_UUID,  uuid);
	crm_xml_add(node_state, XML_ATTR_UNAME, target);
	crm_xml_add(node_state, XML_CIB_ATTR_HASTATE,   DEADSTATUS);
	crm_xml_add(node_state, XML_CIB_ATTR_INCCM,     XML_BOOLEAN_NO);
	crm_xml_add(node_state, XML_CIB_ATTR_CRMDSTATE, OFFLINESTATUS);
	crm_xml_add(node_state, XML_CIB_ATTR_JOINSTATE, CRMD_JOINSTATE_DOWN);
	crm_xml_add(node_state, XML_CIB_ATTR_EXPSTATE,  CRMD_JOINSTATE_DOWN);
	crm_xml_add(node_state, XML_ATTR_ORIGIN,   __FUNCTION__);
	
	rc = fsa_cib_conn->cmds->update(
		fsa_cib_conn, XML_CIB_TAG_STATUS, node_state,
		cib_quorum_override|cib_scope_local|cib_can_create);	
	
	if(rc < cib_ok) {
		crm_err("CIB update failed: %s", cib_error2string(rc));
		abort_transition(
			INFINITY, tg_shutdown, "CIB update failed", node_state);
		
	} else {
		/* delay processing the trigger until the update completes */
	    add_cib_op_callback(fsa_cib_conn, rc, FALSE, crm_strdup(target), cib_fencing_updated);
	}

	erase_status_tag(op->node_name, XML_CIB_TAG_LRM);
	erase_status_tag(op->node_name, XML_TAG_TRANSIENT_NODEATTRS);
	
	free_xml(node_state);

#if 0
	/* Make sure the membership cache is accurate */ 
	crm_update_peer(0, 0, 0, -1, 0, uuid, target, NULL, CRM_NODE_LOST);
#endif
	
	return;
}

static gboolean
te_fence_node(crm_graph_t *graph, crm_action_t *action)
{
	const char *id = NULL;
	const char *uuid = NULL;
	const char *target = NULL;
	const char *type = NULL;
	stonith_ops_t * st_op = NULL;
	
	id = ID(action->xml);
	target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
	type = crm_meta_value(action->params, "stonith_action");
	
	CRM_CHECK(id != NULL,
		  crm_log_xml_warn(action->xml, "BadAction");
		  return FALSE);
	CRM_CHECK(uuid != NULL,
		  crm_log_xml_warn(action->xml, "BadAction");
		  return FALSE);
	CRM_CHECK(type != NULL,
		  crm_log_xml_warn(action->xml, "BadAction");
		  return FALSE);
	CRM_CHECK(target != NULL,
		  crm_log_xml_warn(action->xml, "BadAction");
		  return FALSE);

	te_log_action(LOG_INFO,
		      "Executing %s fencing operation (%s) on %s (timeout=%d)",
		      type, id, target, transition_graph->stonith_timeout);

	/* Passing NULL means block until we can connect... */
	te_connect_stonith(NULL);
	
	crm_malloc0(st_op, sizeof(stonith_ops_t));
	if(safe_str_eq(type, "poweroff")) {
		st_op->optype = POWEROFF;
	} else {
		st_op->optype = RESET;
	}
	
	st_op->timeout = transition_graph->stonith_timeout;
	st_op->node_name = crm_strdup(target);
	st_op->node_uuid = crm_strdup(uuid);
	
	st_op->private_data = generate_transition_key(
	    transition_graph->id, action->id, 0, te_uuid);
	
	CRM_ASSERT(stonithd_input_IPC_channel() != NULL);
		
	if (ST_OK != stonithd_node_fence( st_op )) {
		crm_err("Cannot fence %s: stonithd_node_fence() call failed ",
			target);
	}
	
	return TRUE;
}

static int get_target_rc(crm_action_t *action) 
{
	const char *target_rc_s = crm_meta_value(action->params, XML_ATTR_TE_TARGET_RC);

	if(target_rc_s != NULL) {
		return crm_parse_int(target_rc_s, "0");
	}
	return 0;
}

static gboolean
te_crm_command(crm_graph_t *graph, crm_action_t *action)
{
	char *counter = NULL;
	xmlNode *cmd = NULL;
	gboolean is_local = FALSE;

	const char *id = NULL;
	const char *task = NULL;
	const char *value = NULL;
	const char *on_node = NULL;

	gboolean rc = TRUE;
	gboolean no_wait = FALSE;

	id      = ID(action->xml);
	task    = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

	CRM_CHECK(on_node != NULL && strlen(on_node) != 0,
		  te_log_action(LOG_ERR, "Corrupted command (id=%s) %s: no node",
				crm_str(id), crm_str(task));
		  return FALSE);
	
	te_log_action(LOG_INFO, "Executing crm-event (%s): %s on %s%s%s",
		      crm_str(id), crm_str(task), on_node,
		      is_local?" (local)":"", no_wait?" - no waiting":"");

	if(safe_str_eq(on_node, fsa_our_uname)) {
	    is_local = TRUE;
	}
	
	value = crm_meta_value(action->params, XML_ATTR_TE_NOWAIT);
	if(crm_is_true(value)) {
	    no_wait = TRUE;
	}

	if(is_local && safe_str_eq(task, CRM_OP_SHUTDOWN)) {
	    /* defer until everything else completes */
	    te_log_action(LOG_INFO, "crm-event (%s) is a local shutdown", crm_str(id));
	    graph->completion_action = tg_shutdown;
	    graph->abort_reason = "local shutdown";
	    action->confirmed = TRUE;
	    update_graph(graph, action);
	    trigger_graph();
	    return TRUE;
	}
	
	cmd = create_request(task, NULL, on_node, CRM_SYSTEM_CRMD,
			     CRM_SYSTEM_TENGINE, NULL);
	
	counter = generate_transition_key(
	    transition_graph->id, action->id, get_target_rc(action), te_uuid);
	crm_xml_add(cmd, XML_ATTR_TRANSITION_KEY, counter);

	rc = send_cluster_message(on_node, crm_msg_crmd, cmd, TRUE);
	crm_free(counter);
	free_xml(cmd);
	
	value = crm_meta_value(action->params, XML_ATTR_TE_NOWAIT);
	if(rc == FALSE) {
		crm_err("Action %d failed: send", action->id);
		return FALSE;
		
	} else if(no_wait) {
		action->confirmed = TRUE;
		update_graph(graph, action);
		trigger_graph();
		
	} else {
	    if(action->timeout <= 0) {
		crm_err("Action %d: %s on %s had an invalid timeout (%dms).  Using %dms instead",
			action->id, task, on_node, action->timeout, graph->network_delay);
		action->timeout = graph->network_delay;
	    }
	    te_start_action_timer(graph, action);
	}

	return TRUE;
}

gboolean
cib_action_update(crm_action_t *action, int status, int op_rc)
{
	char *op_id  = NULL;
	char *code   = NULL;
	char *digest = NULL;
	xmlNode *tmp      = NULL;
	xmlNode *params   = NULL;
	xmlNode *state    = NULL;
	xmlNode *rsc      = NULL;
	xmlNode *xml_op   = NULL;
	xmlNode *action_rsc = NULL;

	enum cib_errors rc = cib_ok;

	const char *name   = NULL;
	const char *value  = NULL;
	const char *rsc_id = NULL;
	const char *task   = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	const char *task_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
	const char *target_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

	int call_options = cib_quorum_override|cib_scope_local;

	if(status == LRM_OP_PENDING) {
	    crm_debug("%s %d: Recording pending operation %s on %s",
		     crm_element_name(action->xml), action->id, task_uuid, target);
	} else {
	    crm_warn("%s %d: %s on %s timed out",
		     crm_element_name(action->xml), action->id, task_uuid, target);
	}
	
	action_rsc = find_xml_node(action->xml, XML_CIB_TAG_RESOURCE, TRUE);
	if(action_rsc == NULL) {
		return FALSE;
	}
	
	rsc_id = ID(action_rsc);
	CRM_CHECK(rsc_id != NULL,
		  crm_log_xml_err(action->xml, "Bad:action");
		  return FALSE);
	
/*
  update the CIB

<node_state id="hadev">
      <lrm>
        <lrm_resources>
          <lrm_resource id="rsc2" last_op="start" op_code="0" target="hadev"/>
*/

	state    = create_xml_node(NULL, XML_CIB_TAG_STATE);

	crm_xml_add(state, XML_ATTR_UUID,  target_uuid);
	crm_xml_add(state, XML_ATTR_UNAME, target);
	
	rsc = create_xml_node(state, XML_CIB_TAG_LRM);
	crm_xml_add(rsc, XML_ATTR_ID, target_uuid);

	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCES);
	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCE);
	crm_xml_add(rsc, XML_ATTR_ID, rsc_id);

	name = XML_ATTR_TYPE;
	value = crm_element_value(action_rsc, name);
	crm_xml_add(rsc, name, value);
	name = XML_AGENT_ATTR_CLASS;
	value = crm_element_value(action_rsc, name);
	crm_xml_add(rsc, name, value);
	name = XML_AGENT_ATTR_PROVIDER;
	value = crm_element_value(action_rsc, name);
	crm_xml_add(rsc, name, value);

	xml_op = create_xml_node(rsc, XML_LRM_TAG_RSC_OP);	
	crm_xml_add(xml_op, XML_ATTR_ID, task);
	
	op_id = generate_op_key(rsc_id, task, action->interval);
	crm_xml_add(xml_op, XML_ATTR_ID, op_id);
	crm_free(op_id);
	
	crm_xml_add_int(xml_op, XML_LRM_ATTR_CALLID, -1);
	crm_xml_add(xml_op, XML_LRM_ATTR_TASK, task);
	crm_xml_add(xml_op, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
	crm_xml_add_int(xml_op, XML_LRM_ATTR_OPSTATUS, status);
	crm_xml_add_int(xml_op, XML_LRM_ATTR_INTERVAL, action->interval);
	crm_xml_add_int(xml_op, XML_LRM_ATTR_RC, op_rc);
	crm_xml_add(xml_op, XML_ATTR_ORIGIN, __FUNCTION__);

	code = generate_transition_key(
	    transition_graph->id, action->id, get_target_rc(action), te_uuid);
	crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, code);
	crm_free(code);

	code = generate_transition_magic(
		crm_element_value(xml_op, XML_ATTR_TRANSITION_KEY), status, op_rc);
	crm_xml_add(xml_op,  XML_ATTR_TRANSITION_MAGIC, code);
	crm_free(code);

	tmp = find_xml_node(action->xml, "attributes", TRUE);
	params = create_xml_node(NULL, XML_TAG_PARAMS);
	copy_in_properties(params, tmp);
	
	filter_action_parameters(params, CRM_FEATURE_SET);
	digest = calculate_xml_digest(params, TRUE, FALSE);

	/* info for now as this area has been problematic to debug */
	crm_debug("Calculated digest %s for %s (%s)\n", 
		  digest, ID(xml_op),
		  crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
	crm_log_xml(LOG_DEBUG,  "digest:source", params);

	crm_xml_add(xml_op, XML_LRM_ATTR_OP_DIGEST, digest);
	crm_free(digest);
	free_xml(params);
	
	crm_debug_3("Updating CIB with \"%s\" (%s): %s %s on %s",
		  status<0?"new action":XML_ATTR_TIMEOUT,
		  crm_element_name(action->xml), crm_str(task), rsc_id, target);
	
	rc = fsa_cib_conn->cmds->update(
		fsa_cib_conn, XML_CIB_TAG_STATUS, state, call_options);

	crm_debug_2("Updating CIB with %s action %d: %s on %s (call_id=%d)",
		  op_status2text(status), action->id, task_uuid, target, rc);

	add_cib_op_callback(fsa_cib_conn, rc, FALSE, NULL, cib_action_updated);
	free_xml(state);

	action->sent_update = TRUE;
	
	if(rc < cib_ok) {
		return FALSE;
	}

	return TRUE;
}


static gboolean
te_rsc_command(crm_graph_t *graph, crm_action_t *action) 
{
	/* never overwrite stop actions in the CIB with
	 *   anything other than completed results
	 *
	 * Writing pending stops makes it look like the
	 *   resource is running again
	 */
	xmlNode *cmd = NULL;
	xmlNode *rsc_op  = NULL;

	gboolean rc = TRUE;
	gboolean no_wait = FALSE;
	gboolean is_local = FALSE;
	
	char *counter = NULL;
	const char *task    = NULL;
	const char *value   = NULL;
	const char *on_node = NULL;
	const char *task_uuid = NULL;

	CRM_ASSERT(action != NULL);
	CRM_ASSERT(action->xml != NULL);

	action->executed = FALSE;
	on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

	CRM_CHECK(on_node != NULL && strlen(on_node) != 0,
		  te_log_action(LOG_ERR, "Corrupted command(id=%s) %s: no node",
				ID(action->xml), crm_str(task));
		  return FALSE);

	rsc_op  = action->xml;
	task    = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
	task_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
	on_node = crm_element_value(rsc_op, XML_LRM_ATTR_TARGET);
	counter = generate_transition_key(
	    transition_graph->id, action->id, get_target_rc(action), te_uuid);
	crm_xml_add(rsc_op, XML_ATTR_TRANSITION_KEY, counter);

	if(safe_str_eq(on_node, fsa_our_uname)) {
	    is_local = TRUE;
	}

	value = crm_meta_value(action->params, XML_ATTR_TE_NOWAIT);
	if(crm_is_true(value)) {
	    no_wait = TRUE;
	}
	
	crm_info("Initiating action %d: %s %s on %s%s%s",
		 action->id, task, task_uuid, on_node,
		 is_local?" (local)":"", no_wait?" - no waiting":"");

	cmd = create_request(CRM_OP_INVOKE_LRM, rsc_op, on_node,
			     CRM_SYSTEM_LRMD, CRM_SYSTEM_TENGINE, NULL);
	
	if(is_local) {
	    /* shortcut local resource commands */
	    ha_msg_input_t data = {
		.msg = cmd,
		.xml = rsc_op,
	    };
	    
	    fsa_data_t msg = {
		.id = 0,
		.data = &data,
		.data_type = fsa_dt_ha_msg,
		.fsa_input = I_NULL,
		.fsa_cause = C_FSA_INTERNAL,
		.actions = A_LRM_INVOKE,
		.origin = __FUNCTION__,
	    };

	    do_lrm_invoke(A_LRM_INVOKE, C_FSA_INTERNAL, fsa_state, I_NULL, &msg);

	} else {
	    rc = send_cluster_message(on_node, crm_msg_lrmd, cmd, TRUE);
	}
	
	crm_free(counter);
	free_xml(cmd);
	
	action->executed = TRUE;
	if(rc == FALSE) {
		crm_err("Action %d failed: send", action->id);
		return FALSE;
		
	} else if(no_wait) {
		action->confirmed = TRUE;
		update_graph(transition_graph, action);
		trigger_graph();

	} else {
	    if(action->timeout <= 0) {
		crm_err("Action %d: %s %s on %s had an invalid timeout (%dms).  Using %dms instead",
			action->id, task, task_uuid, on_node, action->timeout, graph->network_delay);
		action->timeout = graph->network_delay;
	    }
	    te_start_action_timer(graph, action);
	}

	value = crm_meta_value(action->params, XML_OP_ATTR_PENDING);
	if(crm_is_true(value)) {
	    /* write a "pending" entry to the CIB, inhibit notification */
	    crm_info("Recording pending op %s in the CIB", task_uuid);
	    cib_action_update(action, LRM_OP_PENDING, EXECRA_STATUS_UNKNOWN);
	}
	
	return TRUE;
}

crm_graph_functions_t te_graph_fns = {
	te_pseudo_action,
	te_rsc_command,
	te_crm_command,
	te_fence_node
};

void
notify_crmd(crm_graph_t *graph)
{
	int log_level = LOG_DEBUG;
	const char *type = "unknown";
	enum crmd_fsa_input event = I_NULL;
	
	crm_debug("Processing transition completion in state %s", fsa_state2string(fsa_state));
	
	CRM_CHECK(graph->complete, graph->complete = TRUE);

	switch(graph->completion_action) {
		case tg_stop:
		    type = "stop";
		    /* fall through */
		case tg_done:
		    type = "done";
		    log_level = LOG_INFO;
		    if(fsa_state == S_TRANSITION_ENGINE) {
			event = I_TE_SUCCESS;
		    }
		    break;
		    
		case tg_restart:
		    type = "restart";
		    if(fsa_state == S_TRANSITION_ENGINE) {
			event = I_PE_CALC;

		    } else if(fsa_state == S_POLICY_ENGINE) {
			register_fsa_action(A_PE_INVOKE);
		    }
		    break;

		case tg_shutdown:
		    type = "shutdown";
		    if(is_set(fsa_input_register, R_SHUTDOWN)) {
			event = I_STOP;			
			
		    } else {
			event = I_TERMINATE;
		    }
	}

	te_log_action(log_level, "Transition %d status: %s - %s",
		      graph->id, type, crm_str(graph->abort_reason));

	graph->abort_reason = NULL;
	graph->completion_action = tg_done;
	clear_bit_inplace(fsa_input_register, R_IN_TRANSITION);

	if(event != I_NULL) {
	    register_fsa_input(C_FSA_INTERNAL, event, NULL);
	}
	
}
