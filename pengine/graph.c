/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>

#include <allocate.h>
#include <lib/pengine/utils.h>
#include <utils.h>

gboolean update_action(action_t *action);
gboolean rsc_update_action(action_t *first, action_t *then, enum pe_ordering type);

static action_t *rsc_expand_action(action_t *action) 
{
    action_t *result = action;
    if(action->rsc && action->rsc->variant >= pe_group) {
	/* Expand 'first' */
	char *uuid = NULL;
	gboolean notify = FALSE;
	if(action->rsc->parent == NULL) {
	    /* Only outter-most resources have notification actions */
	    notify = is_set(action->rsc->flags, pe_rsc_notify);
	}

	uuid = convert_non_atomic_uuid(action->uuid, action->rsc, notify, FALSE);
	crm_trace("Converted %s to %s %d", action->uuid, uuid, is_set(action->rsc->flags, pe_rsc_notify));
	result = find_first_action(action->rsc->actions, uuid, NULL, NULL);
	CRM_CHECK(result != NULL, crm_err("Couldn't expand %s", action->uuid); result = action);
	crm_free(uuid);
    }
    return result;
}

static enum pe_graph_flags graph_update_action(action_t *first, action_t *then, node_t *node, enum pe_action_flags flags, enum pe_ordering type) 
{
    enum pe_graph_flags changed = pe_graph_none;
    gboolean processed = FALSE;

    /* TODO: Do as many of these in parallel as possible */
    
    if(type & pe_order_implies_then) {
	crm_trace("implies right: %s then %s", first->uuid, then->uuid);
	processed = TRUE;
	if(then->rsc) {
	    changed |= then->rsc->cmds->update_actions(
		first, then, node, flags & pe_action_optional, pe_action_optional, pe_order_implies_then);

	} else if(is_set(flags, pe_action_optional) == FALSE) {
	    if(update_action_flags(then, pe_action_optional|pe_action_clear)) {
		changed |= pe_graph_updated_then;
	    }
	}
    }

    if(type & pe_order_restart) {
	enum pe_action_flags restart = (pe_action_optional|pe_action_runnable);
	crm_trace("restart: %s then %s", first->uuid, then->uuid);
	processed = TRUE;
	changed |= then->rsc->cmds->update_actions(
	    first, then, node, flags & restart, restart, pe_order_restart);
    }
    
    if(type & pe_order_implies_first) {
	crm_trace("implies left: %s then %s", first->uuid, then->uuid);
	processed = TRUE;
	if(first->rsc) {
	    changed |= first->rsc->cmds->update_actions(
		first, then, node, flags & pe_action_optional, pe_action_optional, pe_order_implies_first);

	} else if(is_set(flags, pe_action_optional) == FALSE) {
	    if(update_action_flags(first, pe_action_runnable|pe_action_clear)) {
		changed |= pe_graph_updated_first;
	    }
	}
    }

    if(type & pe_order_runnable_left) {
	crm_trace("runnable: %s then %s", first->uuid, then->uuid);
	processed = TRUE;
	if(then->rsc) {
	    changed |= then->rsc->cmds->update_actions(
		first, then, node, flags & pe_action_runnable, pe_action_runnable, pe_order_runnable_left);

	} else if(is_set(flags, pe_action_runnable) == FALSE) {
	    if(update_action_flags(then, pe_action_runnable|pe_action_clear)) {
		changed |= pe_graph_updated_then;
	    }
	}
    }

    if(type & pe_order_optional) {
	crm_trace("optional: %s then %s", first->uuid, then->uuid);
	processed = TRUE;
	if(then->rsc) {
	    changed |= then->rsc->cmds->update_actions(
		first, then, node, flags & pe_action_runnable, pe_action_runnable, pe_order_optional);
	}
    }
    
    if((type & pe_order_implies_then_printed) && (flags & pe_action_optional) == 0) {
	processed = TRUE;
	crm_trace("%s implies %s printed", first->uuid, then->uuid);
	update_action_flags(then, pe_action_print_always); /* dont care about changed */
    }

    if((type & pe_order_implies_first_printed) && (flags & pe_action_optional) == 0) {
	processed = TRUE;
	crm_trace("%s implies %s printed", then->uuid, first->uuid);
	update_action_flags(first, pe_action_print_always); /* dont care about changed */
    }
    
    if(processed == FALSE) {
	crm_trace("Constraint 0x%.6x not applicable", type);
    }

    return changed;
}

gboolean
update_action(action_t *then)
{
    GListPtr lpc = NULL;
    enum pe_graph_flags changed = pe_graph_none;

    crm_trace("Processing %s (%s %s %s)",
	      then->uuid,
	      is_set(then->flags, pe_action_optional)?"optional":"required",
	      is_set(then->flags, pe_action_runnable)?"runnable":"unrunnable",
	      is_set(then->flags, pe_action_pseudo)?"pseudo":then->node?then->node->details->uname:"");
    for(lpc = then->actions_before; lpc != NULL; lpc = lpc->next) {
	action_wrapper_t *other = (action_wrapper_t*)lpc->data;
	action_t *first = other->action;

	enum pe_action_flags first_flags = get_action_flags(first, then->node);
	enum pe_action_flags then_flags  = get_action_flags(then, first->node);
	crm_trace("Checking %s (%s %s %s) against %s (%s %s %s) 0x%.6x",
		  then->uuid,
		  is_set(then_flags, pe_action_optional)?"optional":"required",
		  is_set(then_flags, pe_action_runnable)?"runnable":"unrunnable",
		  is_set(then_flags, pe_action_pseudo)?"pseudo":then->node?then->node->details->uname:"",
		  first->uuid,
		  is_set(first_flags, pe_action_optional)?"optional":"required",
		  is_set(first_flags, pe_action_runnable)?"runnable":"unrunnable",
		  is_set(first_flags, pe_action_pseudo)?"pseudo":first->node?first->node->details->uname:"",
		  other->type);

	clear_bit_inplace(changed, pe_graph_updated_first);
	if(first->rsc != then->rsc
	   && (then->rsc == NULL || first->rsc != then->rsc->parent)) {
	    first = rsc_expand_action(first);
	}

	if(first == other->action) {
	    clear_bit_inplace(first_flags, pe_action_pseudo);
	    changed |= graph_update_action(first, then, then->node, first_flags, other->type);
	    
	} else if(order_actions(first, then, other->type)) {
	    crm_trace("Ordering %s afer %s instead of %s", then->uuid, first->uuid, other->action->uuid);
	    /* Start again to get the new actions_before list */
	    changed |= (pe_graph_updated_then|pe_graph_disable);
	}

	if(changed & pe_graph_disable) {
	    crm_trace("Disabled constraint %s -> %s", then->uuid, first->uuid);
	    clear_bit_inplace(changed, pe_graph_disable);
	    other->type = pe_order_none;	    
	}
	
	if(changed & pe_graph_updated_first) {
	    GListPtr lpc2 = NULL;
	    crm_trace("Updated %s (first %s %s %s), processing dependants ",
		      first->uuid,
		      is_set(first->flags, pe_action_optional)?"optional":"required",
		      is_set(first->flags, pe_action_runnable)?"runnable":"unrunnable",
		      is_set(first->flags, pe_action_pseudo)?"pseudo":first->node?first->node->details->uname:"");
	    for(lpc2 = first->actions_after; lpc2 != NULL; lpc2 = lpc2->next) {
		action_wrapper_t *other = (action_wrapper_t*)lpc2->data;
		update_action(other->action);
	    }
	    update_action(first);
	}
    }

    if(changed & pe_graph_updated_then) {
	crm_trace("Updated %s (then %s %s %s), processing dependants ",
		  then->uuid,
		  is_set(then->flags, pe_action_optional)?"optional":"required",
		  is_set(then->flags, pe_action_runnable)?"runnable":"unrunnable",
		  is_set(then->flags, pe_action_pseudo)?"pseudo":then->node?then->node->details->uname:"");
	    
	update_action(then);
	for(lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
	    action_wrapper_t *other = (action_wrapper_t*)lpc->data;
	    update_action(other->action);
	}
    }
	
    return FALSE;
}


gboolean
shutdown_constraints(
    node_t *node, action_t *shutdown_op, pe_working_set_t *data_set)
{
    /* add the stop to the before lists so it counts as a pre-req
     * for the shutdown
     */
    GListPtr lpc = NULL;
    for(lpc = node->details->running_rsc; lpc != NULL; lpc = lpc->next) {
	resource_t *rsc = (resource_t*)lpc->data;

	if(is_not_set(rsc->flags, pe_rsc_managed)) {
	    continue;
	}
		
	custom_action_order(
	    rsc, stop_key(rsc), NULL,
	    NULL, crm_strdup(CRM_OP_SHUTDOWN), shutdown_op,
	    pe_order_optional, data_set);
    }

    return TRUE;	
}

gboolean
stonith_constraints(
    node_t *node, action_t *stonith_op, pe_working_set_t *data_set)
{
    CRM_CHECK(stonith_op != NULL, return FALSE);
	
    /*
     * Make sure the stonith OP occurs before we start any shared resources
     */
    if(stonith_op != NULL) {
	GListPtr lpc = NULL;
	for(lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
	    resource_t *rsc = (resource_t*)lpc->data;
	    rsc_stonith_ordering(rsc, stonith_op, data_set);
	}
    }
	
    /* add the stonith OP as a stop pre-req and the mark the stop
     * as a pseudo op - since its now redundant
     */
	
    return TRUE;
}

xmlNode *
action2xml(action_t *action, gboolean as_input)
{
    gboolean needs_node_info = TRUE;
    xmlNode * action_xml = NULL;
    xmlNode * args_xml = NULL;
    char *action_id_s = NULL;
	
    if(action == NULL) {
	return NULL;
    }

    crm_debug_4("Dumping action %d as XML", action->id);
    if(safe_str_eq(action->task, CRM_OP_FENCE)) {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);
/* 		needs_node_info = FALSE; */
		
    } else if(safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if(safe_str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT)) {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if(safe_str_eq(action->task, CRM_OP_LRM_REFRESH)) {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

/* 	} else if(safe_str_eq(action->task, RSC_PROBED)) { */
/* 		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT); */

    } else if(is_set(action->flags, pe_action_pseudo)) {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_PSEUDO_EVENT);
	needs_node_info = FALSE;

    } else {
	action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
    }

    action_id_s = crm_itoa(action->id);
    crm_xml_add(action_xml, XML_ATTR_ID, action_id_s);
    crm_free(action_id_s);
	
    crm_xml_add(action_xml, XML_LRM_ATTR_TASK, action->task);
    if(action->rsc != NULL && action->rsc->clone_name != NULL) {
	char *clone_key = NULL;
	const char *interval_s = g_hash_table_lookup(action->meta, "interval");
	int interval = crm_parse_int(interval_s, "0");

	if(safe_str_eq(action->task, RSC_NOTIFY)) {			
	    const char *n_type = g_hash_table_lookup(action->meta, "notify_type");
	    const char *n_task = g_hash_table_lookup(action->meta, "notify_operation");
	    CRM_CHECK(n_type != NULL, crm_err("No notify type value found for %s", action->uuid));
	    CRM_CHECK(n_task != NULL, crm_err("No notify operation value found for %s", action->uuid));
	    clone_key = generate_notify_key(action->rsc->clone_name, n_type, n_task);
			
	} else {
	    clone_key = generate_op_key(action->rsc->clone_name, action->task, interval);
	}
		
	CRM_CHECK(clone_key != NULL, crm_err("Could not generate a key for %s", action->uuid));
	crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, clone_key);
	crm_xml_add(action_xml, "internal_"XML_LRM_ATTR_TASK_KEY, action->uuid);
	crm_free(clone_key);
		
    } else {
	crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, action->uuid);
    }
	
    if(needs_node_info && action->node != NULL) {
	crm_xml_add(action_xml, XML_LRM_ATTR_TARGET,
		    action->node->details->uname);

	crm_xml_add(action_xml, XML_LRM_ATTR_TARGET_UUID,
		    action->node->details->id);		
    }

    if(is_set(action->flags, pe_action_failure_is_fatal) == FALSE) {
	add_hash_param(action->meta,
		       XML_ATTR_TE_ALLOWFAIL, XML_BOOLEAN_TRUE);
    }
	
    if(as_input) {
	return action_xml;
    }

    if(action->rsc) {
	if(is_set(action->flags, pe_action_pseudo) == FALSE) {
	    int lpc = 0;
		
	    xmlNode *rsc_xml = create_xml_node(
		action_xml, crm_element_name(action->rsc->xml));

	    const char *attr_list[] = {
		XML_AGENT_ATTR_CLASS,
		XML_AGENT_ATTR_PROVIDER,
		XML_ATTR_TYPE
	    };

	    if(action->rsc->clone_name != NULL) {
		crm_debug("Using clone name %s for %s", action->rsc->clone_name, action->rsc->id);
		crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->clone_name);
		crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->id);

	    } else {
		crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->id);
		crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->long_name);
	    }
		
	    for(lpc = 0; lpc < DIMOF(attr_list); lpc++) {
		crm_xml_add(rsc_xml, attr_list[lpc],
			    g_hash_table_lookup(action->rsc->meta, attr_list[lpc]));
	    }
	}
    }

    args_xml = create_xml_node(NULL, XML_TAG_ATTRS);
    crm_xml_add(args_xml, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    g_hash_table_foreach(action->extra, hash2field, args_xml);	
    if(action->rsc != NULL) {
	g_hash_table_foreach(action->rsc->parameters, hash2smartfield, args_xml);
    }

    g_hash_table_foreach(action->meta, hash2metafield, args_xml);
    if(action->rsc != NULL) {
	resource_t *parent = action->rsc;
	while(parent != NULL) {
	    parent->cmds->append_meta(parent, args_xml);
	    parent = parent->parent;
	}	    
		
    } else if(safe_str_eq(action->task, CRM_OP_FENCE)) {
	g_hash_table_foreach(action->node->details->attrs, hash2metafield, args_xml);
    }

    sorted_xml(args_xml, action_xml, FALSE);	
    crm_log_xml_debug_4(action_xml, "dumped action");
    free_xml(args_xml);
	
    return action_xml;
}

static gboolean
should_dump_action(action_t *action) 
{
    int log_filter = LOG_DEBUG_5;

    CRM_CHECK(action != NULL, return FALSE);

    if(is_set(action->flags, pe_action_dumped)) {
	do_crm_log_unlikely(log_filter, "action %d (%s) was already dumped",
			    action->id, action->uuid);
	return FALSE;

    } else if(is_set(action->flags, pe_action_runnable) == FALSE) {
	do_crm_log_unlikely(log_filter, "action %d (%s) was not runnable",
			    action->id, action->uuid);
	return FALSE;

    } else if(is_set(action->flags, pe_action_optional) && is_set(action->flags, pe_action_print_always) == FALSE) {
	do_crm_log_unlikely(log_filter, "action %d (%s) was optional",
			    action->id, action->uuid);
	return FALSE;

    } else if(action->rsc != NULL
	      && is_not_set(action->rsc->flags, pe_rsc_managed)) {
	const char * interval = NULL;
	interval = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL);

	/* make sure probes and recurring monitors go through */
	if(safe_str_neq(action->task, RSC_STATUS) && interval == NULL) {
	    do_crm_log_unlikely(log_filter, "action %d (%s) was for an unmanaged resource (%s)",
				action->id, action->uuid, action->rsc->id);
	    return FALSE;
	}
    }
	
    if(is_set(action->flags, pe_action_pseudo)
       || safe_str_eq(action->task,  CRM_OP_FENCE)
       || safe_str_eq(action->task,  CRM_OP_SHUTDOWN)) {
	/* skip the next checks */
	return TRUE;
    }	

    if(action->node == NULL) {
	pe_err("action %d (%s) was not allocated",
	       action->id, action->uuid);
	log_action(LOG_DEBUG, "Unallocated action", action, FALSE);
	return FALSE;
		
    } else if(action->node->details->online == FALSE) {
	pe_err("action %d was (%s) scheduled for offline node",
	       action->id, action->uuid);
	log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
	return FALSE;
#if 0
	/* but this would also affect resources that can be safely
	 *  migrated before a fencing op
	 */
    } else if(action->node->details->unclean == FALSE) {
	pe_err("action %d was (%s) scheduled for unclean node",
	       action->id, action->uuid);
	log_action(LOG_DEBUG, "Action for unclean node", action, FALSE);
	return FALSE;
#endif
    }
    return TRUE;
}

/* lowest to highest */
static gint sort_action_id(gconstpointer a, gconstpointer b)
{
    const action_wrapper_t *action_wrapper2 = (const action_wrapper_t*)a;
    const action_wrapper_t *action_wrapper1 = (const action_wrapper_t*)b;

    if(a == NULL) { return 1; }
    if(b == NULL) { return -1; }
  
    if(action_wrapper1->action->id > action_wrapper2->action->id) {
	return -1;
    }
	
    if(action_wrapper1->action->id < action_wrapper2->action->id) {
	return 1;
    }
    return 0;
}

static gboolean
should_dump_input(int last_action, action_t *action, action_wrapper_t *wrapper)
{
    int type = wrapper->type;
    int log_dump = LOG_DEBUG_3;
    int log_filter = LOG_DEBUG_3;
    
    type &= ~pe_order_implies_first_printed;
    type &= ~pe_order_implies_then_printed;
    type &= ~pe_order_optional;
    
    wrapper->state = pe_link_not_dumped;	
    if(last_action == wrapper->action->id) {
	do_crm_log_unlikely(log_filter, "Input (%d) %s duplicated for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	wrapper->state = pe_link_dup;
	return FALSE;
	
    } else if(wrapper->type == pe_order_none) {
	do_crm_log_unlikely(log_filter, "Input (%d) %s suppressed for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	return FALSE;

    } else if(is_set(wrapper->action->flags, pe_action_runnable) == FALSE
	      && type == pe_order_none
	      && safe_str_neq(wrapper->action->uuid, CRM_OP_PROBED)) {
	do_crm_log_unlikely(log_filter, "Input (%d) %s optional (ordering) for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	return FALSE;

    } else if(is_set(action->flags, pe_action_pseudo)
	      && (wrapper->type & pe_order_stonith_stop)) {
	do_crm_log_unlikely(log_filter, "Input (%d) %s suppressed for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	return FALSE;

    } else if(wrapper->action->rsc
	      && wrapper->action->rsc != action->rsc
	      && is_set(wrapper->action->rsc->flags, pe_rsc_failed)
	      && is_not_set(wrapper->action->rsc->flags, pe_rsc_managed)
	      && strstr(wrapper->action->uuid, "_stop_0")
	      && action->rsc->variant >= pe_clone) {
	crm_warn("Ignoring requirement that %s comeplete before %s:"
		 " unmanaged failed resources cannot prevent clone shutdown",
		 wrapper->action->uuid, action->uuid);
	return FALSE;

    } else if(is_set(wrapper->action->flags, pe_action_dumped) || should_dump_action(wrapper->action)) {
	do_crm_log_unlikely(log_dump, "Input (%d) %s should be dumped for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	goto dump;

#if 0
    } else if(is_set(wrapper->action->flags, pe_action_runnable)
	      && is_set(wrapper->action->flags, pe_action_pseudo)
	      && wrapper->action->rsc->variant != pe_native) {
	do_crm_log(LOG_CRIT, "Input (%d) %s should be dumped for %s",
		   wrapper->action->id, wrapper->action->uuid, action->uuid);
	goto dump;
#endif
    } else if(is_set(wrapper->action->flags, pe_action_optional) == TRUE && is_set(wrapper->action->flags, pe_action_print_always) == FALSE) {
	do_crm_log_unlikely(log_filter, "Input (%d) %s optional for %s",
			    wrapper->action->id, wrapper->action->uuid, action->uuid);
	do_crm_log_unlikely(log_filter, "Input (%d) %s n=%p p=%d r=%d o=%d a=%d f=0x%.6x",
			    wrapper->action->id,
			    wrapper->action->uuid,
			    wrapper->action->node,
			    is_set(wrapper->action->flags, pe_action_pseudo),
			    is_set(wrapper->action->flags, pe_action_runnable),
			    is_set(wrapper->action->flags, pe_action_optional),
			    is_set(wrapper->action->flags, pe_action_print_always),
			    wrapper->type);
	return FALSE;
    } 
	
  dump:
    do_crm_log_unlikely(log_dump, "Input (%d) %s n=%p p=%d r=%d o=%d a=%d f=0x%.6x dumped for %s",
			wrapper->action->id,
			wrapper->action->uuid,
			wrapper->action->node,
			is_set(wrapper->action->flags, pe_action_pseudo),
			is_set(wrapper->action->flags, pe_action_runnable),
			is_set(wrapper->action->flags, pe_action_optional),
			is_set(wrapper->action->flags, pe_action_print_always),
			wrapper->type, action->uuid);
    return TRUE;
}
		   
void
graph_element_from_action(action_t *action, pe_working_set_t *data_set)
{
    GListPtr lpc = NULL;
    int last_action = -1;
    int synapse_priority = 0;
    xmlNode * syn = NULL;
    xmlNode * set = NULL;
    xmlNode * in  = NULL;
    xmlNode * input = NULL;
    xmlNode * xml_action = NULL;

    if(should_dump_action(action) == FALSE) {
	return;
    }
	
    set_bit_inplace(action->flags, pe_action_dumped);
	
    syn = create_xml_node(data_set->graph, "synapse");
    set = create_xml_node(syn, "action_set");
    in  = create_xml_node(syn, "inputs");

    crm_xml_add_int(syn, XML_ATTR_ID, data_set->num_synapse);
    data_set->num_synapse++;

    if(action->rsc != NULL) {
	synapse_priority = action->rsc->priority;
    }
    if(action->priority > synapse_priority) {
	synapse_priority = action->priority;
    }
    if(synapse_priority > 0) {
	crm_xml_add_int(syn, XML_CIB_ATTR_PRIORITY, synapse_priority);
    }
	
    xml_action = action2xml(action, FALSE);
    add_node_nocopy(set, crm_element_name(xml_action), xml_action);

    action->actions_before = g_list_sort(
	action->actions_before, sort_action_id);
	
    for(lpc = action->actions_before; lpc != NULL; lpc = lpc->next) {
	action_wrapper_t *wrapper = (action_wrapper_t*)lpc->data;
	if(should_dump_input(last_action, action, wrapper) == FALSE) {
	    continue;
	}

	wrapper->state = pe_link_dumped;	
	CRM_CHECK(last_action < wrapper->action->id, ;);
	last_action = wrapper->action->id;
	input = create_xml_node(in, "trigger");
		   
	xml_action = action2xml(wrapper->action, TRUE);
	add_node_nocopy(input, crm_element_name(xml_action), xml_action);
    }
}

