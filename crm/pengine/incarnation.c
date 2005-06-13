/* $Id: incarnation.c,v 1.24 2005/06/13 12:35:47 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
#include <crm/msg_xml.h>

extern gboolean rsc_colocation_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh);

typedef struct incarnation_variant_data_s
{
		resource_t *self;

		int incarnation_max;
		int incarnation_max_node;

		int active_incarnation;

		gboolean interleave;
		gboolean ordered;

		GListPtr child_list; /* resource_t* */

		gboolean child_starting;
		gboolean child_stopping;
		
} incarnation_variant_data_t;

void child_stopping_constraints(
	incarnation_variant_data_t *incarnation_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);

void child_starting_constraints(
	incarnation_variant_data_t *incarnation_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);


#define get_incarnation_variant_data(data, rsc)				\
	if(rsc->variant == pe_incarnation) {				\
		data = (incarnation_variant_data_t *)rsc->variant_opaque; \
	} else {							\
		pe_err("Resource %s was not an \"incarnation\" variant", \
			rsc->id);					\
		return;							\
	}

void incarnation_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0;
	crm_data_t * xml_obj_child = NULL;
	crm_data_t * xml_obj = rsc->xml;
	crm_data_t * xml_self = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
	incarnation_variant_data_t *incarnation_data = NULL;
	resource_t *self = NULL;
	char *inc_max = NULL;

	const char *ordered =
		crm_element_value(xml_obj, XML_RSC_ATTR_ORDERED);
	const char *interleave =
		crm_element_value(xml_obj, XML_RSC_ATTR_INTERLEAVE);

	const char *max_incarn =
		get_rsc_param(rsc, XML_RSC_ATTR_INCARNATION_MAX);
	const char *max_incarn_node =
		get_rsc_param(rsc, XML_RSC_ATTR_INCARNATION_NODEMAX);

	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(incarnation_data, sizeof(incarnation_variant_data_t));
	incarnation_data->child_list           = NULL;
	incarnation_data->interleave           = FALSE;
	incarnation_data->ordered              = FALSE;
	incarnation_data->active_incarnation   = 0;
	incarnation_data->incarnation_max      = crm_atoi(max_incarn,     "1");
	incarnation_data->incarnation_max_node = crm_atoi(max_incarn_node,"1");

	/* this is a bit of a hack - but simplifies everything else */
	copy_in_properties(xml_self, xml_obj);

	xml_obj_child = find_xml_node(xml_obj, "resource_group", FALSE);
	if(xml_obj_child == NULL) {
		xml_obj_child = find_xml_node(
			xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
	}

	CRM_DEV_ASSERT(xml_obj_child != NULL);
	if(crm_assert_failed) { return; }
	
	if(common_unpack(xml_self, &self, data_set)) {
		incarnation_data->self = self;

	} else {
		crm_log_xml_err(xml_self, "Couldnt unpack dummy child");
		return;
	}

	if(crm_is_true(interleave)) {
		incarnation_data->interleave = TRUE;
	}
	if(crm_is_true(ordered)) {
		incarnation_data->ordered = TRUE;
	}

	inherit_parent_attributes(xml_self, xml_obj_child, FALSE);
	inc_max = crm_itoa(incarnation_data->incarnation_max);
	for(lpc = 0; lpc < incarnation_data->incarnation_max; lpc++) {
		resource_t *child_rsc = NULL;
		crm_data_t * child_copy = copy_xml(
			xml_obj_child);
		
		set_id(child_copy, rsc->id, lpc);
		
		if(common_unpack(child_copy, &child_rsc, data_set)) {
			char *inc_num = crm_itoa(lpc);
			
			incarnation_data->child_list = g_list_append(
				incarnation_data->child_list, child_rsc);
			
			add_rsc_param(
				child_rsc, XML_RSC_ATTR_INCARNATION, inc_num);
			add_rsc_param(
				child_rsc, XML_RSC_ATTR_INCARNATION_MAX, inc_max);
			
			crm_action_debug_3(
				print_resource("Added", child_rsc, FALSE));
			
			crm_free(inc_num);
			
		} else {
			pe_err("Failed unpacking resource %s",
			       crm_element_value(child_copy, XML_ATTR_ID));
		}
	}
	crm_free(inc_max);
	
	crm_debug_3("Added %d children to resource %s...",
		    incarnation_data->incarnation_max, rsc->id);
	
	rsc->variant_opaque = incarnation_data;
}



resource_t *
incarnation_find_child(resource_t *rsc, const char *id)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	if(rsc->variant == pe_incarnation) {
		incarnation_data = (incarnation_variant_data_t *)rsc->variant_opaque;
	} else {
		pe_err("Resource %s was not a \"incarnation\" variant", rsc->id);
		return NULL;
	}
	return pe_find_resource(incarnation_data->child_list, id);
}

int incarnation_num_allowed_nodes(resource_t *rsc)
{
	int num_nodes = 0;
	incarnation_variant_data_t *incarnation_data = NULL;
	if(rsc->variant == pe_incarnation) {
		incarnation_data = (incarnation_variant_data_t *)rsc->variant_opaque;
	} else {
		pe_err("Resource %s was not an \"incarnation\" variant",
			rsc->id);
		return 0;
	}

	/* what *should* we return here? */
	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		int tmp_num_nodes = child_rsc->fns->num_allowed_nodes(child_rsc);
		if(tmp_num_nodes > num_nodes) {
			num_nodes = tmp_num_nodes;
		}
		);

	return num_nodes;
}

void incarnation_color(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0, lpc2 = 0, max_nodes = 0;
	resource_t *child_0  = NULL;
	resource_t *child_lh = NULL;
	resource_t *child_rh = NULL;
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	child_0 = g_list_nth_data(incarnation_data->child_list, 0);

	max_nodes = rsc->fns->num_allowed_nodes(rsc);

	/* generate up to max_nodes * incarnation_node_max constraints */
	lpc = 0;
	crm_info("Distributing %d incarnations over %d nodes",
		  incarnation_data->incarnation_max, max_nodes);

	for(; lpc < max_nodes && lpc < incarnation_data->incarnation_max; lpc++) {

		child_lh = child_0;
		incarnation_data->active_incarnation++;

		if(lpc != 0) {
			child_rh = g_list_nth_data(incarnation_data->child_list, lpc);
			
			crm_debug_4("Incarnation %d will run on a differnt node to 0",
				  lpc);
			
			rsc_colocation_new("pe_incarnation_internal_must_not",
					   pecs_must_not, child_lh, child_rh);
		} else {
			child_rh = child_0;
		}
		
		child_lh = child_rh;
		
		for(lpc2 = 1; lpc2 < incarnation_data->incarnation_max_node; lpc2++) {
			int offset = lpc + (lpc2 * max_nodes);
			if(offset >= incarnation_data->incarnation_max) {
				break;
			}
			crm_debug_4("Incarnation %d will run on the same node as %d",
				  offset, lpc);

			incarnation_data->active_incarnation++;

			child_rh = g_list_nth_data(
				incarnation_data->child_list, offset);

			rsc_colocation_new("pe_incarnation_internal_must",
					   pecs_must, child_lh, child_rh);
		}
	}

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		if(lpc < incarnation_data->active_incarnation) {
			crm_debug_4("Coloring Incarnation %d", lpc);
			child_rsc->fns->color(child_rsc, data_set);
		} else {
			/* TODO: assign "no color"?  Doesnt seem to need it */
			pe_warn("Incarnation %d cannot be started", lpc+1);
		} 
		);
	crm_info("%d Incarnations are active", incarnation_data->active_incarnation);
}

void incarnation_update_pseudo_status(resource_t *parent, resource_t *child);

void incarnation_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *op = NULL;
	resource_t *last_start_rsc = NULL;
	resource_t *last_stop_rsc = NULL;
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);
	
	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		child_rsc->fns->create_actions(child_rsc, data_set);
		incarnation_update_pseudo_status(rsc, child_rsc);
		if(child_rsc->starting) {
			last_start_rsc = child_rsc;
		}
		if(child_rsc->stopping) {
			last_stop_rsc = child_rsc;
		}
		);

	op = start_action(incarnation_data->self, NULL);
	op->optional = !incarnation_data->child_starting;
	op->pseudo   = TRUE;
	
	op = custom_action(incarnation_data->self, started_key(rsc),
		      CRMD_ACTION_STARTED, NULL, data_set);
 	op->optional = !incarnation_data->child_starting;
	op->pseudo   = TRUE;

	child_starting_constraints(
		incarnation_data, pe_ordering_optional,
		NULL, last_start_rsc, data_set);
	
	op = stop_action(incarnation_data->self, NULL);
	op->optional = !incarnation_data->child_stopping;
	op->pseudo   = TRUE;

	op = custom_action(incarnation_data->self, stopped_key(rsc),
		      CRMD_ACTION_STOPPED, NULL, data_set);
 	op->optional = !incarnation_data->child_stopping;
	op->pseudo   = TRUE;

	child_stopping_constraints(
		incarnation_data, pe_ordering_optional,
		NULL, last_stop_rsc, data_set);
}

void
incarnation_update_pseudo_status(resource_t *parent, resource_t *child) 
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, parent);

	if(incarnation_data->child_stopping
	   && incarnation_data->child_starting) {
		return;
	}
	slist_iter(
		action, action_t, child->actions, lpc,

		if(action->optional) {
			continue;
		}
		if(safe_str_eq(CRMD_ACTION_STOP, action->task)) {
			incarnation_data->child_stopping = TRUE;
		} else if(safe_str_eq(CRMD_ACTION_START, action->task)) {
			incarnation_data->child_starting = TRUE;
		}
		);

}

void
child_starting_constraints(
	incarnation_variant_data_t *incarnation_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(incarnation_data->ordered
	   || incarnation_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	if(child == NULL) {
		if(incarnation_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* last child start before global started */
			custom_action_order(
				last, start_key(last), NULL,
				incarnation_data->self, started_key(incarnation_data->self), NULL,
				type, data_set);
		}
		
	} else if(incarnation_data->ordered) {
		crm_debug_4("Ordered version");
		if(last == NULL) {
			/* global start before first child start */
			last = incarnation_data->self;

		} /* else: child/child relative start */

		order_start_start(last, child, type);

	} else {
		crm_debug_4("Un-ordered version");
		
		/* child start before global started */
		custom_action_order(
			child, start_key(child), NULL,
			incarnation_data->self, started_key(incarnation_data->self), NULL,
			type, data_set);
                
		/* global start before child start */
/* 		order_start_start(incarnation_data->self, child, type); */
		order_start_start(
			incarnation_data->self, child, pe_ordering_manditory);
	}
}

void
child_stopping_constraints(
	incarnation_variant_data_t *incarnation_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(incarnation_data->ordered
	   || incarnation_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	
	if(child == NULL) {
		if(incarnation_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* global stop before first child stop */
			order_stop_stop(incarnation_data->self, last,
					pe_ordering_manditory);
		}
		
	} else if(incarnation_data->ordered && last != NULL) {
		crm_debug_4("Ordered version");

		/* child/child relative stop */
		order_stop_stop(child, last, type);

	} else if(incarnation_data->ordered) {
		crm_debug_4("Ordered version (1st node)");
		/* first child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			incarnation_data->self, stopped_key(incarnation_data->self), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");

		/* child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			incarnation_data->self, stopped_key(incarnation_data->self), NULL,
			type, data_set);
                        
		/* global stop before child stop */
		order_stop_stop(incarnation_data->self, child, type);
	}
}


void
incarnation_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	/* global stopped before start */
	custom_action_order(
		incarnation_data->self, stopped_key(incarnation_data->self), NULL,
		incarnation_data->self, start_key(incarnation_data->self), NULL,
		pe_ordering_manditory, data_set);
	
	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,

		/* child stop before start */
		order_restart(child_rsc);

		child_starting_constraints(
			incarnation_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		child_stopping_constraints(
			incarnation_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		
		);
	
}

void incarnation_rsc_colocation_lh(rsc_colocation_t *constraint)
{
	resource_t *rsc = constraint->rsc_lh;
	incarnation_variant_data_t *incarnation_data = NULL;
	
	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		pe_warn("rsc_dependancies other than \"must_not\" "
			 "are not supported for incarnation resources");
		return;
		
	} else {
		crm_debug_4("Processing constraints from %s", rsc->id);
	}
	
	get_incarnation_variant_data(incarnation_data, rsc);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		
		crm_action_debug_3(print_resource("LHS", child_rsc, TRUE));
		child_rsc->fns->rsc_colocation_rh(child_rsc, constraint);
		);
}

void incarnation_rsc_colocation_rh(resource_t *rsc, rsc_colocation_t *constraint)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	
	crm_debug_3("Processing RH of constraint %s", constraint->id);

	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		pe_warn("rsc_dependancies other than \"must_not\" "
			 "are not supported for incarnation resources");
		return;
		
	} else {
		crm_action_debug_3(print_resource("LHS", rsc, FALSE));
	}
	
	get_incarnation_variant_data(incarnation_data, rsc);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		
		crm_action_debug_3(print_resource("RHS", child_rsc, FALSE));
		child_rsc->fns->rsc_colocation_rh(child_rsc, constraint);
		);
}


void incarnation_rsc_order_lh(resource_t *rsc, order_constraint_t *order)
{
	char *stop_id = NULL;
	char *start_id = NULL;
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	crm_debug_3("Processing LH of ordering constraint %d", order->id);

	stop_id = stop_key(rsc);
	start_id = start_key(rsc);
	
	if(safe_str_eq(order->lh_action_task, start_id)) {
		crm_free(order->lh_action_task);
		order->lh_action_task = started_key(rsc);

	} else if(safe_str_eq(order->lh_action_task, stop_id)) {
		crm_free(order->lh_action_task);
		order->lh_action_task = stopped_key(rsc);
	}

	crm_free(start_id);
	crm_free(stop_id);
	
	incarnation_data->self->fns->rsc_order_lh(incarnation_data->self, order);
}

void incarnation_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	crm_debug_3("Processing RH of ordering constraint %d", order->id);

 	incarnation_data->self->fns->rsc_order_rh(lh_action, incarnation_data->self, order);

}

void incarnation_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	incarnation_data->self->fns->rsc_location(incarnation_data->self, constraint);
	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,

		child_rsc->fns->rsc_location(child_rsc, constraint);
		);
}

void incarnation_expand(resource_t *rsc, pe_working_set_t *data_set)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	incarnation_data->self->fns->expand(incarnation_data->self, data_set);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,

		child_rsc->fns->expand(child_rsc, data_set);

		);
}

void incarnation_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	common_dump(rsc, pre_text, details);
	
	incarnation_data->self->fns->dump(
		incarnation_data->self, pre_text, details);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		
		child_rsc->fns->dump(child_rsc, pre_text, details);
		);
}

void incarnation_free(resource_t *rsc)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	crm_debug_3("Freeing %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,

		crm_debug_3("Freeing child %s", child_rsc->id);
		free_xml(child_rsc->xml);
		child_rsc->fns->free(child_rsc);
		);

	crm_debug_3("Freeing child list");
	pe_free_shallow_adv(incarnation_data->child_list, FALSE);

	free_xml(incarnation_data->self->xml);
	incarnation_data->self->fns->free(incarnation_data->self);

	common_free(rsc);
}


void
incarnation_agent_constraints(resource_t *rsc)
{
	incarnation_variant_data_t *incarnation_data = NULL;
	get_incarnation_variant_data(incarnation_data, rsc);

	slist_iter(
		child_rsc, resource_t, incarnation_data->child_list, lpc,
		
		child_rsc->fns->agent_constraints(child_rsc);
		);
}
