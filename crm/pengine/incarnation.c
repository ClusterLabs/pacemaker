/* $Id: incarnation.c,v 1.37 2005/07/06 12:37:55 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
#include <crm/msg_xml.h>

extern gboolean rsc_colocation_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh);

typedef struct clone_variant_data_s
{
		resource_t *self;

		int clone_max;
		int clone_max_node;

		int active_clones;

		gboolean interleave;
		gboolean ordered;

		GListPtr child_list; /* resource_t* */

		gboolean child_starting;
		gboolean child_stopping;
		
} clone_variant_data_t;

void child_stopping_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);

void child_starting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);


#define get_clone_variant_data(data, rsc)				\
	if(rsc->variant == pe_clone) {				\
		data = (clone_variant_data_t *)rsc->variant_opaque; \
	} else {							\
		pe_err("Resource %s was not an \"" XML_CIB_TAG_INCARNATION "\" variant", \
			rsc->id);					\
		return;							\
	}

void clone_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0;
	crm_data_t * xml_obj_child = NULL;
	crm_data_t * xml_obj = rsc->xml;
	crm_data_t * xml_self = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
	clone_variant_data_t *clone_data = NULL;
	resource_t *self = NULL;
	char *inc_max = NULL;

	const char *ordered =
		crm_element_value(xml_obj, XML_RSC_ATTR_ORDERED);
	const char *interleave =
		crm_element_value(xml_obj, XML_RSC_ATTR_INTERLEAVE);

	const char *max_clones =
		get_rsc_param(rsc, XML_RSC_ATTR_INCARNATION_MAX);
	const char *max_clones_node =
		get_rsc_param(rsc, XML_RSC_ATTR_INCARNATION_NODEMAX);

	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(clone_data, sizeof(clone_variant_data_t));
	clone_data->child_list           = NULL;
	clone_data->interleave           = FALSE;
	clone_data->ordered              = FALSE;
	clone_data->active_clones   = 0;
	clone_data->clone_max      = crm_atoi(max_clones,     "1");
	clone_data->clone_max_node = crm_atoi(max_clones_node,"1");

	/* this is a bit of a hack - but simplifies everything else */
	copy_in_properties(xml_self, xml_obj);

	xml_obj_child = find_xml_node(xml_obj, XML_CIB_TAG_GROUP, FALSE);
	if(xml_obj_child == NULL) {
		xml_obj_child = find_xml_node(
			xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
	}

	CRM_DEV_ASSERT(xml_obj_child != NULL);
	if(crm_assert_failed) { return; }

	xml_obj_child = copy_xml(xml_obj_child);
	
	if(common_unpack(xml_self, &self, data_set)) {
		clone_data->self = self;

	} else {
		crm_log_xml_err(xml_self, "Couldnt unpack dummy child");
		return;
	}

	if(crm_is_true(interleave)) {
		clone_data->interleave = TRUE;
	}
	if(crm_is_true(ordered)) {
		clone_data->ordered = TRUE;
	}

	inherit_parent_attributes(xml_self, xml_obj_child, FALSE);
	inc_max = crm_itoa(clone_data->clone_max);
	for(lpc = 0; lpc < clone_data->clone_max; lpc++) {
		resource_t *child_rsc = NULL;
		crm_data_t * child_copy = copy_xml(xml_obj_child);
		
		set_id(child_copy, rsc->id, lpc);
		
		if(common_unpack(child_copy, &child_rsc, data_set)) {
			char *inc_num = crm_itoa(lpc);
			
			clone_data->child_list = g_list_append(
				clone_data->child_list, child_rsc);
			
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
	free_xml(xml_obj_child);
	
	crm_debug_3("Added %d children to resource %s...",
		    clone_data->clone_max, rsc->id);
	
	rsc->variant_opaque = clone_data;
}



resource_t *
clone_find_child(resource_t *rsc, const char *id)
{
	clone_variant_data_t *clone_data = NULL;
	if(rsc->variant == pe_clone) {
		clone_data = (clone_variant_data_t *)rsc->variant_opaque;
	} else {
		pe_err("Resource %s was not a \"" XML_CIB_TAG_INCARNATION "\" variant", rsc->id);
		return NULL;
	}
	return pe_find_resource(clone_data->child_list, id);
}

int clone_num_allowed_nodes(resource_t *rsc)
{
	int num_nodes = 0;
	clone_variant_data_t *clone_data = NULL;
	if(rsc->variant == pe_clone) {
		clone_data = (clone_variant_data_t *)rsc->variant_opaque;
	} else {
		pe_err("Resource %s was not an \"" XML_CIB_TAG_INCARNATION "\" variant",
			rsc->id);
		return 0;
	}

	/* what *should* we return here? */
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		int tmp_num_nodes = child_rsc->fns->num_allowed_nodes(child_rsc);
		if(tmp_num_nodes > num_nodes) {
			num_nodes = tmp_num_nodes;
		}
		);

	return num_nodes;
}

void clone_color(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0, lpc2 = 0, max_nodes = 0;
	resource_t *child_0  = NULL;
	resource_t *child_lh = NULL;
	resource_t *child_rh = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	if(clone_data->self->is_managed == FALSE) {
		return;
	}
	
	child_0 = g_list_nth_data(clone_data->child_list, 0);

	max_nodes = rsc->fns->num_allowed_nodes(rsc);

	/* generate up to max_nodes * clone_node_max constraints */
	lpc = 0;
	clone_data->active_clones = max_nodes * clone_data->clone_max_node;
	if(clone_data->active_clones > clone_data->clone_max) {
		clone_data->active_clones = clone_data->clone_max;
	}
	crm_info("Distributing %d (of %d) %s clones over %d nodes",
		 clone_data->active_clones, clone_data->clone_max,
		 rsc->id, max_nodes);

	for(; lpc < clone_data->active_clones && lpc < max_nodes; lpc++) {
		child_lh = g_list_nth_data(clone_data->child_list, lpc);
		for(lpc2 = lpc + 1; lpc2 < clone_data->active_clones; lpc2++) {
			child_rh = g_list_nth_data(clone_data->child_list,lpc2);

			if(lpc2 < max_nodes) {
				crm_debug_2("Clone %d will not run with %d",
					    lpc, lpc2);
				rsc_colocation_new(
					"__clone_internal_must_not__",
					pecs_must_not, child_lh, child_rh);

			} else if((lpc2 % max_nodes) == lpc) {
				crm_debug_2("Clone %d can run with %d",
					    lpc, lpc2);
				rsc_colocation_new(
					"__clone_internal_must__",
					pecs_must, child_lh, child_rh);
			}
		}
		for(; lpc2 < clone_data->clone_max; lpc2++) {
			child_rh = g_list_nth_data(clone_data->child_list,lpc2);
			crm_debug_2("Unrunnable: Clone %d will not run with %d",
				    lpc2, lpc);
			rsc_colocation_new("__clone_internal_must_not__",
					   pecs_must_not, child_lh, child_rh);
		}
		
	}
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		if(lpc >= clone_data->active_clones) {
			pe_warn("Clone %s cannot be started", child_rsc->id);
		}
		child_rsc->fns->color(child_rsc, data_set);
		);
}

void clone_update_pseudo_status(resource_t *parent, resource_t *child);

void clone_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *op = NULL;
	resource_t *last_start_rsc = NULL;
	resource_t *last_stop_rsc = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		child_rsc->fns->create_actions(child_rsc, data_set);
		clone_update_pseudo_status(rsc, child_rsc);
		if(child_rsc->starting) {
			last_start_rsc = child_rsc;
		}
		if(child_rsc->stopping) {
			last_stop_rsc = child_rsc;
		}
		);

	op = start_action(clone_data->self, NULL,
			  !clone_data->child_starting);
	op->pseudo = TRUE;
	
	op = custom_action(clone_data->self, started_key(rsc),
		      CRMD_ACTION_STARTED, NULL,
			   !clone_data->child_starting, data_set);
	op->pseudo = TRUE;

	child_starting_constraints(
		clone_data, pe_ordering_optional,
		NULL, last_start_rsc, data_set);
	
	op = stop_action(clone_data->self, NULL,
			 !clone_data->child_stopping);
	op->pseudo = TRUE;

	op = custom_action(clone_data->self, stopped_key(rsc),
			   CRMD_ACTION_STOPPED, NULL,
			   !clone_data->child_stopping, data_set);
	op->pseudo = TRUE;

	child_stopping_constraints(
		clone_data, pe_ordering_optional,
		NULL, last_stop_rsc, data_set);
}

void
clone_update_pseudo_status(resource_t *parent, resource_t *child) 
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, parent);

	if(clone_data->child_stopping
	   && clone_data->child_starting) {
		return;
	}
	slist_iter(
		action, action_t, child->actions, lpc,

		if(action->optional) {
			continue;
		}
		if(safe_str_eq(CRMD_ACTION_STOP, action->task)) {
			clone_data->child_stopping = TRUE;
		} else if(safe_str_eq(CRMD_ACTION_START, action->task)) {
			clone_data->child_starting = TRUE;
		}
		);

}

void
child_starting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(clone_data->ordered
	   || clone_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* last child start before global started */
			custom_action_order(
				last, start_key(last), NULL,
				clone_data->self, started_key(clone_data->self), NULL,
				type, data_set);
		}
		
	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version");
		if(last == NULL) {
			/* global start before first child start */
			last = clone_data->self;

		} /* else: child/child relative start */

		order_start_start(last, child, type);

	} else {
		crm_debug_4("Un-ordered version");
		
		/* child start before global started */
		custom_action_order(
			child, start_key(child), NULL,
			clone_data->self, started_key(clone_data->self), NULL,
			type, data_set);
                
		/* global start before child start */
/* 		order_start_start(clone_data->self, child, type); */
		order_start_start(
			clone_data->self, child, pe_ordering_manditory);
	}
}

void
child_stopping_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(clone_data->ordered
	   || clone_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* global stop before first child stop */
			order_stop_stop(clone_data->self, last,
					pe_ordering_manditory);
		}
		
	} else if(clone_data->ordered && last != NULL) {
		crm_debug_4("Ordered version");

		/* child/child relative stop */
		order_stop_stop(child, last, type);

	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version (1st node)");
		/* first child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			clone_data->self, stopped_key(clone_data->self), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");

		/* child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			clone_data->self, stopped_key(clone_data->self), NULL,
			type, data_set);
                        
		/* global stop before child stop */
		order_stop_stop(clone_data->self, child, type);
	}
}


void
clone_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	/* global stopped before start */
	custom_action_order(
		clone_data->self, stopped_key(clone_data->self), NULL,
		clone_data->self, start_key(clone_data->self), NULL,
		pe_ordering_manditory, data_set);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		/* child stop before start */
		order_restart(child_rsc);

		child_starting_constraints(
			clone_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		child_stopping_constraints(
			clone_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		
		);
	
}

void clone_rsc_colocation_lh(rsc_colocation_t *constraint)
{
	gboolean do_interleave = FALSE;
	resource_t *rsc = constraint->rsc_lh;
	clone_variant_data_t *clone_data = NULL;
	clone_variant_data_t *clone_data_rh = NULL;
	
	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else {
		crm_debug_4("Processing constraints from %s", rsc->id);
	}
	
	get_clone_variant_data(clone_data, rsc);

	if(constraint->rsc_rh->variant == pe_clone) {
		get_clone_variant_data(
			clone_data_rh, constraint->rsc_rh);
		if(clone_data->clone_max_node
		   != clone_data_rh->clone_max_node) {
			pe_err("Cannot interleave "XML_CIB_TAG_INCARNATION" %s and %s because"
			       " they do not support the same number of"
			       " resources per node",
			       constraint->rsc_lh->id, constraint->rsc_rh->id);
			
		/* only the LHS side needs to be labeled as interleave */
		} else if(clone_data->interleave) {
			do_interleave = TRUE;
		}
	}
	
	if(do_interleave) {
		resource_t *child_lh = NULL;
		resource_t *child_rh = NULL;
		resource_t *parent_rh = constraint->rsc_rh;
		
		GListPtr iter_lh = clone_data->child_list;
		GListPtr iter_rh = clone_data_rh->child_list;

		crm_debug_2("Interleaving %s with %s",
			    constraint->rsc_lh->id, constraint->rsc_rh->id);
		/* If the resource have different numbers of incarnations,
		 *   then just do as many as are available
		 */
		while(iter_lh != NULL && iter_rh != NULL) {
			child_lh = iter_lh->data;
			child_rh = iter_rh->data;
			iter_lh = iter_lh->next;
			iter_rh = iter_rh->next;
			
			constraint->rsc_rh = child_rh;
			crm_debug_3("Colocating %s with %s", child_lh->id, child_rh->id);
			child_rh->fns->rsc_colocation_rh(child_lh, constraint);
		}
		/* restore the original RHS of the constraint */
		constraint->rsc_rh = parent_rh;
		return;

	} else if(constraint->strength != pecs_must_not) {
		pe_warn("rsc_colocations other than \"-INFINITY\""
			 " are not supported for non-interleaved"
			" "XML_CIB_TAG_INCARNATION" resources");
		return;
	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		crm_action_debug_3(print_resource("LHS", child_rsc, TRUE));
		child_rsc->fns->rsc_colocation_rh(child_rsc, constraint);
		);
}

void clone_rsc_colocation_rh(resource_t *rsc, rsc_colocation_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	
	crm_debug_3("Processing RH of constraint %s", constraint->id);

	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		pe_warn("rsc_dependencies other than \"must_not\" "
			 "are not supported for incarnation resources");
		return;
		
	} else {
		crm_action_debug_3(print_resource("LHS", rsc, FALSE));
	}
	
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		crm_action_debug_3(print_resource("RHS", child_rsc, FALSE));
		child_rsc->fns->rsc_colocation_rh(child_rsc, constraint);
		);
}


void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order)
{
	char *stop_id = NULL;
	char *start_id = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

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
	
	clone_data->self->fns->rsc_order_lh(clone_data->self, order);
}

void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing RH of ordering constraint %d", order->id);

 	clone_data->self->fns->rsc_order_rh(lh_action, clone_data->self, order);

}

void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	clone_data->self->fns->rsc_location(clone_data->self, constraint);
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->fns->rsc_location(child_rsc, constraint);
		);
}

void clone_expand(resource_t *rsc, pe_working_set_t *data_set)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	clone_data->self->fns->expand(clone_data->self, data_set);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->fns->expand(child_rsc, data_set);

		);
}

void clone_printw(resource_t *rsc, const char *pre_text, int *index)
{
#if CURSES_ENABLED
	const char *child_text = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	if(pre_text != NULL) {
		child_text = "        ";
	} else {
		child_text = "    ";
	}

	move(*index, 0);
	printw("Clone: %s\n", rsc->id);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		(*index)++;
		child_rsc->fns->printw(child_rsc, child_text, index);
		);
#else
	crm_err("printw support requires ncurses to be available during configure");
#endif
}

void clone_html(resource_t *rsc, const char *pre_text, FILE *stream)
{
	const char *child_text = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	if(pre_text != NULL) {
		child_text = "        ";
	} else {
		child_text = "    ";
	}
	
	fprintf(stream, "Clone: %s\n", rsc->id);
	fprintf(stream, "<ul>\n");

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		fprintf(stream, "<li>\n");
		child_rsc->fns->html(child_rsc, child_text, stream);
		fprintf(stream, "</li>\n");
		);
	fprintf(stream, "</ul>\n");
}


void clone_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	common_dump(rsc, pre_text, details);
	
	clone_data->self->fns->dump(
		clone_data->self, pre_text, details);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->fns->dump(child_rsc, pre_text, details);
		);
}

void clone_free(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Freeing %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		crm_debug_3("Freeing child %s", child_rsc->id);
		free_xml(child_rsc->xml);
		child_rsc->fns->free(child_rsc);
		);

	crm_debug_3("Freeing child list");
	pe_free_shallow_adv(clone_data->child_list, FALSE);

	free_xml(clone_data->self->xml);
	clone_data->self->fns->free(clone_data->self);

	common_free(rsc);
}


void
clone_agent_constraints(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->fns->agent_constraints(child_rsc);
		);
}
