/* $Id: group.c,v 1.11 2005/03/31 08:03:37 andrew Exp $ */
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

typedef struct group_variant_data_s
{
		int num_children;
		GListPtr child_list; /* resource_t* */
		resource_t *self;
		resource_t *first_child;
		resource_t *last_child;
		
} group_variant_data_t;


#define get_group_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_group);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (group_variant_data_t *)rsc->variant_opaque;		\

void group_unpack(resource_t *rsc)
{
	crm_data_t * xml_obj = rsc->xml;
	crm_data_t * xml_self = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
	group_variant_data_t *group_data = NULL;
	resource_t *self = NULL;

	crm_verbose("Processing resource %s...", rsc->id);

	crm_malloc(group_data, sizeof(group_variant_data_t));
	group_data->num_children = 0;
	group_data->self	 = NULL;
	group_data->child_list   = NULL;
	group_data->first_child  = NULL;
	group_data->last_child   = NULL;

	/* this is a bit of a hack - but simplifies everything else */
	copy_in_properties(xml_self, xml_obj);
	if(common_unpack(xml_self, &self)) {
		group_data->self = self;
		self->restart_type = pe_restart_restart;

	} else {
		crm_xml_err(xml_self, "Couldnt unpack dummy child");
		return;
	}
	
	xml_child_iter(
		xml_obj, xml_native_rsc, XML_CIB_TAG_RESOURCE,

		resource_t *new_rsc = NULL;
		set_id(xml_native_rsc, rsc->id, -1);

		if(common_unpack(xml_native_rsc, &new_rsc)) {
			group_data->num_children++;
			group_data->child_list = g_list_append(
				group_data->child_list, new_rsc);
			
			group_data->last_child = new_rsc;

			if(group_data->first_child == NULL) {
				group_data->first_child = new_rsc;
			}
			
			rsc_colocation_new("pe_group_internal_colo", pecs_must,
					   group_data->self, new_rsc);
		
			crm_devel_action(
				print_resource("Added", new_rsc, FALSE));
		} else {
			crm_err("Failed unpacking resource %s",
				crm_element_value(xml_obj, XML_ATTR_ID));
		}
		);
	crm_verbose("Added %d children to resource %s...",
		    group_data->num_children, rsc->id);
	
	rsc->variant_opaque = group_data;
}

resource_t *
group_find_child(resource_t *rsc, const char *id)
{
	group_variant_data_t *group_data = NULL;
	if(rsc->variant == pe_group) {
		group_data = (group_variant_data_t *)rsc->variant_opaque;
	} else {
		crm_err("Resource %s was not a \"group\" variant", rsc->id);
		return NULL;
	}
	return pe_find_resource(group_data->child_list, id);
}

int group_num_allowed_nodes(resource_t *rsc)
{
	group_variant_data_t *group_data = NULL;
	if(rsc->variant == pe_native) {
		group_data = (group_variant_data_t *)rsc->variant_opaque;
	} else {
		crm_err("Resource %s was not a \"native\" variant",
			rsc->id);
		return 0;
	}
	if(group_data->self == NULL) {
		return 0;
	}
 	return group_data->self->fns->num_allowed_nodes(group_data->self);
}

void group_color(resource_t *rsc, GListPtr *colors)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	if(group_data->self == NULL) {
		return;
	}

 	group_data->self->fns->color(group_data->self, colors);
}

void group_create_actions(resource_t *rsc)
{
	gboolean child_starting = FALSE;
	gboolean child_stopping = FALSE;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		child_rsc->fns->create_actions(child_rsc);
		child_starting = child_starting || child_rsc->starting;
		child_stopping = child_stopping || child_rsc->stopping;
		);

	if(child_starting) {
		rsc->starting = TRUE;
		action_new(group_data->self, start_rsc, NULL);
		action_new(group_data->self, started_rsc, NULL);
		
	}
	if(child_stopping) {
		rsc->stopping = TRUE;
		action_new(group_data->self, stop_rsc, NULL);
		action_new(group_data->self, stopped_rsc, NULL);
	}
	
	if(group_data->self != NULL) {
		slist_iter(
			action, action_t, group_data->self->actions, lpc,
			action->pseudo   = TRUE;
			);
	}
}

void group_internal_constraints(resource_t *rsc, GListPtr *ordering_constraints)
{
	resource_t *last_rsc = NULL;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	order_new(group_data->self, stop_rsc,  NULL,
		  group_data->self, start_rsc, NULL,
		  pecs_startstop, ordering_constraints);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		order_new(child_rsc, stop_rsc,  NULL,
			  child_rsc, start_rsc, NULL,
			  pecs_startstop, ordering_constraints);

		if(last_rsc != NULL) {
			order_new(last_rsc,  start_rsc, NULL,
				  child_rsc, start_rsc, NULL,
				  pecs_startstop, ordering_constraints);

			order_new(child_rsc, stop_rsc, NULL,
				  last_rsc,  stop_rsc, NULL,
				  pecs_startstop, ordering_constraints);

		} else {
			order_new(child_rsc,        stop_rsc, NULL,
				  group_data->self, stopped_rsc, NULL,
				  pecs_startstop, ordering_constraints);

			order_new(group_data->self, start_rsc, NULL,
				  child_rsc,        start_rsc, NULL,
				  pecs_startstop, ordering_constraints);
		}
		
		last_rsc = child_rsc;
		);

	if(last_rsc != NULL) {
		order_new(last_rsc,         start_rsc, NULL,
			  group_data->self, started_rsc, NULL,
			  pecs_startstop, ordering_constraints);

		order_new(group_data->self, stop_rsc, NULL,
			  last_rsc,         stop_rsc, NULL,
			  pecs_startstop, ordering_constraints);
	}
		
}

void group_rsc_colocation_lh(rsc_colocation_t *constraint)
{
	resource_t *rsc = constraint->rsc_lh;
	group_variant_data_t *group_data = NULL;
	
	if(rsc == NULL) {
		crm_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		crm_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else {
		crm_devel("Processing constraints from %s", rsc->id);
	}

	get_group_variant_data(group_data, rsc);
	if(group_data->self == NULL) {
		return;
	}

	group_data->self->fns->rsc_colocation_rh(group_data->self, constraint);
	
}

void group_rsc_colocation_rh(resource_t *rsc, rsc_colocation_t *constraint)
{
	resource_t *rsc_lh = rsc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing RH of constraint %s", constraint->id);
	crm_devel_action(print_resource("LHS", rsc_lh, TRUE));

	if(group_data->self == NULL) {
		return;
	}
	
	group_data->self->fns->rsc_colocation_rh(group_data->self, constraint);
}


void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing LH of ordering constraint %d", order->id);

	if(group_data->self == NULL) {
		return;

	} else if(order->lh_action_task == start_rsc) {
		order->lh_action_task = started_rsc;
		
	} else if(order->lh_action_task == stop_rsc) {
		order->lh_action_task = stopped_rsc;
	}
	
	group_data->self->fns->rsc_order_lh(group_data->self, order);
}

void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing RH of ordering constraint %d", order->id);

	if(group_data->self == NULL) {
		return;
	}

	group_data->self->fns->rsc_order_rh(lh_action, group_data->self, order);
}

void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing actions from %s", rsc->id);

	if(group_data->self != NULL) {
		group_data->self->fns->rsc_location(group_data->self, constraint);
	}

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		child_rsc->fns->rsc_location(child_rsc, constraint);
		);
}

void group_expand(resource_t *rsc, crm_data_t * *graph)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing actions from %s", rsc->id);

	group_data->self->fns->expand(group_data->self, graph);

	if(group_data->self == NULL) {
		return;
	}
	
	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		child_rsc->fns->expand(child_rsc, graph);
		);

}

void group_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	if(group_data->self == NULL) {
		return;
	}

	common_dump(rsc, pre_text, details);
	
	group_data->self->fns->dump(group_data->self, pre_text, details);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		
		child_rsc->fns->dump(child_rsc, pre_text, details);
		);
}

void group_free(resource_t *rsc)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Freeing %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		crm_verbose("Freeing child %s", child_rsc->id);
		child_rsc->fns->free(child_rsc);
		);

	crm_verbose("Freeing child list");
	pe_free_shallow_adv(group_data->child_list, FALSE);

	if(group_data->self != NULL) {
		group_data->self->fns->free(group_data->self);
	}

	common_free(rsc);
}


void
group_agent_constraints(resource_t *rsc)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		
		child_rsc->fns->agent_constraints(child_rsc);
		);
}
