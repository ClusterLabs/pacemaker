/* $Id: group.c,v 1.3 2004/11/09 16:52:23 andrew Exp $ */
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

extern gboolean rsc_dependancy_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh);

typedef struct group_variant_data_s
{
		int num_children;
		GListPtr child_list; /* resource_t* */
		resource_t *first_child;
		resource_t *last_child;
} group_variant_data_t;


#define get_group_variant_data(data, rsc)				\
	if(rsc->variant == pe_group) {					\
		data = (group_variant_data_t *)rsc->variant_opaque;	\
	} else {							\
		crm_err("Resource %s was not a \"group\" variant",	\
			rsc->id);					\
		return;							\
	}

void group_unpack(resource_t *rsc)
{
	xmlNodePtr xml_obj = rsc->xml;
	group_variant_data_t *group_data = NULL;

	crm_verbose("Processing resource %s...", rsc->id);

	crm_malloc(group_data, sizeof(group_variant_data_t));
	group_data->num_children = 0;
	group_data->child_list   = NULL;
	group_data->first_child  = NULL;
	group_data->last_child   = NULL;
	
	xml_child_iter(
		xml_obj, xml_native_rsc, XML_CIB_TAG_RESOURCE,

		resource_t *new_rsc = NULL;
		if(common_unpack(xml_native_rsc, &new_rsc)) {
			group_data->num_children++;
			group_data->child_list = g_list_append(
				group_data->child_list, new_rsc);
			
			group_data->last_child = new_rsc;

			if(group_data->first_child == NULL) {
				group_data->first_child = new_rsc;
			}
			
			crm_debug_action(
				print_resource("Added", new_rsc, FALSE));
		} else {
			crm_err("Failed unpacking resource %s",
				xmlGetProp(xml_obj, XML_ATTR_ID));
		}
		);
	crm_verbose("Added %d children to resource %s...",
		    group_data->num_children, rsc->id);
	
	rsc->variant_opaque = group_data;
}

void group_color(resource_t *rsc, GListPtr *colors)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

/* 	group_data->first_child->fns->color(group_data->first_child, colors); */
	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		child_rsc->fns->color(child_rsc, colors);
		);

	/* all others are supposed to be inferred by virtue of
	 * the must constraints - but this does not seem to happen (yet)
	 */
}

void group_create_actions(resource_t *rsc)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		child_rsc->fns->create_actions(child_rsc);
		);

}

void group_internal_constraints(resource_t *rsc, GListPtr *ordering_constraints)
{
	int lpc;
	resource_t *last_rsc = NULL;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		if(last_rsc != NULL) {
			order_new(last_rsc, start_rsc, NULL,
				  child_rsc, start_rsc, NULL,
				  pecs_startstop, ordering_constraints);
		}
		
		if(child_rsc != group_data->first_child) {
			rsc_dependancy_new("pe_group_internal", pecs_must,
					   group_data->first_child, child_rsc);
		}
		
		last_rsc = child_rsc;
		);
}

void group_rsc_dependancy_lh(rsc_dependancy_t *constraint)
{
	int lpc;
	resource_t *rsc = constraint->rsc_lh;
	group_variant_data_t *group_data = NULL;
	
	if(rsc == NULL) {
		crm_err("No constraints for NULL resource");
		return;
	} else {
		crm_debug("Processing constraints from %s", rsc->id);
	}
	
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		child_rsc->fns->rsc_dependancy_rh(child_rsc, constraint);
		);

}

void group_rsc_dependancy_rh(resource_t *rsc, rsc_dependancy_t *constraint)
{
	int lpc;
	resource_t *rsc_lh = rsc;
	resource_t *rsc_rh = constraint->rsc_rh;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing RH of constraint %s", constraint->id);
	crm_debug_action(print_resource("LHS", rsc_lh, TRUE));
	
	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		crm_debug_action(print_resource("RHS", rsc_rh, TRUE));
		child_rsc->fns->rsc_dependancy_rh(child_rsc, constraint);
		);
}


void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing LH of ordering constraint %d", order->id);

	if(order->lh_action_task == stop_rsc) {
		group_data->first_child->fns->rsc_order_lh(
			group_data->first_child, order);

	} else if(order->lh_action_task == start_rsc) {
		group_data->last_child->fns->rsc_order_lh(
			group_data->last_child, order);
	}
}

void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing RH of ordering constraint %d", order->id);

	if(order->lh_action_task == stop_rsc) {
		group_data->last_child->fns->rsc_order_rh(
			lh_action, group_data->last_child, order);

	} else if(order->lh_action_task == start_rsc) {
		group_data->first_child->fns->rsc_order_rh(
			lh_action, group_data->first_child, order);
	}
}

void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing actions from %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		child_rsc->fns->rsc_location(child_rsc, constraint);
		);
}

void group_expand(resource_t *rsc, xmlNodePtr *graph)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_verbose("Processing actions from %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,

		child_rsc->fns->expand(child_rsc, graph);
		);

}

void group_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	common_dump(rsc, pre_text, details);
	
	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		
		child_rsc->fns->dump(child_rsc, pre_text, details);
		);
}

void group_free(resource_t *rsc)
{
	int lpc;
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

	common_free(rsc);
}


void
group_agent_constraints(resource_t *rsc)
{
	int lpc;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	slist_iter(
		child_rsc, resource_t, group_data->child_list, lpc,
		
		child_rsc->fns->agent_constraints(child_rsc);
		);
}
