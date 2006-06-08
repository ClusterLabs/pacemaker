/* $Id: utils.c,v 1.145 2006/06/08 13:39:10 andrew Exp $ */
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

#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>
#include <lib/crm/pengine/utils.h>

/* only for rsc_colocation constraints */
rsc_colocation_t *
invert_constraint(rsc_colocation_t *constraint) 
{
	rsc_colocation_t *inverted_con = NULL;

	crm_debug_3("Inverting constraint");
	if(constraint == NULL) {
		pe_err("Cannot invert NULL constraint");
		return NULL;
	}

	crm_malloc0(inverted_con, sizeof(rsc_colocation_t));

	if(inverted_con == NULL) {
		return NULL;
	}
	
	inverted_con->id = constraint->id;
	inverted_con->strength = constraint->strength;

	/* swap the direction */
	inverted_con->rsc_lh = constraint->rsc_rh;
	inverted_con->rsc_rh = constraint->rsc_lh;
	inverted_con->state_lh = constraint->state_rh;
	inverted_con->state_rh = constraint->state_lh;

	crm_action_debug_3(
		print_rsc_colocation("Inverted constraint", inverted_con, FALSE));
	
	return inverted_con;
}

/*
 * Create a new color with the contents of "nodes" as the list of
 *  possible nodes that resources with this color can be run on.
 *
 * Typically, when creating a color you will provide the node list from
 *  the resource you will first assign the color to.
 *
 * If "colors" != NULL, it will be added to that list
 * If "resources" != NULL, it will be added to every provisional resource
 *  in that list
 */
color_t *
create_color(
	pe_working_set_t *data_set, resource_t *resource, GListPtr node_list)
{
	color_t *new_color = NULL;
	
	crm_debug_5("Creating color");
	crm_malloc0(new_color, sizeof(color_t));
	if(new_color == NULL) {
		return NULL;
	}
	
	new_color->id           = data_set->color_id++;
	new_color->local_weight = 1.0;
	
	crm_debug_5("Creating color details");
	crm_malloc0(new_color->details, sizeof(struct color_shared_s));

	if(new_color->details == NULL) {
		crm_free(new_color);
		return NULL;
	}
		
	new_color->details->id                  = new_color->id;
	new_color->details->highest_priority    = -1;
	new_color->details->chosen_node         = NULL;
	new_color->details->candidate_nodes     = NULL;
	new_color->details->allocated_resources = NULL;
	new_color->details->pending             = TRUE;
	
	if(resource != NULL) {
		crm_debug_5("populating node list");
		new_color->details->highest_priority = resource->priority;
		new_color->details->candidate_nodes  =
			node_list_dup(node_list, TRUE, TRUE);
	}
	
	crm_action_debug_3(print_color("Created color", new_color, TRUE));

	CRM_CHECK(data_set != NULL, return NULL);
	data_set->colors = g_list_append(data_set->colors, new_color);
	return new_color;
}

color_t *
copy_color(color_t *a_color) 
{
	color_t *color_copy = NULL;

	if(a_color == NULL) {
		pe_err("Cannot copy NULL");
		return NULL;
	}
	
	crm_malloc0(color_copy, sizeof(color_t));
	if(color_copy != NULL) {
		color_copy->id      = a_color->id;
		color_copy->details = a_color->details;
		color_copy->local_weight = 1.0;
	}
	return color_copy;
}

gint gslist_color_compare(gconstpointer a, gconstpointer b);
color_t *
find_color(GListPtr candidate_colors, color_t *other_color)
{
	GListPtr tmp = g_list_find_custom(candidate_colors, other_color,
					    gslist_color_compare);
	if(tmp != NULL) {
		return (color_t *)tmp->data;
	}
	return NULL;
}


gint gslist_color_compare(gconstpointer a, gconstpointer b)
{
	const color_t *color_a = (const color_t*)a;
	const color_t *color_b = (const color_t*)b;

/*	crm_debug_5("%d vs. %d", a?color_a->id:-2, b?color_b->id:-2); */
	if(a == b) {
		return 0;
	} else if(a == NULL || b == NULL) {
		return 1;
	} else if(color_a->id == color_b->id) {
		return 0;
	}
	return 1;
}

gint sort_cons_strength(gconstpointer a, gconstpointer b)
{
	const rsc_colocation_t *rsc_constraint1 = (const rsc_colocation_t*)a;
	const rsc_colocation_t *rsc_constraint2 = (const rsc_colocation_t*)b;

	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
  
	if(rsc_constraint1->strength > rsc_constraint2->strength) {
		return 1;
	}
	
	if(rsc_constraint1->strength < rsc_constraint2->strength) {
		return -1;
	}
	return 0;
}

gint sort_color_weight(gconstpointer a, gconstpointer b)
{
	const color_t *color1 = (const color_t*)a;
	const color_t *color2 = (const color_t*)b;

	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
  
	if(color1->local_weight > color2->local_weight) {
		return -1;
	}
	
	if(color1->local_weight < color2->local_weight) {
		return 1;
	}
	
	return 0;
}


void
print_color_details(const char *pre_text,
		    struct color_shared_s *color,
		    gboolean details)
{ 
	if(color == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%sColor %d: node=%s (from %d candidates)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       color->id, 
	       color->chosen_node==NULL?"<unset>":color->chosen_node->details->uname,
	       g_list_length(color->candidate_nodes)); 
	if(details) {
		slist_iter(node, node_t, color->candidate_nodes, lpc,
			   print_node("\t", node, FALSE));
	}
}

void
print_color(const char *pre_text, color_t *color, gboolean details)
{ 
	if(color == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%sColor %d: (weight=%d, node=%s, possible=%d)",
		    pre_text==NULL?"":pre_text,
		    pre_text==NULL?"":": ",
		    color->id, 
		    color->local_weight,
		    safe_val5("<unset>",color,details,chosen_node,details,uname),
		    g_list_length(color->details->candidate_nodes)); 
	if(details) {
		print_color_details("\t", color->details, details);
	}
}

void
print_rsc_to_node(const char *pre_text, rsc_to_node_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%s%s Constraint %s (%p) - %d nodes:",
		    pre_text==NULL?"":pre_text,
		    pre_text==NULL?"":": ",
		    "rsc_to_node",
		    cons->id, cons,
		    g_list_length(cons->node_list_rh));

	if(details == FALSE) {
		crm_debug_4("\t%s (node placement rule)",
			  safe_val3(NULL, cons, rsc_lh, id));

		slist_iter(
			node, node_t, cons->node_list_rh, lpc,
			print_node("\t\t-->", node, FALSE)
			);
	}
}

void
print_rsc_colocation(const char *pre_text, rsc_colocation_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%s%s Constraint %s (%p):",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       XML_CONS_TAG_RSC_DEPEND, cons->id, cons);

	if(details == FALSE) {

		crm_debug_4("\t%s --> %s, %s",
			  safe_val3(NULL, cons, rsc_lh, id), 
			  safe_val3(NULL, cons, rsc_rh, id), 
			  strength2text(cons->strength));
	}
} 

void
pe_free_colors(GListPtr colors)
{
	GListPtr iterator = colors;
	while(iterator != NULL) {
		color_t *color = (color_t *)iterator->data;
		struct color_shared_s *details = color->details;
		iterator = iterator->next;
		
		if(details != NULL) {
			pe_free_shallow(details->candidate_nodes);
			pe_free_shallow_adv(details->allocated_resources, FALSE);
			crm_free(details->chosen_node);
			crm_free(details);
		}
		crm_free(color);
	}
	if(colors != NULL) {
		g_list_free(colors);
	}
}


void
pe_free_ordering(GListPtr constraints) 
{
	GListPtr iterator = constraints;
	while(iterator != NULL) {
		order_constraint_t *order = iterator->data;
		iterator = iterator->next;

		crm_free(order->lh_action_task);
		crm_free(order->rh_action_task);
		crm_free(order);
	}
	if(constraints != NULL) {
		g_list_free(constraints);
	}
}


void
pe_free_rsc_to_node(GListPtr constraints)
{
	GListPtr iterator = constraints;
	while(iterator != NULL) {
		rsc_to_node_t *cons = iterator->data;
		iterator = iterator->next;

		pe_free_shallow(cons->node_list_rh);
		crm_free(cons);
	}
	if(constraints != NULL) {
		g_list_free(constraints);
	}
}


rsc_to_node_t *
rsc2node_new(const char *id, resource_t *rsc,
	     int node_weight, node_t *foo_node, pe_working_set_t *data_set)
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
		new_con->role_filter = RSC_ROLE_UNKNOWN;
		
		if(foo_node != NULL) {
			node_t *copy = node_copy(foo_node);
			copy->weight = node_weight;
			new_con->node_list_rh = g_list_append(NULL, copy);
		} else {
			CRM_CHECK(node_weight == 0, return NULL);
		}
		
		data_set->placement_constraints = g_list_append(
			data_set->placement_constraints, new_con);
		rsc->rsc_location = g_list_append(
			rsc->rsc_location, new_con);
	}
	
	return new_con;
}



const char *
strength2text(enum con_strength strength)
{
	const char *result = "<unknown>";
	switch(strength)
	{
		case pecs_ignore:
			result = "ignore";
			break;
		case pecs_must:
			result = XML_STRENGTH_VAL_MUST;
			break;
		case pecs_must_not:
			result = XML_STRENGTH_VAL_MUSTNOT;
			break;
		case pecs_startstop:
			result = "start/stop";
			break;
	}
	return result;
}

const char *
ordering_type2text(enum pe_ordering type)
{
	const char *result = "<unknown>";
	switch(type)
	{
		case pe_ordering_manditory:
			result = "manditory";
			break;
		case pe_ordering_restart:
			result = "restart";
			break;
		case pe_ordering_recover:
			result = "recover";
			break;
		case pe_ordering_optional:
			result = "optional";
			break;
		case pe_ordering_postnotify:
			result = "post_notify";
			break;
	}
	return result;
}
