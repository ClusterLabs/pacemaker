/* $Id: utils.c,v 1.147 2006/07/05 14:20:02 andrew Exp $ */
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
	inverted_con->score = constraint->score;

	/* swap the direction */
	inverted_con->rsc_lh = constraint->rsc_rh;
	inverted_con->rsc_rh = constraint->rsc_lh;
	inverted_con->role_lh = constraint->role_rh;
	inverted_con->role_rh = constraint->role_lh;

	crm_action_debug_3(
		print_rsc_colocation("Inverted constraint", inverted_con, FALSE));
	
	return inverted_con;
}


gint sort_cons_strength(gconstpointer a, gconstpointer b)
{
	const rsc_colocation_t *rsc_constraint1 = (const rsc_colocation_t*)a;
	const rsc_colocation_t *rsc_constraint2 = (const rsc_colocation_t*)b;

	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
  
	if(rsc_constraint1->score > rsc_constraint2->score) {
		return 1;
	}
	
	if(rsc_constraint1->score < rsc_constraint2->score) {
		return -1;
	}
	return 0;
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

		crm_debug_4("\t%s --> %s, %d",
			  safe_val3(NULL, cons, rsc_lh, id), 
			  safe_val3(NULL, cons, rsc_rh, id), 
			  cons->score);
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


gboolean
can_run_resources(const node_t *node)
{
	if(node->details->online == FALSE
	   || node->details->shutdown
	   || node->details->unclean
	   || node->details->standby) {
		crm_debug_2("%s: online=%d, unclean=%d, standby=%d",
			    node->details->uname, node->details->online,
			    node->details->unclean, node->details->standby);
		return FALSE;
	}
	return TRUE;
}

/* return -1 if 'a' is more preferred
 * return  1 if 'b' is more preferred
 */
gint sort_node_weight(gconstpointer a, gconstpointer b)
{
	const node_t *node1 = (const node_t*)a;
	const node_t *node2 = (const node_t*)b;

	int node1_weight = 0;
	int node2_weight = 0;
	
	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }

	node1_weight = node1->weight;
	node2_weight = node2->weight;
	
	if(can_run_resources(node1) == FALSE) {
		node1_weight  = -INFINITY; 
	}
	if(can_run_resources(node2) == FALSE) {
		node2_weight  = -INFINITY; 
	}

	if(node1_weight > node2_weight) {
		crm_debug_3("%s (%d) > %s (%d) : weight",
			    node1->details->uname, node1_weight,
			    node2->details->uname, node2_weight);
		return -1;
	}
	
	if(node1_weight < node2_weight) {
		crm_debug_3("%s (%d) < %s (%d) : weight",
			    node1->details->uname, node1_weight,
			    node2->details->uname, node2_weight);
		return 1;
	}

	crm_debug_3("%s (%d) == %s (%d) : weight",
		    node1->details->uname, node1_weight,
		    node2->details->uname, node2_weight);
	
	/* now try to balance resources across the cluster */
	if(node1->details->num_resources
	   < node2->details->num_resources) {
		crm_debug_3("%s (%d) < %s (%d) : resources",
			    node1->details->uname, node1->details->num_resources,
			    node2->details->uname, node2->details->num_resources);
		return -1;
		
	} else if(node1->details->num_resources
		  > node2->details->num_resources) {
		crm_debug_3("%s (%d) > %s (%d) : resources",
			    node1->details->uname, node1->details->num_resources,
			    node2->details->uname, node2->details->num_resources);
		return 1;
	}
	
	crm_debug_4("%s = %s", node1->details->uname, node2->details->uname);
	return 0;
}


gboolean
native_assign_node(resource_t *rsc, GListPtr nodes, node_t *chosen)
{
	int multiple = 0;
	CRM_ASSERT(rsc->variant == pe_native);

	rsc->provisional = FALSE;
	
	if(chosen == NULL) {
		crm_debug("Could not allocate a node for %s", rsc->id);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;

	} else if(can_run_resources(chosen) == FALSE) {
		crm_debug("All nodes for color %s are unavailable"
			  ", unclean or shutting down", rsc->id);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;
		
	} else if(chosen->weight < 0) {
		crm_debug("Even highest ranked node for %s, had weight %d",
			  rsc->id, chosen->weight);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;
	}

	if(rsc->next_role == RSC_ROLE_UNKNOWN) {
		rsc->next_role = RSC_ROLE_STARTED;
	}
	
	slist_iter(candidate, node_t, nodes, lpc, 
		   crm_debug("Color %s, Node[%d] %s: %d", rsc->id, lpc,
			     candidate->details->uname, candidate->weight);
		   if(chosen->weight > 0
		      && candidate->details->unclean == FALSE
		      && candidate->weight == chosen->weight) {
			   multiple++;
		   }
		);

	if(multiple > 1) {
		int log_level = LOG_INFO;
		char *score = score2char(chosen->weight);
		if(chosen->weight >= INFINITY) {
			log_level = LOG_WARNING;
		}
		
		crm_log_maybe(log_level, "%d nodes with equal score (%s) for"
			      " running the listed resources (chose %s):",
			      multiple, score, chosen->details->uname);
		crm_free(score);
	}
	
	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */

	if(rsc->allocated_to) {
		node_t *old = rsc->allocated_to;
		old->details->allocated_rsc = g_list_remove(
			old->details->allocated_rsc, rsc);
		old->details->num_resources--;
		old->count--;
	}
	
	crm_debug("Assigning %s to %s", chosen->details->uname, rsc->id);
	crm_free(rsc->allocated_to);
	rsc->allocated_to = node_copy(chosen);

	chosen->details->allocated_rsc = g_list_append(chosen->details->allocated_rsc, rsc);
	chosen->details->num_resources++;
	chosen->count++;

	return TRUE;
}
