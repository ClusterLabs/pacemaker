/* $Id: color.c,v 1.15 2004/08/30 03:17:38 msoffen Exp $ */
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
#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>

color_t *no_color = NULL;

color_t *add_color(resource_t *rh_resource, color_t *color);

gboolean has_agent(node_t *a_node, lrm_agent_t *agent);

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);

gboolean rsc_preproc(
	resource_t *lh_resource, GListPtr *colors, GListPtr resources);

gboolean rsc_postproc(
	resource_t *lh_resource, GListPtr *colors, GListPtr resources);

gboolean strict_postproc(rsc_to_rsc_t *constraint,
			 GListPtr *colors,
			 GListPtr resources);

gboolean strict_preproc(rsc_to_rsc_t *constraint,
			GListPtr *colors,
			GListPtr resources);

gboolean is_active(rsc_to_node_t *cons);

gboolean choose_color(resource_t *lh_resource);

gboolean assign_color(resource_t *rsc, color_t *color);

gboolean 
apply_node_constraints(GListPtr constraints, GListPtr nodes)
{
	int lpc = 0;
	int llpc = 0;
	resource_t *rsc_lh = NULL;
	GListPtr or_list = NULL;

	crm_verbose("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,
		crm_debug_action(print_rsc_to_node("Applying", cons, FALSE));
		/* take "lifetime" into account */
		if(cons == NULL) {
			crm_err("Constraint (%d) is NULL", lpc);
			continue;
			
		} else if(is_active(cons) == FALSE) {
			crm_info("Constraint (%d) is not active", lpc);
			/* warning */
			continue;
		}
    
		rsc_lh = cons->rsc_lh;
		if(rsc_lh == NULL) {
			crm_err("LHS of rsc_to_node (%s) is NULL", cons->id);
			continue;
		}

		cons->rsc_lh->node_cons =
			g_list_append(cons->rsc_lh->node_cons, cons);

		if(cons->node_list_rh == NULL) {
			crm_err("RHS of rsc_to_node (%s) is NULL", cons->id);
			continue;
		}
		crm_debug_action(print_resource("before update", rsc_lh,TRUE));

		llpc = 0;
		or_list = node_list_or(
			rsc_lh->allowed_nodes, cons->node_list_rh, FALSE);
		
		pe_free_shallow(rsc_lh->allowed_nodes);
		rsc_lh->allowed_nodes = or_list;
		slist_iter(node_rh, node_t, cons->node_list_rh, llpc,
			   update_node_weight(cons, node_rh->details->uname,
					      rsc_lh->allowed_nodes));

		crm_debug_action(print_resource("after update", rsc_lh, TRUE));
		);
	
	return TRUE;
	
}

gboolean
apply_agent_constraints(GListPtr resources)
{
	int lpc;
	int lpc2;
	slist_iter(
		rsc, resource_t, resources, lpc,

		crm_trace("Applying RA restrictions to %s", rsc->id);
		slist_iter(
			node, node_t, rsc->allowed_nodes, lpc2,
			
			crm_trace("Checking if %s supports %s/%s",
				  node->details->uname,
				  rsc->agent->class, rsc->agent->type);

			if(has_agent(node, rsc->agent) == FALSE) {
				/* remove node from contention */
				crm_trace("Marking node %s unavailable for %s",
					  node->details->uname, rsc->id);
				node->weight = -1.0;
				node->fixed = TRUE;
			}
			if(node->fixed && node->weight < 0) {
				/* the structure of the list will have changed
				 * lpc2-- might be sufficient
				 */
				crm_debug("Removing node %s from %s",
					  node->details->uname, rsc->id);

				lpc2 = -1;
				rsc->allowed_nodes = g_list_remove(
					rsc->allowed_nodes, node);
				crm_free(node);
			}
			
			)
		);
	crm_trace("Finished applying RA restrictions");
	return TRUE;
}

gboolean
has_agent(node_t *a_node, lrm_agent_t *an_agent)
{
	int lpc;
	if(a_node == NULL || an_agent == NULL || an_agent->type == NULL) {
		crm_warn("Invalid inputs");
		return FALSE;
	}
	
	crm_devel("Checking %d agents on %s",
		  g_list_length(a_node->details->agents),
		  a_node->details->uname);

	slist_iter(
		agent, lrm_agent_t, a_node->details->agents, lpc,

		crm_trace("Checking against  %s/%s",agent->class, agent->type);

		if(safe_str_eq(an_agent->type, agent->type)){
			if(an_agent->class == NULL) {
				return TRUE;
				
			} else if(safe_str_eq(an_agent->class, agent->class)) {
				if(compare_version(
					   an_agent->version, agent->version)
				   <= 0) {
					return TRUE;
				}
			}
		}
		);
	
	crm_verbose("%s doesnt support version %s of %s/%s",
		    a_node->details->uname, an_agent->version,
		    an_agent->class, an_agent->type);
	
	return FALSE;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}


gboolean
strict_preproc(rsc_to_rsc_t *constraint, GListPtr *colors, GListPtr resources)
{
	resource_t *lh_resource = constraint->rsc_lh;
	resource_t *rh_resource = constraint->rsc_rh;

	color_t *other_color = constraint->rsc_rh->color;
	color_t *local_color = NULL;
	
	float max_pri = lh_resource->effective_priority;
	float factor = 2.0;

	switch(constraint->strength) {
		case pecs_ignore:
			break;
		case pecs_startstop:
			break;
		case pecs_must:
			if(max_pri < rh_resource->effective_priority) {
				max_pri = rh_resource->effective_priority;
			}
			lh_resource->effective_priority = max_pri;
			rh_resource->effective_priority = max_pri;
			break;
			
		case pecs_should:
		case pecs_should_not:
			if(constraint->variant != same_node) {
				break;

			} else if(constraint->rsc_rh->provisional == FALSE
				&& constraint->rsc_lh->provisional) {
				local_color = add_color(lh_resource, other_color);

				if(local_color == NULL) {
					crm_err("Couldnt add color %d to %s",
						other_color?other_color->id:0,
						lh_resource->id);
					break;
				}

				if(constraint->strength == pecs_should_not) {
					factor = 1 / factor;
					create_color(colors, lh_resource, NULL);
				}
				
				/* x * should * should_not = x */
				local_color->local_weight = 
					local_color->local_weight * factor;
				
/* 			} else if(constraint->rsc_lh->provisional == FALSE */
/* 				&& constraint->rsc_rh->provisional) { */
/* 				add_color(constraint->rsc_rh, constraint->rsc_lh->color); */
			} 
			
			break;
			
		case pecs_must_not:
			if(constraint->variant != same_node) {
				break;
			} else if(constraint->rsc_rh->provisional) {
				break;
			} else if(local_color != NULL) {
				lh_resource->candidate_colors = g_list_remove(
					lh_resource->candidate_colors, local_color);
				
				crm_debug_action(
					print_color(
						"Removed",local_color,FALSE));
				
				crm_free(local_color);
			}
			break;
	}
	return TRUE;
}

gboolean
strict_postproc(rsc_to_rsc_t *constraint, GListPtr *colors, GListPtr resources)
{
	print_rsc_to_rsc("Post processing", constraint, FALSE);

	switch(constraint->strength) {
		case pecs_ignore:
		case pecs_startstop:
		case pecs_should_not:
		case pecs_should:
			break;

		case pecs_must:
			if(constraint->rsc_lh->runnable == FALSE) {
				crm_warn("Resource %s must run on the same"
					 " node as %s (cons %s), but %s is not"
					 " runnable.",
					 constraint->rsc_rh->id,
					 constraint->rsc_lh->id,
					 constraint->id,
					 constraint->rsc_lh->id);
				constraint->rsc_rh->runnable = FALSE;

			} else if(constraint->variant != same_node) {
				break;

			} else if(constraint->rsc_rh->provisional == TRUE) {


				resource_t *rh_resource = constraint->rsc_rh;
				assign_color(rh_resource, constraint->rsc_lh->color);
				color_resource(rh_resource, colors, resources);
				
			} else if(constraint->rsc_rh->provisional == FALSE
				  && constraint->rsc_rh->color->id !=
				  constraint->rsc_lh->color->id) {
				crm_err("Resource %s must run on the same"
					" node as %s (cons %s), but %s is already"
					" assigned to another color.",
					constraint->rsc_rh->id,
					constraint->rsc_lh->id,
					constraint->id,
					constraint->rsc_lh->id);
				constraint->rsc_lh->runnable = FALSE;
				return FALSE;
			}
			break;
			
		case pecs_must_not:
			if(constraint->rsc_rh->provisional == FALSE
			   && constraint->rsc_rh->color->id ==
			      constraint->rsc_lh->color->id) {
				crm_err("Resource %s must run on the same"
					" node as %s (cons %s), but %s is already"
					" assigned to another color.",
					constraint->rsc_rh->id,
					 constraint->rsc_lh->id,
					constraint->id,
					constraint->rsc_lh->id);
				constraint->rsc_lh->runnable = FALSE;
				return FALSE;
			}
			break;
	}
	return TRUE;
}

color_t *
add_color(resource_t *resource, color_t *color)
{
					
	color_t *local_color = NULL;

	if(color == NULL) {
		crm_err("Cannot add NULL color");
		return NULL;
	}
	
	local_color = find_color(resource->candidate_colors, color);

	if(local_color == NULL) {
		crm_debug("Adding color %d", color->id);
		
		local_color = copy_color(color);
		resource->candidate_colors =
			g_list_append(resource->candidate_colors, local_color);

	} else {
		crm_debug("Color %d already present", color->id);
	}

	return local_color;
}

gboolean
choose_color(resource_t *lh_resource)
{
	int lpc = 0;
	GListPtr sorted_colors = NULL;

	if(lh_resource->runnable == FALSE) {
		assign_color(lh_resource, no_color);
	}

	if(lh_resource->provisional == FALSE) {
		return !lh_resource->provisional;
	}
	
	sorted_colors = g_list_sort(
		lh_resource->candidate_colors, sort_color_weight);
	
	lh_resource->candidate_colors = sorted_colors;
	
	crm_verbose("Choose a color from %d possibilities",
		    g_list_length(sorted_colors));
	
	slist_iter(
		this_color, color_t, lh_resource->candidate_colors, lpc,
		GListPtr intersection = NULL;
		GListPtr minus = NULL;
		int len = 0;

		if(this_color == NULL) {
			crm_err("color was NULL");
			continue;
			
		} else if(lh_resource->effective_priority
		   < this_color->details->highest_priority) {

			minus = node_list_minus(
				this_color->details->candidate_nodes, 
				lh_resource->allowed_nodes, TRUE);

			len = g_list_length(minus);
			pe_free_shallow(minus);
			
			if(len > 0) {
				assign_color(lh_resource, this_color);
				break;
			}
			
		} else {
			intersection = node_list_and(
				this_color->details->candidate_nodes, 
				lh_resource->allowed_nodes, TRUE);

			len = g_list_length(intersection);
			pe_free_shallow(intersection);
			
			if(len != 0) {
				assign_color(lh_resource, this_color);
				break;
			}
		}
		);

	return !lh_resource->provisional;
}

gboolean
rsc_preproc(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	int lpc = 0;
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,

		crm_debug_action(
			print_rsc_to_rsc(
				"Processing constraint",constraint,FALSE));
		
		if(constraint->rsc_rh == NULL) {
			crm_err("rsc_rh was NULL for %s", constraint->id);
			continue;
		}		

		strict_preproc(constraint, colors, resources);
		);
	
	return TRUE;
}

gboolean
rsc_postproc(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	int lpc = 0;
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,
		strict_postproc(constraint, colors, resources);
		);
	
	return TRUE;
}

void
color_resource(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	color_t *new_color = NULL;

	crm_debug_action(print_resource("Coloring", lh_resource, FALSE));
	
	if(lh_resource->provisional == FALSE) {
		/* already processed this resource */
		return;
	}
	
	lh_resource->rsc_cons = g_list_sort(
		lh_resource->rsc_cons, sort_cons_strength);

	crm_debug_action(
		print_resource("Pre-processing", lh_resource, FALSE));

	/*------ Pre-processing */
	rsc_preproc(lh_resource, colors, resources);
	
	/* avoid looping through lists when we know this resource
	 * cant be started
	 */
	if( choose_color(lh_resource) ) {
		crm_verbose("Colored resource %s with color %d",
			    lh_resource->id, lh_resource->color->id);
		
	} else if(lh_resource->allowed_nodes != NULL) {
		/* filter out nodes with a negative weight */
		filter_nodes(lh_resource);
		new_color = create_color(colors, lh_resource, NULL);
		assign_color(lh_resource, new_color);
	}
	
	if(lh_resource->color == NULL) {
		crm_err("Could not color resource %s", lh_resource->id);
		print_resource("ERROR: No color", lh_resource, FALSE);
		assign_color(lh_resource, no_color);
	}

	lh_resource->provisional = FALSE;

	crm_debug_action(
		print_resource("Post-processing", lh_resource, FALSE));

	/*------ Post-processing */
	rsc_postproc(lh_resource, colors, resources);
	
	crm_debug_action(print_resource("Colored", lh_resource, FALSE));
}


gboolean
update_node_weight(rsc_to_node_t *cons, const char *id, GListPtr nodes)
{
	node_t *node_rh = pe_find_node(cons->rsc_lh->allowed_nodes, id);

	if(node_rh == NULL) {
		crm_err("Node not found - cant update");
		return FALSE;
	}

	if(node_rh->fixed) {
		/* warning */
		crm_warn("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %f.",
			 cons->id,
			 node_rh->details->uname,
			 node_rh->weight);
		return TRUE;
	}
	
	crm_verbose("Constraint %s (%s): node %s weight %f.",
		    cons->id,
		    cons->can?"can":"cannot",
		    node_rh->details->uname,
		    node_rh->weight);

	if(cons->can == FALSE) {
		node_rh->weight = -1;
	} else {
		node_rh->weight += cons->weight;
	}

	if(node_rh->weight < 0) {
		node_rh->fixed = TRUE;
	}

	crm_debug_action(print_node("Updated", node_rh, FALSE));

	return TRUE;
}

gboolean
assign_color(resource_t *rsc, color_t *color) 
{
	color_t *local_color = add_color(rsc, color);
	GListPtr intersection = NULL;
	GListPtr old_list = NULL;

	
	rsc->color = local_color;
	rsc->provisional = FALSE;

	if(local_color != NULL) {
		local_color->details->allocated_resources =
			g_list_append(
				local_color->details->allocated_resources,rsc);

			intersection = node_list_and(
				local_color->details->candidate_nodes, 
				rsc->allowed_nodes, TRUE);
			   
			old_list =
				local_color->details->candidate_nodes;
				
			pe_free_shallow(old_list);
			
			local_color->details->candidate_nodes = intersection;
				
		return TRUE;
	}
	return FALSE;
}


gboolean
process_colored_constraints(resource_t *rsc) 
{
	int lpc = 0;
	color_t *other_c = NULL;
	node_t *other_n = NULL;


	if(rsc == NULL) {
		crm_err("No constraints for NULL resource");
		return FALSE;
	} else {
		crm_debug("Processing constraints from %s", rsc->id);
	}
	
	slist_iter(
		constraint, rsc_to_rsc_t, rsc->rsc_cons, lpc,
		
		if(constraint->variant != same_node) {
			continue;
		}
		
		/* remove the node from the other color */
		other_c = constraint->rsc_rh->color;
		other_n = pe_find_node(
			other_c->details->candidate_nodes,
			safe_val6(NULL, rsc, color, details,
				  chosen_node, details, uname));
		
		if(other_c == NULL) {
			crm_err("No color associated with %s",
				constraint->id);
			continue;
		} else if(other_n == NULL) {
			crm_err("No node associated with rsc/color %s/%d",
				rsc->id, rsc->color->id);
			continue;
		}
		
		switch(constraint->strength) {
			case pecs_must_not:
				other_c->details->candidate_nodes =
					g_list_remove(
						other_c->details->candidate_nodes,
						other_n);
				
				crm_free(other_n);
				break;
			case pecs_should_not:
				other_n->weight = -1;
				break;
			default:
				break;
		}
		);
	return TRUE;
}

