/* $Id: color.c,v 1.3 2004/06/08 11:47:48 andrew Exp $ */
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

gboolean has_agent(node_t *a_node, const char *class, const char *type);

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);

gboolean rsc_preproc(
	resource_t *lh_resource, GListPtr *colors, GListPtr resources);

gboolean rsc_postproc(
	resource_t *lh_resource, GListPtr *colors, GListPtr resources);

gboolean strict_postproc(rsc_to_rsc_t *constraint,
			 color_t *local_color,
			 color_t *other_color,
			 GListPtr *colors,
			 GListPtr resources);

gboolean strict_preproc(rsc_to_rsc_t *constraint,
			color_t *local_color,
			color_t *other_color,
			GListPtr *colors,
			GListPtr resources);

gboolean is_active(rsc_to_node_t *cons);

gboolean choose_color(resource_t *lh_resource);


gboolean 
apply_node_constraints(GListPtr constraints, GListPtr nodes)
{
	crm_verbose("Applying constraints...");
	int lpc = 0;
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,
		crm_debug_action(print_rsc_to_node("Applying", cons, FALSE));
		// take "lifetime" into account
		if(cons == NULL) {
			crm_err("Constraint (%d) is NULL", lpc);
			continue;
			
		} else if(is_active(cons) == FALSE) {
			crm_info("Constraint (%d) is not active", lpc);
			// warning
			continue;
		}
    
		resource_t *rsc_lh = cons->rsc_lh;
		if(rsc_lh == NULL) {
			crm_err("LHS of rsc_to_node (%s) is NULL", cons->id);
			continue;
		}

		cons->rsc_lh->node_cons =
			g_list_append(cons->rsc_lh->node_cons, cons);

		if(cons->node_list_rh == NULL) {
			crm_err("RHS of rsc_to_node (%s) is NULL", cons->id);
			continue;
		} else {
			int llpc = 0;
			slist_iter(node_rh, node_t, cons->node_list_rh, llpc,
				   update_node_weight(
					   cons, node_rh->details->id, nodes));
		}
		
		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
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
				  node->details->id, rsc->class, rsc->type);
			if(has_agent(node, rsc->class, rsc->type) == FALSE) {
				/* remove node from contention */
				crm_trace("Marking node %s unavailable for %s",
					  node->details->id, rsc->id);
				node->weight = -1.0;
				node->fixed = TRUE;
			}
			if(node->fixed && node->weight < 0) {
				/* the structure of the list will have changed
				 * lpc2-- might be sufficient
				 */
				crm_debug("Removing node %s from %s",
					  node->details->id, rsc->id);

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
has_agent(node_t *a_node, const char *class, const char *type)
{
	int lpc;
	if(a_node == NULL || type == NULL) {
		crm_warn("Invalid inputs");
		return FALSE;
	}
	

	slist_iter(
		agent, lrm_agent_t, a_node->details->agents, lpc,

		crm_trace("Checking against  %s/%s",agent->class, agent->type);

		if(safe_str_eq(type, agent->type)){
			if(class == NULL) {
				return TRUE;
			} else if(safe_str_eq(class, agent->class)) {
				return TRUE;
			}
		}
		);
	
	crm_verbose("%s doesnt support %s/%s",a_node->details->id,class,type);
	
	return FALSE;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}

gboolean
strict_preproc(rsc_to_rsc_t *constraint,
	       color_t *local_color, color_t *other_color,
	       GListPtr *colors, GListPtr resources)
{
	resource_t * lh_resource = constraint->rsc_lh;
	switch(constraint->strength) {
		case must:
			if(constraint->rsc_rh->runnable == FALSE) {
				crm_warn("Resource %s must run on the same"
					 " node as %s (cons %s), but %s is not"
					 " runnable.",
					 constraint->rsc_lh->id,
					 constraint->rsc_rh->id,
					 constraint->id,
					 constraint->rsc_rh->id);
				constraint->rsc_lh->runnable = FALSE;
			}
			break;
			
			// x * should * should_not = x
		case should:
			if(constraint->rsc_rh->provisional == FALSE) {
				local_color->local_weight = 
					local_color->local_weight * 2.0;
			}
				break;
		case should_not:
			if(constraint->rsc_rh->provisional == FALSE) {
				local_color->local_weight = 
					local_color->local_weight * 0.5;
			}

//			if(g_list_length(lh_resource->candidate_colors)==1)
			create_color(
				colors, lh_resource->allowed_nodes, resources);
			
			
			break;
		case must_not:
			if(constraint->rsc_rh->provisional == FALSE
				&& local_color->id != no_color->id) {
				lh_resource->candidate_colors =
					g_list_remove(
						lh_resource->candidate_colors,
						local_color);
				crm_debug_action(
					print_color(
						"Removed",local_color,FALSE));
				
// surely this is required... but mtrace says no...
//				crm_free(local_color);
			}
			break;
		default:
			// error
			break;
	}
	return TRUE;
}

gboolean
strict_postproc(rsc_to_rsc_t *constraint,
		color_t *local_color, color_t *other_color,
		GListPtr *colors, GListPtr resources)
{
	print_rsc_to_rsc("Post processing", constraint, FALSE);
	
	switch(constraint->strength) {
		case must:
			if(constraint->rsc_rh->provisional == TRUE) {
				constraint->rsc_rh->color = other_color;
				constraint->rsc_rh->provisional = FALSE;
				color_resource(constraint->rsc_rh,
					       colors, resources);
			}
			// else check for error
			if(constraint->rsc_lh->runnable == FALSE) {
				crm_warn("Resource %s must run on the same"
					 " node as %s (cons %s), but %s is not"
					 " runnable.",
					 constraint->rsc_rh->id,
					 constraint->rsc_lh->id,
					 constraint->id,
					 constraint->rsc_lh->id);
				constraint->rsc_rh->runnable = FALSE;
			}
			
			break;
			
		case should:
			break;
		case should_not:
			break;
		case must_not:
			if(constraint->rsc_rh->provisional == TRUE) {
				// check for error
			}
			break;
		default:
			// error
			break;
	}
	return TRUE;
}

gboolean
choose_color(resource_t *lh_resource)
{
	int lpc = 0;

	if(lh_resource->runnable == FALSE) {
		lh_resource->color = find_color(
			lh_resource->candidate_colors, no_color);
		lh_resource->provisional = FALSE;

	}

	if(lh_resource->provisional) {
		GListPtr sorted_colors = g_list_sort(
			lh_resource->candidate_colors, sort_color_weight);
		
		lh_resource->candidate_colors = sorted_colors;
	
		crm_verbose("Choose a color from %d possibilities",
			    g_list_length(sorted_colors));

		slist_iter(
			this_color, color_t,lh_resource->candidate_colors, lpc,
			GListPtr intersection = node_list_and(
				this_color->details->candidate_nodes, 
				lh_resource->allowed_nodes);

			if(g_list_length(intersection) != 0) {
				// TODO: merge node weights
				GListPtr old_list =
					this_color->details->candidate_nodes;

				pe_free_shallow(old_list);
				
				this_color->details->candidate_nodes =
					intersection;
				
				lh_resource->color = this_color;
				lh_resource->provisional = FALSE;
				break;
			} else {
				pe_free_shallow(intersection);
			}
			
			);
	}
	return !lh_resource->provisional;
}

gboolean
rsc_preproc(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	int lpc = 0;
	color_t *other_color = NULL;
	color_t *local_color = NULL;
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,
		if(lh_resource->runnable == FALSE) {
			return FALSE;
		}

		crm_debug_action(
			print_rsc_to_rsc(
				"Processing constraint",constraint,FALSE));
		
		if(constraint->rsc_rh == NULL) {
			crm_err("rsc_rh was NULL for %s", constraint->id);
			continue;
		}
		other_color = constraint->rsc_rh->color;
		local_color = find_color(
			lh_resource->candidate_colors, other_color);

		strict_preproc(
			constraint,local_color,other_color,colors,resources);
		);
	
	return TRUE;
}

gboolean
rsc_postproc(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	int lpc = 0;
	color_t *local_color = lh_resource->color;
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,
		color_t *other_color = find_color(
			constraint->rsc_rh->candidate_colors, local_color);
		
		strict_postproc(
			constraint, local_color, other_color,colors,resources);
		);
	
	return TRUE;
}

void
color_resource(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	crm_debug_action(print_resource("Coloring", lh_resource, FALSE));
	
	if(lh_resource->provisional == FALSE) {
		// already processed this resource
		return;
	}
	
	lh_resource->rsc_cons = g_list_sort(
		lh_resource->rsc_cons, sort_cons_strength);

	crm_debug_action(
		print_resource("Pre-processing", lh_resource, FALSE));

	//------ Pre-processing
	rsc_preproc(lh_resource, colors, resources);
	
	// filter out nodes with a negative weight
	filter_nodes(lh_resource);

	/* avoid looping through lists when we know this resource
	 * cant be started
	 */
	if(lh_resource->allowed_nodes != NULL) {
		/* Choose a color from the candidates or,
		 *  create a new one if no color is suitable 
		 * (this may need modification pending further napkin drawings)
		 */
		choose_color(lh_resource);	
  
		crm_verbose("* Colors %d, Nodes %d",
			    g_list_length(*colors),max_valid_nodes);
	
		if(lh_resource->provisional) {
			lh_resource->color = create_color(
				colors, lh_resource->allowed_nodes, resources);
		}
	}
	
	if(lh_resource->color == NULL) {
		crm_err("Could not color resource %s", lh_resource->id);
		print_resource("ERROR: No color", lh_resource, FALSE);
		lh_resource->color = find_color(
			lh_resource->candidate_colors, no_color);
	}

	lh_resource->provisional = FALSE;

	crm_debug_action(
		print_resource("Post-processing", lh_resource, FALSE));

	//------ Post-processing
	rsc_postproc(lh_resource, colors, resources);
	
	crm_debug_action(print_resource("Colored", lh_resource, FALSE));
}


gboolean
update_node_weight(rsc_to_node_t *cons, const char *id, GListPtr nodes)
{
	node_t *node_rh = pe_find_node(cons->rsc_lh->allowed_nodes, id);

	if(node_rh == NULL) {
		node_t *node_tmp = pe_find_node(nodes, id);
		node_rh = node_copy(node_tmp);
		cons->rsc_lh->allowed_nodes =
			g_list_append(cons->rsc_lh->allowed_nodes, node_rh);
	}

	if(node_rh == NULL) {
		// error
		return FALSE;
	}

	if(node_rh->fixed) {
		// warning
		crm_warn("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %f.",
			 cons->id,
			 node_rh->details->id,
			 node_rh->weight);
		return TRUE;
	}
	
	crm_verbose("Constraint %s: node %s weight %s %f.",
		      cons->id,
		      node_rh->details->id,
		      modifier2text(cons->modifier),
		      node_rh->weight);
	
	switch(cons->modifier) {
		case set:
			node_rh->weight = cons->weight;
			node_rh->fixed = TRUE;
			break;
		case inc:
			node_rh->weight += cons->weight;
			break;
		case dec:
			node_rh->weight -= cons->weight;
			break;
		case modifier_none:
			// warning
			break;
	}
	return TRUE;
}
