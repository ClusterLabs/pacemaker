/* $Id: color.c,v 1.19 2004/11/09 09:32:14 andrew Exp $ */
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

gboolean choose_color(resource_t *lh_resource);

gboolean assign_color(resource_t *rsc, color_t *color);

gboolean 
apply_placement_constraints(GListPtr constraints, GListPtr nodes)
{
	int lpc = 0;

	crm_verbose("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,

		cons->rsc_lh->fns->rsc_location(cons);
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
			
			crm_trace("Checking if %s supports %s/%s (%s)",
				  node->details->uname,
				  rsc->agent->class, rsc->agent->type,
				  rsc->agent->version);

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

		crm_trace("Checking against  %s/%s (%s)",
			  agent->class, agent->type, agent->version);

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

void
color_resource(resource_t *lh_resource, GListPtr *colors, GListPtr resources)
{
	int lpc = 0;

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
	slist_iter(
		constraint, rsc_dependancy_t, lh_resource->rsc_cons, lpc,

		crm_debug_action(
			print_rsc_dependancy(
				"Pre-Processing constraint", constraint,FALSE));
		
		if(constraint->rsc_rh == NULL) {
			crm_err("rsc_rh was NULL for %s", constraint->id);
			continue;
		}		
		lh_resource->fns->rsc_dependancy_lh(constraint);
		);
	
	/* avoid looping through lists when we know this resource
	 * cant be started
	 */

	lh_resource->fns->color(lh_resource, colors);

	crm_debug_action(
		print_resource("Post-processing", lh_resource, TRUE));

	/*------ Post-processing */
	slist_iter(
		constraint, rsc_dependancy_t, lh_resource->rsc_cons, lpc,
		crm_debug_action(
			print_rsc_dependancy(
				"Post-Processing constraint",constraint,FALSE));
		lh_resource->fns->rsc_dependancy_lh(constraint);
		);
	
	crm_debug_action(print_resource("Colored", lh_resource, TRUE));
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
			   
			old_list = local_color->details->candidate_nodes;
				
			pe_free_shallow(old_list);
			
			local_color->details->candidate_nodes = intersection;
				
			crm_verbose("Colored resource %s with new color %d",
				    rsc->id, rsc->color->id);
			
			crm_debug_action(
				print_resource("Colored Resource", rsc, TRUE));
			
		return TRUE;
	} else {
		crm_err("local color was NULL");
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
		constraint, rsc_dependancy_t, rsc->rsc_cons, lpc,
		
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
			default:
				break;
		}
		);
	return TRUE;
}

