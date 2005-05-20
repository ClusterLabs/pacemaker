/* $Id: color.c,v 1.28 2005/05/20 09:58:43 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>

color_t *no_color = NULL;

color_t *add_color(resource_t *rh_resource, color_t *color);

gboolean 
apply_placement_constraints(GListPtr constraints, GListPtr nodes)
{
	crm_debug_3("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,

		cons->rsc_lh->fns->rsc_location(cons->rsc_lh, cons);
		);
	
	return TRUE;
	
}

gboolean
apply_agent_constraints(GListPtr resources)
{
	slist_iter(
		rsc, resource_t, resources, lpc,
		rsc->fns->agent_constraints(rsc);
		);
	crm_debug_5("Finished applying RA restrictions");
	return TRUE;
}

color_t *
add_color(resource_t *resource, color_t *color)
{
	color_t *local_color = NULL;

	if(color == NULL) {
		pe_err("Cannot add NULL color");
		return NULL;
	}
	
	local_color = find_color(resource->candidate_colors, color);

	if(local_color == NULL) {
		crm_debug_4("Adding color %d", color->id);
		
		local_color = copy_color(color);
		resource->candidate_colors =
			g_list_append(resource->candidate_colors, local_color);

	} else {
		crm_debug_4("Color %d already present", color->id);
	}

	return local_color;
}

void
color_resource(resource_t *rsc, GListPtr *colors, GListPtr resources)
{
	crm_action_debug_3(print_resource("Coloring", rsc, FALSE));
	
	if(rsc->provisional == FALSE) {
		/* already processed this resource */
		return;
	}
	
	rsc->rsc_cons = g_list_sort(
		rsc->rsc_cons, sort_cons_strength);

	crm_action_debug_3(
		print_resource("Pre-processing", rsc, FALSE));

	/*------ Pre-processing */
	slist_iter(
		constraint, rsc_colocation_t, rsc->rsc_cons, lpc,

		crm_action_debug_3(
			print_rsc_colocation(
				"Pre-Processing constraint", constraint,FALSE));
		
		rsc->fns->rsc_colocation_lh(constraint);
		);
	
	/* avoid looping through lists when we know this resource
	 * cant be started
	 */

	rsc->fns->color(rsc, colors);

	crm_action_debug_3(
		print_resource("Post-processing", rsc, TRUE));

	/*------ Post-processing */
	slist_iter(
		constraint, rsc_colocation_t, rsc->rsc_cons, lpc,
		crm_action_debug_3(
			print_rsc_colocation(
				"Post-Processing constraint",constraint,FALSE));
		rsc->fns->rsc_colocation_lh(constraint);
		);
	
	crm_action_debug_3(print_resource("Colored", rsc, TRUE));
}




