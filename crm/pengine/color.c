/* $Id: color.c,v 1.20 2004/11/09 14:49:14 andrew Exp $ */
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

gboolean 
apply_placement_constraints(GListPtr constraints, GListPtr nodes)
{
	int lpc = 0;

	crm_verbose("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,

		cons->rsc_lh->fns->rsc_location(cons->rsc_lh, cons);
		);
	
	return TRUE;
	
}

gboolean
apply_agent_constraints(GListPtr resources)
{
	int lpc;
	slist_iter(
		rsc, resource_t, resources, lpc,
		rsc->fns->agent_constraints(rsc);
		);
	crm_trace("Finished applying RA restrictions");
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




