/* $Id: utils.h,v 1.3 2006/07/05 14:20:02 andrew Exp $ */
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
#ifndef PENGINE_AUTILS__H
#define PENGINE_AUTILS__H

/* Constraint helper functions */
extern rsc_colocation_t *invert_constraint(rsc_colocation_t *constraint);

extern rsc_to_node_t *copy_constraint(rsc_to_node_t *constraint);

extern void print_rsc_to_node(
	const char *pre_text, rsc_to_node_t *cons, gboolean details);

extern void print_rsc_colocation(
	const char *pre_text, rsc_colocation_t *cons, gboolean details);

extern rsc_to_node_t *rsc2node_new(
	const char *id, resource_t *rsc, int weight, node_t *node,
	pe_working_set_t *data_set);

extern void pe_free_rsc_to_node(GListPtr constraints);
extern void pe_free_ordering(GListPtr constraints);

extern const char *ordering_type2text(enum pe_ordering type);

extern gboolean rsc_colocation_new(
	const char *id, int score,
	resource_t *rsc_lh, resource_t *rsc_rh,
	const char *state_lh, const char *state_rh);

extern rsc_to_node_t *generate_location_rule(
	resource_t *rsc, crm_data_t *location_rule, pe_working_set_t *data_set);

extern gint sort_cons_strength(gconstpointer a, gconstpointer b);
extern gint sort_node_weight(gconstpointer a, gconstpointer b);

extern gboolean can_run_resources(const node_t *node);

#endif
