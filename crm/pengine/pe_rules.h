/* $Id: pe_rules.h,v 1.5 2005/09/15 08:05:24 andrew Exp $ */
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
#ifndef PENGINE_RULES__H
#define PENGINE_RULES__H

enum expression_type {
	not_expr,
	nested_rule,
	attr_expr,
	loc_expr,
	role_expr,
	time_expr
};

extern enum expression_type find_expression_type(crm_data_t *expr);

extern gboolean test_ruleset(
	crm_data_t *ruleset, node_t *node, pe_working_set_t *data_set);

extern gboolean test_rule(crm_data_t *rule, node_t *node, resource_t *rsc,
			  pe_working_set_t *data_set);

extern gboolean test_expression(crm_data_t *expr, node_t *node, resource_t *rsc,
				pe_working_set_t *data_set);

#endif
