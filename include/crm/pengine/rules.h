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

#include <crm/crm.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/common.h>

enum expression_type {
	not_expr,
	nested_rule,
	attr_expr,
	loc_expr,
	role_expr,
	time_expr
};

extern enum expression_type find_expression_type(xmlNode *expr);

extern gboolean test_ruleset(
	xmlNode *ruleset, GHashTable *node_hash, ha_time_t *now);

extern gboolean test_rule(xmlNode *rule, GHashTable *node_hash,
			  enum rsc_role_e role, ha_time_t *now);

extern gboolean test_expression(xmlNode *expr, GHashTable *node_hash,
				enum rsc_role_e role, ha_time_t *now);

extern void unpack_instance_attributes(
	xmlNode *xml_obj, const char *set_name, GHashTable *node_hash,
	GHashTable *hash, const char *always_first, ha_time_t *now);

#endif
