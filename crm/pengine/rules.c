/* $Id: rules.c,v 1.24 2006/05/11 12:13:06 andrew Exp $ */
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

#include <portability.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <pengine.h>
#include <pe_utils.h>
#include <pe_rules.h>

#include <crm/common/iso8601.h>

ha_time_t *parse_xml_duration(ha_time_t *start, crm_data_t *duration_spec);

gboolean test_date_expression(crm_data_t *time_expr, pe_working_set_t *data_set);
gboolean cron_range_satisfied(ha_time_t *now, crm_data_t *cron_spec);
gboolean test_attr_expression(
	crm_data_t *expr, GHashTable *hash, pe_working_set_t *data_set);
gboolean test_role_expression(
	crm_data_t *expr, resource_t *rsc, pe_working_set_t *data_set);

gboolean
test_ruleset(crm_data_t *ruleset, node_t *node, pe_working_set_t *data_set) 
{
	gboolean ruleset_default = TRUE;
	xml_child_iter_filter(
		ruleset, rule, XML_TAG_RULE,

		ruleset_default = FALSE;
		if(test_rule(rule, node, NULL, data_set)) {
			return TRUE;
		}
		);
	
	return ruleset_default;
}

gboolean
test_rule(crm_data_t *rule, node_t *node, resource_t *rsc,
	  pe_working_set_t *data_set) 
{
	gboolean test = TRUE;
	gboolean passed = TRUE;
	gboolean do_and = TRUE;

	const char *value = crm_element_value(rule, "boolean_op");
	if(safe_str_eq(value, "or")) {
		do_and = FALSE;
		passed = FALSE;
	}

	crm_debug_2("Testing rule %s", ID(rule));
	xml_child_iter(
		rule, expr, 
		test = test_expression(expr, node, rsc, data_set);
		
		if(test && do_and == FALSE) {
			crm_debug_3("Expression %s/%s passed",
				    ID(rule), ID(expr));
			return TRUE;
			
		} else if(test == FALSE && do_and) {
			crm_debug_3("Expression %s/%s failed",
				    ID(rule), ID(expr));
			return FALSE;
		}
		);
		
	crm_debug_2("Rule %s %s", ID(rule), passed?"passed":"failed");
	return passed;
}

gboolean
test_expression(crm_data_t *expr, node_t *node, resource_t *rsc,
		pe_working_set_t *data_set)
{
	gboolean accept = FALSE;
	
	switch(find_expression_type(expr)) {
		case nested_rule:
			accept = test_rule(expr, node, rsc, data_set);
			break;
		case attr_expr:
		case loc_expr:
			/* these expressions can never succeed if there is
			 * no node to compare with
			 */
			if(node != NULL) {
				accept = test_attr_expression(
					expr, node->details->attrs, data_set);
			}
			break;

		case time_expr:
			accept = test_date_expression(expr, data_set);
			break;

		case role_expr:
			if(rsc != NULL) {
				accept = test_role_expression(expr, rsc, data_set);
			}
			break;

		default:
			CRM_CHECK(FALSE /* bad type */, return FALSE);
			accept = FALSE;
	}
		
	crm_debug_2("Expression %s %s", ID(expr), accept?"passed":"failed");
	return accept;
}

enum expression_type
find_expression_type(crm_data_t *expr) 
{
	const char *tag = NULL;
	const char *attr  = NULL;
	attr = crm_element_value(expr, XML_EXPR_ATTR_ATTRIBUTE);
	tag = crm_element_name(expr);

	if(safe_str_eq(tag, "date_expression")) {
		return time_expr;
		
	} else if(safe_str_eq(tag, XML_TAG_RULE)) {
		return nested_rule;
		
	} else if(safe_str_neq(tag, "expression")) {
		return not_expr;
		
	} else if(safe_str_eq(attr, "#uname") || safe_str_eq(attr, "#id")) {
		return loc_expr;

	} else if(safe_str_eq(attr, "#role")) {
		return role_expr;
	} 

	return attr_expr;
}

gboolean
test_role_expression(
	crm_data_t *expr, resource_t *rsc, pe_working_set_t *data_set)
{
	gboolean accept = FALSE;
	const char *op      = NULL;
	const char *value   = NULL;

	if(rsc == NULL) {
		return accept;
	}
	
	value = crm_element_value(expr, XML_EXPR_ATTR_VALUE);
	op    = crm_element_value(expr, XML_EXPR_ATTR_OPERATION);

	if(safe_str_eq(op, "defined")) {
		if(rsc->next_role > RSC_ROLE_STARTED) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "not_defined")) {
		if(rsc->next_role < RSC_ROLE_SLAVE
			&& rsc->next_role > RSC_ROLE_UNKNOWN) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "eq")) {
		if(text2role(value) == rsc->next_role) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "ne")) {
		/* we will only test "ne" wtih master/slave roles style */
		if(rsc->next_role < RSC_ROLE_SLAVE
			&& rsc->next_role > RSC_ROLE_UNKNOWN) {
			accept = FALSE;
			
		} else if(text2role(value) != rsc->next_role) {
			accept = TRUE;
		}
	}	   
	return accept;
}

gboolean
test_attr_expression(crm_data_t *expr, GHashTable *hash, pe_working_set_t *data_set)
{
	gboolean accept = FALSE;
	int cmp = 0;
	const char *h_val = NULL;

	const char *op      = NULL;
	const char *type    = NULL;
	const char *attr    = NULL;
	const char *value   = NULL;
	
	attr  = crm_element_value(expr, XML_EXPR_ATTR_ATTRIBUTE);
	op    = crm_element_value(expr, XML_EXPR_ATTR_OPERATION);
	value = crm_element_value(expr, XML_EXPR_ATTR_VALUE);
	type  = crm_element_value(expr, XML_EXPR_ATTR_TYPE);
	
	if(attr == NULL || op == NULL) {
		pe_err("Invlaid attribute or operation in expression"
			" (\'%s\' \'%s\' \'%s\')",
			crm_str(attr), crm_str(op), crm_str(value));
		return FALSE;
	}

	if(hash != NULL) {
		h_val = (const char*)g_hash_table_lookup(hash, attr);
	}
	
	if(value != NULL && h_val != NULL) {
		if(type == NULL || (safe_str_eq(type, "string"))) {
			cmp = strcmp(h_val, value);
			
		} else if(safe_str_eq(type, "number")) {
			int h_val_f = crm_parse_int(h_val, NULL);
			int value_f = crm_parse_int(value, NULL);
			
			if(h_val_f < value_f) {
				cmp = -1;
			} else if(h_val_f > value_f)  {
				cmp = 1;
			} else {
				cmp = 0;
			}
			
		} else if(safe_str_eq(type, "version")) {
			cmp = compare_version(h_val, value);
			
		}
		
	} else if(value == NULL && h_val == NULL) {
		cmp = 0;
	} else if(value == NULL) {
		cmp = 1;
	} else {
		cmp = -1;
	}
	
	if(safe_str_eq(op, "defined")) {
		if(h_val != NULL) { accept = TRUE; }
		
	} else if(safe_str_eq(op, "not_defined")) {
		if(h_val == NULL) { accept = TRUE; }
		
	} else if(safe_str_eq(op, "eq")) {
		if((h_val == value) || cmp == 0) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "ne")) {
		if((h_val == NULL && value != NULL)
		   || (h_val != NULL && value == NULL)
		   || cmp != 0) {
			accept = TRUE;
		}
		
	} else if(value == NULL || h_val == NULL) {
		/* the comparision is meaningless from this point on */
		accept = FALSE;
		
	} else if(safe_str_eq(op, "lt")) {
		if(cmp < 0) { accept = TRUE; }
		
	} else if(safe_str_eq(op, "lte")) {
		if(cmp <= 0) { accept = TRUE; }
		
	} else if(safe_str_eq(op, "gt")) {
		if(cmp > 0) { accept = TRUE; }
		
	} else if(safe_str_eq(op, "gte")) {
		if(cmp >= 0) { accept = TRUE; }		
	}
	
	return accept;
}

/* As per the nethack rules:
 *
 * moon period = 29.53058 days ~= 30, year = 365.2422 days
 * days moon phase advances on first day of year compared to preceding year
 *      = 365.2422 - 12*29.53058 ~= 11
 * years in Metonic cycle (time until same phases fall on the same days of
 *      the month) = 18.6 ~= 19
 * moon phase on first day of year (epact) ~= (11*(year%19) + 29) % 30
 *      (29 as initial condition)
 * current phase in days = first day phase + days elapsed in year
 * 6 moons ~= 177 days
 * 177 ~= 8 reported phases * 22
 * + 11/22 for rounding
 *
 * 0-7, with 0: new, 4: full
 */

static int
phase_of_the_moon(ha_time_t *now)
{
	int epact, diy, goldn;

	diy = now->yeardays;
	goldn = (now->years % 19) + 1;
	epact = (11 * goldn + 18) % 30;
	if ((epact == 25 && goldn > 11) || epact == 24)
		epact++;

	return( (((((diy + epact) * 6) + 11) % 177) / 22) & 7 );
}

#define cron_check(xml_field, time_field)				\
	value = crm_element_value(cron_spec, xml_field);		\
	if(value != NULL) {						\
		decodeNVpair(value, '-', &value_low, &value_high);	\
		CRM_CHECK(value_low != NULL, return FALSE);		\
		value_low_i = crm_parse_int(value_low, "0");		\
		value_high_i = crm_parse_int(value_high, "-1");		\
		if(value_low_i > time_field) {				\
			return FALSE;					\
		} else if(value_high_i < 0) {				\
		} else if(value_high_i < time_field) {			\
			return FALSE;					\
		}							\
	}

gboolean
cron_range_satisfied(ha_time_t *now, crm_data_t *cron_spec) 
{
	const char *value = NULL;
	char *value_low = NULL;
	char *value_high = NULL;

	int value_low_i = 0;
	int value_high_i = 0;

	cron_check("seconds",	now->seconds);
	cron_check("minutes",	now->minutes);
	cron_check("hours",	now->hours);
	cron_check("monthdays",	now->days);
	cron_check("weekdays",	now->weekdays);
	cron_check("yeardays",	now->yeardays);
	cron_check("weeks",	now->weeks);
	cron_check("months",	now->months);
	cron_check("years",	now->years);
	cron_check("weekyears",	now->weekyears);
	cron_check("moon",	phase_of_the_moon(now));
	
	return TRUE;
}

#define update_field(xml_field, time_fn)				\
	value = crm_element_value(duration_spec, xml_field);		\
	if(value != NULL) {						\
		int value_i = crm_parse_int(value, "0");			\
		time_fn(end, value_i);					\
	}

ha_time_t *
parse_xml_duration(ha_time_t *start, crm_data_t *duration_spec) 
{
	ha_time_t *end = NULL;
	const char *value = NULL;

	end = new_ha_date(FALSE);
	ha_set_time(end, start, TRUE);

	update_field("years",   add_years);
	update_field("months",  add_months);
	update_field("weeks",   add_weeks);
	update_field("days",    add_days);
	update_field("hours",   add_hours);
	update_field("minutes", add_minutes);
	update_field("seconds", add_seconds);
	
	return end;
}

	
gboolean
test_date_expression(crm_data_t *time_expr, pe_working_set_t *data_set)
{
	ha_time_t *start = NULL;
	ha_time_t *end = NULL;
	const char *value = NULL;
	char *value_copy = NULL;
	char *value_copy_start = NULL;
	const char *op = crm_element_value(time_expr, "operation");

	crm_data_t *duration_spec = NULL;
	crm_data_t *date_spec = NULL;

	gboolean passed = FALSE;

	crm_debug_2("Testing expression: %s", ID(time_expr));
	
	duration_spec = cl_get_struct(time_expr, "duration");
	date_spec = cl_get_struct(time_expr, "date_spec");
	
	value = crm_element_value(time_expr, "start");
	if(value != NULL) {
		value_copy = crm_strdup(value);
		value_copy_start = value_copy;
		start = parse_date(&value_copy);
		crm_free(value_copy_start);
	}
	value = crm_element_value(time_expr, "end");
	if(value != NULL) {
		value_copy = crm_strdup(value);
		value_copy_start = value_copy;
		end = parse_date(&value_copy);
		crm_free(value_copy_start);
	}

	if(start != NULL && end == NULL) {
 		end = parse_xml_duration(start, duration_spec);
	}
	if(op == NULL) {
		op = "in_range";
	}
	
	if(safe_str_eq(op, "date_spec") || safe_str_eq(op, "in_range")) {
		if(start != NULL && compare_date(start, data_set->now) > 0) {
			passed = FALSE;
		} else if(end != NULL && compare_date(end, data_set->now) < 0) {
			passed = FALSE;
		} else if(safe_str_eq(op, "in_range")) {
			passed = TRUE;
		} else {
			passed = cron_range_satisfied(data_set->now, date_spec);
		}
		
	} else if(safe_str_eq(op, "gt") && compare_date(start, data_set->now) < 0) {
		passed = TRUE;


	} else if(safe_str_eq(op, "lt") && compare_date(end, data_set->now) > 0) {
		passed = TRUE;

	} else if(safe_str_eq(op, "eq") && compare_date(start, data_set->now) == 0) {
		passed = TRUE;

	} else if(safe_str_eq(op, "neq") && compare_date(start, data_set->now) != 0) {
		passed = TRUE;
	}

	free_ha_date(start);
	free_ha_date(end);
	return passed;
}
