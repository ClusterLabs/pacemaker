/* $Id: rules.c,v 1.7 2005/08/03 14:54:27 andrew Exp $ */
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

enum expression_type {
	attr_expr,
	loc_expr,
	time_expr
};

enum expression_type find_expression_type(crm_data_t *expr);
ha_time_t *parse_xml_duration(ha_time_t *start, crm_data_t *duration_spec);

gboolean test_date_expression(crm_data_t *time_expr);
gboolean cron_range_satisfied(ha_time_t *now, crm_data_t *cron_spec);
gboolean test_attr_expression(crm_data_t *expr, GHashTable *hash);


gboolean
test_rule(crm_data_t *rule, node_t *node) 
{
	gboolean test = TRUE;
	gboolean passed = TRUE;
	gboolean do_and = TRUE;

	const char *value = crm_element_value(rule, "boolean_op");
	if(safe_str_eq(value, "or")) {
		do_and = FALSE;
		passed = FALSE;
	}
	
	xml_child_iter(
		rule, expr, XML_TAG_EXPRESSION,
		test = test_expression(expr, node);
		
		if(test && do_and == FALSE) {
			crm_err("Expression %s/%s passed", ID(rule), ID(expr));
			return TRUE;
			
		} else if(test == FALSE && do_and) {
			crm_err("Expression %s/%s failed", ID(rule), ID(expr));
			return FALSE;
		}
		);
		
	if(passed == FALSE) {
		crm_err("Rule %s failed", ID(rule));
	}
	return passed;
}

gboolean
test_expression(crm_data_t *expr, node_t *node)
{
	gboolean accept = FALSE;
	
	switch(find_expression_type(expr)) {
		case attr_expr:
		case loc_expr:
			accept = test_attr_expression(
				expr, node?node->details->attrs:NULL);
			break;

		case time_expr:
			accept = test_date_expression(expr);
			break;

		default:
			CRM_DEV_ASSERT(FALSE /* bad type */);
			accept = FALSE;
	}
		
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
		
	} else if(safe_str_eq(attr, "#uname") || safe_str_eq(attr, "#id")) {
		return loc_expr;
	} 
	
	return attr_expr;
}

gboolean
test_attr_expression(crm_data_t *expr, GHashTable *hash)
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
			float h_val_f = atof(h_val);
			float value_f = atof(value);
			
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

#define cron_check(xml_field, time_field)				\
	value = crm_element_value(cron_spec, xml_field);		\
	if(value != NULL) {						\
		decodeNVpair(value, '-', &value_low, &value_high);	\
		CRM_DEV_ASSERT(value_low != NULL);			\
		value_low_i = crm_atoi(value_low, "0");			\
		value_high_i = crm_atoi(value_high, "-1");		\
		if(value_low_i > now->time_field) {			\
			return FALSE;					\
		} else if(value_high_i < 0) {				\
		} else if(value_high_i < now->time_field) {		\
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

	cron_check("seconds",   seconds);
	cron_check("minutes",   minutes);
	cron_check("hours",     hours);
	cron_check("monthdays", days);
	cron_check("weekdays",  weekdays);
	cron_check("yeardays",  yeardays);
	cron_check("weeks",     weeks);
	cron_check("months",    months);
	cron_check("years",     years);
	cron_check("weekyears", weekyears);

	free_ha_date(now);
	
	return TRUE;
}

#define update_field(xml_field, time_fn)				\
	value = crm_element_value(duration_spec, xml_field);		\
	if(value != NULL) {						\
		int value_i = crm_atoi(value, "0");			\
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
test_date_expression(crm_data_t *time_expr)
{
	ha_time_t *start = NULL;
	ha_time_t *end = NULL;
	const char *value = NULL;
	char *value_copy = NULL;
	const char *op = crm_element_value(time_expr, "operation");
	ha_time_t *now = new_ha_date(TRUE);

	crm_data_t *duration_spec = NULL;
	crm_data_t *date_spec = NULL;

	duration_spec = cl_get_struct(time_expr, "duration");
	date_spec = cl_get_struct(time_expr, "date_spec");
	
	value = crm_element_value(time_expr, "start");
	if(value != NULL) {
		value_copy = crm_strdup(value);
		start = parse_date(&value_copy);
		crm_free(value_copy);
	}
	value = crm_element_value(time_expr, "end");
	if(value != NULL) {
		value_copy = crm_strdup(value);
		end = parse_date(&value_copy);
		crm_free(value_copy);
	}

	if(start != NULL && end == NULL) {
 		end = parse_xml_duration(start, duration_spec);
	}
	
	if(safe_str_eq(op, "date_spec") || safe_str_eq(op, "in_range")) {
		if(start != NULL && compare_date(start, now) > 0) {
			return FALSE;

		} else if(end != NULL && compare_date(end, now) < 0) {
			return FALSE;
		}
		if(safe_str_eq(op, "in_range")) {
			return TRUE;
		}
		return cron_range_satisfied(now, date_spec);

	} else if(safe_str_eq(op, "gt") && compare_date(start, now) < 0) {
		return TRUE;

	} else if(safe_str_eq(op, "lt") && compare_date(end, now) > 0) {
		return TRUE;

	} else if(safe_str_eq(op, "eq") && compare_date(start, now) == 0) {
		return TRUE;

	} else if(safe_str_eq(op, "neq") && compare_date(start, now) != 0) {
		return TRUE;
	}

	return FALSE;
}
