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

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <crm/pengine/rules.h>

ha_time_t *parse_xml_duration(ha_time_t *start, xmlNode *duration_spec);

gboolean test_date_expression(xmlNode *time_expr, ha_time_t *now);
gboolean cron_range_satisfied(ha_time_t *now, xmlNode *cron_spec);
gboolean test_attr_expression(
	xmlNode *expr, GHashTable *hash, ha_time_t *now);
gboolean test_role_expression(
	xmlNode *expr, enum rsc_role_e role, ha_time_t *now);

gboolean
test_ruleset(xmlNode *ruleset, GHashTable *node_hash, ha_time_t *now) 
{
	gboolean ruleset_default = TRUE;
	xml_child_iter_filter(
		ruleset, rule, XML_TAG_RULE,

		ruleset_default = FALSE;
		if(test_rule(rule, node_hash, RSC_ROLE_UNKNOWN, now)) {
			return TRUE;
		}
		);
	
	return ruleset_default;
}

gboolean
test_rule(xmlNode *rule, GHashTable *node_hash, enum rsc_role_e role,
	  ha_time_t *now) 
{
	gboolean test = TRUE;
	gboolean empty = TRUE;
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
		test = test_expression(expr, node_hash, role, now);
		empty = FALSE;
		
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

	if(empty) {
		crm_err("Invalid Rule %s: rules must contain at least one expression", ID(rule));
	}
	
	crm_debug_2("Rule %s %s", ID(rule), passed?"passed":"failed");
	return passed;
}

gboolean
test_expression(xmlNode *expr, GHashTable *node_hash, enum rsc_role_e role,
		ha_time_t *now)
{
	gboolean accept = FALSE;
	const char *uname = NULL;
	
	switch(find_expression_type(expr)) {
		case nested_rule:
			accept = test_rule(expr, node_hash, role, now);
			break;
		case attr_expr:
		case loc_expr:
			/* these expressions can never succeed if there is
			 * no node to compare with
			 */
			if(node_hash != NULL) {
				accept = test_attr_expression(expr, node_hash, now);
			}
			break;

		case time_expr:
			accept = test_date_expression(expr, now);
			break;

		case role_expr:
			accept = test_role_expression(expr, role, now);
			break;

		default:
			CRM_CHECK(FALSE /* bad type */, return FALSE);
			accept = FALSE;
	}
	if(node_hash) {
		uname = g_hash_table_lookup(node_hash, "#uname");
	}
	
	crm_debug_2("Expression %s %s on %s",
		    ID(expr), accept?"passed":"failed",
		    uname?uname:"all ndoes");
	return accept;
}

enum expression_type
find_expression_type(xmlNode *expr) 
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
	xmlNode *expr, enum rsc_role_e role, ha_time_t *now)
{
	gboolean accept = FALSE;
	const char *op      = NULL;
	const char *value   = NULL;

	if(role == RSC_ROLE_UNKNOWN) {
		return accept;
	}
	
	value = crm_element_value(expr, XML_EXPR_ATTR_VALUE);
	op    = crm_element_value(expr, XML_EXPR_ATTR_OPERATION);

	if(safe_str_eq(op, "defined")) {
		if(role > RSC_ROLE_STARTED) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "not_defined")) {
		if(role < RSC_ROLE_SLAVE && role > RSC_ROLE_UNKNOWN) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "eq")) {
		if(text2role(value) == role) {
			accept = TRUE;
		}
		
	} else if(safe_str_eq(op, "ne")) {
		/* we will only test "ne" wtih master/slave roles style */
		if(role < RSC_ROLE_SLAVE && role > RSC_ROLE_UNKNOWN) {
			accept = FALSE;
			
		} else if(text2role(value) != role) {
			accept = TRUE;
		}
	}	   
	return accept;
}

gboolean
test_attr_expression(xmlNode *expr, GHashTable *hash, ha_time_t *now)
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
			cmp = strcasecmp(h_val, value);
			
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
		gboolean pass = TRUE;					\
		decodeNVpair(value, '-', &value_low, &value_high);	\
		if(value_low == NULL) {					\
			value_low = crm_strdup(value);			\
		}							\
		value_low_i = crm_parse_int(value_low, "0");		\
		value_high_i = crm_parse_int(value_high, "-1");		\
		if(value_high_i < 0) {					\
			if(value_low_i != time_field) {			\
				pass = FALSE;				\
			}						\
		} else if(value_low_i > time_field) {			\
			pass = FALSE;					\
		} else if(value_high_i < time_field) {			\
			pass = FALSE;					\
		}							\
		crm_free(value_low);					\
		crm_free(value_high);					\
		if(pass == FALSE) {					\
			crm_debug("Condition '%s' in %s: failed", value, xml_field); \
			return pass;					\
		}							\
		crm_debug("Condition '%s' in %s: passed", value, xml_field); \
	}

gboolean
cron_range_satisfied(ha_time_t *now, xmlNode *cron_spec) 
{
	const char *value = NULL;
	char *value_low = NULL;
	char *value_high = NULL;

	int value_low_i = 0;
	int value_high_i = 0;

	CRM_CHECK(now != NULL, return FALSE);
	
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
parse_xml_duration(ha_time_t *start, xmlNode *duration_spec) 
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
test_date_expression(xmlNode *time_expr, ha_time_t *now)
{
	ha_time_t *start = NULL;
	ha_time_t *end = NULL;
	const char *value = NULL;
	char *value_copy = NULL;
	char *value_copy_start = NULL;
	const char *op = crm_element_value(time_expr, "operation");

	xmlNode *duration_spec = NULL;
	xmlNode *date_spec = NULL;

	gboolean passed = FALSE;

	crm_debug_2("Testing expression: %s", ID(time_expr));
	
	duration_spec = first_named_child(time_expr, "duration");
	date_spec = first_named_child(time_expr, "date_spec");
	
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

	if(start != NULL && end == NULL && duration_spec != NULL) {
 		end = parse_xml_duration(start, duration_spec);
	}
	if(op == NULL) {
		op = "in_range";
	}
	
	if(safe_str_eq(op, "date_spec") || safe_str_eq(op, "in_range")) {
		if(start != NULL && compare_date(start, now) > 0) {
			passed = FALSE;
		} else if(end != NULL && compare_date(end, now) < 0) {
			passed = FALSE;
		} else if(safe_str_eq(op, "in_range")) {
			passed = TRUE;
		} else {
			passed = cron_range_satisfied(now, date_spec);
		}
		
	} else if(safe_str_eq(op, "gt") && compare_date(start, now) < 0) {
		passed = TRUE;


	} else if(safe_str_eq(op, "lt") && compare_date(end, now) > 0) {
		passed = TRUE;

	} else if(safe_str_eq(op, "eq") && compare_date(start, now) == 0) {
		passed = TRUE;

	} else if(safe_str_eq(op, "neq") && compare_date(start, now) != 0) {
		passed = TRUE;
	}

	free_ha_date(start);
	free_ha_date(end);
	return passed;
}


typedef struct sorted_set_s 
{
		const char *name;
		const char *special_name;
		int score;
		xmlNode *attr_set;
		gboolean overwrite;
		GHashTable *node_hash;
		GHashTable *hash;
		ha_time_t *now;		
} sorted_set_t;

static gint
sort_pairs(gconstpointer a, gconstpointer b)
{
	const sorted_set_t *pair_a = a;
	const sorted_set_t *pair_b = b;
	
	if(a == NULL && b == NULL) {
		return 0;
	} else if(a == NULL) {
		return 1;
	} else if(b == NULL) {
		return -1;
	}

	if(safe_str_eq(pair_a->name, pair_a->special_name)) {
		return -1;

	} else if(safe_str_eq(pair_b->name, pair_a->special_name)) {
		return 1;
	}
	
	if(pair_a->score < pair_b->score) {
		return 1;
	} else if(pair_a->score > pair_b->score) {
		return -1;
	}
	return 0;
}


static void
populate_hash(xmlNode *nvpair_list, GHashTable *hash, gboolean overwrite) 
{
	const char *name = NULL;
	const char *value = NULL;
	const char *old_value = NULL;

	xml_child_iter_filter(
		nvpair_list, an_attr, XML_CIB_TAG_NVPAIR,
		
		name  = crm_element_value(an_attr, XML_NVPAIR_ATTR_NAME);
		
		crm_debug_4("Setting attribute: %s", name);
		value = crm_element_value(
			an_attr, XML_NVPAIR_ATTR_VALUE);
		
		if(name == NULL || value == NULL) {
			continue;

		}

		old_value = g_hash_table_lookup(hash, name);
		
		if(safe_str_eq(value, "#default")) {
		    if(old_value) {
			crm_crit("Removing value for %s (%s)", name, value);
			g_hash_table_remove(hash, name);
		    }
		    continue;

		} else if(old_value == NULL) {
			g_hash_table_insert(hash, crm_strdup(name), crm_strdup(value));

		} else if(overwrite) {
		    crm_crit("Overwriting value of %s: %s -> %s", name, old_value, value);
		    g_hash_table_replace(hash, crm_strdup(name), crm_strdup(value));
		}
		
		);
}

static void
unpack_attr_set(gpointer data, gpointer user_data)
{
	sorted_set_t *pair = data;
	sorted_set_t *unpack_data = user_data;
	xmlNode *attributes = NULL;
	
	if(test_ruleset(pair->attr_set,
			unpack_data->node_hash, unpack_data->now) == FALSE) {
		return;
	}
	
	crm_debug_3("Adding attributes from %s", pair->name);
	attributes = first_named_child(pair->attr_set, XML_TAG_ATTRS);
	populate_hash(attributes, unpack_data->hash, unpack_data->overwrite);
}

static void
free_pair(gpointer data, gpointer user_data)
{
	sorted_set_t *pair = data;
	crm_free(pair);
}

void
unpack_instance_attributes(
	xmlNode *xml_obj, const char *set_name, GHashTable *node_hash, 
	GHashTable *hash, const char *always_first, gboolean overwrite, ha_time_t *now)
{
	GListPtr sorted = NULL;
	const char *score = NULL;
	sorted_set_t *pair = NULL;
	
	if(xml_obj == NULL) {
		crm_debug_4("No instance attributes");
		return;
	}

	crm_debug_4("Checking for attributes");
	xml_child_iter_filter(
		xml_obj, attr_set, set_name,

		pair = NULL;
		crm_malloc0(pair, sizeof(sorted_set_t));
		pair->name     = ID(attr_set);
		pair->special_name = always_first;
		pair->attr_set = attr_set;
		score = crm_element_value(attr_set, XML_RULE_ATTR_SCORE);
		pair->score = char2score(score);

		sorted = g_list_prepend(sorted, pair);

		);

	if(pair != NULL) {
		pair->hash = hash;
		pair->node_hash = node_hash;
		pair->now = now;
		pair->overwrite = overwrite;
	}
	
	sorted = g_list_sort(sorted, sort_pairs);
	g_list_foreach(sorted, unpack_attr_set, pair);
	g_list_foreach(sorted, free_pair, NULL);
	g_list_free(sorted);
}

