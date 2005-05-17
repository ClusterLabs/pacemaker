/* $Id: rules.c,v 1.3 2005/05/17 14:33:39 andrew Exp $ */
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

enum expression_type {
	attr_expr,
	coloc_expr,
	loc_expr,
	time_expr
};

enum expression_type find_expression_type(
	const char *attr, const char *op, const char *value);

typedef struct native_variant_data_s
{
		lrm_agent_t *agent;
		GListPtr running_on;       /* node_t*           */
		color_t *color;
		GListPtr node_cons;        /* rsc_to_node_t*    */
		GListPtr allowed_nodes;    /* node_t*         */

} native_variant_data_t;

enum expression_type
find_expression_type(const char *attr, const char *op, const char *value) 
{
	if(safe_str_eq(op, "colocated")
	   || safe_str_eq(op, "not_colocated")) {
		return coloc_expr;

	} else if(safe_str_eq(attr, "uname")
		  || safe_str_eq(attr, "id")) {
		return loc_expr;		
	}
	
	return attr_expr;
}

/* do NOT free the nodes returned here */
GListPtr
apply_node_expression(const char *attr, const char *op, const char *value,
		 const char *type, GListPtr node_list)
{
	gboolean accept = FALSE;
	GListPtr result = NULL;
	slist_iter(
		node, node_t, node_list, lpc,

		switch(find_expression_type(attr, op, value)) {
			case attr_expr:
				accept = attr_expression(attr, op, value, type,
							 node->details->attrs);
				break;
			case coloc_expr:
				accept = coloc_expression(
					attr, op, value, type, node);
				break;
			case loc_expr:
				accept = loc_expression(
					attr, op, value, type, node);
				break;
			default:
				accept = FALSE;
		}
		
		if(accept) {
			result = g_list_append(result, node);
			crm_trace("node %s matched", node->details->uname);
		} else {
			crm_trace("node %s did not match", node->details->uname);
		}
		);
	
	return result;
}

gboolean
test_node_attr_expression(const char *attr, const char *op, const char *value,
			  const char *type, node_t *node)
{
	gboolean accept = FALSE;
	
	switch(find_expression_type(attr, op, value)) {
		case attr_expr:
			accept = attr_expression(attr, op, value, type,
						 node->details->attrs);
			break;
#if 0
		case time_expr:
			accept = time_expression(attr, op, value, type);
			break;
#endif
		default:
			accept = FALSE;
	}
		
	return accept;
}

gboolean
test_resource_attr_expression(
	const char *attr, const char *op, const char *value,
	const char *type, resource_t *rsc)
{
	gboolean accept = FALSE;
	native_variant_data_t *native_data = NULL;
	color_t *color = NULL;
	node_t *node = NULL;
	
	if(rsc->variant == pe_native) {
		native_data = rsc->variant_opaque;
	}
	if(native_data != NULL) {
		color = native_data->color;
	}
	if(color != NULL) {
		node = color->details->chosen_node;
	}
	
	switch(find_expression_type(attr, op, value)) {
		case attr_expr:
			accept = attr_expression(attr, op, value, type,
						 rsc->parameters);
			break;
		case coloc_expr:
			if(native_data == NULL || color == NULL) {
				break;
			}
			accept = coloc_expression(attr, op, value, type, node);
			break;
		case loc_expr:
			if(native_data == NULL || color == NULL) {
				break;
			}
			accept = loc_expression(attr, op, value, type, node);
			break;
#if 0
		case time_expr:
			accept = time_expression(attr, op, value, type);
			break;
#endif
		default:
			accept = FALSE;
	}
		
	return accept;
}


gboolean
coloc_expression(const char *attr, const char *op, const char *value,
		const char *type, node_t *node)
{
	gboolean accept = FALSE;
	
	if(attr == NULL || op == NULL) {
		pe_err("Invlaid attribute or operation in expression"
			" (\'%s\' \'%s\' \'%s\')",
			crm_str(attr), crm_str(op), crm_str(value));
		return FALSE;
	}
	
	if(safe_str_eq(op, "colocated") && node != NULL) {
		GListPtr rsc_list = node->details->running_rsc;
		slist_iter(
			rsc, resource_t, rsc_list, lpc2,
			if(safe_str_eq(rsc->id, attr)) {
				accept = TRUE;
			}
			);
		
	} else if(node == NULL && safe_str_eq(op, "not_colocated")) {
		accept = TRUE;

	} else if(safe_str_eq(op, "not_colocated")) {
		GListPtr rsc_list = node->details->running_rsc;
		accept = TRUE;
		slist_iter(
			rsc, resource_t, rsc_list, lpc2,
			if(safe_str_eq(rsc->id, attr)) {
				accept = FALSE;
				break;
			}
			);
	}
	
	if(accept && node != NULL) {
		crm_trace("node %s matched", node->details->uname);
		return TRUE;
		
	} else if(accept) {
		crm_trace("node <NULL> matched");
		return TRUE;
		
	} else if(node != NULL) {
		crm_trace("node %s did not match", node->details->uname);

	} else {
		crm_trace("node <NULL> not matched");
	}
	
	return FALSE;
}

gboolean
loc_expression(const char *attr, const char *op, const char *value,
	       const char *type, node_t *node)
{
	return attr_expression(attr, op, value, type,
			       node?node->details->attrs:NULL);
}

gboolean
attr_expression(const char *attr, const char *op, const char *value,
		const char *type, GHashTable *hash)
{
	gboolean accept = FALSE;
	int cmp = 0;
	const char *h_val = NULL;
	
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
