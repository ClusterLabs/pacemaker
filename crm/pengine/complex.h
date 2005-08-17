/* $Id: complex.h,v 1.22 2005/08/17 09:15:13 andrew Exp $ */
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
#ifndef CRM_PENGINE_COMPLEX__H
#define CRM_PENGINE_COMPLEX__H

#include <crm/common/xml.h>
#include <crm/pengine/pengine.h>
#include <glib.h>

#define n_object_classes 3

/*#define PE_OBJ_F_	""*/

#define PE_OBJ_T_NATIVE		"native"
#define PE_OBJ_T_GROUP		"group"
#define PE_OBJ_T_INCARNATION	"incarnation"

enum pe_obj_types 
{
	pe_native = 0,
	pe_group = 1,
	pe_clone = 2,
	pe_unknown = -1
};

extern int get_resource_type(const char *name);


typedef struct notify_entry_s {
	resource_t *rsc;
	node_t *node;
} notify_entry_t;

typedef struct notify_data_s {
	GHashTable *keys;
	GListPtr active;   /* notify_entry_t*  */
	GListPtr inactive; /* notify_entry_t*  */
	GListPtr start;    /* notify_entry_t*  */
	GListPtr stop;     /* notify_entry_t*  */
	
} notify_data_t;


typedef struct resource_object_functions_s 
{
		void (*unpack)(resource_t *, pe_working_set_t *);
		resource_t *(*find_child)(resource_t *, const char *);
		int  (*num_allowed_nodes)(resource_t *);
		void (*color)(resource_t *, pe_working_set_t *);
		void (*create_actions)(resource_t *, pe_working_set_t *);
		void (*internal_constraints)(resource_t *, pe_working_set_t *);
		void (*agent_constraints)(resource_t *);

		void (*rsc_colocation_lh)(rsc_colocation_t *);
		void (*rsc_colocation_rh)(resource_t *, rsc_colocation_t *);

		void (*rsc_order_lh)(resource_t *, order_constraint_t *);
		void (*rsc_order_rh)(
			action_t *, resource_t *, order_constraint_t *);

		void (*rsc_location)(resource_t *, rsc_to_node_t *);

		void (*expand)(resource_t *, pe_working_set_t *);
		void (*dump)(resource_t *, const char *, gboolean);
		void (*printw)(resource_t *, const char *, int*);
		void (*html)(resource_t *, const char *, FILE*);
		gboolean (*active)(resource_t *,gboolean);
		rsc_state_t (*state)(resource_t *);
		void (*create_notify_element)(resource_t*,action_t*,
					      notify_data_t*,pe_working_set_t*);
		void (*free)(resource_t *);
		
} resource_object_functions_t;

extern void native_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern resource_t *native_find_child(resource_t *rsc, const char *id);
extern int  native_num_allowed_nodes(resource_t *rsc);
extern void native_color(resource_t *rsc, pe_working_set_t *data_set);
extern void native_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_agent_constraints(resource_t *rsc);
extern void native_rsc_colocation_lh(rsc_colocation_t *constraint);
extern void native_rsc_colocation_rh(
	resource_t *rsc, rsc_colocation_t *constraint);
extern void native_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void native_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void native_expand(resource_t *rsc, pe_working_set_t *data_set);
extern void native_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern gboolean native_active(resource_t *rsc, gboolean all);
extern void native_printw(resource_t *rsc, const char *pre_text, int *index);
extern void native_html(resource_t *rsc, const char *pre_text, FILE *stream);
extern void native_free(resource_t *rsc);
extern rsc_state_t native_resource_state(resource_t *rsc);
extern void native_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);

extern void group_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern resource_t *group_find_child(resource_t *rsc, const char *id);
extern int  group_num_allowed_nodes(resource_t *rsc);
extern void group_color(resource_t *rsc, pe_working_set_t *data_set);
extern void group_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_agent_constraints(resource_t *rsc);
extern void group_rsc_colocation_lh(rsc_colocation_t *constraint);
extern void group_rsc_colocation_rh(
	resource_t *rsc, rsc_colocation_t *constraint);
extern void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void group_expand(resource_t *rsc, pe_working_set_t *data_set);
extern void group_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern gboolean group_active(resource_t *rsc, gboolean all);
extern void group_printw(resource_t *rsc, const char *pre_text, int *index);
extern void group_html(resource_t *rsc, const char *pre_text, FILE *stream);
extern void group_free(resource_t *rsc);
extern rsc_state_t group_resource_state(resource_t *rsc);
extern void group_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);

extern void clone_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern resource_t *clone_find_child(resource_t *rsc, const char *id);
extern int  clone_num_allowed_nodes(resource_t *rsc);
extern void clone_color(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_create_actions(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void clone_agent_constraints(resource_t *rsc);
extern void clone_rsc_colocation_lh(rsc_colocation_t *constraint);
extern void clone_rsc_colocation_rh(
	resource_t *rsc, rsc_colocation_t *constraint);
extern void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void clone_expand(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern gboolean clone_active(resource_t *rsc, gboolean all);
extern void clone_printw(resource_t *rsc, const char *pre_text, int *index);
extern void clone_html(resource_t *rsc, const char *pre_text, FILE *stream);
extern void clone_free(resource_t *rsc);
extern rsc_state_t clone_resource_state(resource_t *rsc);
extern void clone_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);

/* extern resource_object_functions_t resource_variants[]; */
extern resource_object_functions_t resource_class_functions[];
extern gboolean common_unpack(crm_data_t *xml_obj, resource_t **rsc,
			      GHashTable *defaults, pe_working_set_t *data_set);
extern void common_dump(
	resource_t *rsc, const char *pre_text, gboolean details);
extern void common_printw(resource_t *rsc, const char *pre_text, int *index);
extern void common_html(resource_t *rsc, const char *pre_text, FILE *stream);

extern void common_free(resource_t *rsc);
extern void native_add_running(
	resource_t *rsc, node_t *node, pe_working_set_t *data_set);
extern gboolean is_active(rsc_to_node_t *cons);

extern gboolean native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);

extern void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);
extern void common_agent_constraints(
	GListPtr node_list, lrm_agent_t *agent, const char *id);

extern void unpack_instance_attributes(
	crm_data_t *xml_obj, const char *set_name, node_t *node, GHashTable *hash,
	const char **attr_filter, int attrs_length, pe_working_set_t *data_set);
extern const char *get_rsc_param(resource_t *rsc, const char *prop);
extern void add_rsc_param(resource_t *rsc, const char *name, const char *value);
extern void add_hash_param(GHashTable *hash, const char *name, const char *value);
extern void hash2nvpair(gpointer key, gpointer value, gpointer user_data);
#endif
