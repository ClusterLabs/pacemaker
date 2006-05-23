/* $Id: complex.h,v 1.35 2006/05/23 07:45:37 andrew Exp $ */
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
#define PE_OBJ_T_INCARNATION	"clone"
#define PE_OBJ_T_MASTER		"master"

enum pe_obj_types 
{
	pe_unknown = -1,
	pe_native = 0,
	pe_group = 1,
	pe_clone = 2,
	pe_master = 3
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
	GListPtr demote;   /* notify_entry_t*  */
	GListPtr promote;  /* notify_entry_t*  */
	GListPtr master;   /* notify_entry_t*  */
	GListPtr slave;    /* notify_entry_t*  */
		
} notify_data_t;


typedef struct resource_object_functions_s 
{
		void (*unpack)(resource_t *, pe_working_set_t *);
		resource_t *(*find_child)(resource_t *, const char *);
		int  (*num_allowed_nodes)(resource_t *);
		color_t *(*color)(resource_t *, pe_working_set_t *);
		void (*create_actions)(resource_t *, pe_working_set_t *);
		gboolean (*create_probe)(
			resource_t *, node_t *, action_t *, gboolean, pe_working_set_t *);
		void (*internal_constraints)(resource_t *, pe_working_set_t *);
		void (*agent_constraints)(resource_t *);

		void (*rsc_colocation_lh)(resource_t *, resource_t *, rsc_colocation_t *);
		void (*rsc_colocation_rh)(resource_t *, resource_t *, rsc_colocation_t *);

		void (*rsc_order_lh)(resource_t *, order_constraint_t *);
		void (*rsc_order_rh)(
			action_t *, resource_t *, order_constraint_t *);

		void (*rsc_location)(resource_t *, rsc_to_node_t *);

		void (*expand)(resource_t *, pe_working_set_t *);
		GListPtr (*children)(resource_t *);
		void (*stonith_ordering)(
			resource_t *, action_t *, pe_working_set_t *);

		/* parameter result must be free'd */
		char *(*parameter)(
			resource_t *, node_t *, gboolean, const char *,
			pe_working_set_t *);

		void (*print)(resource_t *, const char *, long, void *);
		gboolean (*active)(resource_t *,gboolean);
		enum rsc_role_e (*state)(resource_t *);
		void (*create_notify_element)(resource_t*,action_t*,
					      notify_data_t*,pe_working_set_t*);
		void (*free)(resource_t *);
		
} resource_object_functions_t;

extern char *native_parameter(
	resource_t *rsc, node_t *node, gboolean create, const char *name,
	pe_working_set_t *data_set);
extern void native_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern GListPtr native_children(resource_t *rsc);
extern resource_t *native_find_child(resource_t *rsc, const char *id);
extern int  native_num_allowed_nodes(resource_t *rsc);
extern color_t * native_color(resource_t *rsc, pe_working_set_t *data_set);
extern void native_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_agent_constraints(resource_t *rsc);
extern void native_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void native_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void native_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void native_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void native_expand(resource_t *rsc, pe_working_set_t *data_set);
extern void native_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern gboolean native_active(resource_t *rsc, gboolean all);
extern void native_print(resource_t *rsc, const char *pre_text, long options, void *print_data);
extern void native_print(resource_t *rsc, const char *pre_text, long options, void *print_data);

extern void native_html(resource_t *rsc, const char *pre_text, FILE *stream);
extern void native_free(resource_t *rsc);
extern enum rsc_role_e native_resource_state(resource_t *rsc);
extern void native_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);
extern void native_assign_color(resource_t *rsc, color_t *color);
extern gboolean native_create_probe(
	resource_t *rsc, node_t *node, action_t *complete, gboolean force, 
	pe_working_set_t *data_set);
extern void native_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set);

extern void group_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern GListPtr group_children(resource_t *rsc);
extern resource_t *group_find_child(resource_t *rsc, const char *id);
extern int  group_num_allowed_nodes(resource_t *rsc);
extern color_t *group_color(resource_t *rsc, pe_working_set_t *data_set);
extern void group_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_agent_constraints(resource_t *rsc);
extern void group_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void group_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void group_expand(resource_t *rsc, pe_working_set_t *data_set);
extern gboolean group_active(resource_t *rsc, gboolean all);
extern void group_print(resource_t *rsc, const char *pre_text, long options, void *print_data);
extern void group_free(resource_t *rsc);
extern enum rsc_role_e group_resource_state(resource_t *rsc);
extern void group_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);
extern gboolean group_create_probe(
	resource_t *rsc, node_t *node, action_t *complete, gboolean force,
	pe_working_set_t *data_set);
extern void group_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set);

extern void clone_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern GListPtr clone_children(resource_t *rsc);
extern resource_t *clone_find_child(resource_t *rsc, const char *id);
extern int  clone_num_allowed_nodes(resource_t *rsc);
extern color_t *clone_color(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_create_actions(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void clone_agent_constraints(resource_t *rsc);
extern void clone_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void clone_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void clone_expand(resource_t *rsc, pe_working_set_t *data_set);
extern gboolean clone_active(resource_t *rsc, gboolean all);
extern void clone_print(resource_t *rsc, const char *pre_text, long options, void *print_data);
extern void clone_free(resource_t *rsc);
extern enum rsc_role_e clone_resource_state(resource_t *rsc);
extern void clone_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);
extern gboolean clone_create_probe(
	resource_t *rsc, node_t *node, action_t *complete, gboolean force,
	pe_working_set_t *data_set);
extern void clone_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set);

extern void master_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern void master_create_actions(resource_t *rsc, pe_working_set_t *data_set);
extern void master_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);


/* extern resource_object_functions_t resource_variants[]; */
extern resource_object_functions_t resource_class_functions[];
extern gboolean	common_unpack(crm_data_t * xml_obj, resource_t **rsc,
			      resource_t *parent, pe_working_set_t *data_set);

extern void common_print(resource_t *rsc, const char *pre_text, long options, void *print_data);

extern void common_free(resource_t *rsc);
extern void native_add_running(
	resource_t *rsc, node_t *node, pe_working_set_t *data_set);
extern gboolean is_active(rsc_to_node_t *cons);

extern gboolean native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);

extern void common_agent_constraints(
	GListPtr node_list, lrm_agent_t *agent, const char *id);

extern void unpack_instance_attributes(
	crm_data_t *xml_obj, const char *set_name, node_t *node, GHashTable *hash,
	const char **attr_filter, int attrs_length, pe_working_set_t *data_set);
extern void add_hash_param(GHashTable *hash, const char *name, const char *value);

#if CURSES_ENABLED
#  define status_printw(fmt...) printw(fmt)
#else
#  define status_printw(fmt...) \
	crm_err("printw support requires ncurses to be available during configure"); \
	do_crm_log(LOG_WARNING, NULL, NULL, fmt);
#endif

#define status_print(fmt...)				\
	if(options & pe_print_html) {			\
		FILE *stream = print_data;		\
		fprintf(stream, fmt);			\
	} else if(options & pe_print_ncurses) {		\
		status_printw(fmt);			\
	} else if(options & pe_print_printf) {		\
		FILE *stream = print_data;		\
		fprintf(stream, fmt);			\
	} else if(options & pe_print_log) {		\
		int log_level = *(int*)print_data;	\
		do_crm_log(log_level, NULL, NULL, fmt);	\
	}

#endif
