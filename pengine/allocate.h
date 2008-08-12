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
#ifndef CRM_PENGINE_COMPLEX_ALLOC__H
#define CRM_PENGINE_COMPLEX_ALLOC__H

#include <glib.h>
#include <crm/common/xml.h>
#include <crm/pengine/status.h>
#include <crm/pengine/complex.h>
#include <pengine.h>

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


struct resource_alloc_functions_s 
{
		GListPtr(*merge_weights)(resource_t*, const char*, GListPtr, int, gboolean);
		node_t *(*color)(resource_t *, pe_working_set_t *);
		void (*create_actions)(resource_t *, pe_working_set_t *);
		gboolean (*create_probe)(
			resource_t *, node_t *, action_t *, gboolean, pe_working_set_t *);
		void (*internal_constraints)(resource_t *, pe_working_set_t *);

		void (*rsc_colocation_lh)(resource_t *, resource_t *, rsc_colocation_t *);
		void (*rsc_colocation_rh)(resource_t *, resource_t *, rsc_colocation_t *);

		void (*rsc_order_lh)(resource_t *, order_constraint_t *, pe_working_set_t *);
		void (*rsc_order_rh)(
			action_t *, resource_t *, order_constraint_t *);

		void (*rsc_location)(resource_t *, rsc_to_node_t *);

		void (*expand)(resource_t *, pe_working_set_t *);
		void (*migrate_reload)(resource_t *, pe_working_set_t *);
		void (*stonith_ordering)(
			resource_t *, action_t *, pe_working_set_t *);

		void (*create_notify_element)(resource_t*,action_t*,
					      notify_data_t*,pe_working_set_t*);
		
};

extern GListPtr native_merge_weights(
    resource_t *rsc, const char *rhs, GListPtr nodes, int factor, gboolean allow_rollback);
extern node_t * native_color(resource_t *rsc, pe_working_set_t *data_set);
extern void native_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void native_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void native_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void native_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set);
extern void native_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void native_expand(resource_t *rsc, pe_working_set_t *data_set);
extern void native_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern void complex_create_notify_element(
	resource_t *rsc, action_t *op,
	notify_data_t *n_data,pe_working_set_t *data_set);
extern void native_assign_color(resource_t *rsc, node_t *node);
extern gboolean native_create_probe(
	resource_t *rsc, node_t *node, action_t *complete, gboolean force, 
	pe_working_set_t *data_set);
extern void complex_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set);
extern void complex_migrate_reload(resource_t *rsc, pe_working_set_t *data_set);

extern GListPtr group_merge_weights(
    resource_t *rsc, const char *rhs, GListPtr nodes, int factor, gboolean allow_rollback);
extern int  group_num_allowed_nodes(resource_t *rsc);
extern node_t *group_color(resource_t *rsc, pe_working_set_t *data_set);
extern void group_create_actions(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void group_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void group_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set);
extern void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void group_expand(resource_t *rsc, pe_working_set_t *data_set);

extern int  clone_num_allowed_nodes(resource_t *rsc);
extern node_t *clone_color(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_create_actions(resource_t *rsc, pe_working_set_t *data_set);
extern void clone_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void clone_rsc_colocation_lh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void clone_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);
extern void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set);
extern void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void clone_expand(resource_t *rsc, pe_working_set_t *data_set);
extern gboolean clone_create_probe(
	resource_t *rsc, node_t *node, action_t *complete, gboolean force,
	pe_working_set_t *data_set);

extern gboolean master_unpack(resource_t *rsc, pe_working_set_t *data_set);
extern node_t *master_color(resource_t *rsc, pe_working_set_t *data_set);
extern void master_create_actions(resource_t *rsc, pe_working_set_t *data_set);
extern void master_internal_constraints(
	resource_t *rsc, pe_working_set_t *data_set);
extern void master_rsc_colocation_rh(
	resource_t *lh_rsc, resource_t *rh_rsc, rsc_colocation_t *constraint);


/* extern resource_object_functions_t resource_variants[]; */
extern resource_alloc_functions_t resource_class_alloc_functions[];
extern gboolean is_active(rsc_to_node_t *cons);

extern gboolean native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);

extern gboolean unpack_rsc_to_attr(xmlNode *xml_obj, pe_working_set_t *data_set);

extern gboolean unpack_rsc_to_node(xmlNode *xml_obj, pe_working_set_t *data_set);

extern gboolean unpack_rsc_order(xmlNode *xml_obj, pe_working_set_t *data_set);

extern gboolean unpack_rsc_colocation(xmlNode *xml_obj, pe_working_set_t *data_set);

extern gboolean unpack_rsc_location(xmlNode *xml_obj, pe_working_set_t *data_set);

extern void cleanup_alloc_calculations(pe_working_set_t *data_set);

#endif
