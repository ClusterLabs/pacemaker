/* $Id: complex.h,v 1.3 2004/11/09 14:49:14 andrew Exp $ */
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

#include <crm/common/xml.h>

#define n_object_classes 3

//#define PE_OBJ_F_	""

#define PE_OBJ_T_NATIVE		"native"
#define PE_OBJ_T_GROUP		"group"
#define PE_OBJ_T_INCARNATION	"incarnation"

enum pe_obj_types 
{
	pe_native = 0,
	pe_group = 1,
	pe_incarnation = 2,
	pe_unknown = -1
};

extern int get_resource_type(const char *name);

typedef struct resource_object_functions_s 
{
		void (*unpack)(resource_t *);
		void (*color)(resource_t *, GListPtr *);
		void (*create_actions)(resource_t *);
		void (*internal_constraints)(resource_t *, GListPtr *);
		void (*agent_constraints)(resource_t *);

		void (*rsc_dependancy_lh)(rsc_dependancy_t *);
		void (*rsc_dependancy_rh)(resource_t *, rsc_dependancy_t *);

		void (*rsc_order_lh)(resource_t *, order_constraint_t *);
		void (*rsc_order_rh)(
			action_t *, resource_t *, order_constraint_t *);

		void (*rsc_location)(resource_t *, rsc_to_node_t *);

		void (*expand)(resource_t *, xmlNodePtr *);
		void (*dump)(resource_t *, const char *, gboolean);
		void (*free)(resource_t *);
		
} resource_object_functions_t;

extern void native_unpack(resource_t *rsc);
extern void native_color(resource_t *rsc, GListPtr *colors);
extern void native_create_actions(resource_t *rsc);
extern void native_internal_constraints(
	resource_t *rsc, GListPtr *ordering_constraints);
extern void native_agent_constraints(resource_t *rsc);
extern void native_rsc_dependancy_lh(rsc_dependancy_t *constraint);
extern void native_rsc_dependancy_rh(
	resource_t *rsc, rsc_dependancy_t *constraint);
extern void native_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void native_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void native_expand(resource_t *rsc, xmlNodePtr *graph);
extern void native_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern void native_free(resource_t *rsc);


extern void group_unpack(resource_t *rsc);
extern void group_color(resource_t *rsc, GListPtr *colors);
extern void group_create_actions(resource_t *rsc);
extern void group_internal_constraints(
	resource_t *rsc, GListPtr *ordering_constraints);
extern void group_agent_constraints(resource_t *rsc);
extern void group_rsc_dependancy_lh(rsc_dependancy_t *constraint);
extern void group_rsc_dependancy_rh(
	resource_t *rsc, rsc_dependancy_t *constraint);
extern void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order);
extern void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order);
extern void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint);
extern void group_expand(resource_t *rsc, xmlNodePtr *graph);
extern void group_dump(resource_t *rsc, const char *pre_text, gboolean details);
extern void group_free(resource_t *rsc);


/* extern resource_object_functions_t resource_variants[]; */
extern resource_object_functions_t resource_class_functions[];
extern gboolean common_unpack(xmlNodePtr xml_obj, resource_t **rsc);
extern void common_dump(
	resource_t *rsc, const char *pre_text, gboolean details);
extern void common_free(resource_t *rsc);
extern void native_add_running(resource_t *rsc, node_t *node);
extern gboolean is_active(rsc_to_node_t *cons);

extern gboolean native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint);

extern void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);
