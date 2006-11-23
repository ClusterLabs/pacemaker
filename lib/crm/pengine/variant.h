/* $Id: utils.h,v 1.4 2006/06/21 11:06:13 andrew Exp $ */
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
#ifndef PE_VARIANT__H
#define PE_VARIANT__H

#if VARIANT_CLONE

typedef struct clone_variant_data_s {
		resource_t *self;

		int clone_max;
		int clone_node_max;

		int master_max;
		int master_node_max;

		int active_clones;
		int max_nodes;
		
		gboolean interleave;
		gboolean ordered;

		crm_data_t *xml_obj_child;
		
		gboolean notify_confirm;
		
		GListPtr child_list; /* resource_t* */
		
} clone_variant_data_t;

#  define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_clone || rsc->variant == pe_master); \
	data = (clone_variant_data_t *)rsc->variant_opaque;

#elif VARIANT_GROUP

typedef struct group_variant_data_s {
		int num_children;
		GListPtr child_list; /* resource_t* */
		resource_t *self;
		resource_t *first_child;
		resource_t *last_child;

		gboolean colocated;
		gboolean ordered;
		
		gboolean child_starting;
		gboolean child_stopping;
		
} group_variant_data_t;

#  define get_group_variant_data(data, rsc)				\
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_group);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (group_variant_data_t *)rsc->variant_opaque;		\

#elif VARIANT_NATIVE

typedef struct native_variant_data_s {
} native_variant_data_t;

#  define get_native_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_native);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (native_variant_data_t *)rsc->variant_opaque;

#endif

#endif
