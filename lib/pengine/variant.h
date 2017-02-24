/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PE_VARIANT__H
#  define PE_VARIANT__H

#  if VARIANT_CLONE

typedef struct clone_variant_data_s {
    int clone_max;
    int clone_node_max;

    int master_max;
    int master_node_max;

    int total_clones;
    int active_clones;
    int max_nodes;

    int masters_active;
    int masters_allocated;

    gboolean interleave;
    gboolean ordered;
    gboolean applied_master_prefs;
    gboolean merged_master_weights;

    notify_data_t *stop_notify;
    notify_data_t *start_notify;
    notify_data_t *demote_notify;
    notify_data_t *promote_notify;

    xmlNode *xml_obj_child;

    gboolean notify_confirm;

} clone_variant_data_t;

#    define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_clone || rsc->variant == pe_master); \
	data = (clone_variant_data_t *)rsc->variant_opaque;

#  elif VARIANT_CONTAINER

typedef struct
{
        int offset;
        node_t *node;
        resource_t *ip;
        resource_t *child;
        resource_t *docker;
        resource_t *remote;

} container_grouping_t;

typedef struct container_variant_data_s {
        int replicas;
        char *prefix;
        char *image;
        char *ip_last;
        char *ip_range_start;
        char *docker_run_options;
        xmlNode *xml_docker_options;
        xmlNode *xml_network;
        xmlNode *xml_mounts;

        resource_t *child;

        GListPtr tuples;     /* container_grouping_t *       */
        GListPtr ports;      /*        */
        GListPtr mounts;     /*        */


} container_variant_data_t;

#    define get_container_variant_data(data, rsc)                       \
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_container);                       \
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (container_variant_data_t *)rsc->variant_opaque;		\

#  elif VARIANT_GROUP

typedef struct group_variant_data_s {
    int num_children;
    resource_t *first_child;
    resource_t *last_child;

    gboolean colocated;
    gboolean ordered;

    gboolean child_starting;
    gboolean child_stopping;

} group_variant_data_t;

#    define get_group_variant_data(data, rsc)				\
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_group);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (group_variant_data_t *)rsc->variant_opaque;		\

#  elif VARIANT_NATIVE

typedef struct native_variant_data_s {
    int dummy;
} native_variant_data_t;

#    define get_native_variant_data(data, rsc)				\
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_native);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (native_variant_data_t *)rsc->variant_opaque;

#  endif

#endif
