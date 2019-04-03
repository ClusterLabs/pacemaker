/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_VARIANT__H
#  define PE_VARIANT__H

#  if VARIANT_CLONE

typedef struct clone_variant_data_s {
    int clone_max;
    int clone_node_max;

    int promoted_max;
    int promoted_node_max;

    int total_clones;

    // @TODO make these a bitmask
    gboolean ordered;
    gboolean applied_master_prefs;
    gboolean merged_master_weights;

    notify_data_t *stop_notify;
    notify_data_t *start_notify;
    notify_data_t *demote_notify;
    notify_data_t *promote_notify;

    xmlNode *xml_obj_child;
} clone_variant_data_t;

#    define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_clone); \
	data = (clone_variant_data_t *)rsc->variant_opaque;

#  elif PE__VARIANT_BUNDLE

typedef struct {
    int offset;
    char *ipaddr;
    pe_node_t *node;
    pe_resource_t *ip;
    pe_resource_t *child;
    pe_resource_t *docker;
    pe_resource_t *remote;
} pe__bundle_grouping_t;

typedef struct {
    char *source;
    char *target;
    char *options;
    int flags;
} pe__bundle_mount_t;

typedef struct {
    char *source;
    char *target;
} pe__bundle_port_t;

enum container_type {
        PE_CONTAINER_TYPE_UNKNOWN,
        PE_CONTAINER_TYPE_DOCKER,
        PE_CONTAINER_TYPE_RKT,
        PE_CONTAINER_TYPE_PODMAN
};

#define PE_CONTAINER_TYPE_UNKNOWN_S "unknown"
#define PE_CONTAINER_TYPE_DOCKER_S  "Docker"
#define PE_CONTAINER_TYPE_RKT_S     "rkt"
#define PE_CONTAINER_TYPE_PODMAN_S  "podman"

typedef struct pe__bundle_variant_data_s {
        int promoted_max;
        int nreplicas;
        int nreplicas_per_host;
        char *prefix;
        char *image;
        const char *ip_last;
        char *host_network;
        char *host_netmask;
        char *control_port;
        char *docker_network;
        char *ip_range_start;
        gboolean add_host;
        char *docker_host_options;
        char *docker_run_options;
        char *docker_run_command;
        const char *attribute_target;

        resource_t *child;

        GList *tuples;      // pe__bundle_grouping_t *
        GList *ports;       // pe__bundle_port_t *
        GList *mounts;      // pe__bundle_mount_t *

        enum container_type type;
} pe__bundle_variant_data_t;

#    define get_bundle_variant_data(data, rsc)                       \
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_container);                       \
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (pe__bundle_variant_data_t *)rsc->variant_opaque;		\

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
