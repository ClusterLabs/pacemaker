/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

    uint32_t flags; // Group of enum pe__clone_flags

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
    pe_resource_t *container;
    pe_resource_t *remote;
} pe__bundle_replica_t;

enum pe__bundle_mount_flags {
    pe__bundle_mount_none       = 0x00,

    // mount instance-specific subdirectory rather than source directly
    pe__bundle_mount_subdir     = 0x01
};

typedef struct {
    char *source;
    char *target;
    char *options;
    uint32_t flags; // bitmask of pe__bundle_mount_flags
} pe__bundle_mount_t;

typedef struct {
    char *source;
    char *target;
} pe__bundle_port_t;

enum pe__container_agent {
    PE__CONTAINER_AGENT_UNKNOWN,
    PE__CONTAINER_AGENT_DOCKER,
    PE__CONTAINER_AGENT_RKT,
    PE__CONTAINER_AGENT_PODMAN,
};

#define PE__CONTAINER_AGENT_UNKNOWN_S "unknown"
#define PE__CONTAINER_AGENT_DOCKER_S  "docker"
#define PE__CONTAINER_AGENT_RKT_S     "rkt"
#define PE__CONTAINER_AGENT_PODMAN_S  "podman"

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
        char *container_network;
        char *ip_range_start;
        gboolean add_host;
        gchar *container_host_options;
        char *container_command;
        char *launcher_options;
        const char *attribute_target;

        pe_resource_t *child;

        GList *replicas;    // pe__bundle_replica_t *
        GList *ports;       // pe__bundle_port_t *
        GList *mounts;      // pe__bundle_mount_t *

        enum pe__container_agent agent_type;
} pe__bundle_variant_data_t;

#    define get_bundle_variant_data(data, rsc)                       \
	CRM_ASSERT(rsc != NULL);					\
	CRM_ASSERT(rsc->variant == pe_container);                       \
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (pe__bundle_variant_data_t *)rsc->variant_opaque;		\

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
