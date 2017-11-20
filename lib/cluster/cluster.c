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

#include <crm_internal.h>
#include <dlfcn.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>

#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

CRM_TRACE_INIT_DATA(cluster);

const char *
crm_peer_uuid(crm_node_t *peer)
{
    char *uuid = NULL;
    enum cluster_type_e type = get_cluster_type();

    // Check simple cases first, to avoid any calls that might block
    if(peer == NULL) {
        return NULL;

    } else if (peer->uuid) {
        return peer->uuid;
    }

    switch (type) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            uuid = get_corosync_uuid(peer);
#endif
            break;

        case pcmk_cluster_unknown:
        case pcmk_cluster_invalid:
            crm_err("Unsupported cluster type");
            break;
    }

    peer->uuid = uuid;
    return peer->uuid;
}

gboolean
crm_cluster_connect(crm_cluster_t * cluster)
{
    enum cluster_type_e type = get_cluster_type();

    crm_notice("Connecting to cluster infrastructure: %s",
               name_for_cluster_type(type));
    switch (type) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            if (is_corosync_cluster()) {
                crm_peer_init();
                return init_cs_connection(cluster);
            }
#endif
            break;
        default:
            break;
    }
    return FALSE;
}

void
crm_cluster_disconnect(crm_cluster_t * cluster)
{
    enum cluster_type_e type = get_cluster_type();

    crm_info("Disconnecting from cluster infrastructure: %s",
             name_for_cluster_type(type));
    switch (type) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            if (is_corosync_cluster()) {
                crm_peer_destroy();
                terminate_cs_connection(cluster);
            }
#endif
            break;
        default:
            break;
    }
}

gboolean
send_cluster_message(crm_node_t * node, enum crm_ais_msg_types service, xmlNode * data,
                     gboolean ordered)
{
    switch (get_cluster_type()) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            return send_cluster_message_cs(data, FALSE, node, service);
#endif
            break;
        default:
            break;
    }
    return FALSE;
}

const char *
get_local_node_name(void)
{
    static char *name = NULL;

    if(name) {
        return name;
    }
    name = get_node_name(0);
    return name;
}

char *
get_node_name(uint32_t nodeid)
{
    char *name = NULL;
    const char *isolation_host = NULL;
    enum cluster_type_e stack;

    if (nodeid == 0) {
        isolation_host = getenv("OCF_RESKEY_"CRM_META"_isolation_host");
        if (isolation_host) {
            return strdup(isolation_host);
        }
    }

    stack = get_cluster_type();
    switch (stack) {
#  if SUPPORT_COROSYNC
        case pcmk_cluster_corosync:
            name = corosync_node_name(0, nodeid);
            break;
#  endif

        default:
            crm_err("Unknown cluster type: %s (%d)", name_for_cluster_type(stack), stack);
    }

    if(name == NULL && nodeid == 0) {
        struct utsname res;
        int rc = uname(&res);

        if (rc == 0) {
            crm_notice("Defaulting to uname -n for the local %s node name",
                       name_for_cluster_type(stack));
            name = strdup(res.nodename);
        }

        if (name == NULL) {
            crm_err("Could not obtain the local %s node name", name_for_cluster_type(stack));
            crm_exit(DAEMON_RESPAWN_STOP);
        }
    }

    if (name == NULL) {
        crm_notice("Could not obtain a node name for %s nodeid %u",
                   name_for_cluster_type(stack), nodeid);
    }
    return name;
}

/*!
 * \brief Get the node name corresponding to a node UUID
 *
 * \param[in] uuid  UUID of desired node
 *
 * \return name of desired node
 *
 * \note This relies on the remote peer cache being populated with all
 *       remote nodes in the cluster, so callers should maintain that cache.
 */
const char *
crm_peer_uname(const char *uuid)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;

    CRM_CHECK(uuid != NULL, return NULL);

    /* remote nodes have the same uname and uuid */
    if (g_hash_table_lookup(crm_remote_peer_cache, uuid)) {
        return uuid;
    }

    /* avoid blocking calls where possible */
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        if(node->uuid && strcasecmp(node->uuid, uuid) == 0) {
            if(node->uname) {
                return node->uname;
            }
            break;
        }
    }
    node = NULL;

#if SUPPORT_COROSYNC
    if (is_corosync_cluster()) {
        uint32_t id = crm_int_helper(uuid, NULL);

        if (id != 0) {
            node = crm_find_peer(id, NULL);
        } else {
            crm_err("Invalid node id: %s", uuid);
        }

        if (node) {
            crm_info("Setting uuid for node %s[%u] to '%s'", node->uname, node->id, uuid);
            node->uuid = strdup(uuid);
            if(node->uname) {
                return node->uname;
            }
        }
        return NULL;
    }
#endif

    return NULL;
}

void
set_uuid(xmlNode *xml, const char *attr, crm_node_t *node)
{
    const char *uuid_calc = crm_peer_uuid(node);

    crm_xml_add(xml, attr, uuid_calc);
    return;
}

const char *
name_for_cluster_type(enum cluster_type_e type)
{
    switch (type) {
        case pcmk_cluster_corosync:
            return "corosync";
        case pcmk_cluster_unknown:
            return "unknown";
        case pcmk_cluster_invalid:
            return "invalid";
    }
    crm_err("Invalid cluster type: %d", type);
    return "invalid";
}

/* Do not expose these two */
int set_cluster_type(enum cluster_type_e type);
static enum cluster_type_e cluster_type = pcmk_cluster_unknown;

int
set_cluster_type(enum cluster_type_e type)
{
    if (cluster_type == pcmk_cluster_unknown) {
        crm_info("Cluster type set to: %s", name_for_cluster_type(type));
        cluster_type = type;
        return 0;

    } else if (cluster_type == type) {
        return 0;

    } else if (pcmk_cluster_unknown == type) {
        cluster_type = type;
        return 0;
    }

    crm_err("Cluster type already set to %s, ignoring %s",
            name_for_cluster_type(cluster_type), name_for_cluster_type(type));
    return -1;
}
enum cluster_type_e
get_cluster_type(void)
{
    bool detected = FALSE;
    const char *cluster = NULL;

    /* Return the previous calculation, if any */
    if (cluster_type != pcmk_cluster_unknown) {
        return cluster_type;
    }

    cluster = daemon_option("cluster_type");

#if SUPPORT_COROSYNC
    /* If nothing is defined in the environment, try corosync (if supported) */
    if(cluster == NULL) {
        crm_debug("Testing with Corosync");
        cluster_type = find_corosync_variant();
        if (cluster_type != pcmk_cluster_unknown) {
            detected = TRUE;
            goto done;
        }
    }
#endif

    /* Something was defined in the environment, test it against what we support */
    crm_info("Verifying cluster type: '%s'", cluster?cluster:"-unspecified-");
    if (cluster == NULL) {

#if SUPPORT_COROSYNC
    } else if (safe_str_eq(cluster, "corosync")) {
        cluster_type = pcmk_cluster_corosync;
#endif

    } else {
        cluster_type = pcmk_cluster_invalid;
        goto done; /* Keep the compiler happy when no stacks are supported */
    }

  done:
    if (cluster_type == pcmk_cluster_unknown) {
        crm_notice("Could not determine the current cluster type");

    } else if (cluster_type == pcmk_cluster_invalid) {
        crm_notice("This installation does not support the '%s' cluster infrastructure: terminating.",
                   cluster);
        crm_exit(DAEMON_RESPAWN_STOP);

    } else {
        crm_info("%s an active '%s' cluster", detected?"Detected":"Assuming", name_for_cluster_type(cluster_type));
    }

    return cluster_type;
}

gboolean
is_corosync_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_corosync;
}

gboolean
node_name_is_valid(const char *key, const char *name)
{
    int octet;

    if (name == NULL) {
        crm_trace("%s is empty", key);
        return FALSE;

    } else if (sscanf(name, "%d.%d.%d.%d", &octet, &octet, &octet, &octet) == 4) {
        crm_trace("%s contains an ipv4 address, ignoring: %s", key, name);
        return FALSE;

    } else if (strstr(name, ":") != NULL) {
        crm_trace("%s contains an ipv6 address, ignoring: %s", key, name);
        return FALSE;
    }
    crm_trace("%s is valid", key);
    return TRUE;
}
