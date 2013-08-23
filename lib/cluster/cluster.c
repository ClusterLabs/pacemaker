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

#if SUPPORT_HEARTBEAT
void *hb_library = NULL;
#endif

static char *
get_heartbeat_uuid(const char *uname)
{
    char *uuid_calc = NULL;

#if SUPPORT_HEARTBEAT
    cl_uuid_t uuid_raw;
    const char *unknown = "00000000-0000-0000-0000-000000000000";

    if (heartbeat_cluster == NULL) {
        crm_warn("No connection to heartbeat, using uuid=uname");
        return NULL;
    } else if(uname == NULL) {
        return NULL;
    }

    if (heartbeat_cluster->llc_ops->get_uuid_by_name(heartbeat_cluster, uname, &uuid_raw) ==
        HA_FAIL) {
        crm_err("get_uuid_by_name() call failed for host %s", uname);
        free(uuid_calc);
        return NULL;
    }

    uuid_calc = calloc(1, 50);
    cl_uuid_unparse(&uuid_raw, uuid_calc);

    if (safe_str_eq(uuid_calc, unknown)) {
        crm_warn("Could not calculate UUID for %s", uname);
        free(uuid_calc);
        return NULL;
    }
#endif
    return uuid_calc;
}

static gboolean
uname_is_uuid(void)
{
    static const char *uuid_pref = NULL;

    if (uuid_pref == NULL) {
        uuid_pref = getenv("PCMK_uname_is_uuid");
    }

    if (uuid_pref == NULL) {
        /* true is legacy mode */
        uuid_pref = "false";
    }

    return crm_is_true(uuid_pref);
}

int
get_corosync_id(int id, const char *uuid)
{
    if (id == 0 && !uname_is_uuid() && is_corosync_cluster()) {
        id = crm_atoi(uuid, "0");
    }

    return id;
}

char *
get_corosync_uuid(crm_node_t *node)
{
    if(node == NULL) {
        return NULL;

    } else if (!uname_is_uuid() && is_corosync_cluster()) {
        if (node->id > 0) {
            int len = 32;
            char *buffer = NULL;

            buffer = calloc(1, (len + 1));
            if (buffer != NULL) {
                snprintf(buffer, len, "%u", node->id);
            }

            return buffer;

        } else {
            crm_info("Node %s is not yet known by corosync", node->uname);
        }

    } else if (node->uname != NULL) {
        return strdup(node->uname);
    }

    return NULL;
}

const char *
crm_peer_uuid(crm_node_t *peer)
{
    char *uuid = NULL;
    enum cluster_type_e type = get_cluster_type();

    /* avoid blocking heartbeat calls where possible */
    if(peer == NULL) {
        return NULL;

    } else if (peer->uuid) {
        return peer->uuid;
    }

    switch (type) {
        case pcmk_cluster_corosync:
            uuid = get_corosync_uuid(peer);
            break;

        case pcmk_cluster_cman:
        case pcmk_cluster_classic_ais:
            if (peer->uname) {
                uuid = strdup(peer->uname);
            }
            break;

        case pcmk_cluster_heartbeat:
            uuid = get_heartbeat_uuid(peer->uname);
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

    crm_notice("Connecting to cluster infrastructure: %s", name_for_cluster_type(type));
#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        crm_peer_init();
        return init_cs_connection(cluster);
    }
#endif

#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        int rv;

        /* coverity[var_deref_op] False positive */
        if (cluster->hb_conn == NULL) {
            /* No object passed in, create a new one. */
            ll_cluster_t *(*new_cluster) (const char *llctype) =
                find_library_function(&hb_library, HEARTBEAT_LIBRARY, "ll_cluster_new", 1);

            cluster->hb_conn = (*new_cluster) ("heartbeat");
            /* dlclose(handle); */

        } else {
            /* Object passed in. Disconnect first, then reconnect below. */
            cluster->hb_conn->llc_ops->signoff(cluster->hb_conn, FALSE);
        }

        /* make sure we are disconnected first with the old object, if any. */
        if (heartbeat_cluster && heartbeat_cluster != cluster->hb_conn) {
            heartbeat_cluster->llc_ops->signoff(heartbeat_cluster, FALSE);
        }

        CRM_ASSERT(cluster->hb_conn != NULL);
        heartbeat_cluster = cluster->hb_conn;

        rv = register_heartbeat_conn(cluster);
        if (rv) {
            /* we'll benefit from a bigger queue length on heartbeat side.
             * Otherwise, if peers send messages faster than we can consume
             * them right now, heartbeat messaging layer will kick us out once
             * it's (small) default queue fills up :(
             * If we fail to adjust the sendq length, that's not yet fatal, though.
             */
            if (HA_OK != heartbeat_cluster->llc_ops->set_sendq_len(heartbeat_cluster, 1024)) {
                crm_warn("Cannot set sendq length: %s",
                         heartbeat_cluster->llc_ops->errmsg(heartbeat_cluster));
            }
        }
        return rv;
    }
#endif
    crm_info("Unsupported cluster stack: %s", getenv("HA_cluster_type"));
    return FALSE;
}

void
crm_cluster_disconnect(crm_cluster_t * cluster)
{
    enum cluster_type_e type = get_cluster_type();
    const char *type_str = name_for_cluster_type(type);

    crm_info("Disconnecting from cluster infrastructure: %s", type_str);
#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        crm_peer_destroy();
        terminate_cs_connection(cluster);
        crm_info("Disconnected from %s", type_str);
        return;
    }
#endif

#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        if (cluster == NULL) {
            crm_info("No cluster connection");
            return;

        } else if (cluster->hb_conn) {
            cluster->hb_conn->llc_ops->signoff(cluster->hb_conn, FALSE);
            cluster->hb_conn = NULL;
            crm_info("Disconnected from %s", type_str);
            return;

        } else {
            crm_info("No %s connection", type_str);
            return;
        }
    }
#endif
    crm_info("Unsupported cluster stack: %s", getenv("HA_cluster_type"));
}

gboolean
send_cluster_message(crm_node_t * node, enum crm_ais_msg_types service, xmlNode * data,
                     gboolean ordered)
{

#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        return send_cluster_message_cs(data, FALSE, node, service);
    }
#endif
#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        return send_ha_message(heartbeat_cluster, data, node ? node->uname : NULL, ordered);
    }
#endif
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
    enum cluster_type_e stack = get_cluster_type();

    switch (stack) {
        case pcmk_cluster_heartbeat:
            break;

#if SUPPORT_PLUGIN
        case pcmk_cluster_classic_ais:
            name = classic_node_name(nodeid);
            break;
#else
#  if SUPPORT_COROSYNC
        case pcmk_cluster_corosync:
            name = corosync_node_name(0, nodeid);
            break;
#  endif
#endif

#if SUPPORT_CMAN
        case pcmk_cluster_cman:
            name = cman_node_name(nodeid);
            break;
#endif

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

/* Only used by update_failcount() in te_utils.c */
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

#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        if (uname_is_uuid() == FALSE && is_corosync_cluster()) {
            uint32_t id = crm_int_helper(uuid, NULL);

            node = crm_get_peer(id, NULL);

        } else {
            node = crm_get_peer(0, uuid);
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

#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        if (heartbeat_cluster != NULL) {
            cl_uuid_t uuid_raw;
            char *uuid_copy = strdup(uuid);
            char *uname = malloc(MAX_NAME);

            cl_uuid_parse(uuid_copy, &uuid_raw);

            if (heartbeat_cluster->llc_ops->get_name_by_uuid(heartbeat_cluster, &uuid_raw, uname,
                                                             MAX_NAME) == HA_FAIL) {
                crm_err("Could not calculate uname for %s", uuid);
            } else {
                node = crm_get_peer(0, uname);
            }

            free(uuid_copy);
            free(uname);
        }

        if (node) {
            crm_info("Setting uuid for node %s to '%s'", node->uname, uuid);
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
        case pcmk_cluster_classic_ais:
            return "classic openais (with plugin)";
        case pcmk_cluster_cman:
            return "cman";
        case pcmk_cluster_corosync:
            return "corosync";
        case pcmk_cluster_heartbeat:
            return "heartbeat";
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

    cluster = getenv("HA_cluster_type");

#if SUPPORT_HEARTBEAT
    /* If nothing is defined in the environment, try heartbeat (if supported) */
    if(cluster == NULL) {
        ll_cluster_t *hb;
        ll_cluster_t *(*new_cluster) (const char *llctype) = find_library_function(
            &hb_library, HEARTBEAT_LIBRARY, "ll_cluster_new", 1);

        hb = (*new_cluster) ("heartbeat");

        crm_debug("Testing with Heartbeat");
        if (hb->llc_ops->signon(hb, crm_system_name) == HA_OK) {
            hb->llc_ops->signoff(hb, FALSE);

            cluster_type = pcmk_cluster_heartbeat;
            detected = TRUE;
            goto done;
        }
    }
#endif

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

#if SUPPORT_HEARTBEAT
    } else if (safe_str_eq(cluster, "heartbeat")) {
        cluster_type = pcmk_cluster_heartbeat;
#endif

#if SUPPORT_COROSYNC
    } else if (safe_str_eq(cluster, "openais")
               || safe_str_eq(cluster, "classic openais (with plugin)")) {
        cluster_type = pcmk_cluster_classic_ais;

    } else if (safe_str_eq(cluster, "corosync")) {
        cluster_type = pcmk_cluster_corosync;
#endif

#if SUPPORT_CMAN
    } else if (safe_str_eq(cluster, "cman")) {
        cluster_type = pcmk_cluster_cman;
#endif

    } else {
        cluster_type = pcmk_cluster_invalid;
        goto done; /* Keep the compiler happy when no stacks are supported */
    }

  done:
    if (cluster_type == pcmk_cluster_unknown) {
        crm_notice("Could not determin the current cluster type");

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
is_cman_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_cman;
}

gboolean
is_corosync_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_corosync;
}

gboolean
is_classic_ais_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_classic_ais;
}

gboolean
is_openais_cluster(void)
{
    enum cluster_type_e type = get_cluster_type();

    if (type == pcmk_cluster_classic_ais) {
        return TRUE;
    } else if (type == pcmk_cluster_corosync) {
        return TRUE;
    } else if (type == pcmk_cluster_cman) {
        return TRUE;
    }
    return FALSE;
}

gboolean
is_heartbeat_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_heartbeat;
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
