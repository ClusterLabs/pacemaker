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

static GHashTable *crm_uuid_cache = NULL;
static GHashTable *crm_uname_cache = NULL;

static char *
get_heartbeat_uuid(uint32_t unused, const char *uname)
{
    char *uuid_calc = NULL;

#if SUPPORT_HEARTBEAT
    cl_uuid_t uuid_raw;
    const char *unknown = "00000000-0000-0000-0000-000000000000";

    if (heartbeat_cluster == NULL) {
        crm_warn("No connection to heartbeat, using uuid=uname");
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
get_corosync_uuid(uint32_t id, const char *uname)
{
    if (!uname_is_uuid() && is_corosync_cluster()) {
        if (id <= 0) {
            /* Try the membership cache... */
            crm_node_t *node = g_hash_table_lookup(crm_peer_cache, uname);

            if (node != NULL) {
                id = node->id;
            }
        }

        if (id > 0) {
            int len = 32;
            char *buffer = NULL;

            buffer = calloc(1, (len + 1));
            if (buffer != NULL) {
                snprintf(buffer, len, "%u", id);
            }

            return buffer;

        } else {
            crm_warn("Node %s is not yet known by corosync", uname);
        }

    } else if (uname != NULL) {
        return strdup(uname);
    }

    return NULL;
}

void
set_node_uuid(const char *uname, const char *uuid)
{
    CRM_CHECK(uuid != NULL, return);
    CRM_CHECK(uname != NULL, return);

    if (crm_uuid_cache == NULL) {
        crm_uuid_cache = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                               g_hash_destroy_str, g_hash_destroy_str);
    }

    g_hash_table_insert(crm_uuid_cache, strdup(uname), strdup(uuid));
}

const char *
get_node_uuid(uint32_t id, const char *uname)
{
    char *uuid = NULL;
    enum cluster_type_e type = get_cluster_type();

    if (crm_uuid_cache == NULL) {
        crm_uuid_cache = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                               g_hash_destroy_str, g_hash_destroy_str);
    }

    /* avoid blocking heartbeat calls where possible */
    if (uname) {
        uuid = g_hash_table_lookup(crm_uuid_cache, uname);
    }
    if (uuid != NULL) {
        return uuid;
    }

    switch (type) {
        case pcmk_cluster_corosync:
            uuid = get_corosync_uuid(id, uname);
            break;

        case pcmk_cluster_cman:
        case pcmk_cluster_classic_ais:
            if (uname) {
                uuid = strdup(uname);
            }
            break;

        case pcmk_cluster_heartbeat:
            uuid = get_heartbeat_uuid(id, uname);
            break;

        case pcmk_cluster_unknown:
        case pcmk_cluster_invalid:
            crm_err("Unsupported cluster type");
            break;
    }

    if (uuid == NULL) {
        return NULL;
    }

    if (uname) {
        g_hash_table_insert(crm_uuid_cache, strdup(uname), uuid);
        return g_hash_table_lookup(crm_uuid_cache, uname);
    }

    /* Memory leak! */
    CRM_LOG_ASSERT(uuid != NULL);
    return uuid;
}

gboolean
crm_cluster_connect(crm_cluster_t *cluster)
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

        CRM_ASSERT(cluster->hb_conn != NULL);
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
                crm_warn("Cannot set sendq length: %s", heartbeat_cluster->llc_ops->errmsg(heartbeat_cluster));
            }
        }
        return rv;
    }
#endif
    crm_info("Unsupported cluster stack: %s", getenv("HA_cluster_type"));
    return FALSE;
}

void
crm_cluster_disconnect(crm_cluster_t *cluster)
{
    enum cluster_type_e type = get_cluster_type();
    const char *type_str = name_for_cluster_type(type);

    crm_info("Disconnecting from cluster infrastructure: %s", type_str);
#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        crm_peer_destroy();
        terminate_cs_connection();
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
send_cluster_message(crm_node_t *node, enum crm_ais_msg_types service, xmlNode * data,
                     gboolean ordered)
{

#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        return send_ais_message(data, FALSE, node, service);
    }
#endif
#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        return send_ha_message(heartbeat_cluster, data, node->uname, ordered);
    }
#endif
    return FALSE;
}

void
empty_uuid_cache(void)
{
    if (crm_uuid_cache != NULL) {
        g_hash_table_destroy(crm_uuid_cache);
        crm_uuid_cache = NULL;
    }
}

void
unget_uuid(const char *uname)
{
    if (crm_uuid_cache == NULL) {
        return;
    }
    g_hash_table_remove(crm_uuid_cache, uname);
}

const char *
get_uuid(const char *uname)
{
    return get_node_uuid(0, uname);
}

char *
get_local_node_name(void)
{
    int rc;
    char *name = NULL;
    struct utsname res;
    enum cluster_type_e stack = get_cluster_type();

    switch(stack) {

#if SUPPORT_CMAN
        case pcmk_cluster_cman:
            name = cman_node_name(0 /* AKA. CMAN_NODEID_US */);
            break;
#endif

#if SUPPORT_COROSYNC
# if !SUPPORT_PLUGIN
        case pcmk_cluster_corosync:
            name = corosync_node_name(0, 0);
            break;
# endif
#endif
        case pcmk_cluster_heartbeat:
        case pcmk_cluster_classic_ais:
            rc = uname(&res);
            if(rc == 0) {
                name = strdup(res.nodename);
            }
            break;
        default:
            crm_err("Unknown cluster type: %s (%d)", name_for_cluster_type(stack), stack);
    }

    if(name == NULL) {
        crm_err("Could not obtain the local %s node name", name_for_cluster_type(stack));
        exit(100);
    }
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
        case pcmk_cluster_corosync:
            name = corosync_node_name(0, nodeid);
            break;
#endif

#if SUPPORT_CMAN
        case pcmk_cluster_cman:
            name = cman_node_name(nodeid);
            break;
#endif

        default:
            crm_err("Unknown cluster type: %s (%d)", name_for_cluster_type(stack), stack);
    }
    
    if(name == NULL) {
        crm_notice("Could not obtain a node name for %s nodeid %u",
                   name_for_cluster_type(stack), nodeid);
    }
    return name;
}

/* Only used by update_failcount() in te_utils.c */
const char *
get_uname(const char *uuid)
{
    char *uname = NULL;

    if (crm_uname_cache == NULL) {
        crm_uname_cache = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                g_hash_destroy_str, g_hash_destroy_str);
    }

    CRM_CHECK(uuid != NULL, return NULL);

    /* avoid blocking calls where possible */
    uname = g_hash_table_lookup(crm_uname_cache, uuid);
    if (uname != NULL) {
        crm_trace("%s = %s (cached)", uuid, uname);
        return uname;
    }

#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        if (!uname_is_uuid() && is_corosync_cluster()) {
            uint32_t id = crm_int_helper(uuid, NULL);
            crm_node_t *node = g_hash_table_lookup(crm_peer_id_cache, GUINT_TO_POINTER(id));

            if(node && node->uname) {
                uname = strdup(node->uname);
            }

        } else {
            uname = strdup(uuid);
        }
    }
#endif

#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
        if (heartbeat_cluster != NULL) {
            cl_uuid_t uuid_raw;
            char *uuid_copy = strdup(uuid);

            cl_uuid_parse(uuid_copy, &uuid_raw);
            uname = malloc( MAX_NAME);

            if (heartbeat_cluster->llc_ops->get_name_by_uuid(
                    heartbeat_cluster, &uuid_raw, uname, MAX_NAME) == HA_FAIL) {
                crm_err("Could not calculate uname for %s", uuid);
                free(uuid_copy);
                free(uname);
                uname = NULL;
            }
        }
    }
#endif

    if (uname) {
        crm_trace("Storing %s = %s", uuid, uname);
        g_hash_table_insert(crm_uname_cache, strdup(uuid), uname);
    }
    return uname;
}

void
set_uuid(xmlNode * node, const char *attr, const char *uname)
{
    const char *uuid_calc = get_uuid(uname);

    crm_xml_add(node, attr, uuid_calc);
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
    if (cluster_type == pcmk_cluster_unknown) {
        const char *cluster = getenv("HA_cluster_type");

        cluster_type = pcmk_cluster_invalid;
        if (cluster) {
            crm_info("Cluster type is: '%s'", cluster);

        } else {
#if SUPPORT_COROSYNC
            cluster_type = find_corosync_variant();
            if (cluster_type == pcmk_cluster_unknown) {
                cluster = "heartbeat";
                crm_info("Assuming a 'heartbeat' based cluster");
            } else {
                cluster = name_for_cluster_type(cluster_type);
                crm_info("Detected an active '%s' cluster", cluster);
            }
#else
            cluster = "heartbeat";
#endif
        }

        if (safe_str_eq(cluster, "heartbeat")) {
#if SUPPORT_HEARTBEAT
            cluster_type = pcmk_cluster_heartbeat;
#else
            cluster_type = pcmk_cluster_invalid;
#endif
        } else if (safe_str_eq(cluster, "openais")
                   || safe_str_eq(cluster, "classic openais (with plugin)")) {
#if SUPPORT_COROSYNC
            cluster_type = pcmk_cluster_classic_ais;
#else
            cluster_type = pcmk_cluster_invalid;
#endif
        } else if (safe_str_eq(cluster, "corosync")) {
#if SUPPORT_COROSYNC
            cluster_type = pcmk_cluster_corosync;
#else
            cluster_type = pcmk_cluster_invalid;
#endif
        } else if (safe_str_eq(cluster, "cman")) {
#if SUPPORT_CMAN
            cluster_type = pcmk_cluster_cman;
#else
            cluster_type = pcmk_cluster_invalid;
#endif
        } else {
            cluster_type = pcmk_cluster_invalid;
        }

        if (cluster_type == pcmk_cluster_invalid) {
            crm_notice
                ("This installation of Pacemaker does not support the '%s' cluster infrastructure.  Terminating.",
                 cluster);
            exit(100);
        }
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

    if(name == NULL) {
        crm_trace("%s is empty", key);
        return FALSE;

    } else if(sscanf(name, "%d.%d.%d.%d", &octet, &octet, &octet, &octet) == 4) {
        crm_trace("%s contains an ipv4 address, ignoring: %s", key, name);
        return FALSE;

    } else if(strstr(name, ":") != NULL) {
        crm_trace("%s contains an ipv6 address, ignoring: %s", key, name);
        return FALSE;
    }
    crm_trace("%s is valid", key);
    return TRUE;
}
