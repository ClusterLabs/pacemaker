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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>

#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

#if SUPPORT_HEARTBEAT
ll_cluster_t *heartbeat_cluster = NULL;

static void
convert_ha_field(xmlNode * parent, void *msg_v, int lpc)
{
    int type = 0;
    const char *name = NULL;
    const char *value = NULL;
    xmlNode *xml = NULL;
    HA_Message *msg = msg_v;

    int rc = BZ_OK;
    size_t orig_len = 0;
    unsigned int used = 0;
    char *uncompressed = NULL;
    char *compressed = NULL;
    int size = orig_len * 10;

    CRM_CHECK(parent != NULL, return);
    CRM_CHECK(msg != NULL, return);

    name = msg->names[lpc];
    type = cl_get_type(msg, name);

    switch (type) {
        case FT_STRUCT:
            convert_ha_message(parent, msg->values[lpc], name);
            break;
        case FT_COMPRESS:
        case FT_UNCOMPRESS:
            convert_ha_message(parent, cl_get_struct(msg, name), name);
            break;
        case FT_STRING:
            value = msg->values[lpc];
            CRM_CHECK(value != NULL, return);
            crm_trace("Converting %s/%d/%s", name, type, value[0] == '<' ? "xml" : "field");

            if (value[0] != '<') {
                crm_xml_add(parent, name, value);
                break;
            }

            /* unpack xml string */
            xml = string2xml(value);
            if (xml == NULL) {
                crm_err("Conversion of field '%s' failed", name);
                return;
            }

            add_node_nocopy(parent, NULL, xml);
            break;

        case FT_BINARY:
            value = cl_get_binary(msg, name, &orig_len);
            size = orig_len * 10 + 1;   /* +1 because an exact 10x compression factor happens occasionally */

            if (orig_len < 3 || value[0] != 'B' || value[1] != 'Z' || value[2] != 'h') {
                if (strstr(name, "uuid") == NULL) {
                    crm_err("Skipping non-bzip binary field: %s", name);
                }
                return;
            }

            compressed = calloc(1, orig_len);
            memcpy(compressed, value, orig_len);

            crm_trace("Trying to decompress %d bytes", (int)orig_len);
  retry:
            uncompressed = realloc(uncompressed, size);
            memset(uncompressed, 0, size);
            used = size - 1;    /* always leave room for a trailing '\0'
                                 * BZ2_bzBuffToBuffDecompress wont say anything if
                                 * the uncompressed data is exactly 'size' bytes
                                 */

            rc = BZ2_bzBuffToBuffDecompress(uncompressed, &used, compressed, orig_len, 1, 0);

            if (rc == BZ_OUTBUFF_FULL) {
                size = size * 2;
                /* dont try to allocate more memory than we have */
                if (size > 0) {
                    goto retry;
                }
            }

            if (rc != BZ_OK) {
                crm_err("Decompression of %s (%d bytes) into %d failed: %d",
                        name, (int)orig_len, size, rc);

            } else if (used >= size) {
                CRM_ASSERT(used < size);

            } else {
                CRM_LOG_ASSERT(uncompressed[used] == 0);
                uncompressed[used] = 0;
                xml = string2xml(uncompressed);
            }

            if (xml != NULL) {
                add_node_copy(parent, xml);
                free_xml(xml);
            }

            free(uncompressed);
            free(compressed);
            break;
    }
}

xmlNode *
convert_ha_message(xmlNode * parent, HA_Message * msg, const char *field)
{
    int lpc = 0;
    xmlNode *child = NULL;
    const char *tag = NULL;

    CRM_CHECK(msg != NULL, crm_err("Empty message for %s", field);
              return parent);

    tag = cl_get_string(msg, F_XML_TAGNAME);
    if (tag == NULL) {
        tag = field;

    } else if (parent && safe_str_neq(field, tag)) {
        /* For compatability with 0.6.x */
        crm_debug("Creating intermediate parent %s between %s and %s", field,
                  crm_element_name(parent), tag);
        parent = create_xml_node(parent, field);
    }

    if (parent == NULL) {
        parent = create_xml_node(NULL, tag);
        child = parent;

    } else {
        child = create_xml_node(parent, tag);
    }

    for (lpc = 0; lpc < msg->nfields; lpc++) {
        convert_ha_field(child, msg, lpc);
    }

    return parent;
}

static void
add_ha_nocopy(HA_Message * parent, HA_Message * child, const char *field)
{
    int next = parent->nfields;

    if (parent->nfields >= parent->nalloc && ha_msg_expand(parent) != HA_OK) {
        crm_err("Parent expansion failed");
        return;
    }

    parent->names[next] = strdup(field);
    parent->nlens[next] = strlen(field);
    parent->values[next] = child;
    parent->vlens[next] = sizeof(HA_Message);
    parent->types[next] = FT_UNCOMPRESS;
    parent->nfields++;
}

static HA_Message *
convert_xml_message_struct(HA_Message * parent, xmlNode * src_node, const char *field)
{
    xmlNode *child = NULL;
    xmlNode *__crm_xml_iter = src_node->children;
    xmlAttrPtr prop_iter = src_node->properties;
    const char *name = NULL;
    const char *value = NULL;

    HA_Message *result = ha_msg_new(3);

    ha_msg_add(result, F_XML_TAGNAME, (const char *)src_node->name);

    while (prop_iter != NULL) {
        name = (const char *)prop_iter->name;
        value = (const char *)xmlGetProp(src_node, prop_iter->name);
        prop_iter = prop_iter->next;
        ha_msg_add(result, name, value);
    }

    while (__crm_xml_iter != NULL) {
        child = __crm_xml_iter;
        __crm_xml_iter = __crm_xml_iter->next;
        convert_xml_message_struct(result, child, NULL);
    }

    if (parent == NULL) {
        return result;
    }

    if (field) {
        HA_Message *holder = ha_msg_new(3);

        CRM_ASSERT(holder != NULL);

        ha_msg_add(holder, F_XML_TAGNAME, field);
        add_ha_nocopy(holder, result, (const char *)src_node->name);

        ha_msg_addstruct_compress(parent, field, holder);
        ha_msg_del(holder);

    } else {
        add_ha_nocopy(parent, result, (const char *)src_node->name);
    }
    return result;
}

static void
convert_xml_child(HA_Message * msg, xmlNode * xml)
{
    int orig = 0;
    int rc = BZ_OK;
    unsigned int len = 0;

    char *buffer = NULL;
    char *compressed = NULL;
    const char *name = NULL;

    name = (const char *)xml->name;
    buffer = dump_xml_unformatted(xml);
    orig = strlen(buffer);
    if (orig < CRM_BZ2_THRESHOLD) {
        ha_msg_add(msg, name, buffer);
        goto done;
    }

    len = (orig * 1.1) + 600;   /* recomended size */

    compressed = malloc(len);
    rc = BZ2_bzBuffToBuffCompress(compressed, &len, buffer, orig, CRM_BZ2_BLOCKS, 0, CRM_BZ2_WORK);

    if (rc != BZ_OK) {
        crm_err("Compression failed: %d", rc);
        free(compressed);
        convert_xml_message_struct(msg, xml, name);
        goto done;
    }

    free(buffer);
    buffer = compressed;
    crm_trace("Compression details: %d -> %d", orig, len);
    ha_msg_addbin(msg, name, buffer, len);
  done:
    free(buffer);

#  if 0
    {
        unsigned int used = orig;
        char *uncompressed = NULL;

        crm_debug("Trying to decompress %d bytes", len);
        uncompressed = calloc(1, orig);
        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &used, compressed, len, 1, 0);
        CRM_CHECK(rc == BZ_OK,;
            );
        CRM_CHECK(used == orig,;
            );
        crm_debug("rc=%d, used=%d", rc, used);
        if (rc != BZ_OK) {
            crm_exit(100);
        }
        crm_debug("Original %s, decompressed %s", buffer, uncompressed);
        free(uncompressed);
    }
#  endif
}

static HA_Message *
convert_xml_message(xmlNode * xml)
{
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;
    HA_Message *result = NULL;

    result = ha_msg_new(3);
    ha_msg_add(result, F_XML_TAGNAME, (const char *)xml->name);

    for (pIter = xml->properties; pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;

        if (pIter->children) {
            const char *p_value = (const char *)pIter->children->content;

            ha_msg_add(result, p_name, p_value);
        }
    }
    for (child = __xml_first_child(xml); child != NULL; child = __xml_next(child)) {
        convert_xml_child(result, child);
    }

    return result;
}

gboolean
crm_is_heartbeat_peer_active(const crm_node_t * node)
{
    enum crm_proc_flag proc = text2proc(crm_system_name);

    if (node == NULL) {
        crm_trace("NULL");
        return FALSE;

    } else if (safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        crm_trace("%s: state=%s", node->uname, node->state);
        return FALSE;

    } else if ((node->processes & crm_proc_heartbeat) == 0) {
        crm_trace("%s: processes=%.16x", node->uname, node->processes);
        return FALSE;

    } else if (proc == crm_proc_none) {
        return TRUE;

    } else if ((node->processes & proc) == 0) {
        crm_trace("%s: proc %.16x not in %.16x", node->uname, proc, node->processes);
        return FALSE;
    }
    return TRUE;
}

crm_node_t *
crm_update_ccm_node(const oc_ev_membership_t * oc, int offset, const char *state, uint64_t seq)
{
    crm_node_t *peer = NULL;
    const char *uuid = NULL;

    CRM_CHECK(oc->m_array[offset].node_uname != NULL, return NULL);
    uuid = get_uuid(oc->m_array[offset].node_uname);
    peer = crm_update_peer(__FUNCTION__, oc->m_array[offset].node_id,
                           oc->m_array[offset].node_born_on, seq, -1, 0,
                           uuid, oc->m_array[offset].node_uname, NULL, state);

    if (safe_str_eq(CRM_NODE_ACTIVE, state)) {
        /* Heartbeat doesn't send status notifications for nodes that were already part of the cluster */
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_heartbeat, ONLINESTATUS);

        /* Nor does it send status notifications for processes that were already active */
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_crmd, ONLINESTATUS);
    }
    return peer;
}

gboolean
send_ha_message(ll_cluster_t * hb_conn, xmlNode * xml, const char *node, gboolean force_ordered)
{
    gboolean all_is_good = TRUE;
    HA_Message *msg = convert_xml_message(xml);

    if (msg == NULL) {
        crm_err("cant send NULL message");
        all_is_good = FALSE;

    } else if (hb_conn == NULL) {
        crm_err("No heartbeat connection specified");
        all_is_good = FALSE;

    } else if (hb_conn->llc_ops->chan_is_connected(hb_conn) == FALSE) {
        crm_err("Not connected to Heartbeat");
        all_is_good = FALSE;

    } else if (node != NULL) {
        char *host_lowercase = g_ascii_strdown(node, -1);

        if (hb_conn->llc_ops->send_ordered_nodemsg(hb_conn, msg, host_lowercase) != HA_OK) {
            all_is_good = FALSE;
            crm_err("Send failed");
        }
        free(host_lowercase);

    } else if (force_ordered) {
        if (hb_conn->llc_ops->send_ordered_clustermsg(hb_conn, msg) != HA_OK) {
            all_is_good = FALSE;
            crm_err("Broadcast Send failed");
        }

    } else {
        if (hb_conn->llc_ops->sendclustermsg(hb_conn, msg) != HA_OK) {
            all_is_good = FALSE;
            crm_err("Broadcast Send failed");
        }
    }

    if (all_is_good == FALSE && hb_conn != NULL) {
        IPC_Channel *ipc = NULL;
        IPC_Queue *send_q = NULL;

        if (hb_conn->llc_ops->chan_is_connected(hb_conn) != HA_OK) {
            ipc = hb_conn->llc_ops->ipcchan(hb_conn);
        }
        if (ipc != NULL) {
/* 			ipc->ops->resume_io(ipc); */
            send_q = ipc->send_queue;
        }
        if (send_q != NULL) {
            CRM_CHECK(send_q->current_qlen < send_q->max_qlen,;
                );
        }
    }

    if (all_is_good) {
        crm_log_xml_trace(xml, "outbound");
    } else {
        crm_log_xml_warn(xml, "outbound");
    }

    if (msg != NULL) {
        ha_msg_del(msg);
    }
    return all_is_good;
}

gboolean
ha_msg_dispatch(ll_cluster_t * cluster_conn, gpointer user_data)
{
    IPC_Channel *channel = NULL;

    crm_trace("Invoked");

    if (cluster_conn != NULL) {
        channel = cluster_conn->llc_ops->ipcchan(cluster_conn);
    }

    CRM_CHECK(cluster_conn != NULL, return FALSE);
    CRM_CHECK(channel != NULL, return FALSE);

    if (channel != NULL && IPC_ISRCONN(channel)) {
        if (cluster_conn->llc_ops->msgready(cluster_conn) == 0) {
            crm_trace("no message ready yet");
        }
        /* invoke the callbacks but dont block */
        cluster_conn->llc_ops->rcvmsg(cluster_conn, 0);
    }

    if (channel == NULL || channel->ch_status != IPC_CONNECT) {
        crm_info("Lost connection to heartbeat service.");
        return FALSE;
    }

    return TRUE;
}

gboolean
register_heartbeat_conn(crm_cluster_t * cluster)
{
    const char *const_uuid = NULL;
    const char *const_uname = NULL;

    crm_debug("Signing in with Heartbeat");
    if (cluster->hb_conn->llc_ops->signon(cluster->hb_conn, crm_system_name) != HA_OK) {
        crm_err("Cannot sign on with heartbeat: %s",
                cluster->hb_conn->llc_ops->errmsg(cluster->hb_conn));
        return FALSE;
    }

    if (HA_OK !=
        cluster->hb_conn->llc_ops->set_msg_callback(cluster->hb_conn, crm_system_name,
                                                    cluster->hb_dispatch, cluster->hb_conn)) {

        crm_err("Cannot set msg callback: %s", cluster->hb_conn->llc_ops->errmsg(cluster->hb_conn));
        return FALSE;

    } else {
        void *handle = NULL;
        GLLclusterSource *(*g_main_add_cluster) (int priority, ll_cluster_t * api,
                                                 gboolean can_recurse,
                                                 gboolean(*dispatch) (ll_cluster_t * source_data,
                                                                      gpointer user_data),
                                                 gpointer userdata, GDestroyNotify notify) =
            find_library_function(&handle, HEARTBEAT_LIBRARY, "G_main_add_ll_cluster", 1);

        (*g_main_add_cluster) (G_PRIORITY_HIGH, cluster->hb_conn,
                               FALSE, ha_msg_dispatch, cluster->hb_conn, cluster->destroy);
        dlclose(handle);
    }

    const_uname = cluster->hb_conn->llc_ops->get_mynodeid(cluster->hb_conn);
    CRM_CHECK(const_uname != NULL, return FALSE);

    const_uuid = get_uuid(const_uname);
    CRM_CHECK(const_uuid != NULL, return FALSE);

    crm_info("Hostname: %s", const_uname);
    crm_info("UUID: %s", const_uuid);

    cluster->uname = strdup(const_uname);
    cluster->uuid = strdup(const_uuid);

    return TRUE;
}

gboolean
ccm_have_quorum(oc_ed_t event)
{
    if (event == OC_EV_MS_NEW_MEMBERSHIP || event == OC_EV_MS_PRIMARY_RESTORED) {
        return TRUE;
    }
    return FALSE;
}

const char *
ccm_event_name(oc_ed_t event)
{

    if (event == OC_EV_MS_NEW_MEMBERSHIP) {
        return "NEW MEMBERSHIP";

    } else if (event == OC_EV_MS_NOT_PRIMARY) {
        return "NOT PRIMARY";

    } else if (event == OC_EV_MS_PRIMARY_RESTORED) {
        return "PRIMARY RESTORED";

    } else if (event == OC_EV_MS_EVICTED) {
        return "EVICTED";

    } else if (event == OC_EV_MS_INVALID) {
        return "INVALID";
    }

    return "NO QUORUM MEMBERSHIP";

}

gboolean
heartbeat_initialize_nodelist(void *cluster, gboolean force_member, xmlNode * xml_parent)
{
    const char *ha_node = NULL;
    ll_cluster_t *conn = cluster;

    if (conn == NULL) {
        crm_debug("Not connected");
        return FALSE;
    }

    /* Async get client status information in the cluster */
    crm_info("Requesting the list of configured nodes");
    conn->llc_ops->init_nodewalk(conn);

    do {
        xmlNode *node = NULL;
        const char *ha_node_type = NULL;
        const char *ha_node_uuid = NULL;

        ha_node = conn->llc_ops->nextnode(conn);
        if (ha_node == NULL) {
            continue;
        }

        ha_node_type = conn->llc_ops->node_type(conn, ha_node);
        if (safe_str_neq(NORMALNODE, ha_node_type)) {
            crm_debug("Node %s: skipping '%s'", ha_node, ha_node_type);
            continue;
        }

        ha_node_uuid = get_uuid(ha_node);
        if (ha_node_uuid == NULL) {
            crm_warn("Node %s: no uuid found", ha_node);
            continue;
        }

        crm_debug("Node: %s (uuid: %s)", ha_node, ha_node_uuid);
        node = create_xml_node(xml_parent, XML_CIB_TAG_NODE);
        crm_xml_add(node, XML_ATTR_ID, ha_node_uuid);
        crm_xml_add(node, XML_ATTR_UNAME, ha_node);
        crm_xml_add(node, XML_ATTR_TYPE, ha_node_type);

    } while (ha_node != NULL);

    conn->llc_ops->end_nodewalk(conn);
    return TRUE;
}

#endif
