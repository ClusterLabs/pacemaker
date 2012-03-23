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
#include <crm/common/msg.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>
#include "stack.h"

xmlNode *create_common_message(xmlNode * original_request, xmlNode * xml_response_data);

#if SUPPORT_HEARTBEAT
ll_cluster_t *heartbeat_cluster = NULL;

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
        if (hb_conn->llc_ops->send_ordered_nodemsg(hb_conn, msg, node) != HA_OK) {
            all_is_good = FALSE;
            crm_err("Send failed");
        }

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
            CRM_CHECK(send_q->current_qlen < send_q->max_qlen,;);
        }
    }

    if (all_is_good) {
        crm_log_xml_trace(xml, "outbound");
    } else {
        crm_log_xml_warn(xml, "outbound");
    }

    crm_msg_del(msg);
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
register_heartbeat_conn(ll_cluster_t * hb_cluster, char **uuid, char **uname,
                        void (*hb_message) (HA_Message * msg, void *private_data),
                        void (*hb_destroy) (gpointer user_data))
{
    const char *const_uuid = NULL;
    const char *const_uname = NULL;

    crm_debug("Signing in with Heartbeat");
    if (hb_cluster->llc_ops->signon(hb_cluster, crm_system_name) != HA_OK) {
        crm_err("Cannot sign on with heartbeat: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
        return FALSE;
    }

    if (HA_OK !=
        hb_cluster->llc_ops->set_msg_callback(hb_cluster, crm_system_name, hb_message,
                                              hb_cluster)) {

        crm_err("Cannot set msg callback: %s", hb_cluster->llc_ops->errmsg(hb_cluster));
        return FALSE;
    }
    {
        void *handle = NULL;
        GLLclusterSource *(*g_main_add_cluster) (int priority, ll_cluster_t * api,
                                                 gboolean can_recurse,
                                                 gboolean(*dispatch) (ll_cluster_t * source_data,
                                                                      gpointer user_data),
                                                 gpointer userdata, GDestroyNotify notify) =
            find_library_function(&handle, HEARTBEAT_LIBRARY, "G_main_add_ll_cluster");

        (*g_main_add_cluster) (G_PRIORITY_HIGH, hb_cluster,
                               FALSE, ha_msg_dispatch, hb_cluster, hb_destroy);
        dlclose(handle);
    }

    const_uname = hb_cluster->llc_ops->get_mynodeid(hb_cluster);
    CRM_CHECK(const_uname != NULL, return FALSE);

    const_uuid = get_uuid(const_uname);
    CRM_CHECK(const_uuid != NULL, return FALSE);

    crm_info("Hostname: %s", const_uname);
    crm_info("UUID: %s", const_uuid);

    if (uname) {
        *uname = crm_strdup(const_uname);
    }
    if (uuid) {
        *uuid = crm_strdup(const_uuid);
    }

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

#endif
