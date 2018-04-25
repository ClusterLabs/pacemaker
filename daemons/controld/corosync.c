/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cluster/internal.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>
#include <controld_fsa.h>
#include <controld_messages.h>
#include <controld_callbacks.h>
#include <controld_lrm.h>
#include <tengine.h>

#include <sys/types.h>
#include <sys/stat.h>

#if SUPPORT_COROSYNC

extern void post_cache_update(int seq);

/*	 A_HA_CONNECT	*/

static void
crmd_cs_dispatch(cpg_handle_t handle, const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }
    if (kind == crm_class_cluster) {
        crm_node_t *peer = NULL;
        xmlNode *xml = string2xml(data);

        if (xml == NULL) {
            crm_err("Could not parse message content (%d): %.100s", kind, data);
            free(data);
            return;
        }

        crm_xml_add(xml, F_ORIG, from);
        /* crm_xml_add_int(xml, F_SEQ, wrapper->id); Fake? */

        peer = crm_get_peer(0, from);
        if (is_not_set(peer->processes, crm_proc_cpg)) {
            /* If we can still talk to our peer process on that node,
             * then it must be part of the corosync membership
             */
            crm_warn("Receiving messages from a node we think is dead: %s[%d]",
                     peer->uname, peer->id);
            crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg,
                                 ONLINESTATUS);
        }
        crmd_ha_msg_filter(xml);
        free_xml(xml);
    } else {
        crm_err("Invalid message class (%d): %.100s", kind, data);
    }
    free(data);
}

static gboolean
crmd_quorum_callback(unsigned long long seq, gboolean quorate)
{
    crm_update_quorum(quorate, FALSE);
    post_cache_update(seq);
    return TRUE;
}

static void
crmd_cs_destroy(gpointer user_data)
{
    if (is_not_set(fsa_input_register, R_HA_DISCONNECTED)) {
        crm_err("Corosync connection lost");
        crmd_exit(CRM_EX_DISCONNECT);

    } else {
        crm_info("Corosync connection closed");
    }
}

extern gboolean crm_connect_corosync(crm_cluster_t * cluster);

gboolean
crm_connect_corosync(crm_cluster_t * cluster)
{
    if (is_corosync_cluster()) {
        crm_set_status_callback(&peer_update_callback);
        cluster->cpg.cpg_deliver_fn = crmd_cs_dispatch;
        cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;
        cluster->destroy = crmd_cs_destroy;

        if (crm_cluster_connect(cluster)) {
            cluster_connect_quorum(crmd_quorum_callback, crmd_cs_destroy);
            return TRUE;
        }
    }
    return FALSE;
}

#endif
