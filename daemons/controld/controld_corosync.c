/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/cluster/internal.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

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
        if (!pcmk_is_set(peer->processes, crm_proc_cpg)) {
            /* If we can still talk to our peer process on that node,
             * then it must be part of the corosync membership
             */
            crm_warn("Receiving messages from a node we think is dead: %s[%d]",
                     peer->uname, peer->id);
            crm_update_peer_proc(__func__, peer, crm_proc_cpg,
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
    if (!pcmk_is_set(fsa_input_register, R_HA_DISCONNECTED)) {
        crm_crit("Lost connection to cluster layer, shutting down");
        crmd_exit(CRM_EX_DISCONNECT);

    } else {
        crm_info("Corosync connection closed");
    }
}

/*!
 * \brief Handle a Corosync notification of a CPG configuration change
 *
 * \param[in] handle               CPG connection
 * \param[in] cpg_name             CPG group name
 * \param[in] member_list          List of current CPG members
 * \param[in] member_list_entries  Number of entries in \p member_list
 * \param[in] left_list            List of CPG members that left
 * \param[in] left_list_entries    Number of entries in \p left_list
 * \param[in] joined_list          List of CPG members that joined
 * \param[in] joined_list_entries  Number of entries in \p joined_list
 */
static void
cpg_membership_callback(cpg_handle_t handle, const struct cpg_name *cpg_name,
                        const struct cpg_address *member_list,
                        size_t member_list_entries,
                        const struct cpg_address *left_list,
                        size_t left_list_entries,
                        const struct cpg_address *joined_list,
                        size_t joined_list_entries)
{
    /* When nodes leave CPG, the DC clears their transient node attributes.
     *
     * However if there is no DC, or the DC is among the nodes that left, each
     * remaining node needs to do the clearing, to ensure it gets done.
     * Otherwise, the attributes would persist when the nodes rejoin, which
     * could have serious consequences for unfencing, agents that use attributes
     * for internal logic, etc.
     *
     * Here, we set a global boolean if the DC is among the nodes that left, for
     * use by the peer callback.
     */
    if (controld_globals.dc_name != NULL) {
        crm_node_t *peer = NULL;

        peer = pcmk__search_cluster_node_cache(0, controld_globals.dc_name);
        if (peer != NULL) {
            for (int i = 0; i < left_list_entries; ++i) {
                if (left_list[i].nodeid == peer->id) {
                    controld_globals.flags |= controld_dc_left;
                    break;
                }
            }
        }
    }

    // Process the change normally, which will call the peer callback as needed
    pcmk_cpg_membership(handle, cpg_name, member_list, member_list_entries,
                        left_list, left_list_entries,
                        joined_list, joined_list_entries);

    controld_globals.flags &= ~controld_dc_left;
}

extern gboolean crm_connect_corosync(crm_cluster_t * cluster);

gboolean
crm_connect_corosync(crm_cluster_t * cluster)
{
    if (is_corosync_cluster()) {
        crm_set_status_callback(&peer_update_callback);
        cluster->cpg.cpg_deliver_fn = crmd_cs_dispatch;
        cluster->cpg.cpg_confchg_fn = cpg_membership_callback;
        cluster->destroy = crmd_cs_destroy;

        if (crm_cluster_connect(cluster)) {
            pcmk__corosync_quorum_connect(crmd_quorum_callback,
                                          crmd_cs_destroy);
            return TRUE;
        }
    }
    return FALSE;
}

#endif
