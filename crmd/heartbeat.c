/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* put these first so that uuid_t is defined without conflicts */
#include <crm_internal.h>

#include <string.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/cluster.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>
#include <tengine.h>
#include <membership.h>

#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

void oc_ev_special(const oc_ev_t *, oc_ev_class_t, int);
void ccm_event_detail(const oc_ev_membership_t * oc, oc_ed_t event);
gboolean crmd_ha_msg_dispatch(ll_cluster_t * cluster_conn, gpointer user_data);
void crmd_ccm_msg_callback(oc_ed_t event, void *cookie, size_t size, const void *data);
int ccm_dispatch(gpointer user_data);

#define CCM_EVENT_DETAIL 0
#define CCM_EVENT_DETAIL_PARTIAL 0

int (*ccm_api_callback_done) (void *cookie) = NULL;
int (*ccm_api_handle_event) (const oc_ev_t * token) = NULL;
static gboolean fsa_have_quorum = FALSE;

static oc_ev_t *fsa_ev_token;
static void *ccm_library = NULL;
static int num_ccm_register_fails = 0;
static int max_ccm_register_fails = 30;

static void
ccm_connection_destroy(void *userdata)
{
}

/*	 A_CCM_CONNECT	*/
void
do_ccm_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    static struct mainloop_fd_callbacks ccm_fd_callbacks = 
        {
            .dispatch = ccm_dispatch,
            .destroy = ccm_connection_destroy,
        };

    if (is_heartbeat_cluster()) {
        int (*ccm_api_register) (oc_ev_t ** token) =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_register");

        int (*ccm_api_set_callback) (const oc_ev_t * token,
                                     oc_ev_class_t class,
                                     oc_ev_callback_t * fn,
                                     oc_ev_callback_t ** prev_fn) =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_set_callback");

        void (*ccm_api_special) (const oc_ev_t *, oc_ev_class_t, int) =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_special");
        int (*ccm_api_activate) (const oc_ev_t * token, int *fd) =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_activate");
        int (*ccm_api_unregister) (oc_ev_t * token) =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_unregister");

        if (action & A_CCM_DISCONNECT) {
            set_bit_inplace(fsa_input_register, R_CCM_DISCONNECTED);
            (*ccm_api_unregister) (fsa_ev_token);
        }

        if (action & A_CCM_CONNECT) {
            int ret;
            int fsa_ev_fd;
            gboolean did_fail = FALSE;

            crm_trace("Registering with CCM");
            clear_bit_inplace(fsa_input_register, R_CCM_DISCONNECTED);
            ret = (*ccm_api_register) (&fsa_ev_token);
            if (ret != 0) {
                crm_warn("CCM registration failed");
                did_fail = TRUE;
            }

            if (did_fail == FALSE) {
                crm_trace("Setting up CCM callbacks");
                ret = (*ccm_api_set_callback) (fsa_ev_token, OC_EV_MEMB_CLASS,
                                               crmd_ccm_msg_callback, NULL);
                if (ret != 0) {
                    crm_warn("CCM callback not set");
                    did_fail = TRUE;
                }
            }
            if (did_fail == FALSE) {
                (*ccm_api_special) (fsa_ev_token, OC_EV_MEMB_CLASS, 0 /*don't care */ );

                crm_trace("Activating CCM token");
                ret = (*ccm_api_activate) (fsa_ev_token, &fsa_ev_fd);
                if (ret != 0) {
                    crm_warn("CCM Activation failed");
                    did_fail = TRUE;
                }
            }

            if (did_fail) {
                num_ccm_register_fails++;
                (*ccm_api_unregister) (fsa_ev_token);

                if (num_ccm_register_fails < max_ccm_register_fails) {
                    crm_warn("CCM Connection failed"
                             " %d times (%d max)", num_ccm_register_fails, max_ccm_register_fails);

                    crm_timer_start(wait_timer);
                    crmd_fsa_stall(NULL);
                    return;

                } else {
                    crm_err("CCM Activation failed %d (max) times", num_ccm_register_fails);
                    register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
                    return;
                }
            }

            crm_info("CCM connection established... waiting for first callback");
            mainloop_add_fd("heartbeat-ccm", fsa_ev_fd, fsa_ev_token, &ccm_fd_callbacks);

        }
    }

    if (action & ~(A_CCM_CONNECT | A_CCM_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action), __FUNCTION__);
    }
}

void
ccm_event_detail(const oc_ev_membership_t * oc, oc_ed_t event)
{
    int lpc;
    gboolean member = FALSE;

    member = FALSE;

    crm_trace("-----------------------");
    crm_info("%s: trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
             "new_idx=%d, old_idx=%d",
             ccm_event_name(event),
             oc->m_instance,
             oc->m_n_member, oc->m_n_in, oc->m_n_out, oc->m_memb_idx, oc->m_in_idx, oc->m_out_idx);

#  if !CCM_EVENT_DETAIL_PARTIAL
    for (lpc = 0; lpc < oc->m_n_member; lpc++) {
        crm_info("\tCURRENT: %s [nodeid=%d, born=%d]",
                 oc->m_array[oc->m_memb_idx + lpc].node_uname,
                 oc->m_array[oc->m_memb_idx + lpc].node_id,
                 oc->m_array[oc->m_memb_idx + lpc].node_born_on);

        if (safe_str_eq(fsa_our_uname, oc->m_array[oc->m_memb_idx + lpc].node_uname)) {
            member = TRUE;
        }
    }
    if (member == FALSE) {
        crm_warn("MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
    }
#  endif
    for (lpc = 0; lpc < (int)oc->m_n_in; lpc++) {
        crm_info("\tNEW:     %s [nodeid=%d, born=%d]",
                 oc->m_array[oc->m_in_idx + lpc].node_uname,
                 oc->m_array[oc->m_in_idx + lpc].node_id,
                 oc->m_array[oc->m_in_idx + lpc].node_born_on);
    }

    for (lpc = 0; lpc < (int)oc->m_n_out; lpc++) {
        crm_info("\tLOST:    %s [nodeid=%d, born=%d]",
                 oc->m_array[oc->m_out_idx + lpc].node_uname,
                 oc->m_array[oc->m_out_idx + lpc].node_id,
                 oc->m_array[oc->m_out_idx + lpc].node_born_on);
    }

    crm_trace("-----------------------");

}


/*	 A_CCM_UPDATE_CACHE	*/
/*
 * Take the opportunity to update the node status in the CIB as well
 */
void
do_ccm_update_cache(enum crmd_fsa_cause cause, enum crmd_fsa_state cur_state,
                    oc_ed_t event, const oc_ev_membership_t * oc, xmlNode * xml)
{
    unsigned long long instance = 0;
    unsigned int lpc = 0;

    if (is_heartbeat_cluster()) {
        CRM_ASSERT(oc != NULL);
        instance = oc->m_instance;
    }

    CRM_ASSERT(crm_peer_seq <= instance);

    switch (cur_state) {
        case S_STOPPING:
        case S_TERMINATE:
        case S_HALT:
            crm_debug("Ignoring %s CCM event %llu, we're in state %s",
                      ccm_event_name(event), instance, fsa_state2string(cur_state));
            return;
        case S_ELECTION:
            register_fsa_action(A_ELECTION_CHECK);
            break;
        default:
            break;
    }

    if (is_heartbeat_cluster()) {
        ccm_event_detail(oc, event);

        /*--*-- Recently Dead Member Nodes --*--*/
        for (lpc = 0; lpc < oc->m_n_out; lpc++) {
            crm_update_ccm_node(oc, lpc + oc->m_out_idx, CRM_NODE_LOST, instance);
        }

            /*--*-- All Member Nodes --*--*/
        for (lpc = 0; lpc < oc->m_n_member; lpc++) {
            crm_update_ccm_node(oc, lpc + oc->m_memb_idx, CRM_NODE_ACTIVE, instance);
        }
    }

    if (event == OC_EV_MS_EVICTED) {
        crm_update_peer(__FUNCTION__, 0, 0, 0, -1, 0, fsa_our_uuid, fsa_our_uname, NULL, CRM_NODE_EVICTED);

        /* todo: drop back to S_PENDING instead */
        /* get out... NOW!
         *
         * go via the error recovery process so that HA will
         *    restart us if required
         */
        register_fsa_error_adv(cause, I_ERROR, NULL, NULL, __FUNCTION__);
    }

    post_cache_update(instance);
    return;
}

int
ccm_dispatch(gpointer user_data)
{
    int rc = 0;
    oc_ev_t *ccm_token = (oc_ev_t *) user_data;
    gboolean was_error = FALSE;

    crm_trace("Invoked");
    if (ccm_api_handle_event == NULL) {
        ccm_api_handle_event =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_handle_event");
    }
    rc = (*ccm_api_handle_event) (ccm_token);

    if (rc != 0) {
        if (is_set(fsa_input_register, R_CCM_DISCONNECTED) == FALSE) {
            /* we signed out, so this is expected */
            register_fsa_input(C_CCM_CALLBACK, I_ERROR, NULL);
            crm_err("CCM connection appears to have failed: rc=%d.", rc);
        }
        was_error = TRUE;
    }

    trigger_fsa(fsa_source);
    if(was_error) {
        return -1;
    }

    return 0;
}

void
crmd_ccm_msg_callback(oc_ed_t event, void *cookie, size_t size, const void *data)
{
    gboolean update_cache = FALSE;
    const oc_ev_membership_t *membership = data;

    gboolean update_quorum = FALSE;

    crm_trace("Invoked");
    CRM_ASSERT(data != NULL);

    crm_info("Quorum %s after event=%s (id=%d)",
             ccm_have_quorum(event) ? "(re)attained" : "lost",
             ccm_event_name(event), membership->m_instance);

    if (crm_peer_seq > membership->m_instance) {
        crm_err("Membership instance ID went backwards! %llu->%d",
                crm_peer_seq, membership->m_instance);
        CRM_ASSERT(crm_peer_seq <= membership->m_instance);
        return;
    }

    /*
     * OC_EV_MS_NEW_MEMBERSHIP:   membership with quorum
     * OC_EV_MS_MS_INVALID:       membership without quorum
     * OC_EV_MS_NOT_PRIMARY:      previous membership no longer valid
     * OC_EV_MS_PRIMARY_RESTORED: previous membership restored
     * OC_EV_MS_EVICTED:          the client is evicted from ccm.
     */

    switch (event) {
        case OC_EV_MS_NEW_MEMBERSHIP:
        case OC_EV_MS_INVALID:
            update_cache = TRUE;
            update_quorum = TRUE;
            break;
        case OC_EV_MS_NOT_PRIMARY:
            break;
        case OC_EV_MS_PRIMARY_RESTORED:
            update_cache = TRUE;
            crm_peer_seq = membership->m_instance;
            break;
        case OC_EV_MS_EVICTED:
            update_quorum = TRUE;
            register_fsa_input(C_FSA_INTERNAL, I_STOP, NULL);
            crm_err("Shutting down after CCM event: %s", ccm_event_name(event));
            break;
        default:
            crm_err("Unknown CCM event: %d", event);
    }

    if (update_quorum) {
        crm_have_quorum = ccm_have_quorum(event);
        crm_update_quorum(crm_have_quorum, FALSE);

        if (crm_have_quorum == FALSE) {
            /* did we just loose quorum? */
            if (fsa_have_quorum) {
                crm_info("Quorum lost: %s", ccm_event_name(event));
            }
        }
    }

    if (update_cache) {
        crm_trace("Updating cache after event %s", ccm_event_name(event));
        do_ccm_update_cache(C_CCM_CALLBACK, fsa_state, event, data, NULL);

    } else if (event != OC_EV_MS_NOT_PRIMARY) {
        crm_peer_seq = membership->m_instance;
        register_fsa_action(A_TE_CANCEL);
    }

    if (ccm_api_callback_done == NULL) {
        ccm_api_callback_done =
            find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_callback_done");
    }
    (*ccm_api_callback_done) (cookie);
    return;
}


void
crmd_ha_status_callback(const char *node, const char *status, void *private)
{
    xmlNode *update = NULL;
    crm_node_t *peer = NULL;

    crm_notice("Status update: Node %s now has status [%s]", node, status);

    peer = crm_get_peer(0, node);
    if (safe_str_eq(status, PINGSTATUS)) {
        return;
    }

    if (safe_str_eq(status, DEADSTATUS)) {
        /* this node is toast */
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_heartbeat, OFFLINESTATUS);
        if (AM_I_DC) {
            update = create_node_state(node, DEADSTATUS, XML_BOOLEAN_NO, OFFLINESTATUS,
                                       CRMD_JOINSTATE_DOWN, NULL, TRUE, __FUNCTION__);
        }

    } else {
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_heartbeat, ONLINESTATUS);
        if (AM_I_DC) {
            update = create_node_state(node, ACTIVESTATUS, NULL, NULL,
                                       CRMD_JOINSTATE_PENDING, NULL, FALSE, __FUNCTION__);
        }
    }

    trigger_fsa(fsa_source);

    if (update != NULL) {
        fsa_cib_anon_update(XML_CIB_TAG_STATUS, update,
                            cib_scope_local | cib_quorum_override | cib_can_create);
        free_xml(update);
    }
}

void
crmd_client_status_callback(const char *node, const char *client, const char *status, void *private)
{
    const char *join = NULL;
    crm_node_t *peer = NULL;
    gboolean clear_shutdown = FALSE;

    crm_trace("Invoked");
    if (safe_str_neq(client, CRM_SYSTEM_CRMD)) {
        return;
    }

    if (safe_str_eq(status, JOINSTATUS)) {
        clear_shutdown = TRUE;
        status = ONLINESTATUS;
        join = CRMD_JOINSTATE_PENDING;

    } else if (safe_str_eq(status, LEAVESTATUS)) {
        status = OFFLINESTATUS;
        join = CRMD_JOINSTATE_DOWN;
/* 		clear_shutdown = TRUE; */
    }

    set_bit_inplace(fsa_input_register, R_PEER_DATA);

    crm_notice("Status update: Client %s/%s now has status [%s] (DC=%s)",
               node, client, status, AM_I_DC ? "true" : "false");

    if (safe_str_eq(status, ONLINESTATUS)) {
        /* remove the cached value in case it changed */
        crm_trace("Uncaching UUID for %s", node);
        unget_uuid(node);
    }

    peer = crm_get_peer(0, node);

    if (AM_I_DC) {
        xmlNode *update = NULL;

        crm_trace("Got client status callback");
        update =
            create_node_state(node, NULL, NULL, status, join, NULL, clear_shutdown, __FUNCTION__);

        fsa_cib_anon_update(XML_CIB_TAG_STATUS, update,
                            cib_scope_local | cib_quorum_override | cib_can_create);
        free_xml(update);
    }
    crm_update_peer_proc(__FUNCTION__, peer, crm_proc_crmd, status);
}

void
crmd_ha_msg_callback(HA_Message * hamsg, void *private_data)
{
    int level = LOG_DEBUG;
    crm_node_t *from_node = NULL;

    xmlNode *msg = convert_ha_message(NULL, hamsg, __FUNCTION__);
    const char *from = crm_element_value(msg, F_ORIG);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);

    CRM_CHECK(from != NULL, crm_log_xml_err(msg, "anon"); goto bail);

    crm_trace("HA[inbound]: %s from %s", op, from);

    if (crm_peer_cache == NULL || crm_active_peers() == 0) {
        crm_debug("Ignoring HA messages until we are"
                  " connected to the CCM (%s op from %s)", op, from);
        crm_log_xml_trace(msg, "HA[inbound]: Ignore (No CCM)");
        goto bail;
    }

    from_node = crm_get_peer(0, from);
    if (crm_is_peer_active(from_node) == FALSE) {
        if (safe_str_eq(op, CRM_OP_VOTE)) {
            level = LOG_WARNING;

        } else if (AM_I_DC && safe_str_eq(op, CRM_OP_JOIN_ANNOUNCE)) {
            level = LOG_WARNING;

        } else if (safe_str_eq(sys_from, CRM_SYSTEM_DC)) {
            level = LOG_WARNING;
        }
        do_crm_log(level,
                   "Ignoring HA message (op=%s) from %s: not in our"
                   " membership list (size=%d)", op, from, crm_active_peers());

        crm_log_xml_trace(msg, "HA[inbound]: CCM Discard");

    } else {
        crmd_ha_msg_filter(msg);
    }

  bail:
    free_xml(msg);
    return;
}

gboolean
crmd_ha_msg_dispatch(ll_cluster_t * cluster_conn, gpointer user_data)
{
    IPC_Channel *channel = NULL;
    gboolean stay_connected = TRUE;

    crm_trace("Invoked");

    if (cluster_conn != NULL) {
        channel = cluster_conn->llc_ops->ipcchan(cluster_conn);
    }

    CRM_CHECK(cluster_conn != NULL,;);
    CRM_CHECK(channel != NULL,;);

    if (channel != NULL && IPC_ISRCONN(channel)) {
        if (cluster_conn->llc_ops->msgready(cluster_conn) == 0) {
            crm_trace("no message ready yet");
        }
        /* invoke the callbacks but dont block */
        cluster_conn->llc_ops->rcvmsg(cluster_conn, 0);
    }

    if (channel == NULL || channel->ch_status != IPC_CONNECT) {
        if (is_set(fsa_input_register, R_HA_DISCONNECTED) == FALSE) {
            crm_crit("Lost connection to heartbeat service.");
        } else {
            crm_info("Lost connection to heartbeat service.");
        }
        trigger_fsa(fsa_source);
        stay_connected = FALSE;
    }

    return stay_connected;
}
