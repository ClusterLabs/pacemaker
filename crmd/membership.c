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
#include <crm/cluster.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>
#include <tengine.h>
#include <membership.h>

gboolean membership_flux_hack = FALSE;
void post_cache_update(int instance);

void ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data);

int last_peer_update = 0;

extern GHashTable *voted;

struct update_data_s {
    const char *state;
    const char *caller;
    xmlNode *updates;
    gboolean overwrite_join;
};

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

static void
check_dead_member(const char *uname, GHashTable * members)
{
    CRM_CHECK(uname != NULL, return);
    if (members != NULL && g_hash_table_lookup(members, uname) != NULL) {
        crm_err("%s didnt really leave the membership!", uname);
        return;
    }
    erase_node_from_join(uname);
    if (voted != NULL) {
        g_hash_table_remove(voted, uname);
    }

    if (safe_str_eq(fsa_our_uname, uname)) {
        crm_err("We're not part of the cluster anymore");
        register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);

    } else if (AM_I_DC == FALSE && safe_str_eq(uname, fsa_our_dc)) {
        crm_warn("Our DC node (%s) left the cluster", uname);
        register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);

    } else if (fsa_state == S_INTEGRATION || fsa_state == S_FINALIZE_JOIN) {
        check_join_state(fsa_state, __FUNCTION__);
    }
}


static void
reap_dead_nodes(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    if (crm_is_peer_active(node) == FALSE) {
        check_dead_member(node->uname, NULL);
        fail_incompletable_actions(transition_graph, node->uuid);
    }
}

gboolean ever_had_quorum = FALSE;

void
post_cache_update(int instance)
{
    xmlNode *no_op = NULL;

    crm_peer_seq = instance;
    crm_debug("Updated cache after membership event %d.", instance);

    g_hash_table_foreach(crm_peer_cache, reap_dead_nodes, NULL);
    set_bit_inplace(fsa_input_register, R_MEMBERSHIP);

    if (AM_I_DC) {
        populate_cib_nodes(FALSE);
        do_update_cib_nodes(FALSE, __FUNCTION__);
    }

    /*
     * If we lost nodes, we should re-check the election status
     * Safe to call outside of an election
     */
    register_fsa_action(A_ELECTION_CHECK);

    /* Membership changed, remind everyone we're here.
     * This will aid detection of duplicate DCs
     */
    no_op = create_request(CRM_OP_NOOP, NULL, NULL, CRM_SYSTEM_CRMD,
                           AM_I_DC ? CRM_SYSTEM_DC : CRM_SYSTEM_CRMD, NULL);
    send_cluster_message(NULL, crm_msg_crmd, no_op, FALSE);
    free_xml(no_op);
}

static void
crmd_node_update_complete(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    fsa_data_t *msg_data = NULL;

    last_peer_update = 0;

    if (rc == cib_ok) {
        crm_trace("Node update %d complete", call_id);

    } else {
        crm_err("Node update %d failed", call_id);
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

void
ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data)
{
    xmlNode *tmp1 = NULL;
    const char *join = NULL;
    crm_node_t *node = value;
    struct update_data_s *data = (struct update_data_s *)user_data;
    enum crm_proc_flag messaging = crm_proc_plugin | crm_proc_heartbeat | crm_proc_cpg;

    data->state = XML_BOOLEAN_NO;
    if (safe_str_eq(node->state, CRM_NODE_ACTIVE)) {
        data->state = XML_BOOLEAN_YES;
    }

    crm_debug("Updating %s: %s (overwrite=%s) hash_size=%d",
              node->uname, data->state, data->overwrite_join ? "true" : "false",
              g_hash_table_size(confirmed_nodes));

    if (data->overwrite_join) {
        if ((node->processes & proc_flags) == FALSE) {
            join = CRMD_JOINSTATE_DOWN;

        } else {
            const char *peer_member = g_hash_table_lookup(confirmed_nodes, node->uname);

            if (peer_member != NULL) {
                join = CRMD_JOINSTATE_MEMBER;
            } else {
                join = CRMD_JOINSTATE_PENDING;
            }
        }
    }

    tmp1 =
        create_node_state(node->uname, (node->processes & messaging) ? ACTIVESTATUS : DEADSTATUS,
                          data->state,
                          (node->processes & proc_flags) ? ONLINESTATUS : OFFLINESTATUS, join,
                          NULL, FALSE, data->caller);

    add_node_copy(data->updates, tmp1);
    free_xml(tmp1);
}

void
do_update_cib_nodes(gboolean overwrite, const char *caller)
{
    int call_id = 0;
    int call_options = cib_scope_local | cib_quorum_override;
    struct update_data_s update_data;
    xmlNode *fragment = NULL;

    if (crm_peer_cache == NULL) {
        /* We got a replace notification before being connected to
         *   the CCM.
         * So there is no need to update the local CIB with our values
         *   - since we have none.
         */
        return;

    } else if (AM_I_DC == FALSE) {
        return;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_STATUS);

    update_data.caller = caller;
    update_data.updates = fragment;
    update_data.overwrite_join = overwrite;

    g_hash_table_foreach(crm_peer_cache, ghash_update_cib_node, &update_data);

    fsa_cib_update(XML_CIB_TAG_STATUS, fragment, call_options, call_id, NULL);
    add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, crmd_node_update_complete);
    last_peer_update = call_id;

    free_xml(fragment);
}

static void
cib_quorum_update_complete(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    fsa_data_t *msg_data = NULL;

    if (rc == cib_ok) {
        crm_trace("Quorum update %d complete", call_id);

    } else {
        crm_err("Quorum update %d failed", call_id);
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

void
crm_update_quorum(gboolean quorum, gboolean force_update)
{
    ever_had_quorum |= quorum;
    if (AM_I_DC && (force_update || fsa_has_quorum != quorum)) {
        int call_id = 0;
        xmlNode *update = NULL;
        int call_options = cib_scope_local | cib_quorum_override;

        update = create_xml_node(NULL, XML_TAG_CIB);
        crm_xml_add_int(update, XML_ATTR_HAVE_QUORUM, quorum);
        set_uuid(update, XML_ATTR_DC_UUID, fsa_our_uname);

        fsa_cib_update(XML_TAG_CIB, update, call_options, call_id, NULL);
        crm_debug("Updating quorum status to %s (call=%d)", quorum ? "true" : "false", call_id);
        add_cib_op_callback(fsa_cib_conn, call_id, FALSE, NULL, cib_quorum_update_complete);
        free_xml(update);
    }
    fsa_has_quorum = quorum;
}
