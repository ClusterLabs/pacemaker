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

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <crmd_lrm.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>
#include <tengine.h>
#include <membership.h>
#include <crmd.h>

gboolean membership_flux_hack = FALSE;
void post_cache_update(int instance);

int last_peer_update = 0;
guint highest_born_on = -1;

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

static void
reap_dead_nodes(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    if (crm_is_peer_active(node) == FALSE) {
        crm_update_peer_join(__FUNCTION__, node, crm_join_none);

        if(node && node->uname) {
            election_remove(fsa_election, node->uname);

            if (safe_str_eq(fsa_our_uname, node->uname)) {
                crm_err("We're not part of the cluster anymore");
                register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);

            } else if (AM_I_DC == FALSE && safe_str_eq(node->uname, fsa_our_dc)) {
                crm_warn("Our DC node (%s) left the cluster", node->uname);
                register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
            }
        }

        if (fsa_state == S_INTEGRATION || fsa_state == S_FINALIZE_JOIN) {
            check_join_state(fsa_state, __FUNCTION__);
        }
        if(node && node->uuid) {
            fail_incompletable_actions(transition_graph, node->uuid);
        }
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
    set_bit(fsa_input_register, R_MEMBERSHIP);

    if (AM_I_DC) {
        populate_cib_nodes(node_update_quick | node_update_cluster | node_update_peer |
                           node_update_expected, __FUNCTION__);
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

    if (rc == pcmk_ok) {
        crm_trace("Node update %d complete", call_id);

    } else if(call_id < pcmk_ok) {
        crm_err("Node update failed: %s (%d)", pcmk_strerror(call_id), call_id);
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

    } else {
        crm_err("Node update %d failed: %s (%d)", call_id, pcmk_strerror(rc), rc);
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

xmlNode *
do_update_node_cib(crm_node_t * node, int flags, xmlNode * parent, const char *source)
{
    const char *value = NULL;
    xmlNode *node_state;

    if (is_set(node->flags, crm_remote_node)) {
        return simple_remote_node_status(node->uname, parent, source);
    }

    if (!node->state) {
        crm_info("Node update for %s cancelled: no state, not seen yet", node->uname);
       return NULL;
    }

    node_state = create_xml_node(parent, XML_CIB_TAG_STATE);
    set_uuid(node_state, XML_ATTR_UUID, node);

    if (crm_element_value(node_state, XML_ATTR_UUID) == NULL) {
        crm_info("Node update for %s cancelled: no id", node->uname);
        free_xml(node_state);
        return NULL;
    }

    crm_xml_add(node_state, XML_ATTR_UNAME, node->uname);

    if (flags & node_update_cluster) {
        if (safe_str_eq(node->state, CRM_NODE_ACTIVE)) {
            value = XML_BOOLEAN_YES;
        } else if (node->state) {
            value = XML_BOOLEAN_NO;
        } else {
            value = NULL;
        }
        crm_xml_add(node_state, XML_NODE_IN_CLUSTER, value);
    }

    if (flags & node_update_peer) {
        value = OFFLINESTATUS;
        if (node->processes & proc_flags) {
            value = ONLINESTATUS;
        }
        crm_xml_add(node_state, XML_NODE_IS_PEER, value);
    }

    if (flags & node_update_join) {
        if(node->join <= crm_join_none) {
            value = CRMD_JOINSTATE_DOWN;
        } else {
            value = CRMD_JOINSTATE_MEMBER;
        }
        crm_xml_add(node_state, XML_NODE_JOIN_STATE, value);
    }

    if (flags & node_update_expected) {
        crm_xml_add(node_state, XML_NODE_EXPECTED, node->expected);
    }

    crm_xml_add(node_state, XML_ATTR_ORIGIN, source);

    return node_state;
}

static void
remove_conflicting_node_callback(xmlNode * msg, int call_id, int rc,
                                 xmlNode * output, void *user_data)
{
    char *node_uuid = user_data;

    do_crm_log_unlikely(rc == 0 ? LOG_DEBUG : LOG_NOTICE,
                        "Deletion of the unknown conflicting node \"%s\": %s (rc=%d)",
                        node_uuid, pcmk_strerror(rc), rc);
    free(node_uuid);
}

static void
search_conflicting_node_callback(xmlNode * msg, int call_id, int rc,
                                 xmlNode * output, void *user_data)
{
    char *new_node_uuid = user_data;
    xmlNode *node_xml = NULL;

    if (rc != pcmk_ok) {
        if (rc != -ENXIO) {
            crm_notice("Searching conflicting nodes for %s failed: %s (%d)",
                       new_node_uuid, pcmk_strerror(rc), rc);
        }
        free(new_node_uuid);
        return;

    } else if (output == NULL) {
        free(new_node_uuid);
        return;
    }

    if (safe_str_eq(crm_element_name(output), XML_CIB_TAG_NODE)) {
        node_xml = output;

    } else {
        node_xml = __xml_first_child(output);
    }

    for (; node_xml != NULL; node_xml = __xml_next(node_xml)) {
        const char *node_uuid = NULL;
        const char *node_uname = NULL;
        GHashTableIter iter;
        crm_node_t *node = NULL;
        gboolean known = FALSE;

        if (safe_str_neq(crm_element_name(node_xml), XML_CIB_TAG_NODE)) {
            continue;
        }

        node_uuid = crm_element_value(node_xml, XML_ATTR_ID);
        node_uname = crm_element_value(node_xml, XML_ATTR_UNAME);

        if (node_uuid == NULL || node_uname == NULL) {
            continue;
        }

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (node->uuid
                && safe_str_eq(node->uuid, node_uuid)
                && node->uname
                && safe_str_eq(node->uname, node_uname)) {

                known = TRUE;
                break;
            }
        }

        if (known == FALSE) {
            int delete_call_id = 0;
            xmlNode *node_state_xml = NULL;

            crm_notice("Deleting unknown node %s/%s which has conflicting uname with %s",
                       node_uuid, node_uname, new_node_uuid);

            delete_call_id = fsa_cib_conn->cmds->delete(fsa_cib_conn, XML_CIB_TAG_NODES, node_xml,
                                                        cib_scope_local | cib_quorum_override);
            fsa_register_cib_callback(delete_call_id, FALSE, strdup(node_uuid),
                                      remove_conflicting_node_callback);

            node_state_xml = create_xml_node(NULL, XML_CIB_TAG_STATE);
            crm_xml_add(node_state_xml, XML_ATTR_ID, node_uuid);
            crm_xml_add(node_state_xml, XML_ATTR_UNAME, node_uname);

            delete_call_id = fsa_cib_conn->cmds->delete(fsa_cib_conn, XML_CIB_TAG_STATUS, node_state_xml,
                                                        cib_scope_local | cib_quorum_override);
            fsa_register_cib_callback(delete_call_id, FALSE, strdup(node_uuid),
                                      remove_conflicting_node_callback);
            free_xml(node_state_xml);
        }
    }

    free(new_node_uuid);
}

static void
node_list_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    fsa_data_t *msg_data = NULL;

    if(call_id < pcmk_ok) {
        crm_err("Node list update failed: %s (%d)", pcmk_strerror(call_id), call_id);
        crm_log_xml_debug(msg, "update:failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

    } else if(rc < pcmk_ok) {
        crm_err("Node update %d failed: %s (%d)", call_id, pcmk_strerror(rc), rc);
        crm_log_xml_debug(msg, "update:failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

#define NODE_PATH_MAX 512

void
populate_cib_nodes(enum node_update_flags flags, const char *source)
{
    int call_id = 0;
    gboolean from_hashtable = TRUE;
    int call_options = cib_scope_local | cib_quorum_override;
    xmlNode *node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);

#if SUPPORT_HEARTBEAT
    if (is_not_set(flags, node_update_quick) && is_heartbeat_cluster()) {
        from_hashtable = heartbeat_initialize_nodelist(fsa_cluster_conn, FALSE, node_list);
    }
#endif

#if SUPPORT_COROSYNC
#  if !SUPPORT_PLUGIN
    if (is_not_set(flags, node_update_quick) && is_corosync_cluster()) {
        from_hashtable = corosync_initialize_nodelist(NULL, FALSE, node_list);
    }
#  endif
#endif

    if (from_hashtable) {
        GHashTableIter iter;
        crm_node_t *node = NULL;

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            xmlNode *new_node = NULL;

            crm_trace("Creating node entry for %s/%s", node->uname, node->uuid);
            if(node->uuid && node->uname) {
                char xpath[NODE_PATH_MAX];

                /* We need both to be valid */
                new_node = create_xml_node(node_list, XML_CIB_TAG_NODE);
                crm_xml_add(new_node, XML_ATTR_ID, node->uuid);
                crm_xml_add(new_node, XML_ATTR_UNAME, node->uname);

                /* Search and remove unknown nodes with the conflicting uname from CIB */
                snprintf(xpath, NODE_PATH_MAX,
                         "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_NODES
                         "/" XML_CIB_TAG_NODE "[@uname='%s'][@id!='%s']",
                         node->uname, node->uuid);

                call_id = fsa_cib_conn->cmds->query(fsa_cib_conn, xpath, NULL,
                                                    cib_scope_local | cib_xpath);
                fsa_register_cib_callback(call_id, FALSE, strdup(node->uuid),
                                          search_conflicting_node_callback);
            }
        }
    }

    crm_trace("Populating <nodes> section from %s", from_hashtable ? "hashtable" : "cluster");

    fsa_cib_update(XML_CIB_TAG_NODES, node_list, call_options, call_id, NULL);
    fsa_register_cib_callback(call_id, FALSE, NULL, node_list_update_callback);

    free_xml(node_list);

    if (call_id >= pcmk_ok && crm_peer_cache != NULL && AM_I_DC) {
        /*
         * There is no need to update the local CIB with our values if
         * we've not seen valid membership data
         */
        GHashTableIter iter;
        crm_node_t *node = NULL;

        node_list = create_xml_node(NULL, XML_CIB_TAG_STATUS);

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            xmlNode *update = NULL;
            update = do_update_node_cib(node, flags, node_list, source);
        	free_xml(update);
        }

        if (crm_remote_peer_cache) {
            g_hash_table_iter_init(&iter, crm_remote_peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                xmlNode *update = NULL;
                update = do_update_node_cib(node, flags, node_list, source);
            	free_xml(update);
            }
        }

        fsa_cib_update(XML_CIB_TAG_STATUS, node_list, call_options, call_id, NULL);
        fsa_register_cib_callback(call_id, FALSE, NULL, crmd_node_update_complete);
        last_peer_update = call_id;

        free_xml(node_list);
    }
}

static void
cib_quorum_update_complete(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    fsa_data_t *msg_data = NULL;

    if (rc == pcmk_ok) {
        crm_trace("Quorum update %d complete", call_id);

    } else {
        crm_err("Quorum update %d failed: %s (%d)", call_id, pcmk_strerror(rc), rc);
        crm_log_xml_debug(msg, "failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

void
crm_update_quorum(gboolean quorum, gboolean force_update)
{
    ever_had_quorum |= quorum;

    if(ever_had_quorum && quorum == FALSE && no_quorum_suicide_escalation) {
        pcmk_panic(__FUNCTION__);
    }

    if (AM_I_DC && (force_update || fsa_has_quorum != quorum)) {
        int call_id = 0;
        xmlNode *update = NULL;
        int call_options = cib_scope_local | cib_quorum_override;

        update = create_xml_node(NULL, XML_TAG_CIB);
        crm_xml_add_int(update, XML_ATTR_HAVE_QUORUM, quorum);
        crm_xml_add(update, XML_ATTR_DC_UUID, fsa_our_uuid);

        fsa_cib_update(XML_TAG_CIB, update, call_options, call_id, NULL);
        crm_debug("Updating quorum status to %s (call=%d)", quorum ? "true" : "false", call_id);
        fsa_register_cib_callback(call_id, FALSE, NULL, cib_quorum_update_complete);
        free_xml(update);
    }
    fsa_has_quorum = quorum;
}
