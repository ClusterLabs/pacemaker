/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/* put these first so that uuid_t is defined without conflicts */
#include <crm_internal.h>

#include <string.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/cluster/internal.h>

#include <pacemaker-controld.h>

void post_cache_update(int instance);

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

static void
reap_dead_nodes(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    if (crm_is_peer_active(node) == FALSE) {
        crm_update_peer_join(__func__, node, crm_join_none);

        if(node && node->uname) {
            if (pcmk__str_eq(controld_globals.our_nodename, node->uname,
                             pcmk__str_casei)) {
                crm_err("We're not part of the cluster anymore");
                register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);

            } else if (!AM_I_DC
                       && pcmk__str_eq(node->uname, controld_globals.dc_name,
                                       pcmk__str_casei)) {
                crm_warn("Our DC node (%s) left the cluster", node->uname);
                register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
            }
        }

        if ((controld_globals.fsa_state == S_INTEGRATION)
            || (controld_globals.fsa_state == S_FINALIZE_JOIN)) {
            check_join_state(controld_globals.fsa_state, __func__);
        }
        if ((node != NULL) && (node->uuid != NULL)) {
            fail_incompletable_actions(controld_globals.transition_graph,
                                       node->uuid);
        }
    }
}

void
post_cache_update(int instance)
{
    xmlNode *no_op = NULL;

    crm_peer_seq = instance;
    crm_debug("Updated cache after membership event %d.", instance);

    g_hash_table_foreach(crm_peer_cache, reap_dead_nodes, NULL);
    controld_set_fsa_input_flags(R_MEMBERSHIP);

    if (AM_I_DC) {
        populate_cib_nodes(node_update_quick | node_update_cluster | node_update_peer |
                           node_update_expected, __func__);
    }

    /*
     * If we lost nodes, we should re-check the election status
     * Safe to call outside of an election
     */
    controld_set_fsa_action_flags(A_ELECTION_CHECK);
    controld_trigger_fsa();

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

/*!
 * \internal
 * \brief Create an XML node state tag with updates
 *
 * \param[in,out] node    Node whose state will be used for update
 * \param[in]     flags   Bitmask of node_update_flags indicating what to update
 * \param[in,out] parent  XML node to contain update (or NULL)
 * \param[in]     source  Who requested the update (only used for logging)
 *
 * \return Pointer to created node state tag
 */
xmlNode *
create_node_state_update(crm_node_t *node, int flags, xmlNode *parent,
                         const char *source)
{
    const char *value = NULL;
    xmlNode *node_state;

    if (!node->state) {
        crm_info("Node update for %s cancelled: no state, not seen yet", node->uname);
       return NULL;
    }

    node_state = create_xml_node(parent, XML_CIB_TAG_STATE);

    if (pcmk_is_set(node->flags, crm_remote_node)) {
        pcmk__xe_set_bool_attr(node_state, XML_NODE_IS_REMOTE, true);
    }

    set_uuid(node_state, XML_ATTR_ID, node);

    if (crm_element_value(node_state, XML_ATTR_ID) == NULL) {
        crm_info("Node update for %s cancelled: no id", node->uname);
        free_xml(node_state);
        return NULL;
    }

    crm_xml_add(node_state, XML_ATTR_UNAME, node->uname);

    if ((flags & node_update_cluster) && node->state) {
        if (compare_version(controld_globals.dc_version, "3.18.0") >= 0) {
            // A value 0 means the node is not a cluster member.
            crm_xml_add_ll(node_state, XML_NODE_IN_CLUSTER, node->when_member);

        } else {
            pcmk__xe_set_bool_attr(node_state, XML_NODE_IN_CLUSTER,
                                   pcmk__str_eq(node->state, CRM_NODE_MEMBER,
                                                pcmk__str_casei));
        }
    }

    if (!pcmk_is_set(node->flags, crm_remote_node)) {
        if (flags & node_update_peer) {
            if (compare_version(controld_globals.dc_version, "3.18.0") >= 0) {
                // A value 0 means the peer is offline in CPG.
                crm_xml_add_ll(node_state, XML_NODE_IS_PEER,
                               node->when_online);

            } else {
                value = OFFLINESTATUS;
                if (pcmk_is_set(node->processes, crm_get_cluster_proc())) {
                    value = ONLINESTATUS;
                }
                crm_xml_add(node_state, XML_NODE_IS_PEER, value);
            }
        }

        if (flags & node_update_join) {
            if (node->join <= crm_join_none) {
                value = CRMD_JOINSTATE_DOWN;
            } else {
                value = CRMD_JOINSTATE_MEMBER;
            }
            crm_xml_add(node_state, XML_NODE_JOIN_STATE, value);
        }

        if (flags & node_update_expected) {
            crm_xml_add(node_state, XML_NODE_EXPECTED, node->expected);
        }
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
        return;

    } else if (output == NULL) {
        return;
    }

    if (pcmk__xe_is(output, XML_CIB_TAG_NODE)) {
        node_xml = output;

    } else {
        node_xml = pcmk__xml_first_child(output);
    }

    for (; node_xml != NULL; node_xml = pcmk__xml_next(node_xml)) {
        const char *node_uuid = NULL;
        const char *node_uname = NULL;
        GHashTableIter iter;
        crm_node_t *node = NULL;
        gboolean known = FALSE;

        if (!pcmk__xe_is(node_xml, XML_CIB_TAG_NODE)) {
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
                && pcmk__str_eq(node->uuid, node_uuid, pcmk__str_casei)
                && node->uname
                && pcmk__str_eq(node->uname, node_uname, pcmk__str_casei)) {

                known = TRUE;
                break;
            }
        }

        if (known == FALSE) {
            cib_t *cib_conn = controld_globals.cib_conn;
            int delete_call_id = 0;
            xmlNode *node_state_xml = NULL;

            crm_notice("Deleting unknown node %s/%s which has conflicting uname with %s",
                       node_uuid, node_uname, new_node_uuid);

            delete_call_id = cib_conn->cmds->remove(cib_conn, XML_CIB_TAG_NODES,
                                                    node_xml, cib_scope_local);
            fsa_register_cib_callback(delete_call_id, strdup(node_uuid),
                                      remove_conflicting_node_callback);

            node_state_xml = create_xml_node(NULL, XML_CIB_TAG_STATE);
            crm_xml_add(node_state_xml, XML_ATTR_ID, node_uuid);
            crm_xml_add(node_state_xml, XML_ATTR_UNAME, node_uname);

            delete_call_id = cib_conn->cmds->remove(cib_conn,
                                                    XML_CIB_TAG_STATUS,
                                                    node_state_xml,
                                                    cib_scope_local);
            fsa_register_cib_callback(delete_call_id, strdup(node_uuid),
                                      remove_conflicting_node_callback);
            free_xml(node_state_xml);
        }
    }
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

void
populate_cib_nodes(enum node_update_flags flags, const char *source)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    int call_id = 0;
    gboolean from_hashtable = TRUE;
    xmlNode *node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);

#if SUPPORT_COROSYNC
    if (!pcmk_is_set(flags, node_update_quick) && is_corosync_cluster()) {
        from_hashtable = pcmk__corosync_add_nodes(node_list);
    }
#endif

    if (from_hashtable) {
        GHashTableIter iter;
        crm_node_t *node = NULL;
        GString *xpath = NULL;

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            xmlNode *new_node = NULL;

            if ((node->uuid != NULL) && (node->uname != NULL)) {
                crm_trace("Creating node entry for %s/%s", node->uname, node->uuid);
                if (xpath == NULL) {
                    xpath = g_string_sized_new(512);
                } else {
                    g_string_truncate(xpath, 0);
                }

                /* We need both to be valid */
                new_node = create_xml_node(node_list, XML_CIB_TAG_NODE);
                crm_xml_add(new_node, XML_ATTR_ID, node->uuid);
                crm_xml_add(new_node, XML_ATTR_UNAME, node->uname);

                /* Search and remove unknown nodes with the conflicting uname from CIB */
                pcmk__g_strcat(xpath,
                               "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION
                               "/" XML_CIB_TAG_NODES "/" XML_CIB_TAG_NODE
                               "[@" XML_ATTR_UNAME "='", node->uname, "']"
                               "[@" XML_ATTR_ID "!='", node->uuid, "']", NULL);

                call_id = cib_conn->cmds->query(cib_conn,
                                                (const char *) xpath->str,
                                                NULL,
                                                cib_scope_local|cib_xpath);
                fsa_register_cib_callback(call_id, strdup(node->uuid),
                                          search_conflicting_node_callback);
            }
        }

        if (xpath != NULL) {
            g_string_free(xpath, TRUE);
        }
    }

    crm_trace("Populating <nodes> section from %s", from_hashtable ? "hashtable" : "cluster");

    if ((controld_update_cib(XML_CIB_TAG_NODES, node_list, cib_scope_local,
                             node_list_update_callback, NULL) == pcmk_rc_ok)
         && (crm_peer_cache != NULL) && AM_I_DC) {
        /*
         * There is no need to update the local CIB with our values if
         * we've not seen valid membership data
         */
        GHashTableIter iter;
        crm_node_t *node = NULL;

        free_xml(node_list);
        node_list = create_xml_node(NULL, XML_CIB_TAG_STATUS);

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            create_node_state_update(node, flags, node_list, source);
        }

        if (crm_remote_peer_cache) {
            g_hash_table_iter_init(&iter, crm_remote_peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                create_node_state_update(node, flags, node_list, source);
            }
        }

        controld_update_cib(XML_CIB_TAG_STATUS, node_list, cib_scope_local,
                            crmd_node_update_complete, NULL);
    }
    free_xml(node_list);
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
    bool has_quorum = pcmk_is_set(controld_globals.flags, controld_has_quorum);

    if (quorum) {
        controld_set_global_flags(controld_ever_had_quorum);

    } else if (pcmk_all_flags_set(controld_globals.flags,
                                  controld_ever_had_quorum
                                  |controld_no_quorum_suicide)) {
        pcmk__panic(__func__);
    }

    if (AM_I_DC
        && ((has_quorum && !quorum) || (!has_quorum && quorum)
            || force_update)) {
        xmlNode *update = NULL;

        update = create_xml_node(NULL, XML_TAG_CIB);
        crm_xml_add_int(update, XML_ATTR_HAVE_QUORUM, quorum);
        crm_xml_add(update, XML_ATTR_DC_UUID, controld_globals.our_uuid);

        crm_debug("Updating quorum status to %s", pcmk__btoa(quorum));
        controld_update_cib(XML_TAG_CIB, update, cib_scope_local,
                            cib_quorum_update_complete, NULL);
        free_xml(update);

        /* Quorum changes usually cause a new transition via other activity:
         * quorum gained via a node joining will abort via the node join,
         * and quorum lost via a node leaving will usually abort via resource
         * activity and/or fencing.
         *
         * However, it is possible that nothing else causes a transition (e.g.
         * someone forces quorum via corosync-cmaptcl, or quorum is lost due to
         * a node in standby shutting down cleanly), so here ensure a new
         * transition is triggered.
         */
        if (quorum) {
            /* If quorum was gained, abort after a short delay, in case multiple
             * nodes are joining around the same time, so the one that brings us
             * to quorum doesn't cause all the remaining ones to be fenced.
             */
            abort_after_delay(INFINITY, pcmk__graph_restart, "Quorum gained",
                              5000);
        } else {
            abort_transition(INFINITY, pcmk__graph_restart, "Quorum lost",
                             NULL);
        }
    }

    if (quorum) {
        controld_set_global_flags(controld_has_quorum);
    } else {
        controld_clear_global_flags(controld_has_quorum);
    }
}
