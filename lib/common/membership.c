/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <glib.h> 
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>
#include <crm/ais.h> 
#include <crm/msg_xml.h>

GHashTable *crm_peer_id_cache = NULL;
GHashTable *crm_peer_cache = NULL;
unsigned long long crm_peer_seq = 0;
gboolean crm_have_quorum = FALSE;

gboolean crm_is_member_active(const crm_node_t *node) 
{
    if(node && safe_str_eq(node->state, CRM_NODE_MEMBER)) {
	return TRUE;
    }
    return FALSE;
}

static gboolean crm_reap_dead_member(
    gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    crm_node_t *search = user_data;

    if(search != NULL && node->id != search->id) {
	return FALSE;

    } else if(crm_is_member_active(value) == FALSE) {
	crm_notice("Removing %s/%u from the membership list", node->uname, node->id);
	return TRUE;
    }
    return FALSE;
}

guint reap_crm_member(uint32_t id) 
{
    int matches = 0;
    crm_node_t *node = g_hash_table_lookup(crm_peer_id_cache, GUINT_TO_POINTER(id));

    if(node == NULL) {
	crm_info("Peer %u is unknown", id);

    } else if(crm_is_member_active(node)) {
	crm_warn("Peer %u/%s is still active", id, node->uname);

    } else {
	if(g_hash_table_remove(crm_peer_id_cache, GUINT_TO_POINTER(id))) {
	    crm_notice("Removed dead peer %u from the uuid cache", id);
	    
	} else {
	    crm_warn("Peer %u/%s was not removed", id, node->uname);
	}

	matches = g_hash_table_foreach_remove(
	    crm_peer_cache, crm_reap_dead_member, node);

	crm_notice("Removed %d dead peers with id=%u from the membership list", matches, id);
    }
    
    return matches;
}

static void crm_count_member(
    gpointer key, gpointer value, gpointer user_data)
{
    guint *count = user_data;
    if(crm_is_member_active(value)) {
	*count = *count + 1;
    }
}

guint crm_active_members(void) 
{
    guint count = 0;
    g_hash_table_foreach(crm_peer_cache, crm_count_member, &count);
    return count;
}

struct peer_count_s 
{
	uint32_t peer;
	guint count;
};

static void crm_count_peer(
    gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    struct peer_count_s *search = user_data;
    if(crm_is_member_active(node) && (node->processes & search->peer)) {
	search->count = search->count + 1;
    }
}

guint crm_active_peers(uint32_t peer) 
{
    struct peer_count_s search;
    search.count = 0;
    search.peer = peer;
    g_hash_table_foreach(crm_peer_cache, crm_count_peer, &search);
    return search.count;
}

void destroy_crm_node(gpointer data)
{
    crm_node_t *node = data;
    crm_debug_2("Destroying entry for node %u", node->id);

    crm_free(node->addr);
    crm_free(node->uname);
    crm_free(node->state);
    crm_free(node->uuid);
    crm_free(node);
}

void crm_peer_init(void)
{
    static gboolean initialized = FALSE;
    if(initialized) {
	return;
    }
    initialized = TRUE;

    crm_peer_destroy();
    if(crm_peer_cache == NULL) {
	crm_peer_cache = g_hash_table_new_full(
	    g_str_hash, g_str_equal, NULL, destroy_crm_node);
    }

    if(crm_peer_id_cache == NULL) {
	crm_peer_id_cache = g_hash_table_new_full(
	    g_direct_hash, g_direct_equal, NULL, NULL);
    }
}

void crm_peer_destroy(void)
{
    if(crm_peer_cache != NULL) {
	g_hash_table_destroy(crm_peer_cache);
	crm_peer_cache = NULL;
    }
    
    if(crm_peer_id_cache != NULL) {
	g_hash_table_destroy(crm_peer_id_cache);
	crm_peer_id_cache = NULL;
    }
}

void (*crm_status_callback)(enum crm_status_type, crm_node_t*, const void*) = NULL;
    
void crm_set_status_callback(
    void (*dispatch)(enum crm_status_type,crm_node_t*, const void*))
{
    crm_status_callback = dispatch;
}

static crm_node_t *crm_new_peer(unsigned int id, const char *uname)
{
    crm_node_t *node = NULL;
    CRM_CHECK(uname != NULL || id > 0, return NULL);

    crm_debug("Creating entry for node %s/%u", uname, id);
    
    crm_malloc0(node, sizeof(crm_node_t));
    node->state = crm_strdup("unknown");

    if(id > 0) {
	node->id = id;
	crm_info("Node %s now has id: %u", crm_str(uname), id);
	g_hash_table_replace(crm_peer_id_cache, GUINT_TO_POINTER(node->id), node);
    }
    
    if(uname) {
	node->uname = crm_strdup(uname);
	CRM_ASSERT(node->uname != NULL);
	crm_info("Node %u is now known as %s", id, node->uname);
	g_hash_table_replace(crm_peer_cache, node->uname, node);

	if(is_openais_cluster()) {
	    node->uuid = crm_strdup(node->uname);
	}

	if(crm_status_callback) {
	    crm_status_callback(crm_status_uname, node, NULL);
	}	
    }
    
    return node;
}

crm_node_t *crm_get_peer(unsigned int id, const char *uname)
{
    crm_node_t *node = NULL;
    if(uname != NULL) {
	node = g_hash_table_lookup(crm_peer_cache, uname);
    }
    
    if(node == NULL && id > 0) {
	node = g_hash_table_lookup(crm_peer_id_cache, GUINT_TO_POINTER(id));
	if(node && node->uname && uname) {
	    crm_crit("Node %s and %s share the same cluster node id '%u'!",
		     node->uname, uname, id);
	    
	    /* NOTE: Calling crm_new_peer() means the entry in 
	     * crm_peer_id_cache will point to the new entity
	     */

	    /* TODO: Replace the old uname instead? */
	    node = crm_new_peer(id, uname);
	    CRM_ASSERT(node->uname != NULL);
	}
    }

    if(node && uname && node->uname == NULL) {
	node->uname = crm_strdup(uname);
	crm_info("Node %u is now known as %s", id, uname);	
	g_hash_table_insert(crm_peer_cache, node->uname, node);
	if(crm_status_callback) {
	    crm_status_callback(crm_status_uname, node, NULL);
	}
	
    }

    if(node && id > 0 && id != node->id) {
	g_hash_table_remove(crm_peer_id_cache, GUINT_TO_POINTER(node->id));
	g_hash_table_insert(crm_peer_id_cache, GUINT_TO_POINTER(id), node);
	node->id = id;
	crm_info("Node %s now has id: %u", crm_str(uname), id);	
    }
    
    return node;
}

crm_node_t *crm_update_peer(
    unsigned int id, uint64_t born, uint64_t seen, int32_t votes, uint32_t children,
    const char *uuid, const char *uname, const char *addr, const char *state) 
{
    gboolean state_changed = FALSE;
    gboolean addr_changed = FALSE;
    gboolean procs_changed = FALSE;
    gboolean votes_changed = FALSE;
    
    crm_node_t *node = NULL;
    CRM_CHECK(uname != NULL || id > 0, return NULL);
    CRM_ASSERT(crm_peer_cache != NULL);
    CRM_ASSERT(crm_peer_id_cache != NULL);

    node = crm_get_peer(id, uname);
    if(node == NULL) {
	node = crm_new_peer(id, uname);

	/* do it now so we don't get '(new)' everywhere */
	node->votes = votes;
	node->processes = children;
	if(addr) {
	    node->addr = crm_strdup(addr);
	}
    }

    if(votes > 0 && node->votes != votes) {
	votes_changed = TRUE;
	node->votes = votes;
    }
    
    if(node->uuid == NULL) {
	if(uuid != NULL) {
	    node->uuid = crm_strdup(uuid);
	    
	} else if(node->uname != NULL && is_openais_cluster()) {
	    node->uuid = crm_strdup(node->uname);
	}
    }

    if(children > 0 && children != node->processes) {
	uint32_t last = node->processes;
	node->processes = children;
	procs_changed = TRUE;

	if(crm_status_callback) {
	    crm_status_callback(crm_status_processes, node, &last);
	}
    }

    if(born != 0) {
	node->born = born;
    }

    if(state != NULL && safe_str_neq(node->state, state)) {
	char *last = node->state;
	node->state = crm_strdup(state);
	state_changed = TRUE;

	if(crm_status_callback) {
	    crm_status_callback(crm_status_nstate, node, last);
	}
	crm_free(last);
    }

    if(seen != 0 && crm_is_member_active(node)) {
	node->last_seen = seen;
    }
    
    if(addr != NULL) {
	if(node->addr == NULL || crm_str_eq(node->addr, addr, FALSE) == FALSE) {
	    addr_changed = TRUE;
	    crm_free(node->addr);
	    node->addr = crm_strdup(addr);
	}
    }

    if(state_changed || addr_changed || votes_changed || procs_changed) {
	crm_info("Node %s: id=%u state=%s%s addr=%s%s votes=%d%s born="U64T" seen="U64T" proc=%.32x%s",
		 node->uname, node->id, 
		 node->state, state_changed?" (new)":"",
		 node->addr, addr_changed?" (new)":"",
		 node->votes, votes_changed?" (new)":"",
		 node->born, node->last_seen,
		 node->processes, procs_changed?" (new)":""
	);
    }
    
    return node;
}

crm_node_t *crm_update_ais_node(xmlNode *member, long long seq)
{
    const char *id_s = crm_element_value(member, "id");
    const char *addr = crm_element_value(member, "addr");
    const char *uname = crm_element_value(member, "uname");
    const char *state = crm_element_value(member, "state");
    const char *born_s = crm_element_value(member, "born");
    const char *seen_s = crm_element_value(member, "seen");
    const char *votes_s = crm_element_value(member, "votes");
    const char *procs_s = crm_element_value(member, "processes");

    int votes = crm_int_helper(votes_s, NULL);
    unsigned int id = crm_int_helper(id_s, NULL);
    unsigned int procs = crm_int_helper(procs_s, NULL);

    /* TODO: These values will contain garbage if version < 0.7.1 */
    uint64_t born = crm_int_helper(born_s, NULL);
    uint64_t seen = crm_int_helper(seen_s, NULL);

    return crm_update_peer(id, born, seen, votes, procs, uname, uname, addr, state);
}

#if SUPPORT_HEARTBEAT
crm_node_t *crm_update_ccm_node(
    const oc_ev_membership_t *oc, int offset, const char *state, uint64_t seq)
{
    crm_node_t *node = NULL;
    const char *uuid = NULL;
    CRM_CHECK(oc->m_array[offset].node_uname != NULL, return NULL);
    uuid = get_uuid(oc->m_array[offset].node_uname);
    node = crm_update_peer(oc->m_array[offset].node_id,
			   oc->m_array[offset].node_born_on, seq, -1, 0,
			   uuid, oc->m_array[offset].node_uname, NULL, state);

    if(safe_str_eq(CRM_NODE_ACTIVE, state)) {
	/* Heartbeat doesn't send status notifications for nodes that were already part of the cluster */
	crm_update_peer_proc(
	    oc->m_array[offset].node_uname, crm_proc_ais, ONLINESTATUS);

	/* Nor does it send status notifications for processes that were already active */
	crm_update_peer_proc(
	   oc->m_array[offset].node_uname, crm_proc_crmd, ONLINESTATUS);
    }
    return node;
}
#endif

void crm_update_peer_proc(const char *uname, uint32_t flag, const char *status) 
{
    crm_node_t *node = NULL;
    gboolean changed = FALSE;
    CRM_ASSERT(crm_peer_cache != NULL);

    CRM_CHECK(uname != NULL, return);
    node = g_hash_table_lookup(crm_peer_cache, uname);	
    CRM_CHECK(node != NULL,
	      crm_err("Could not set %s.%s to %s", uname, peer2text(flag), status);
	      return);

    if(safe_str_eq(status, ONLINESTATUS)) {
	if((node->processes & flag) == 0) {
	    set_bit_inplace(node->processes, flag);
	    changed = TRUE;
	}
	
    } else if(node->processes & flag) {
	clear_bit_inplace(node->processes, flag);
	changed = TRUE;
    }

    if(changed) {
	crm_info("%s.%s is now %s", uname, peer2text(flag), status);
    }
}

#include <../../tools/attrd.h>

int crm_terminate_member(int nodeid, const char *uname, IPC_Channel *cluster)
{
    crm_node_t *node = NULL;
    gboolean success = FALSE;
    const char *reason = "Cluster connection failed";

    node = crm_get_peer(nodeid, uname);
    if(cluster == NULL) {
	reason = "No connection to the cluster";

    } else if(node == NULL) {
	if(uname) {
	    crm_err("Nothing known about node uname=%s", uname);
	    
	} else if(nodeid > 0) {
	    crm_err("Nothing known about node id=%d", nodeid);

	} else {
	    crm_err("A node id or uname is required, got %d/%p", nodeid, uname);	    
	}
	return -1;

    } else {
	time_t now = time(NULL);
	xmlNode *update = create_xml_node(NULL, __FUNCTION__);
	
	crm_xml_add(update, F_TYPE, T_ATTRD);
	crm_xml_add(update, F_ORIG, crm_system_name?crm_system_name:"unknown");
	
	crm_xml_add(update, F_ATTRD_TASK, "update");
	crm_xml_add(update, F_ATTRD_SECTION, XML_CIB_TAG_STATUS);
	crm_xml_add(update, F_ATTRD_ATTRIBUTE, "terminate");
	crm_xml_add_int(update, F_ATTRD_VALUE, now);
	crm_xml_add(update, F_ATTRD_HOST, node->uname);
	success = send_ipc_message(cluster, update);
	free_xml(update);
    }
 
    if(success) {
	crm_info("Requested that node %d/%s be terminated", nodeid, node->uname);
	return 1;
    }

    crm_err("Could not terminate node %d/%s: %s", nodeid, node->uname, reason);
    return 0;
}

int crm_terminate_member_no_mainloop(int nodeid, const char *uname, int *connection)
{
    int max = 5;
    int terminated = 0;
    static IPC_Channel *cluster = NULL;
    
    while(terminated == 0 && max > 0) {
	if(cluster == NULL) {
	    crm_info("Connecting to cluster... %d retries remaining", max);
	    cluster = init_client_ipc_comms_nodispatch(T_ATTRD);
	}

	if(connection) {
	    if(cluster != NULL) {
		*connection = cluster->ops->get_recv_select_fd(cluster);
	    } else {
		*connection = 0;
	    }
	}
	
	if(cluster != NULL) {
	    terminated = crm_terminate_member(nodeid, uname, cluster);
	}
	
	if(terminated == 0) {
	    cluster = NULL;
	    sleep(2);
	    max--;
	}
    }
    return terminated;
}
