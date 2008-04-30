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
#include <crm/common/cluster.h>
#include <heartbeat.h>
#include <crm/ais.h> 

struct quorum_count_s 
{
	guint votes_max;
	guint votes_active;
	guint votes_total;
	guint nodes_max;
	guint nodes_total;
};

GHashTable *crm_peer_cache = NULL;
unsigned long long crm_peer_seq = 0;
unsigned long long crm_max_peers = 0;
struct quorum_count_s quorum_stats;
gboolean crm_have_quorum = FALSE;

gboolean crm_is_member_active(const crm_node_t *node) 
{
    if(safe_str_eq(node->state, CRM_NODE_MEMBER)) {
	return TRUE;
    }
    return FALSE;
}

static gboolean crm_reap_dead_member(
    gpointer key, gpointer value, gpointer user_data)
{
    if(crm_is_member_active(value) == FALSE) {
	return TRUE;
    }
    return FALSE;
}

guint reap_crm_membership(void) 
{
    /* remove all dead members */
    return g_hash_table_foreach_remove(
	crm_peer_cache, crm_reap_dead_member, NULL);
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
    crm_info("Destroying entry for node %u", node->id);

    crm_free(node->addr);
    crm_free(node->uname);
    crm_free(node->state);
    crm_free(node);
}

void crm_peer_init(void)
{
    crm_warn("Set these options via openais.conf");
    
    quorum_stats.votes_max    = 2;
    quorum_stats.votes_active = 0;
    quorum_stats.votes_total  = 0;
    quorum_stats.nodes_max    = 1;
    quorum_stats.nodes_total  = 0;

    crm_peer_destroy();
    if(crm_peer_cache == NULL) {
	crm_peer_cache = g_hash_table_new_full(
	    g_str_hash, g_str_equal, NULL, destroy_crm_node);
    }
}

void crm_peer_destroy(void)
{
    if(crm_peer_cache != NULL) {
	g_hash_table_destroy(crm_peer_cache);
	crm_peer_cache = NULL;
    }
}

crm_node_t *crm_update_peer(
    unsigned int id, unsigned long long born, int32_t votes, uint32_t children,
    const char *uuid, const char *uname, const char *addr, const char *state) 
{
    crm_node_t *node = NULL;
    CRM_CHECK(uname != NULL, return NULL);
    CRM_ASSERT(crm_peer_cache != NULL);

    node = g_hash_table_lookup(crm_peer_cache, uname);	

    if(node == NULL) {	
	crm_info("Creating entry for node %s/%u/%llu", uname, id, born);
	CRM_CHECK(id >= 0, return NULL);
	CRM_CHECK(uuid != NULL, return NULL);

	crm_malloc0(node, sizeof(crm_node_t));
	node->id = id;
	node->born = 0;
	node->processes = 0;
	node->uuid = crm_strdup(uuid);
	node->uname = crm_strdup(uname);
	node->votes = votes;

	node->addr = NULL;
	node->state = crm_strdup("unknown");
	
	g_hash_table_insert(crm_peer_cache, node->uname, node);
	node = g_hash_table_lookup(crm_peer_cache, uname);
	CRM_ASSERT(node != NULL);
    }

    if(votes > 0 && node->votes != votes) {
	node->votes = votes;
	crm_info("Node %s now has %d votes", node->uname, votes);
    }
    
    if(id > 0 && id != node->id) {
	node->id = id;
	crm_info("Node %s now has id %u", node->uname, id);
    }

    if(children > 0 && children != node->processes) {
	crm_info("Node %s now has children: %.32x (%u)",
		 node->uname, children, children);
	node->processes = children;
    }
    
    if(state != NULL) {
	if(node->state == NULL
	   || crm_str_eq(node->state, state, FALSE) == FALSE) {
	    crm_free(node->state);
	    node->state = crm_strdup(state);
	    crm_info("Node %s is now: %s", node->uname, state);
	    if(crm_is_member_active(node)) {
		node->born = born;
	    } else {
		node->born = -1;
	    }
	}
    }

    if(addr != NULL) {
	if(node->addr == NULL || crm_str_eq(node->addr, addr, FALSE) == FALSE) {
	    crm_free(node->addr);
	    node->addr = crm_strdup(addr);
	    crm_info("Node %s now has address: %s", node->uname, addr);
	}
    }
    return node;
}

crm_node_t *crm_update_ais_node(xmlNode *member, long long seq)
{
    const char *addr = crm_element_value(member, "addr");
    const char *uname = crm_element_value(member, "uname");
    const char *state = crm_element_value(member, "state");
    const char *id_s = crm_element_value(member, "id");
    const char *votes_s = crm_element_value(member, "votes");
    const char *procs_s = crm_element_value(member, "processes");

    int votes = crm_int_helper(votes_s, NULL);
    unsigned int id = crm_int_helper(id_s, NULL);
    unsigned int procs = crm_int_helper(procs_s, NULL);

    return crm_update_peer(id, seq, votes, procs, uname, uname, addr, state);
}

#if SUPPORT_HEARTBEAT
crm_node_t *crm_update_ccm_node(
    const oc_ev_membership_t *oc, int offset, const char *state)
{
    crm_node_t *node = NULL;
    const char *uuid = NULL;
    CRM_CHECK(oc->m_array[offset].node_uname != NULL, return NULL);
    uuid = get_uuid(oc->m_array[offset].node_uname);
    node = crm_update_peer(oc->m_array[offset].node_id,
			   oc->m_array[offset].node_born_on, -1, 0,
			   uuid, oc->m_array[offset].node_uname, NULL, state);

    if(safe_str_eq(CRM_NODE_ACTIVE, state)) {
	crm_update_peer_proc(
	    oc->m_array[offset].node_uname, crm_proc_ais, ONLINESTATUS);
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
    CRM_CHECK(node != NULL, return);

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

static void crm_count_quorum(
    gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    quorum_stats.nodes_total += 1;
    quorum_stats.votes_total += node->votes;
    if(crm_is_member_active(node)) {
	quorum_stats.votes_active = quorum_stats.votes_active + node->votes;
    }
}

gboolean crm_calculate_quorum(void) 
{
    unsigned int limit = 0;
    gboolean quorate = TRUE;
    quorum_stats.votes_total = 0;
    quorum_stats.nodes_total = 0;
    quorum_stats.votes_active = 0;

    g_hash_table_foreach(crm_peer_cache, crm_count_quorum, NULL);

    if(quorum_stats.votes_total > quorum_stats.votes_max) {
	crm_info("Known quorum votes: %u -> %u",
		 quorum_stats.votes_max, quorum_stats.votes_total);
	quorum_stats.votes_max = quorum_stats.votes_total;
    }

    if(quorum_stats.nodes_total > quorum_stats.nodes_max) {
	crm_info("Known quorum nodes: %u -> %u",
		 quorum_stats.nodes_max, quorum_stats.nodes_total);
	quorum_stats.nodes_max = quorum_stats.nodes_total;
    }

    limit = (quorum_stats.votes_max + 2) / 2;
    if(quorum_stats.votes_active < limit) {
	quorate = FALSE;
    }

    crm_debug("known: %u, available: %u, limit: %u, active: %u: %s",
	      quorum_stats.votes_max, quorum_stats.votes_total,
	      limit, quorum_stats.votes_active, quorate?"true":"false");

    if(quorate != crm_have_quorum) {
	crm_notice("Membership %llu: quorum %s",
		   crm_peer_seq, quorate?"attained":"lost");

    } else {
	crm_debug("Membership %llu: quorum %s",
		  crm_peer_seq, quorate?"retained":"lost");
    }

    crm_have_quorum = quorate;
    return quorate;
}

/* Code appropriated (with permission) from cman/daemon/commands.c under GPLv2 */

#if 0
static int calculate_quorum(int allow_decrease, int max_expected, unsigned int *ret_total_votes)
{
	struct list *nodelist;
	struct cluster_node *node;
	unsigned int total_votes = 0;
	unsigned int highest_expected = 0;
	unsigned int newquorum, q1, q2;
	unsigned int total_nodes = 0;

	list_iterate(nodelist, &cluster_members_list) {
		node = list_item(nodelist, struct cluster_node);

		if (node->state == NODESTATE_MEMBER) {
			highest_expected =
				max(highest_expected, node->expected_votes);
			total_votes += node->votes;
			total_nodes++;
		}
	}
	if (quorum_device && quorum_device->state == NODESTATE_MEMBER)
		total_votes += quorum_device->votes;

	if (max_expected > 0)
		highest_expected = max_expected;

	/* This quorum calculation is taken from the OpenVMS Cluster Systems
	 * manual, but, then, you guessed that didn't you */
	q1 = (highest_expected + 2) / 2;
	q2 = (total_votes + 2) / 2;
	newquorum = max(q1, q2);

	/* Normally quorum never decreases but the system administrator can
	 * force it down by setting expected votes to a maximum value */
	if (!allow_decrease)
		newquorum = max(quorum, newquorum);

	/* The special two_node mode allows each of the two nodes to retain
	 * quorum if the other fails.  Only one of the two should live past
	 * fencing (as both nodes try to fence each other in split-brain.)
	 * Also: if there are more than two nodes, force us inquorate to avoid
	 * any damage or confusion.
	 */
	if (two_node && total_nodes <= 2)
		newquorum = 1;

	if (ret_total_votes)
		*ret_total_votes = total_votes;
	return newquorum;
}
#endif
