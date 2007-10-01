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
#include <lha_internal.h>

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

#ifdef WITH_NATIVE_AIS
#  include <crm/ais.h> 
#endif

GHashTable *crm_membership_cache = NULL;
unsigned long long crm_membership_seq = 0;

extern crm_node_t *update_membership(const char *uuid, const char *uname,
				     uint32_t id, unsigned long long born,
				     const char *addr, const char *state);

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
	crm_membership_cache, crm_reap_dead_member, NULL);
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
    g_hash_table_foreach(crm_membership_cache, crm_count_member, &count);
    return count;
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

void crm_membership_init(void)
{
    crm_membership_destroy();
    if(crm_membership_cache == NULL) {
	crm_membership_cache = g_hash_table_new_full(
	    g_str_hash, g_str_equal, NULL, destroy_crm_node);
    }
}

void crm_membership_destroy(void)
{
    if(crm_membership_cache != NULL) {
	g_hash_table_destroy(crm_membership_cache);
	crm_membership_cache = NULL;
    }
}

crm_node_t *update_membership(const char *uuid, const char *uname,
			      uint32_t id, unsigned long long born,
			      const char *addr, const char *state) 
{
    crm_node_t *node = NULL;
    CRM_CHECK(uname != NULL, return NULL);
    CRM_ASSERT(crm_membership_cache != NULL);

    node = g_hash_table_lookup(crm_membership_cache, uname);	

    if(node == NULL) {	
	crm_info("Creating entry for node %s/%u/%llu", uname, id, born);
	CRM_CHECK(id > 0, return NULL);
	CRM_CHECK(uuid != NULL, return NULL);

	crm_malloc0(node, sizeof(crm_node_t));
	node->id = id;
	node->born = -1;
	node->uuid = crm_strdup(uuid);
	node->uname = crm_strdup(uname);

	node->addr = NULL;
	node->state = crm_strdup("unknown");
	
	g_hash_table_insert(crm_membership_cache, node->uname, node);
	node = g_hash_table_lookup(crm_membership_cache, uname);
	CRM_ASSERT(node != NULL);
    }

    if(id > 0 && id != node->id) {
	node->id = id;
	crm_info("Node %s now has id %u", node->uname, id);
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

crm_node_t *update_ais_node(crm_data_t *member, long long seq)
{
    const char *addr = crm_element_value(member, "addr");
    const char *uname = crm_element_value(member, "uname");
    const char *state = crm_element_value(member, "state");
    const char *id_s = crm_element_value(member, "id");

    unsigned long id = crm_int_helper(id_s, NULL);

    return update_membership(uname, uname, id, seq, addr, state);
}

crm_node_t *update_ccm_node(
    ll_cluster_t *cluster, 
    const oc_ev_membership_t *oc, int offset, const char *state)
{
    const char *uuid = NULL;
    CRM_CHECK(oc->m_array[offset].node_uname != NULL, return NULL);
    uuid = get_uuid(cluster, oc->m_array[offset].node_uname);
    return update_membership(uuid,
			     oc->m_array[offset].node_uname,
			     oc->m_array[offset].node_id,
			     oc->m_array[offset].node_born_on,
			     NULL, state);
}

