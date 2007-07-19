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

#include <crm/ais.h>
GHashTable *uname_table = NULL;
GHashTable *nodeid_table = NULL;

char *uname_lookup(uint32_t nodeid) 
{
	if(uname_table == NULL) {
		uname_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal, NULL, g_hash_destroy_str);
	}
	return g_hash_table_lookup(uname_table, GUINT_TO_POINTER(nodeid));
}

uint32_t nodeid_lookup(const char *uname) 
{
	void *rc = 0;
	if(nodeid_table == NULL) {
		nodeid_table = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_hash_destroy_str, NULL);
	}
	rc = g_hash_table_lookup(nodeid_table, uname);
	return GPOINTER_TO_UINT(rc);
}

void update_uname_table(const char *uname, uint32_t nodeid) 
{
	const char *mapping = NULL;
	if(uname_table == NULL) {
		uname_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal, NULL, g_hash_destroy_str);
	}
	if(nodeid_table == NULL) {
		nodeid_table = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_hash_destroy_str, NULL);
	}

	mapping = uname_lookup(nodeid);
	if(mapping == NULL) {
		CRM_ASSERT(uname != NULL);
		crm_info("Mapping %s <-> %u", uname, nodeid);
		g_hash_table_insert(uname_table, GINT_TO_POINTER(nodeid), crm_strdup(uname));
		g_hash_table_insert(nodeid_table, crm_strdup(uname), GINT_TO_POINTER(nodeid));
		
	} else if(safe_str_neq(mapping, uname)) {
		crm_err("%s is now claiming to be node %u (current %s)", uname, nodeid, mapping);
	}
 	
	return;
}

