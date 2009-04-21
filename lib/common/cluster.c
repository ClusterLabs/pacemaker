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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>
#include "stack.h"


xmlNode *create_common_message(
	xmlNode *original_request, xmlNode *xml_response_data);

gboolean crm_cluster_connect(
    char **our_uname, char **our_uuid, void *dispatch, void *destroy,
#if SUPPORT_HEARTBEAT
    ll_cluster_t **hb_conn
#else
    void **hb_conn
#endif
    ) {
    if(hb_conn != NULL) {
	*hb_conn = NULL;
    }
    
#if SUPPORT_AIS
    if(is_openais_cluster()) {
	crm_peer_init();
	crm_info("Connecting to OpenAIS");
	return init_ais_connection(dispatch, destroy, our_uuid, our_uname, NULL);
    }
#endif
    
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {	
	CRM_ASSERT(hb_conn != NULL);

	if(*hb_conn == NULL) {
	    *hb_conn = ll_cluster_new("heartbeat");
	}
	heartbeat_cluster = *hb_conn;

	/* make sure we are disconnected first */
	heartbeat_cluster->llc_ops->signoff(heartbeat_cluster, FALSE);

	crm_info("Connecting to Heartbeat");
	return register_heartbeat_conn(
	    heartbeat_cluster, our_uuid, our_uname, dispatch, destroy);
    }
#endif
    crm_info("Unsupported cluster stack: %s", getenv("HA_cluster_type"));
    return FALSE;
}

gboolean send_cluster_message(
    const char *node, enum crm_ais_msg_types service, xmlNode *data, gboolean ordered) {

#if SUPPORT_AIS
    if(is_openais_cluster()) {
	return send_ais_message(data, FALSE, node, service);
    }
#endif
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	return send_ha_message(heartbeat_cluster, data, node, ordered);
    }
#endif
    return FALSE;
}

static GHashTable *crm_uuid_cache = NULL;
static GHashTable *crm_uname_cache = NULL;

void
empty_uuid_cache(void)
{
	if(crm_uuid_cache != NULL) {
		g_hash_table_destroy(crm_uuid_cache);
		crm_uuid_cache = NULL;
	}
}

void
unget_uuid(const char *uname)
{
	if(crm_uuid_cache == NULL) {
		return;
	}
	g_hash_table_remove(crm_uuid_cache, uname);
}

const char *
get_uuid(const char *uname) 
{
    char *uuid_calc = NULL;
    CRM_CHECK(uname != NULL, return NULL);

    if(crm_uuid_cache == NULL) {
	crm_uuid_cache = g_hash_table_new_full(
	    g_str_hash, g_str_equal,
	    g_hash_destroy_str, g_hash_destroy_str);
    }
	
    CRM_CHECK(uname != NULL, return NULL);
    
    /* avoid blocking calls where possible */
    uuid_calc = g_hash_table_lookup(crm_uuid_cache, uname);
    if(uuid_calc != NULL) {
	return uuid_calc;
    }
    
#if SUPPORT_AIS
    if(is_openais_cluster()) {
	uuid_calc = crm_strdup(uname);
	goto fallback;
    }
#endif
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	cl_uuid_t uuid_raw;
	const char *unknown = "00000000-0000-0000-0000-000000000000";

	if(heartbeat_cluster == NULL) {
	    crm_warn("No connection to heartbeat, using uuid=uname");
	    uuid_calc = crm_strdup(uname);
	    goto fallback;
	}
	
	if(heartbeat_cluster->llc_ops->get_uuid_by_name(
	       heartbeat_cluster, uname, &uuid_raw) == HA_FAIL) {
	    crm_err("get_uuid_by_name() call failed for host %s", uname);
	    crm_free(uuid_calc);
	    return NULL;	
	} 

	crm_malloc0(uuid_calc, 50);
	cl_uuid_unparse(&uuid_raw, uuid_calc);

	if(safe_str_eq(uuid_calc, unknown)) {
		crm_warn("Could not calculate UUID for %s", uname);
		crm_free(uuid_calc);
		return NULL;
	}
    }
#endif
    
  fallback:
	g_hash_table_insert(crm_uuid_cache, crm_strdup(uname), uuid_calc);
	uuid_calc = g_hash_table_lookup(crm_uuid_cache, uname);

	return uuid_calc;
}

const char *
get_uname(const char *uuid) 
{
    char *uname = NULL;
    
    if(crm_uuid_cache == NULL) {
	crm_uname_cache = g_hash_table_new_full(
	    g_str_hash, g_str_equal,
	    g_hash_destroy_str, g_hash_destroy_str);
    }
    
    CRM_CHECK(uuid != NULL, return NULL);
    
    /* avoid blocking calls where possible */
    uname = g_hash_table_lookup(crm_uname_cache, uuid);
    if(uname != NULL) {
	return uname;
    }
    
#if SUPPORT_AIS
    if(is_openais_cluster()) {
	g_hash_table_insert(crm_uuid_cache, crm_strdup(uuid), crm_strdup(uuid));
    }
#endif
    
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	if(heartbeat_cluster != NULL && uuid != NULL) {
	    cl_uuid_t uuid_raw;
	    char *uuid_copy = crm_strdup(uuid);
	    cl_uuid_parse(uuid_copy, &uuid_raw);
	    
	    if(heartbeat_cluster->llc_ops->get_name_by_uuid(
		   heartbeat_cluster, &uuid_raw, uname, 256) == HA_FAIL) {
		crm_err("Could not calculate UUID for %s", uname);
		crm_free(uuid_copy);
	    } else {
		g_hash_table_insert(crm_uuid_cache, uuid_copy, crm_strdup(uname));
	    }
	}
    }
#endif
    return g_hash_table_lookup(crm_uname_cache, uuid);
}

void
set_uuid(xmlNode *node,const char *attr,const char *uname) 
{
	const char *uuid_calc = get_uuid(uname);
	crm_xml_add(node, attr, uuid_calc);
	return;
}

xmlNode*
createPingAnswerFragment(const char *from, const char *status)
{
	xmlNode *ping = NULL;
	
	
	ping = create_xml_node(NULL, XML_CRM_TAG_PING);
	
	crm_xml_add(ping, XML_PING_ATTR_STATUS, status);
	crm_xml_add(ping, XML_PING_ATTR_SYSFROM, from);

	return ping;
}
