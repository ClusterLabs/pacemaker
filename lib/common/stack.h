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

#ifndef CRM_STACK__H
#define CRM_STACK__H

#if SUPPORT_HEARTBEAT
extern ll_cluster_t *heartbeat_cluster;
extern gboolean send_ha_message(ll_cluster_t *hb_conn, xmlNode *msg,
				const char *node, gboolean force_ordered);
extern gboolean ha_msg_dispatch(ll_cluster_t *cluster_conn, gpointer user_data);

extern gboolean register_heartbeat_conn(
    ll_cluster_t *hb_cluster, char **uuid, char **uname,
    void (*hb_message)(HA_Message *msg, void* private_data),
    void (*hb_destroy)(gpointer user_data));

#endif

#if SUPPORT_AIS

extern gboolean send_ais_message(
    xmlNode *msg, gboolean local,
    const char *node, enum crm_ais_msg_types dest);

extern void terminate_ais_connection(void);
extern gboolean init_ais_connection(
    gboolean (*dispatch)(AIS_Message*,char*,int),
    void (*destroy)(gpointer), char **our_uuid, char **our_uname);

#endif

#endif
