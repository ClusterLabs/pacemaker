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
#ifndef CRMD__H
#define CRMD__H

extern const char* daemon_name;
extern oc_ev_t   * ev_token;     // for CCM comms
extern int	   my_ev_fd;     // for CCM comms
extern gboolean    i_am_dc;
extern int         i_am_in;

extern ll_cluster_t *hb_cluster;
extern GHashTable   *pending_actions;
extern IPC_Channel  *cib_channel;

extern gboolean crmd_ipc_input_dispatch(IPC_Channel *client, gpointer user_data);
extern void msg_ccm_join(const struct ha_msg *msg, void *foo);
extern void crmd_msg_callback(const struct ha_msg* msg, void* private_data);
extern void my_ms_events(oc_ed_t event, void *cookie, size_t size, const void *data);
extern void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );
extern void process_message(xmlNodePtr root_xml_node, gboolean from_ipc, const char *src_node_name);
extern gboolean crmd_client_connect(IPC_Channel *newclient, gpointer user_data);

#endif
