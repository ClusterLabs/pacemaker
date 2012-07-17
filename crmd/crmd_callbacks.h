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

#include <crm/cluster.h>

extern void crmd_ha_msg_filter(xmlNode * msg);

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */

extern void crmd_ipc_connection_destroy(gpointer user_data);

extern void lrm_op_callback(lrmd_event_data_t * op);

extern void crmd_ha_status_callback(const char *node, const char *status, void *private_data);

extern void crmd_client_status_callback(const char *node, const char *client, const char *status,
                                        void *private);

extern void msg_ccm_join(const xmlNode * msg, void *foo);

extern void crmd_cib_connection_destroy(gpointer user_data);

extern gboolean crm_fsa_trigger(gpointer user_data);

extern void peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data);

void default_cib_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data);

#if SUPPORT_HEARTBEAT
void crmd_ha_msg_callback(HA_Message * hamsg, void *private_data);
#endif
