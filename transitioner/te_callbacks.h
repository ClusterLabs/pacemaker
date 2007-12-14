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
#ifndef TE_CALLBACKS__H
#define TE_CALLBACKS__H

extern void cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
				crm_data_t *output, void *user_data);

extern void cib_action_updated(const HA_Message *msg, int call_id, int rc,
			       crm_data_t *output, void *user_data);

extern gboolean global_timer_callback(gpointer data);
extern gboolean action_timer_callback(gpointer data);

extern gboolean te_graph_trigger(gpointer user_data);

extern void tengine_stonith_callback(stonith_ops_t * op);

extern void tengine_stonith_connection_destroy(gpointer user_data);

#if SUPPORT_HEARTBEAT
extern gboolean tengine_stonith_dispatch(IPC_Channel *sender, void *user_data);
#endif

#endif
