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

#include <hb_api.h>
#include <clplumbing/ipc.h>


extern void crmd_ha_input_callback(const struct ha_msg* msg,
				   void* private_data);

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */
extern gboolean crmd_ipc_input_callback(IPC_Channel *client,
					gpointer user_data);

extern void lrm_op_callback (lrm_op_t* op);

extern void lrm_monitor_callback (lrm_mon_t* monitor);

extern void CrmdClientStatus(const char * node, const char * client,
			     const char * status, void * private);
