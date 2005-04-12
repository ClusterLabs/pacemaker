/* $Id: callbacks.h,v 1.8 2005/04/12 09:25:03 andrew Exp $ */
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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <hb_api.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>

#include <ocf/oc_event.h>
/* #include <ocf/oc_membership.h> */

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>

extern gboolean   cib_is_master;
extern gboolean   cib_have_quorum;
extern GHashTable *client_list;
extern GHashTable *peer_hash;

typedef struct cib_client_s 
{
		char  *id;
		char  *name;
		char  *callback_id;

		const char  *channel_name;

		IPC_Channel *channel;
		GCHSource   *source;

		int pre_notify;
		int post_notify;
		int confirmations;
		
		GList *delegated_calls;
} cib_client_t;

typedef struct cib_operation_s
{
		const char* 	operation;
		gboolean	modifies_cib;
		gboolean	needs_privileges;
		gboolean	needs_quorum;
		gboolean	needs_section;
		gboolean	needs_data;
		enum cib_errors (*fn)(
		const char *, int, const char *, crm_data_t*, crm_data_t**);
} cib_operation_t;

extern cib_operation_t cib_server_ops[];

extern gboolean cib_client_connect(IPC_Channel *channel, gpointer user_data);
extern gboolean cib_null_callback (IPC_Channel *channel, gpointer user_data);
extern gboolean cib_rw_callback   (IPC_Channel *channel, gpointer user_data);
extern gboolean cib_ro_callback   (IPC_Channel *channel, gpointer user_data);
extern gboolean cib_ha_dispatch   (IPC_Channel *channel, gpointer user_data);

extern void cib_peer_callback(const HA_Message * msg, void* private_data);
extern void cib_client_status_callback(const char * node, const char * client,
				       const char * status, void * private);

extern gboolean cib_ccm_dispatch(int fd, gpointer user_data);

extern void cib_ccm_msg_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data);
