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
#ifndef XML_CRM_MESSAGES__H
#define XML_CRM_MESSAGES__H


#include <crm/crm.h>
#include <crm/common/ipcutils.h>
#include <crmd_fsa.h>
#include <libxml/tree.h>

struct fsa_message_queue_s 
{
		gboolean processed;
		xmlNodePtr message;
		struct fsa_message_queue_s *next;
};
typedef struct fsa_message_queue_s *fsa_message_queue_t;

fsa_message_queue_t put_message(xmlNodePtr new_message);
fsa_message_queue_t get_message(void);
gboolean is_message(void);

extern gboolean relay_message(xmlNodePtr xml_relay_message,
		       gboolean originated_locally);

extern void crmd_ha_input_callback(const struct ha_msg* msg,
				   void* private_data);

extern gboolean crmd_ipc_input_callback(IPC_Channel *client,
					gpointer user_data);

extern void process_message(xmlNodePtr root_xml_node,
		     gboolean originated_locally,
		     const char *src_node_name);

extern gboolean crm_dc_process_message(xmlNodePtr whole_message,
				       xmlNodePtr action,
				       const char *host_from,
				       const char *sys_from,
				       const char *sys_to,
				       const char *op,
				       gboolean dc_mode);

extern void send_msg_via_ha(xmlNodePtr action, const char *dest_node);
extern void send_msg_via_ipc(xmlNodePtr action, const char *sys);

extern gboolean add_pending_outgoing_reply(const char *originating_node_name,
					   const char *crm_msg_reference,
					   const char *sys_to,
					   const char *sys_from);

extern gboolean crmd_authorize_message(xmlNodePtr root_xml_node,
				       IPC_Message *client_msg,
				       crmd_client_t *curr_client);
extern gboolean send_request(xmlNodePtr msg_options,
			     xmlNodePtr msg_data, 
			     const char *operation,
			     const char *host_to,
			     const char *sys_to);

extern enum crmd_fsa_input handle_message(xmlNodePtr stored_msg);

extern void lrm_op_callback (lrm_op_t* op);
extern void lrm_monitor_callback (lrm_mon_t* monitor);

#endif
