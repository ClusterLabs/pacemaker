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
#include <crm/common/ipc.h>
#include <crmd_fsa.h>
#include <libxml/tree.h>

void register_fsa_input_adv(
	enum crmd_fsa_cause cause, enum crmd_fsa_input input,
	void *data, long long with_actions,
	gboolean after, const char *raised_from);


#define crmd_fsa_stall() register_fsa_input_adv(msg_data->fsa_cause, I_WAIT_FOR_EVENT, msg_data->data, action, FALSE, __FUNCTION__)

#define register_fsa_input(cause, input, data) register_fsa_input_adv(cause, input, data, A_NOTHING, FALSE, __FUNCTION__)

#define register_fsa_input_later(cause, input, data) register_fsa_input_adv(cause, input, data, A_NOTHING, TRUE, __FUNCTION__)

#define register_fsa_input_w_actions(cause, input, data, actions) register_fsa_input_adv(cause, input, data, actions, FALSE, __FUNCTION__)

void delete_fsa_input(fsa_data_t *fsa_data);

GListPtr put_message(fsa_data_t *new_message);
fsa_data_t *get_message(void);
gboolean is_message(void);
gboolean have_wait_message(void);

extern gboolean relay_message(xmlNodePtr xml_relay_message,
		       gboolean originated_locally);

extern void crmd_ha_msg_callback(const struct ha_msg* msg,
				   void* private_data);

extern gboolean crmd_ipc_msg_callback(IPC_Channel *client,
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
			     const char *sys_to,
			     char **msg_reference);

extern gboolean store_request(xmlNodePtr msg_options,
			      xmlNodePtr msg_data, 
			      const char *operation,
			      const char *sys_to);

extern enum crmd_fsa_input handle_message(xmlNodePtr stored_msg);

extern gboolean send_ha_reply(ll_cluster_t *hb_cluster,
			      xmlNodePtr xml_request,
			      xmlNodePtr xml_response_data);

extern void lrm_op_callback (lrm_op_t* op);

extern char *create_dc_heartbeat(void);
extern int send_dc_heartbeat(const char *xml_text);

#endif
