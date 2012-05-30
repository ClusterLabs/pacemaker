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
#ifndef XML_CRM_MESSAGES__H
#  define XML_CRM_MESSAGES__H

#  include <crm/crm.h>
#  include <crm/common/ipc.h>
#  include <crm/common/xml.h>
#  include <crm/common/cluster.h>
#  include <crmd_fsa.h>

extern void *fsa_typed_data_adv(fsa_data_t * fsa_data, enum fsa_data_type a_type,
                                const char *caller);

#  define fsa_typed_data(x) fsa_typed_data_adv(msg_data, x, __FUNCTION__)

extern void register_fsa_error_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                                   fsa_data_t * cur_data, void *new_data, const char *raised_from);

#  define register_fsa_error(cause, input, new_data) register_fsa_error_adv(cause, input, msg_data, new_data, __FUNCTION__)

extern int register_fsa_input_adv(enum crmd_fsa_cause cause, enum crmd_fsa_input input,
                                  void *data, long long with_actions,
                                  gboolean prepend, const char *raised_from);

extern void fsa_dump_queue(int log_level);
extern void route_message(enum crmd_fsa_cause cause, xmlNode * input);

#  define crmd_fsa_stall(cur_input) if(cur_input != NULL) {		\
		register_fsa_input_adv(					\
			((fsa_data_t*)cur_input)->fsa_cause, I_WAIT_FOR_EVENT, \
			((fsa_data_t*)cur_input)->data, action, TRUE, __FUNCTION__);	\
	} else {							\
		register_fsa_input_adv(					\
			C_FSA_INTERNAL, I_WAIT_FOR_EVENT,		\
			NULL, action, TRUE, __FUNCTION__);		\
	}								\

#  define register_fsa_input(cause, input, data) register_fsa_input_adv(cause, input, data, A_NOTHING, FALSE, __FUNCTION__)

#  define register_fsa_action(action) {					\
		fsa_actions |= action;					\
		if(fsa_source) {					\
			mainloop_set_trigger(fsa_source);			\
		}							\
		crm_debug("%s added action %s to the FSA",		\
			  __FUNCTION__, fsa_action2string(action));	\
	}

#  define register_fsa_input_before(cause, input, data) register_fsa_input_adv(cause, input, data, A_NOTHING, TRUE, __FUNCTION__)

#  define register_fsa_input_later(cause, input, data) register_fsa_input_adv(cause, input, data, A_NOTHING, FALSE, __FUNCTION__)

void delete_fsa_input(fsa_data_t * fsa_data);

GListPtr put_message(fsa_data_t * new_message);
fsa_data_t *get_message(void);
gboolean is_message(void);
gboolean have_wait_message(void);

extern gboolean relay_message(xmlNode * relay_message, gboolean originated_locally);

extern gboolean crmd_ipc_msg_callback(IPC_Channel * client, gpointer user_data);

extern void process_message(xmlNode * msg, gboolean originated_locally, const char *src_node_name);

extern gboolean crm_dc_process_message(xmlNode * whole_message,
                                       xmlNode * action,
                                       const char *host_from,
                                       const char *sys_from,
                                       const char *sys_to, const char *op, gboolean dc_mode);

extern gboolean send_msg_via_ipc(xmlNode * msg, const char *sys);

extern gboolean add_pending_outgoing_reply(const char *originating_node_name,
                                           const char *crm_msg_reference,
                                           const char *sys_to, const char *sys_from);

extern gboolean crmd_authorize_message(xmlNode * client_msg, crmd_client_t * curr_client);

extern gboolean send_request(xmlNode * msg, char **msg_reference);

extern enum crmd_fsa_input handle_message(xmlNode * stored_msg);

extern void lrm_op_callback(lrmd_event_data_t * op);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t * orig);

#endif
