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

#include <hb_config.h>

#include <tengine.h>

long long fsa_actions = a_nothing;

enum te_fsa_state_t
s_te_fsa(void)
{
	while(g_list_length(input_queue)) {
		te_input_t *fsa_input = get_input();;

		crm_debug("Processing input %d", fsa_input->id);
		
		new_actions  = te_action_matrix[fsa_input->input][te_fsa_state];
		te_fsa_state = te_state_matrix[fsa_input->input][te_fsa_state];
		fsa_actions |= new_actions;
		
		s_crmd_fsa_actions(fsa_input);
	}
}

void
s_crmd_fsa_actions(te_input_t *fsa_input)
{
	while(fsa_action != a_nothing) {
		IF_FSA_ACTION(A_EXIT_1,		do_exit)
			
		else IF_FSA_ACTION(A_PROCESS_CIB_CALLBACK, do_cib_callback)
		else IF_FSA_ACTION(A_PROCESS_CIB_NOTIFY,   do_cib_notify)
		else IF_FSA_ACTION(A_PROCESS_DC_COMMAND,   do_dc_command)
		else IF_FSA_ACTION(A_DC_NOTIFY,            do_notify_dc)
	}
}

/* A command from the DC */
void
do_dc_command(enum te_fsa_state_t fsa_state, te_input_t *fsa_input)
{
	struct te_data_command_s *data = fsa_data->data;
	CRM_CHECK(fsa_input->ops->type() == te_data_command);
	process_te_message(data->msg, data->xml);
}

/* A CIB update was confirmed */ 
void
do_cib_callback(enum te_fsa_state_t fsa_state, te_input_t *fsa_input)
{
	struct te_data_cib_s *data = fsa_data->data;
	CRM_CHECK(fsa_input->ops->type() == te_data_cib);
	cib_action_updated(data->msg, data->call_id, data->rc,
			   data->output, data->user_data);
}

/* Notification of an external CIB update */ 
void
do_cib_notify(enum te_fsa_state_t fsa_state, te_input_t *fsa_input)
{
	struct te_data_command_s *data = fsa_data->data;
	CRM_CHECK(fsa_input->ops->type() == te_data_command);
	te_update_confirm(NULL, data->msg);
}

void
do_notify_dc(enum te_fsa_state_t fsa_state, te_input_t *fsa_input)
{
	struct te_data_complete_s *data = fsa_data->data;
	CRM_CHECK(fsa_input->ops->type() == te_data_complete);
	send_complete(data->text, data->msg, data->reason, data->input);
}
