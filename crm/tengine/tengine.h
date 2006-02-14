/* $Id: tengine.h,v 1.32 2006/02/14 11:40:25 andrew Exp $ */
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
#ifndef TENGINE__H
#define TENGINE__H

#include <crm/transition.h>
#include <clplumbing/ipc.h>
#include <fencing/stonithd_api.h>

extern IPC_Channel *crm_ch;
extern GMainLoop*  mainloop;

typedef enum te_reason_e {
	te_update,
	te_done,
	te_halt,
	te_abort,
	te_abort_confirmed,
	te_failed,
	te_abort_timeout,
	te_timeout,
} te_reason_t;

typedef enum te_fsa_states_e {
	s_idle,
	s_in_transition,
	s_abort_pending,
	s_updates_pending,
	s_invalid
	
} te_fsa_state_t;

typedef enum te_fsa_inputs_e {
	i_transition,
	i_cancel,
	i_complete,
	i_cmd_complete,
	i_cib_complete,
	i_cib_confirm,
	i_cib_notify,
	i_invalid	
} te_fsa_input_t;

extern const te_fsa_state_t te_state_matrix[i_invalid][s_invalid];
extern te_fsa_state_t te_fsa_state;

/* tengine */
extern gboolean process_graph_event(crm_data_t *event, const char *event_node);
extern int match_graph_event(
	crm_action_t *action, crm_data_t *event, const char *event_node);
extern crm_action_t *match_down_event(
	int rc, const char *target, const char *filter);
extern void send_stonith_update(stonith_ops_t * op);

extern gboolean cib_action_update(crm_action_t *action, int status);

/* utils */
extern void send_complete(const char *text, crm_data_t *msg,
			  te_reason_t reason, te_fsa_input_t input);
extern gboolean stop_te_timer(te_timer_t *timer);
extern gboolean start_te_timer(te_timer_t *timer);
extern const char *get_rsc_state(const char *task, op_status_t status);

/* unpack */
extern gboolean extract_event(crm_data_t *msg);
extern gboolean process_te_message(
	HA_Message * msg, crm_data_t *xml_data, IPC_Channel *sender);

extern GTRIGSource  *transition_trigger;
extern crm_graph_t *transition_graph;
extern char *te_uuid;
extern uint default_transition_idle_timeout;

extern te_timer_t *transition_timer;
extern te_timer_t *abort_timer;
extern cib_t *te_cib_conn;

extern int unconfirmed_actions(void);
extern void notify_crmd(crm_graph_t *graph);

#include <te_callbacks.h>

extern void trigger_graph_processing(const char *fn, int line);
extern void abort_transition_graph(
	int abort_priority, enum transition_action abort_action,
	const char *abort_text, crm_data_t *reason, const char *fn, int line);

#define trigger_graph()	trigger_graph_processing(__FUNCTION__, __LINE__)
#define abort_transition(pri, action, text, reason)			\
	abort_transition_graph(pri, action, text, reason,__FUNCTION__,__LINE__);

#endif

