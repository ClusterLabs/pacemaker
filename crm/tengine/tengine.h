/* $Id: tengine.h,v 1.30 2005/10/31 08:53:04 andrew Exp $ */
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

#include <clplumbing/ipc.h>
#include <fencing/stonithd_api.h>

extern IPC_Channel *crm_ch;
extern GListPtr graph;
extern GMainLoop*  mainloop;
extern gboolean in_transition;

typedef enum {
	action_type_pseudo,
	action_type_rsc,
	action_type_crm
} action_type_e;

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


typedef struct synapse_s {
		int id;
		gboolean triggers_complete;
		gboolean complete;
		gboolean confirmed;
		GListPtr actions; /* action_t* */
		GListPtr inputs;  /* action_t* */
} synapse_t;

typedef struct te_timer_s te_timer_t;

typedef struct action_s {
		int id;
		int timeout;
		int interval;
		te_timer_t *timer;

		action_type_e type;

		GHashTable *params;
		
		gboolean sent_update;	/* sent to the CIB */
		gboolean invoked;	/* sent to the CRM */
		gboolean complete;
		gboolean can_fail;
		gboolean failed;
		
		crm_data_t *xml;
		
} action_t;


enum timer_reason {
	timeout_action,
	timeout_action_warn,
	timeout_timeout,
	timeout_abort,
};

struct te_timer_s
{
	int source_id;
	int timeout;
	enum timer_reason reason;
	action_t *action;

};

/* tengine */
extern gboolean initialize_graph(void);
extern gboolean process_graph_event(crm_data_t *event, const char *event_node);
/*	const char *event_node,   const char *event_rsc, const char *rsc_state,
 *	const char *event_action, const char *event_rc, const char *op_status); */
extern int match_graph_event(
	action_t *action, crm_data_t *event, const char *event_node);
extern action_t *match_down_event(
	int rc, const char *target, const char *filter);
extern void send_stonith_update(stonith_ops_t * op);

extern gboolean initiate_transition(void);
extern gboolean cib_action_update(action_t *action, int status);

/* utils */
extern void print_state(unsigned int log_level);
extern void send_complete(const char *text, crm_data_t *msg,
			  te_reason_t reason, te_fsa_input_t input);
extern gboolean stop_te_timer(te_timer_t *timer);
extern gboolean start_te_timer(te_timer_t *timer);
extern const char *get_rsc_state(const char *task, op_status_t status);

/* unpack */
extern gboolean unpack_graph(crm_data_t *xml_graph);
extern gboolean extract_event(crm_data_t *msg);
extern gboolean process_te_message(
	HA_Message * msg, crm_data_t *xml_data, IPC_Channel *sender);

extern uint transition_idle_timeout;
extern uint default_transition_idle_timeout;

extern te_timer_t *transition_timer;
extern te_timer_t *abort_timer;
extern cib_t *te_cib_conn;

extern const char *actiontype2text(action_type_e type);

extern void tengine_stonith_callback(stonith_ops_t * op);
extern void tengine_stonith_connection_destroy(gpointer user_data);
extern gboolean tengine_stonith_dispatch(IPC_Channel *sender, void *user_data);
extern void check_for_completion(void);
extern void process_trigger(int action_id);
extern int unconfirmed_actions(void);

#ifdef TESTING
#   define te_log_action(log_level, fmt...) {				\
		do_crm_log(log_level, __FILE__, __FUNCTION__, fmt);	\
		fprintf(stderr, fmt);					\
		fprintf(stderr, "\n");					\
	}
#else
#   define te_log_action(log_level, fmt...) do_crm_log(log_level, __FILE__, __FUNCTION__, fmt)
#endif

#endif


