/* $Id: tengine.h,v 1.5 2004/09/14 05:54:44 andrew Exp $ */
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

extern FILE *msg_te_strm;
extern IPC_Channel *crm_ch;
extern GListPtr graph;
extern uint default_op_timeout;
extern GMainLoop*  mainloop;
extern gboolean in_transition;

typedef enum {
	action_type_pseudo,
	action_type_rsc,
	action_type_crm,

} action_type_e;

typedef struct synapse_s {
		int id;
		gboolean complete;
		GListPtr actions; /* action_t* */
		GListPtr inputs;  /* action_t* */
} synapse_t;

typedef struct action_s {
		int id;
		int timeout;
		int timer_id;

		action_type_e type;

		gboolean invoked;
		gboolean complete;
		gboolean can_fail;
		
		xmlNodePtr xml;
		
} action_t;

/* tengine */
extern gboolean initialize_graph(void);
extern gboolean process_graph_event(xmlNodePtr event);
//	const char *event_node,   const char *event_rsc, const char *rsc_state,
//	const char *event_action, const char *event_rc, const char *op_status);
extern int match_graph_event(action_t *action, xmlNodePtr event);

extern gboolean initiate_transition(void);

/* utils */
extern void print_state(gboolean to_file);
extern void send_success(const char *text);
extern void send_abort(const char *text, xmlNodePtr msg);
extern gboolean timer_callback(gpointer data);
extern gboolean do_update_cib(xmlNodePtr xml_action, int status);

/* unpack */
extern gboolean unpack_graph(xmlNodePtr xml_graph);
extern gboolean extract_event(xmlNodePtr msg);
extern gboolean process_te_message(xmlNodePtr msg, IPC_Channel *sender);


#endif


