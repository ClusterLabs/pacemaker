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
#ifndef TENGINE__H
#  define TENGINE__H

#  include <crm/transition.h>
#  include <crm/common/mainloop.h>
#  include <crm/stonith-ng.h>
#  include <crm/services.h>
extern stonith_t *stonith_api;
extern GListPtr stonith_cleanup_list;
extern void send_stonith_update(crm_action_t * stonith_action, const char *target,
                                const char *uuid);

/* tengine */
extern crm_action_t *match_down_event(int rc, const char *target, const char *filter);
extern crm_action_t *get_cancel_action(const char *id, const char *node);

extern gboolean cib_action_update(crm_action_t * action, int status, int op_rc);
extern gboolean fail_incompletable_actions(crm_graph_t * graph, const char *down_node);
extern gboolean process_graph_event(xmlNode * event, const char *event_node);

/* utils */
extern crm_action_t *get_action(int id, gboolean confirmed);
extern gboolean start_global_timer(crm_action_timer_t * timer, int timeout);
extern gboolean stop_te_timer(crm_action_timer_t * timer);
extern const char *get_rsc_state(const char *task, enum op_status status);

/* unpack */
extern gboolean process_te_message(xmlNode * msg, xmlNode * xml_data);

extern crm_graph_t *transition_graph;
extern crm_trigger_t *transition_trigger;

extern char *te_uuid;

extern void notify_crmd(crm_graph_t * graph);

#  include <te_callbacks.h>

extern void trigger_graph_processing(const char *fn, int line);
extern void abort_transition_graph(int abort_priority, enum transition_action abort_action,
                                   const char *abort_text, xmlNode * reason, const char *fn,
                                   int line);

#  define trigger_graph()	trigger_graph_processing(__FUNCTION__, __LINE__)
#  define abort_transition(pri, action, text, reason)			\
	abort_transition_graph(pri, action, text, reason,__FUNCTION__,__LINE__);

extern gboolean te_connect_stonith(gpointer user_data);

extern crm_trigger_t *transition_trigger;
extern crm_trigger_t *stonith_reconnect;

extern char *failed_stop_offset;
extern char *failed_start_offset;
extern int active_timeout;
extern int stonith_op_active;
#endif
