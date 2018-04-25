/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef TENGINE__H
#  define TENGINE__H

#  include <crm/transition.h>
#  include <crm/common/mainloop.h>
#  include <crm/stonith-ng.h>
#  include <crm/services.h>
extern stonith_t *stonith_api;
extern void send_stonith_update(crm_action_t * stonith_action, const char *target,
                                const char *uuid);

/* stonith cleanup list */
void add_stonith_cleanup(const char *target);
void remove_stonith_cleanup(const char *target);
void purge_stonith_cleanup(void);
void execute_stonith_cleanup(void);

/* tengine */
extern crm_action_t *match_down_event(const char *target);
extern crm_action_t *get_cancel_action(const char *id, const char *node);

extern gboolean cib_action_update(crm_action_t * action, int status, int op_rc);
extern gboolean fail_incompletable_actions(crm_graph_t * graph, const char *down_node);
void process_graph_event(xmlNode *event, const char *event_node);

/* utils */
extern crm_action_t *get_action(int id, gboolean confirmed);
extern gboolean stop_te_timer(crm_action_timer_t * timer);
extern const char *get_rsc_state(const char *task, enum op_status status);

/* unpack */
extern gboolean process_te_message(xmlNode * msg, xmlNode * xml_data);

extern crm_graph_t *transition_graph;
extern crm_trigger_t *transition_trigger;

extern char *te_uuid;

extern void notify_crmd(crm_graph_t * graph);

void cib_fencing_updated(xmlNode *msg, int call_id, int rc, xmlNode *output,
                         void *user_data);
void cib_action_updated(xmlNode *msg, int call_id, int rc, xmlNode *output,
                        void *user_data);
gboolean action_timer_callback(gpointer data);
gboolean te_graph_trigger(gpointer user_data);
void te_update_diff(const char *event, xmlNode *msg);
void tengine_stonith_callback(stonith_t *stonith,
                              stonith_callback_data_t *data);
void update_stonith_max_attempts(const char* value);

extern void trigger_graph_processing(const char *fn, int line);
void abort_after_delay(int abort_priority, enum transition_action abort_action,
                       const char *abort_text, guint delay_ms);
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

void te_action_confirmed(crm_action_t * action);
void te_reset_job_counts(void);

#endif
