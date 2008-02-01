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

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
/* #include <sys/param.h> */
/* #include <clplumbing/cl_misc.h> */

typedef enum {
	action_type_pseudo,
	action_type_rsc,
	action_type_crm
} action_type_e;

typedef struct te_timer_s crm_action_timer_t;


typedef struct synapse_s {
		int id;
		int priority;

		gboolean ready;
		gboolean executed;
		gboolean confirmed;

		GListPtr actions; /* crm_action_t* */
		GListPtr inputs;  /* crm_action_t* */
} synapse_t;

typedef struct crm_action_s {
		int id;
		int timeout;
		int interval;
		GHashTable *params;
		action_type_e type;

		crm_action_timer_t *timer;
		synapse_t *synapse;

		gboolean sent_update;	/* sent to the CIB */
		gboolean executed;	/* sent to the CRM */
		gboolean confirmed;

		gboolean failed;
		gboolean can_fail;
		
		xmlNode *xml;
		
} crm_action_t;

enum timer_reason {
	timeout_action,
	timeout_action_warn,
	timeout_abort,
};

struct te_timer_s
{
	int source_id;
	int timeout;
	enum timer_reason reason;
	crm_action_t *action;
};


/* order matters here */
enum transition_action {
	tg_stop,
	tg_abort,
	tg_restart,
	tg_shutdown,
};

typedef struct crm_graph_s 
{
		int id;
		int abort_priority;
		
		gboolean complete;
		const char *abort_reason;
		enum transition_action completion_action;
		
		int num_actions;
		int num_synapses;

		int batch_limit;
		int network_delay;
		int transition_timeout;

		GListPtr synapses; /* synpase_t* */
		
} crm_graph_t;

typedef struct crm_graph_functions_s 
{
		gboolean (*pseudo)(crm_graph_t *graph, crm_action_t *action);
		gboolean (*rsc)(crm_graph_t *graph, crm_action_t *action);
		gboolean (*crmd)(crm_graph_t *graph, crm_action_t *action);
		gboolean (*stonith)(crm_graph_t *graph, crm_action_t *action);
} crm_graph_functions_t;

enum transition_status {
	transition_active,
	transition_pending, /* active but no actions performed this time */
	transition_complete,
	transition_stopped,
	transition_terminated,
	transition_action_failed,
	transition_failed,
};


extern void set_default_graph_functions(void);
extern void set_graph_functions(crm_graph_functions_t *fns);
extern crm_graph_t *unpack_graph(xmlNode *xml_graph);
extern int run_graph(crm_graph_t *graph);
extern gboolean update_graph(crm_graph_t *graph, crm_action_t *action);
extern void destroy_graph(crm_graph_t *graph);
extern const char *transition_status(enum transition_status state);
extern void print_graph(unsigned int log_level, crm_graph_t *graph);
extern void print_action(
	int log_level, const char *prefix, crm_action_t *action);
extern void update_abort_priority(
	crm_graph_t *graph, int priority,
	enum transition_action action, const char *abort_reason);
extern const char *actiontype2text(action_type_e type);

#ifdef TESTING
#   define te_log_action(log_level, fmt, args...) {			\
		do_crm_log(log_level, fmt, ##args);			\
		fprintf(stderr, fmt"\n", ##args);			\
	}
#else
#   define te_log_action(log_level, fmt, args...) do_crm_log(log_level, fmt, ##args)
#endif
