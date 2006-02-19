/* $Id: utils.c,v 1.55 2006/02/19 09:08:32 andrew Exp $ */
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

#include <portability.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <tengine.h>
#include <heartbeat.h>
#include <clplumbing/Gmain_timeout.h>
#include <lrm/lrm_api.h>

extern cib_t *te_cib_conn;

gboolean timer_callback(gpointer data);
void set_timer_value(te_timer_t *timer, const char *time, int time_default);

const char *
get_rsc_state(const char *task, op_status_t status) 
{
	if(safe_str_eq(CRMD_ACTION_START, task)) {
		if(status == LRM_OP_PENDING) {
			return CRMD_ACTION_START_PENDING;
		} else if(status == LRM_OP_DONE) {
			return CRMD_ACTION_STARTED;
		} else {
			return CRMD_ACTION_START_FAIL;
		}
		
	} else if(safe_str_eq(CRMD_ACTION_STOP, task)) {
		if(status == LRM_OP_PENDING) {
			return CRMD_ACTION_STOP_PENDING;
		} else if(status == LRM_OP_DONE) {
			return CRMD_ACTION_STOPPED;
		} else {
			return CRMD_ACTION_STOP_FAIL;
		}
		
	} else {
		if(safe_str_eq(CRMD_ACTION_MON, task)) {
			if(status == LRM_OP_PENDING) {
				return CRMD_ACTION_MON_PENDING;
			} else if(status == LRM_OP_DONE) {
				return CRMD_ACTION_MON_OK;
			} else {
				return CRMD_ACTION_MON_FAIL;
			}
		} else {
			const char *rsc_state = NULL;
			if(status == LRM_OP_PENDING) {
				rsc_state = CRMD_ACTION_GENERIC_PENDING;
			} else if(status == LRM_OP_DONE) {
				rsc_state = CRMD_ACTION_GENERIC_OK;
			} else {
				rsc_state = CRMD_ACTION_GENERIC_FAIL;
			}
			crm_warn("Using status \"%s\" for op \"%s\"..."
				 " this is still in the experimental stage.",
				 rsc_state, task);
			return rsc_state;
		}
	}
}

void
set_timer_value(te_timer_t *timer, const char *time, int time_default)
{
	int tmp_time;

	if(timer == NULL) {
		return;
	}
	
	timer->timeout = time_default;
	tmp_time = crm_get_msec(time);
	if(tmp_time > 0) {
		timer->timeout = tmp_time;
	}
}

gboolean
start_te_timer(te_timer_t *timer)
{
	if(timer == NULL) {
		return FALSE;

	} else if(timer->source_id != 0) {
		timer->source_id = Gmain_timeout_add(
			timer->timeout, timer_callback, (void*)timer);
		CRM_ASSERT(timer->source_id != 0);
		return TRUE;

	} else if(timer->timeout < 0) {
		crm_err("Tried to start timer with -ve period");
		
	} else {
		crm_debug_3("#!!#!!# Timer already running (%d)",
			  timer->source_id);
	}
	return FALSE;		
}


gboolean
stop_te_timer(te_timer_t *timer)
{
	if(timer == NULL) {
		return FALSE;
	}
	
	if(timer->source_id != 0) {
		Gmain_timeout_remove(timer->source_id);
		timer->source_id = 0;

	} else {
		return FALSE;
	}

	return TRUE;
}

void
trigger_graph_processing(const char *fn, int line) 
{
	G_main_set_trigger(transition_trigger);
	crm_debug_2("%s:%d - Triggered graph processing", fn, line);
}

void
abort_transition_graph(
	int abort_priority, enum transition_action abort_action,
	const char *abort_text, crm_data_t *reason, const char *fn, int line) 
{
	int log_level = LOG_DEBUG;
	if(abort_priority >= INFINITY) {
		log_level = LOG_INFO;
	}

	update_abort_priority(
		transition_graph, abort_priority, abort_action, abort_text);

	crm_log_maybe(log_level, "%s:%d - Triggered graph processing : %s",
		      fn, line, abort_text);

	if(reason != NULL) {
		crm_log_xml(log_level, "Cause", reason);
	}
	
	if(transition_graph->complete) {
		notify_crmd(transition_graph);
		
	} else {
		G_main_set_trigger(transition_trigger);
	}
}
