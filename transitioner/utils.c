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

#include <crm_internal.h>

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

GCHSource *stonith_src = NULL;
GTRIGSource *stonith_reconnect = NULL;

gboolean
te_connect_stonith(gpointer user_data)
{
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	int lpc = 0;
	int rc = ST_OK;
	IPC_Channel *fence_ch = NULL;
	if(stonith_src != NULL) {
	    crm_debug("Still connected");
	    return TRUE;
	}
	
	for(lpc = 0; lpc < 30; lpc++) {
	    crm_info("Attempting connection to fencing daemon...");
	    
	    sleep(1);
	    rc = stonithd_signon("tengine");
	    if(rc == ST_OK) {
		break;
	    }
	    
	    if(user_data != NULL) {
		crm_err("Sign-in failed: triggered a retry");
		G_main_set_trigger(stonith_reconnect);
		return TRUE;
	    }
	    
	    crm_err("Sign-in failed: pausing and trying again in 2s...");
	    sleep(1);
	}
	
	CRM_ASSERT(rc == ST_OK); /* If not, we failed 30 times... just get out */
	CRM_ASSERT(stonithd_set_stonith_ops_callback(
		       tengine_stonith_callback) == ST_OK);
	
	crm_debug_2("Grabbing IPC channel");
	fence_ch = stonithd_input_IPC_channel();
	CRM_ASSERT(fence_ch != NULL);
	
	crm_debug_2("Attaching to mainloop");
	stonith_src = G_main_add_IPC_Channel(
	    G_PRIORITY_LOW, fence_ch, FALSE, tengine_stonith_dispatch, NULL,
	    tengine_stonith_connection_destroy);
	
	CRM_ASSERT(stonith_src != NULL);
	crm_info("Connected");
	return TRUE;
    }
#endif
    return FALSE;
}

gboolean
stop_te_timer(crm_action_timer_t *timer)
{
	const char *timer_desc = "action timer";
	
	if(timer == NULL) {
		return FALSE;
	}
	if(timer->reason == timeout_abort) {
		timer_desc = "global timer";
	}
	
	if(timer->source_id != 0) {
		crm_debug_2("Stopping %s", timer_desc);
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
/*
	if(abort_priority >= INFINITY) {
		log_level = LOG_INFO;
	}
*/
	update_abort_priority(
		transition_graph, abort_priority, abort_action, abort_text);

	do_crm_log(log_level, "%s:%d - Triggered graph processing : %s",
		      fn, line, abort_text);

	if(reason != NULL) {
		const char *magic = crm_element_value(
			reason, XML_ATTR_TRANSITION_MAGIC);
		if(magic) {
			do_crm_log(log_level, "Caused by update to %s: %s",
				   ID(reason), magic);
		} else {
			crm_log_xml(log_level, "Cause", reason);
		}
	}
	
	if(transition_graph->complete) {
		notify_crmd(transition_graph);
		
	} else {
		G_main_set_trigger(transition_trigger);
	}
}
